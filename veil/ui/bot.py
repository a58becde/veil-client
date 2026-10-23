"""Стандартный интерфейс бота (docs/ARCHITECTURE.md, «Интерфейс по умолчанию»). Пользуется только veil.core.api.

Бот обслуживает только владельца (owner_id). Сообщения приёмного бота сервера уходят в Exchange.
Каждое действие владельца выполняется отдельной задачей: операции ждут ответ сервера, который
приходит через этот же цикл апдейтов.
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import re
import secrets
import time
import tomllib
from pathlib import Path

from veil import plugin_engine
from veil import plugin_manifest as pm
from veil import plugins as plug
from veil.core import api, privacy
from veil.core import export as ex
from veil.core.crypto.keys import KeyMismatchError, display_name
from veil.core.identity.nick import NickError
from veil.core.protocol import b64
from veil.core.transport.exchange import NoReplyError, ServerError
from veil.core.transport.telegram import Bot, TelegramError, keyboard, safe_filename, safe_mime
from veil.core.wallet.issue import IssueFormatError
from veil.ui.market_ui import MarketUI

log = logging.getLogger("veil.ui")
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
MEDIA_SEND = {"photo": ("sendPhoto", "photo"), "video": ("sendVideo", "video"),
              "animation": ("sendAnimation", "animation"),
              "document": ("sendDocument", "document"), "audio": ("sendAudio", "audio"),
              "voice": ("sendVoice", "voice"),
              "video_note": ("sendVideoNote", "video_note"), "sticker": ("sendSticker", "sticker")}
# MIME по умолчанию для вида, если присланный не подошёл (файлы «лично для» присылает другой человек).
MEDIA_MIME = {"photo": "image/jpeg", "video": "video/mp4", "animation": "video/mp4", "audio": "audio/mpeg",
              "voice": "audio/ogg", "video_note": "video/mp4", "sticker": "image/webp",
              "document": "application/octet-stream"}
ALBUM_WAIT = 1.5  # секунд тишины после последнего элемента альбома
SPLIT_WAIT = 2.0  # секунд тишины после части длинного текста
SPLIT_THRESHOLD = 3900  # UTF-16: текст такой длины мог быть отрезан Telegram на 4096
PLUGIN_UI_KEEP = 300     # сообщений плагинов с кнопками помнит бот (старые кнопки отвечают «устарело»)
PLUGIN_ASK_TTL = 600     # с: столько вопрос плагина ждёт ответа владельца


class Texts:
    def __init__(self, locale_file: Path, overrides: dict):
        data = tomllib.loads(locale_file.read_text("utf-8"))
        self.t = {f"{sec}.{k}": v for sec, kv in data.items() for k, v in kv.items()}
        for k, v in overrides.items():
            if k not in self.t:
                raise KeyError(f"unknown label {k}")
            self.t[k] = v

    def __call__(self, key: str, **kw) -> str:
        """Подстановка только {имя} → значение. Не str.format: тексты можно переопределить в конфиге,
        а format по «{err.__traceback__…}» достаёт внутренности процесса."""
        return _PLACEHOLDER.sub(lambda m: str(kw[m.group(1)]) if m.group(1) in kw else m.group(0),
                                self.t.get(key, key))

    def has(self, key: str) -> bool:
        return key in self.t


def _u16(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def human_wait(seconds: int) -> str:
    """3 ч 20 мин / 5 мин / 40 с."""
    h, rest = divmod(max(int(seconds), 1), 3600)
    m, sec = divmod(rest, 60)
    if h:
        return f"{h} ч {m} мин" if m else f"{h} ч"
    return f"{m} мин" if m else f"{sec} с"


DEFAULT_DELAY = [15, 90]  # с: privacy.random_delay_seconds, если в конфиге не задано


def draft_urls(msgs: list[dict]) -> list[str]:
    """Ссылки черновика (url и text_link из текста и подписей) — для кнопок плагинов on_link."""
    out = []
    for m in msgs:
        text, ents = privacy.text_of(m)
        raw = text.encode("utf-16-le")
        for e in ents or []:
            if e.get("type") == "text_link" and e.get("url"):
                out.append(e["url"])
            elif e.get("type") == "url":
                out.append(raw[2 * e["offset"]:2 * (e["offset"] + e["length"])].decode("utf-16-le", "replace"))
    return list(dict.fromkeys(out))


def outgoing(d: api.Draft) -> plug.Outgoing:
    """Черновик глазами плагина (before_send): вид, текст, режим — только чтение."""
    msgs = sorted(d.messages, key=lambda m: m["message_id"])
    text = next((t for t, _ in map(privacy.text_of, msgs) if t), "")
    return plug.Outgoing(privacy.kind(msgs), text, d.anonymous, d.hide, d.reply_to, d.to_label)


class PluginHost:
    """Действия плагинов: что можно плагину, уже проверил движок (veil.plugin_engine.Runner)."""

    def __init__(self, ui: "UI"):
        self.ui = ui
        self.proxy = ui.cfg["telegram"].get("proxy") or None
        self.http_transport = None  # подменяется в тестах

    async def notify(self, text: str) -> None:
        await self.ui._say(text)

    async def propose(self, text: str, reply_to: int | None, source: str | None = None) -> None:
        if source:
            await self.ui._say(self.ui.T("text.plugin_proposes", name=source))
        msg = await self.ui._say(text)
        if msg:
            await self.ui._new_draft([msg], reply_to=reply_to)

    async def tokens_today(self) -> int:
        return self.ui.core.store.token_counts().get(api.today(), 0)

    def storage_load(self, plugin: str) -> dict:
        return self.ui.core.store.get(plug.storage_key(plugin)) or {}

    def storage_save(self, plugin: str, data: dict) -> None:
        self.ui.core.store.put(plug.storage_key(plugin), data or None)

    async def report(self, plugin: str, event: str, err: str) -> None:
        await self.ui._say(self.ui.T("text.plugin_error", name=plugin, event=event, err=err))

    # Интерфейс плагина. plugin — его id: его называет движок бота, а не сам плагин.
    async def show(self, plugin: str, text: str, rows: list) -> int:
        token = secrets.token_urlsafe(6)
        msg = await self.ui._say(self.ui.plugin_text(plugin, text), self.ui.plugin_keyboard(token, rows))
        if not msg:
            raise plug.PluginError("владелец бота ещё не привязан")
        self.ui.plugin_ui_save(token, plugin, msg["message_id"], rows)
        return msg["message_id"]

    async def edit(self, plugin: str, message: int, text: str, rows: list) -> None:
        token = next((t for t, e in (self.ui.core.store.get("plugin_ui") or {}).items()
                      if e["m"] == message and e["p"] == plugin), None)
        if token is None:
            raise plug.PluginError("edit: это не сообщение плагина (или оно слишком старое)")
        await self.ui.bot.edit(self.ui.owner, message, self.ui.plugin_text(plugin, text),
                               markup=self.ui.plugin_keyboard(token, rows) or {"inline_keyboard": []})
        self.ui.plugin_ui_save(token, plugin, message, rows)

    async def ask(self, plugin: str, prompt: str, action: str) -> None:
        if self.ui.plugin_turn.get(plugin, 0) < time.monotonic():
            raise plug.PluginError("ask: спросить можно только в ответ на действие владельца")
        msg = await self.ui._say(self.ui.plugin_text(plugin, prompt) + "\n\n" +
                                 self.ui.T("text.plugin_ask_hint", name=self.ui.plugin_name(plugin)),
                                 self.ui._cancel_kb())
        if msg:
            self.ui.core.store.put("await", {"what": "plugin", "p": plugin, "a": action, "ask": msg["message_id"],
                                             "until": int(time.time()) + PLUGIN_ASK_TTL})


class UI:
    def __init__(self, core: api.Core, bot: Bot, texts: Texts, cfg: dict):
        self.core, self.bot, self.T, self.cfg = core, bot, texts, cfg
        # Владелец: из конфига или привязанный кодом при первом запуске (см. claim_code).
        self.owner = cfg["telegram"].get("owner_id") or core.store.get("owner_id") or 0
        self.issuer = cfg["server"]["issuer_bot"]
        self.albums: dict[str, list[dict]] = {}
        self.tasks: set[asyncio.Task] = set()
        self.split_buf: list[dict] | None = None
        self.claim_fails: dict[int, list[float]] = {}
        self.config_name = cfg.get("_config_name", "config.toml")  # для подсказок «python -m veil … init»
        # Бот в пуле (veil.pool): терминала нет, личность создаётся кнопкой в чате (docs/POOL.md).
        self.pool = cfg.get("pool") or None
        self.plugins = plug.Registry()  # плагины владельца (docs/PLUGINS.md); пустой — плагинов нет
        self.plugin_turn: dict[str, float] = {}  # плагин → до какого времени он отвечает на действие владельца (ask)
        self.market_ui = MarketUI(self, None)  # каталог плагинов (docs/MARKET.md); маркет задаёт __main__

    def claim_code(self) -> str | None:
        """Одноразовый код привязки владельца, если owner_id не задан. Печатается в журнал при запуске.

        128 случайных бит (base64url, 22 символа): подобрать нельзя. Передаётся ссылкой t.me/<бот>?start=<код>.
        """
        if self.owner:
            return None
        code = self.core.store.get("claim_code")
        if not code or len(code) < 22:
            code = secrets.token_urlsafe(16)
            self.core.store.put("claim_code", code)
        return code

    def _claim_allowed(self, user_id: int) -> bool:
        """Не больше 5 неверных кодов в час на человека (в памяти)."""
        now = time.monotonic()
        hits = [t for t in self.claim_fails.get(user_id, []) if now - t < 3600]
        self.claim_fails[user_id] = hits
        return len(hits) < 5

    async def setup(self) -> None:
        """Меню команд, проверка, что бот может писать серверу (режим bot-to-bot в @BotFather), и регистрация
        устройства личности (spec/02)."""
        await self._set_menu()
        try:
            await self.core.refresh_keys()
            self.core.store.put("b2b_error", None)
        except TelegramError as e:
            log.warning("cannot reach the server bot: %s", e)
            self.core.store.put("b2b_error", True)
        except Exception as e:
            log.warning("keys refresh: %s", e)
        await self._sync_identity(quiet=True)
        await self._announce_plugins()
        self.plugins.fire("start")

    async def _announce_plugins(self) -> None:
        """Владелец видит, какой код работает с ключами его бота: при смене набора или содержимого плагинов —
        сообщение (в том числе о подмене файла), о не загрузившихся — при каждом запуске."""
        seen, lines = plug.changes(self.plugins, self.core.store.get("plugins_seen"))
        if lines and self.owner:
            self.core.store.put("plugins_seen", seen or None)
            await self._say(self.T("text.plugins_changed", lines="\n".join(lines)))
        for name, why in self.plugins.failed:
            await self._say(self.T("text.plugin_not_loaded", name=name, err=why))
        for p in self.plugins.pending:
            await self._ask_grant(p)

    def grant_text(self, m: pm.Manifest) -> str:
        """Что просит плагин — словами: чувствительное отдельно, сеть и предупреждение о связке «чтение + сеть»."""
        tr = self.T
        lines = [tr(f"perm.{p}") for p in m.permissions if p not in pm.SENSITIVE and p != "net"]
        lines += [tr(f"perm.{p}") + " ⚠️" for p in m.sensitive]
        if m.network:
            lines.append(tr("perm.net", hosts=", ".join(m.network)))
        text = tr("text.plugin_grant", name=m.name, id=m.id, version=m.version, author=m.author,
                 perms="\n".join(f"• {x}" for x in lines) or tr("text.plugin_grant_nothing"))
        if m.leaks_to_network:
            text += "\n\n" + tr("text.plugin_grant_leak")
        if plugin_engine.os_sandbox():
            text += "\n\n" + tr("text.plugin_grant_wasm_only")
        return text

    async def _ask_grant(self, p: plug.Loaded) -> None:
        await self._say(self.grant_text(p.manifest), keyboard([[(self.T("button.plugin_allow"), f"pg:{p.name}:ok"),
                                                                 (self.T("button.plugin_deny"), f"pg:{p.name}:no")]]))

    async def _grant(self, name: str, ok: bool, msg: dict) -> None:
        """Ответ владельца на запрос разрешений. Согласие хранится по id и наборе разрешений (docs/MARKET.md)."""
        p = next((x for x in self.plugins.pending if x.name == name), None)
        if p is None:
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.cancelled"))
            return
        if not ok:
            await self.bot.edit(msg["chat"]["id"], msg["message_id"],
                                self.T("text.plugin_denied", name=p.manifest.name))
            return
        grants = dict(self.core.store.get("plugin_grants") or {})
        grants[name] = p.manifest.grant()
        self.core.store.put("plugin_grants", grants)
        await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.plugin_starting", name=p.manifest.name))
        if await self.plugins.start_package(p):
            self.core.store.put("plugins_seen", plug.changes(self.plugins, None)[0] or None)
            await self._say(self.T("text.plugin_started", name=p.manifest.name))
            await self._set_menu()
        else:
            await self._say(self.T("text.plugin_not_loaded", name=name, err=self.plugins.failed[-1][1]))

    async def _set_menu(self) -> None:
        base = ("start", "tokens", "nick", "market", "help") if self.market_ui.market else \
            ("start", "tokens", "nick", "help")
        if self.plugins.loaded:
            base = base[:-1] + ("plugins", base[-1])
        cmds = [(c, self.T(f"commands.{c}")) for c in base] + self.plugins.menu()
        try:
            await self.bot.set_commands(cmds)
        except TelegramError as e:
            log.warning("setMyCommands: %s", e)

    async def _sync_identity(self, quiet: bool = False) -> None:
        """Сверить личность с сервером: зарегистрировать устройство, сменить ключ шифрования (раз в 7 дней).
        Владельцу сообщается только то, что требует его действия, и не чаще раза на причину."""
        try:
            await self.core.sync_device()
            self.core.store.put("identity_problem", None)
            return
        except api.NoTokensError:
            problem = "text.device_need_token"
        except api.DeviceRevokedError:
            problem = "text.device_revoked"
        except api.OtherBotError:
            problem = "text.other_bot"
        except (ServerError, NoReplyError, TelegramError) as e:
            log.info("identity sync: %s", e)
            return
        if self.core.store.get("identity_problem") != problem or not quiet:
            self.core.store.put("identity_problem", problem)
            await self._say(self.T(problem, config=self.config_name))

    async def _daily_loop(self) -> None:
        """Раз в сутки: смена ключа шифрования, если ему 7 дней (прошлое «лично для» на старые ключи остаётся читаемым
        ещё 30 дней после их срока, затем они удаляются), и чистка хранилища — бот, работающий месяцами без
        перезапуска, тоже забывает «мой пост ↔ секрет» старше privacy.keep_posts_days."""
        while True:
            await asyncio.sleep(86400)
            if n := self.core.store.housekeeping(int(self.cfg["privacy"].get("keep_posts_days", 30))):
                log.info("forgot %d own posts older than privacy.keep_posts_days", n)
            await self._sync_identity(quiet=True)
            await self.market_ui.daily()  # отзыв сборок каталогом и новые версии

    # --- цикл апдейтов ---
    async def run(self) -> None:
        offset = 0
        self._spawn(self.setup())  # ответ на keys.get приходит через этот же цикл — нельзя ждать его до цикла
        sync = self.cfg["privacy"].get("auto_sync_feed_seconds", 60)
        if sync:
            self._spawn(self._feed_loop(sync))
        self._spawn(self._daily_loop())
        self._spawn(self._resume_scheduled())
        self._spawn(self._wipe_loop())
        while True:
            try:
                ups = await self.bot.get_updates(offset)
            except TelegramError as e:
                log.warning("getUpdates: %s", e)
                await asyncio.sleep(max(e.retry_after, 3))
                continue
            for u in ups:
                offset = u["update_id"] + 1
                try:
                    self._route(u)
                except Exception:
                    log.exception("update")

    def _spawn(self, coro) -> None:
        t = asyncio.create_task(self._guard(coro))
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    async def _guard(self, coro) -> None:
        try:
            await coro
        except Exception:
            log.exception("handler")

    def _route(self, u: dict) -> None:
        if "callback_query" in u:
            q = u["callback_query"]
            if q["from"]["id"] == self.owner:
                self._spawn(self._callback(q))
            return
        m = u.get("message")
        if not m or m["chat"]["type"] != "private":
            return
        sender = m.get("from") or {}
        if self.core.exchange.is_inbox(sender):
            self.core.exchange.on_inbox_message(m)
            return
        if self.pool and sender.get("id") == self.owner and callable(self.pool.get("feed_now")):
            self._spawn(self.pool["feed_now"]())  # действие владельца — лента пула обновится (не чаще раза в минуту)
        if not self.owner:
            if sender.get("is_bot"):
                return
            code = self.claim_code()
            text = m.get("text", "").strip()
            given = text[7:].strip() if text.startswith("/start ") else ""
            if given and not self._claim_allowed(sender["id"]):
                self._spawn(self.bot.send(m["chat"]["id"], self.T("text.claim_locked")))
            elif given and hmac.compare_digest(given, code):
                self.owner = sender["id"]
                self.core.owner_id = self.owner
                self.core.store.put("owner_id", self.owner)
                self.core.store.put("claim_code", None)
                self.core.store.owner_link_path.unlink(missing_ok=True)  # ссылка больше не действует
                self._spawn(self._after_claim())
            else:
                if given:
                    self.claim_fails.setdefault(sender["id"], []).append(time.monotonic())
                    reply = self.T("text.claim_wrong")
                else:
                    reply = self.T("text.not_configured")
                    if self.core.store.get("b2b_error"):
                        reply += self.T("text.not_configured_b2b")
                self._spawn(self.bot.send(m["chat"]["id"], reply))
            return
        if sender.get("id") != self.owner:
            return  # бот обслуживает только владельца
        if m.get("media_group_id"):
            self._album(m)
            return
        if self._split_part(m):
            return
        self._spawn(self._owner_message(m))

    async def _after_claim(self) -> None:
        await self._say(self.T("text.claimed"))
        await self._command("/start")  # сразу создать личность и показать 12 слов

    def _album(self, m: dict) -> None:
        g = m["media_group_id"]
        first = g not in self.albums
        self.albums.setdefault(g, []).append(m)
        if first:
            self._spawn(self._album_done(g))

    def _split_part(self, m: dict) -> bool:
        """Telegram режет текст длиннее 4096 на несколько сообщений. Длинный текст и идущие сразу за ним
        тексты собираются в один черновик — иначе владелец увидит два черновика и отправит только хвост."""
        text = m.get("text", "")
        if self.split_buf is not None and text and not text.startswith("/") and "forward_origin" not in m:
            self.split_buf.append(m)
            return True
        if privacy.utf16(text) >= SPLIT_THRESHOLD and not text.startswith("/"):
            self.split_buf = [m]
            self._spawn(self._split_done())
            return True
        return False

    async def _split_done(self) -> None:
        n = -1
        while n != len(self.split_buf):
            n = len(self.split_buf)
            await asyncio.sleep(SPLIT_WAIT)
        msgs, self.split_buf = self.split_buf, None
        if len(msgs) == 1:
            await self._owner_message(msgs[0])  # длинный, но целый: обычный путь (проверка покажет длину)
            return
        state = self.core.store.get("await")
        self.core.store.put("await", None)
        reply_to = state["n"] if state and state.get("what") == "reply" else None
        await self._new_draft(msgs, reply_to=reply_to)

    async def _album_done(self, g: str) -> None:
        n = -1
        while n != len(self.albums[g]):
            n = len(self.albums[g])
            await asyncio.sleep(ALBUM_WAIT)
        msgs = self.albums.pop(g)
        await self._new_draft(msgs)

    async def _say(self, text: str, markup: dict | None = None, reply_to: int | None = None) -> dict | None:
        if not self.owner:
            return None  # владелец ещё не привязан
        return await self.bot.send(self.owner, text, markup=markup, reply_to=reply_to)

    # --- сообщения владельца ---
    async def _owner_message(self, m: dict) -> None:
        text = m.get("text", "")
        state = self.core.store.get("await")
        if text.startswith("/"):
            self.core.store.put("await", None)
            if self.core.store.get("b2b_error"):
                await self.setup()  # владелец мог включить режим в @BotFather
                if self.core.store.get("b2b_error"):
                    await self._say(self.T("text.b2b_off"))
                    return
            await self._command(text)
            return
        if text.strip().startswith("VEILLICRES "):  # ответ бота-магазина: лицензия платного плагина
            await self.market_ui.license_response(text)
            return
        if text.strip().startswith("VEILRES "):
            await self._token_part(text)
            return
        if text.strip().startswith("VEILTOK "):
            await self._token_import(m)
            return
        if text.strip().startswith("VEILIMP "):  # ключ места назначения экспорта — без команды (docs/EXPORT.md)
            self.core.store.put("await", None)
            await self._export(text.strip())
            return
        if state and state.get("what") == "plugin":
            if int(state.get("until", 0)) < time.time():
                self.core.store.put("await", None)
                state = None
            elif "text" not in m:
                await self._say(self.T("text.plugin_ask_text_only", name=self.plugin_name(state["p"])))
                return
            else:
                self.core.store.put("await", None)
                await self.plugin_answer(state["p"], state["a"], text)
                return
        if state and state.get("what") == "nick":
            self.core.store.put("await", None)
            await self._nick(text.strip()) if text.strip() else await self._say(self.T("text.cancelled"))
            return
        if state and state.get("what") == "import" and m.get("document"):
            self.core.store.put("await", None)
            await self._import_file(m)
            return
        if state and state.get("what") == "to_nick":
            self.core.store.put("await", None)
            await self._set_recipient(state, text)
            return
        if state:
            self.core.store.put("await", None)
            if state["what"] in ("append", "replace") and "text" not in m:
                await self._say(self.T("text.edit_text_only"))
                return
            await self._awaited(state, [m])
            return
        n = api.post_number(m)
        if m.get("forward_origin") and n:
            await self._post_menu(n)
            return
        await self._new_draft([m])

    async def _command(self, text: str) -> None:
        cmd, _, arg = text.partition(" ")
        cmd = cmd.split("@")[0]
        if cmd == "/start":
            # 12 слов в Telegram не показываются и не принимаются никогда (spec/02): личность создаётся в терминале.
            # Исключение — бот в пуле: терминала у владельца нет (spec/02, «Бот в пуле»).
            await self._say(self.status_text(), self.status_keyboard())
            if self.core.has_identity():
                await self._sync_identity()
        elif cmd == "/help":
            await self._say(self.T("text.help"))
        elif cmd == "/tokens":
            await self._tokens()
        elif cmd == "/nick":
            if arg.strip():
                await self._nick(arg.strip())  # набрано вручную: /nick Имя, /nick - (убрать)
            else:
                await self._nick_menu()
        elif cmd == "/sync":
            await self._sync_once()
        elif cmd == "/export":
            await self._export(arg.strip())
        elif cmd == "/import":
            await self._import_start()
        elif cmd == "/leave" and self.pool:
            await self._say(self.T("text.pool_leave_ask"), keyboard([[(self.T("button.pool_leave"), "pool:leave"),
                                                                     (self.T("button.cancel"), "pool:stay")]]))
        elif cmd == "/market":
            await self.market_ui.open()
        elif cmd == "/cancel":
            await self._say(self.T("text.cancelled"))
        elif cmd == "/plugins":
            await self._plugins_menu()
        else:
            owner = self.plugins.commands.get(cmd[1:])
            if owner:
                self.plugin_turn[owner[0]] = time.monotonic() + plug.COMMAND_TIMEOUT
            if not await self.plugins.run_command(cmd[1:], arg.strip()):
                await self._say(self.T("text.unknown"))

    # --- черновики ---
    def _draft_markup(self, i: int, d: api.Draft, sendable: bool = True) -> dict:
        """Кнопки черновика. Варианты скрытия — только из таблицы privacy.modes (одно место для всех видов)."""
        tr = self.T
        rows = [[(tr("button.send"), f"d:{i}:send")]] if sendable else []
        if d.mode == "create":
            if self.core.nick():  # без ника пост и так выходит без подписи
                rows.append([(tr("button.anon_on") if d.anonymous else tr("button.anon_off"), f"d:{i}:anon")])
            labels = {"links": (tr("button.hide_links"), "hl"), "message": (tr("button.hide_message"), "hm"),
                      "to": (tr("button.hide_to"), "hto")}
            hide = [(labels[m][0], f"d:{i}:{labels[m][1]}") for m in privacy.modes(d.messages) if m and m != d.hide]
            if d.hide:
                hide.append((tr("button.hide_off"), f"d:{i}:h0"))
            if hide:
                rows.append(hide)
            for j, (_, _, label, _) in enumerate(self.plugins.link_buttons(draft_urls(d.messages))):
                rows.append([(f"🧩 {label}", f"pl:{i}:{j}")])
        rows.append([(tr("button.cancel"), f"d:{i}:x")])
        return keyboard(rows)

    def _draft_text(self, d: api.Draft, problems: list[tuple[str, dict]] = ()) -> str:
        tr = self.T
        hide = {"": tr("text.hide_none"), "links": tr("text.hide_links"), "message": tr("text.hide_message"),
                "to": tr("text.hide_to", who=d.to_label)}[d.hide]
        reply = tr("text.draft_reply", n=d.reply_to) if d.reply_to else ""
        nick = self.core.nick()
        sign = tr("text.sign_none") if not nick else (tr("text.sign_anon") if d.anonymous else nick)
        text = tr("text.draft", sign=sign, hide=hide, reply=reply)
        if problems:
            text += "\n\n" + "\n".join(tr("text.draft_problem", text=tr(k, **kw)) for k, kw in problems)
            text += "\n" + tr("text.draft_fix")
        return text

    async def _show_draft(self, i: int, d: api.Draft, edit: dict | None = None) -> None:
        """Показать черновик после проверки (privacy + post.check): «Отправить» есть, только если пройдёт.
        edit — сообщение, которое заменить на месте (нажатие кнопки); иначе новое сообщение внизу."""
        problems = await self.core.check_draft(d)
        text, markup = self._draft_text(d, problems), self._draft_markup(i, d, sendable=not problems)
        if edit:
            await self.bot.edit(edit["chat"]["id"], edit["message_id"], text, markup=markup)
        else:
            await self._say(text, markup, reply_to=d.messages[0]["message_id"])

    async def _new_draft(self, msgs: list[dict], **kw) -> None:
        d = api.Draft(chat_id=self.owner, messages=msgs, **kw)
        i = self.core.store.save_draft(d.to_json())
        await self._show_draft(i, d)

    async def _awaited(self, state: dict, msgs: list[dict]) -> None:
        what, n = state["what"], state["n"]
        if what == "reply":
            await self._new_draft(msgs, reply_to=n)
        else:  # append | replace — правка сразу, без черновика
            await self._run(lambda: self.core.edit_post(api.Draft(self.owner, msgs, mode=what, target=n)),
                            lambda r: self.T("text.edited", n=n, left=r.get("edits_left", "?")), name="post.edit")

    def explain(self, e: ServerError) -> str:
        """Понятное объяснение ошибки сервера вместо кода (коды пользователю не показываются)."""
        if e.code == "E_TOO_LONG":
            return self.T("text.too_long", n=e.overflow)
        key = f"error.{e.code}"
        if self.T.has(key):
            return self.T(key, wait=human_wait(e.retry_after))
        log.warning("server error without explanation: %s", e.code)  # код — только в журнал, не владельцу
        return self.T("error.default")

    async def _run(self, op, ok_text, status: dict | None = None, delay: bool = False,
                   scheduled=None, name: str = "") -> None:
        """Выполнить операцию ядра и сообщить итог: правкой сообщения status (например, «Отправляю…») или новым.
        delay — новый пост: случайная задержка privacy.random_delay_seconds, чтобы время поста в группе не совпадало
        со временем, когда владелец писал боту. Сколько ждать, владелец видит сразу. name — операция протокола
        (post.create, …): с ним плагины узнают о сбое (on_error) и о том, что токенов осталось мало."""
        failed = await self._run_op(op, ok_text, status, delay, scheduled)
        if not name:
            return
        if failed:
            self.plugins.fire("error", plug.Failure(name, failed))
            return
        left = self.core.store.token_counts().get(api.today(), 0)
        if left <= self.plugins.tokens_low and self.core.store.get("plugins_tokens_low") != api.today():
            self.core.store.put("plugins_tokens_low", api.today())  # раз в сутки, а не после каждого поста
            self.plugins.fire("tokens_low", left)

    async def _run_op(self, op, ok_text, status, delay, scheduled) -> str | None:
        """Сама операция; возвращает вид сбоя (код протокола или no_tokens, queued, …) или None — успех."""
        async def report(text: str, markup: dict | None = None) -> None:
            if status:
                await self.bot.edit(status["chat"]["id"], status["message_id"], text, markup=markup)
            else:
                await self._say(text, markup)

        lo, hi = self.cfg["privacy"].get("random_delay_seconds", DEFAULT_DELAY)
        if delay and hi > 0:
            wait = secrets.SystemRandom().uniform(max(lo, 0), hi)
            if wait >= 1:
                if scheduled:
                    scheduled(int(time.time() + wait))  # срок — в базе: перезапуск во время ожидания не теряет пост
                await report(self.T("text.sending_in", wait=human_wait(int(wait))))
                await asyncio.sleep(wait)
                await report(self.T("text.sending"))
        try:
            res = await op()
            log.info("operation ok")
            await report(ok_text(res))
            return None
        except api.NoTokensError:
            await report(self.T("text.no_tokens"), keyboard([[(self.T("button.top_up"), "tok:req")]]))
            return "no_tokens"
        except api.PostQueuedError:
            await report(self.T("text.post_queued"))
            return "queued"
        except api.NotMineError:
            await report(self.T("text.not_mine"))
            return "not_mine"
        except ServerError as e:
            log.info("server refused: %s", e.code)
            if e.hint and e.code == "E_DECRYPT":
                try:
                    await self.core.refresh_keys()
                except Exception as err:  # ответ владельцу важнее: ключи обновятся при следующем запросе
                    log.info("refresh keys failed: %s", type(err).__name__)
            await report(self.explain(e))
            return e.code
        except NoReplyError:
            await report(self.T("text.no_reply"))
            return "no_reply"
        except NickError as e:
            await report(self.T("text.nick_invalid", err=e))
            return "nick_invalid"
        except api.NoIdentityError:
            await report(self.T("text.need_identity", config=self.config_name))
            return "no_identity"
        except api.DeviceRevokedError:
            await report(self.T("text.device_revoked", config=self.config_name))
            return "device_revoked"
        except api.OtherBotError:
            await report(self.T("text.other_bot", config=self.config_name))
            return "other_bot"
        except ValueError as e:
            if "envelope too large" in str(e):
                await report(self.T("text.envelope_too_big"))
                return "too_large"
            log.exception("operation failed")
            await report(self.T("text.internal"))
            return "internal"
        except Exception:
            log.exception("operation failed")  # статус «Отправляю…» не должен зависать ни при какой ошибке
            await report(self.T("text.internal"))
            return "internal"

    async def _set_recipient(self, state: dict, text: str) -> None:
        """«Лично для…»: найти ключ получателя по нику·метке, проверить подпись (spec/02) и сверить
        с ключом, который бот уже видел у этого ника (доверие при первом использовании)."""
        m = re.fullmatch(r"\s*(.+?)\s*[·.:\s]\s*([0-9a-hjkmnp-tv-z]{6})\s*", text, re.IGNORECASE)
        if not m:
            await self._say(self.T("text.recipient_bad"))
            return
        nick, tag = m.group(1), m.group(2).lower()
        try:
            match = await self.core.find_recipient(nick, tag)
        except ServerError as e:
            await self._say(self.T("text.recipient_not_found") if e.code in ("E_NOT_FOUND", "E_NICK_INVALID")
                            else self.explain(e))
            return
        except KeyMismatchError:
            await self._say(self.T("text.recipient_unverified"))
            return
        except api.AmbiguousError:
            await self._say(self.T("text.recipient_ambiguous"))
            return
        except NickError:
            await self._say(self.T("text.recipient_bad"))
            return
        except NoReplyError:
            await self._say(self.T("text.no_reply"))
            return
        label = display_name(match["nick"], tag)
        known = self.core.known_recipient(label)
        state = dict(state, label=label, enc=match["enc_pk"], id=match["id_pk"], seq=match.get("seq", 0))
        if known and known != match["id_pk"]:
            self.core.store.put("pending_recipient", state)
            await self._say(self.T("text.recipient_changed", who=label),
                            keyboard([[(self.T("button.trust_new"), "tn:yes"), (self.T("button.cancel"), "tn:no")]]))
            return
        await self._apply_recipient(state)

    async def _apply_recipient(self, state: dict) -> None:
        raw = self.core.store.draft(state["draft"])
        if raw is None:
            return
        self.core.remember_recipient(state["label"], state["id"], state.get("seq", 0))
        d = api.Draft.from_json(raw)
        d.hide, d.to_label, d.to_pk = "to", state["label"], state["enc"]
        i = state["draft"]
        self.core.store.save_draft(d.to_json(), i)
        # Черновик выше по чату легко не заметить: старый и вопрос «Кому?» убираем, новый — внизу.
        await self.bot.delete(state["chat"], state["mid"])
        if state.get("ask"):
            await self.bot.delete(state["chat"], state["ask"])
        await self._show_draft(i, d)

    async def _post_menu(self, n: int) -> None:
        tr = self.T
        if self.core.store.post_secret(n):
            mk = keyboard([[(tr("button.upd"), f"p:{n}:append"), (tr("button.fix"), f"p:{n}:replace"),
                            (tr("button.delete"), f"p:{n}:del")],
                           [(tr("button.reply"), f"p:{n}:reply"), (tr("button.cancel"), f"p:{n}:none")]])
            await self._say(tr("text.post_actions_mine", n=n), mk)
        else:
            await self._say(tr("text.post_actions_other", n=n),
                            keyboard([[(tr("button.reply"), f"p:{n}:reply"), (tr("button.cancel"), f"p:{n}:none")]]))

    # --- интерфейс плагинов: их сообщения с кнопками, вопросы, кнопки у ссылок, меню ---
    def plugin_name(self, plugin: str) -> str:
        p = next((x for x in self.plugins.loaded if x.name == plugin), None)
        return p.manifest.name if p else plugin

    def plugin_text(self, plugin: str, text: str) -> str:
        return f"🧩 {self.plugin_name(plugin)}: {text}"

    def plugin_keyboard(self, token: str, rows: list) -> dict | None:
        """Кнопки плагина: в callback_data — только номер записи бота, данные кнопок бот хранит у себя."""
        out, k = [], 0
        for row in rows:
            out.append([])
            for text, _, _ in row:
                out[-1].append((text, f"pb:{token}:{k}"))
                k += 1
        return keyboard(out) if out else None

    def plugin_ui_save(self, token: str, plugin: str, mid: int, rows: list) -> None:
        table = dict(self.core.store.get("plugin_ui") or {})
        table[token] = {"p": plugin, "m": mid, "b": [b for row in rows for b in row], "at": int(time.time())}
        if len(table) > PLUGIN_UI_KEEP:
            table = dict(sorted(table.items(), key=lambda kv: kv[1]["at"])[-PLUGIN_UI_KEEP:])
        self.core.store.put("plugin_ui", table)

    async def _plugin_press(self, rest: str, msg: dict) -> None:
        token, _, k = rest.partition(":")
        e = (self.core.store.get("plugin_ui") or {}).get(token)
        if not e or not k.isdigit() or int(k) >= len(e["b"]) or e["m"] != msg.get("message_id"):
            await self._say(self.T("text.plugin_button_old"))
            return
        _, action, data = e["b"][int(k)]
        self.plugin_turn[e["p"]] = time.monotonic() + plug.COMMAND_TIMEOUT
        if not await self.plugins.press(e["p"], plug.Press(action, data, e["m"])):
            await self._say(self.T("text.plugin_gone", name=self.plugin_name(e["p"])))

    async def plugin_answer(self, plugin: str, action: str, text: str) -> None:
        # ответ — снова ход владельца: можно спросить ещё
        self.plugin_turn[plugin] = time.monotonic() + plug.COMMAND_TIMEOUT
        if not await self.plugins.answer(plugin, action, text):
            await self._say(self.T("text.plugin_gone", name=self.plugin_name(plugin)))

    async def _plugin_link(self, i: int, j: int) -> None:
        """Кнопка плагина у черновика со ссылкой: плагин получает только эту ссылку, не сам черновик."""
        raw = self.core.store.draft(i)
        links = self.plugins.link_buttons(draft_urls(api.Draft.from_json(raw).messages)) if raw else []
        if not 0 <= j < len(links):
            await self._say(self.T("text.plugin_button_old"))
            return
        plugin, k, _, url = links[j]
        self.plugin_turn[plugin] = time.monotonic() + plug.COMMAND_TIMEOUT
        if not await self.plugins.open_link(plugin, k, url):
            await self._say(self.T("text.plugin_gone", name=self.plugin_name(plugin)))

    async def _plugins_menu(self) -> None:
        """/plugins: работающие плагины и их команды — кнопками, набирать ничего не нужно."""
        if not self.plugins.loaded:
            await self._say(self.T("text.plugins_none"))
            return
        rows = []
        for p in self.plugins.loaded:
            for name, (owner, desc, _) in sorted(self.plugins.commands.items()):
                if owner == p.name:
                    rows.append([(f"🧩 {desc}"[:60], f"pc:{name}")])
        lines = [f"• {self.plugin_name(p.name)} {p.manifest.version}" for p in self.plugins.loaded]
        if self.market_ui.market:
            rows.append([(self.T("button.market"), "mk:p:0")])
        await self._say(self.T("text.plugins_menu", lines="\n".join(lines)), keyboard(rows) if rows else None)

    # --- ник кнопками: команда из меню уходит без аргумента ---
    async def _nick_menu(self) -> None:
        nick = self.core.nick()
        rows = [[(self.T("button.nick_change") if nick else self.T("button.nick_set"), "nk:set")]]
        if nick:
            rows[0].append((self.T("button.nick_remove"), "nk:rm"))
        text = self.T("text.nick_current", nick=nick) if nick else self.T("text.nick_none")
        await self._say(text, keyboard(rows))

    async def _nick_action(self, data: str, msg: dict) -> None:
        if data == "nk:set":
            ask = await self._say(self.T("text.nick_ask"), self._cancel_kb())
            if ask:
                self.core.store.put("await", {"what": "nick", "ask": ask["message_id"]})
        elif data == "nk:rm":  # убрать ник — токен и сутки до следующей смены: сначала спросить
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.nick_remove_ask"),
                                markup=keyboard([[(self.T("button.nick_remove_yes"), "nk:rm!"),
                                                  (self.T("button.cancel"), "aw:x")]]))
        else:
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.nick_removing"))
            await self._nick("-")

    # --- кнопки ---
    async def _callback(self, q: dict) -> None:
        await self.bot.answer(q["id"])
        data = q.get("data", "")
        msg = q.get("message") or {}
        kind, _, rest = data.partition(":")
        if kind == "d":
            i, _, action = rest.partition(":")
            await self._draft_action(int(i), action, msg)
        elif kind == "p":
            n, _, action = rest.partition(":")
            await self._post_action(int(n), action, msg)
        elif data == "aw:x":
            await self._cancel_wait(msg)
        elif data == "tok:req":
            await self._top_up()
        elif data == "tok:give" or data.startswith("tok:give:"):
            await self._token_give(data)
        elif data in ("pool:leave", "pool:stay") and self.pool:
            if data == "pool:stay":
                await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.cancelled"))
            elif callable(self.pool.get("leave")):
                await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.pool_leaving"))
                await self.pool["leave"]()
        elif data in ("id:new", "id:ok") and self.pool:
            await self._pool_identity(data, msg)
        elif data in ("ex:ok", "ex:no"):
            if data == "ex:ok":
                await self._export_confirmed(msg)
            else:
                self.core.store.put("export_pending", None)
                await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.cancelled"))
        elif kind == "pf":
            await self._private_files(int(rest), msg)
        elif kind == "mk":
            await self.market_ui.callback(rest, msg)
        elif kind == "pg":
            name, _, answer = rest.partition(":")
            await self._grant(name, answer == "ok", msg)
        elif kind == "pb":
            await self._plugin_press(rest, msg)
        elif kind == "pl":
            i, _, j = rest.partition(":")
            await self._plugin_link(int(i), int(j))
        elif kind == "pc":
            await self._command("/" + rest)
        elif data in ("nk:set", "nk:rm", "nk:rm!"):
            await self._nick_action(data, msg)
        elif data in ("tn:yes", "tn:no"):
            pending = self.core.store.get("pending_recipient")
            self.core.store.put("pending_recipient", None)
            await self.bot.edit(msg["chat"]["id"], msg["message_id"],
                                self.T("text.recipient_ok", who=pending["label"]) if pending and data == "tn:yes"
                                else self.T("text.cancelled"))
            if pending and data == "tn:yes":
                await self._apply_recipient(pending)

    def _cancel_kb(self) -> dict:
        return keyboard([[(self.T("button.cancel"), "aw:x")]])

    async def _cancel_wait(self, msg: dict) -> None:
        """«Отмена» под вопросом или выбором. Ожидание (ответ, правка, «Кому?», файл импорта) снимается, только если
        кнопка — под его же вопросом: старая кнопка не сбросит начатое позже."""
        state = self.core.store.get("await")
        if state and state.get("ask") == msg.get("message_id"):
            self.core.store.put("await", None)
            if state.get("what") == "import":
                self.core.store.put("import_sk", None)
        await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.cancelled"))

    def status_text(self) -> str:
        """Что умеет бот и что осталось сделать, чтобы публиковать: связь, токены, личность, задержка. Показывается
        на /start — владелец узнаёт всё до первой публикации, а не по очереди после каждой ошибки."""
        tr = self.T
        tokens = self.core.store.token_counts().get(api.today(), 0)
        lo, hi = self.cfg["privacy"].get("random_delay_seconds", DEFAULT_DELAY)
        lines = [tr("text.status_b2b_off") if self.core.store.get("b2b_error") else tr("text.status_b2b_ok"),
                 tr("text.status_tokens", n=tokens) if tokens else tr("text.status_tokens_none")]
        if self.core.has_identity():
            lines.append(tr("text.status_identity", sign=self.core.nick() or f"·{self.core.device.tag}"))
        else:
            lines.append(tr("text.status_identity_pool") if self.pool else
                         tr("text.status_identity_none", config=self.config_name))
        lines.append(tr("text.status_delay", lo=lo, hi=hi) if hi > 0 else tr("text.status_no_delay"))
        if self.core.store.get("issuer_repin"):
            lines.append(tr("text.status_issuer_repin", config=self.config_name))
        if self.plugins.loaded:
            lines.append(tr("text.status_plugins", names=", ".join(p.name for p in self.plugins.loaded)))
        if self.plugins.pending:
            lines.append(tr("text.status_plugins_pending", names=", ".join(p.name for p in self.plugins.pending)))
        if self.plugins.failed:
            lines.append(tr("text.status_plugins_failed", names=", ".join(n for n, _ in self.plugins.failed)))
        out = tr("text.status", lines="\n".join(lines))
        return out + ("\n\n" + tr("text.status_pool") if self.pool else "")

    def status_keyboard(self) -> dict | None:
        rows = []
        if not self.core.store.token_counts().get(api.today(), 0):
            rows.append([(self.T("button.top_up"), "tok:req")])
        if self.pool and not self.core.has_identity():
            rows.append([(self.T("button.pool_identity"), "id:new")])
        if self.plugins.loaded:
            rows.append([(self.T("button.plugins"), "pc:plugins")])
        return keyboard(rows) if rows else None

    def blocker(self) -> tuple[str, dict | None] | None:
        """Почему пост сейчас не уйдёт — до случайной задержки, чтобы владелец не ждал её впустую."""
        if self.core.store.get("b2b_error"):
            return self.T("text.b2b_off"), None
        if not self.core.store.token_counts().get(api.today(), 0):
            later = any(c for d, c in self.core.store.token_counts().items() if d > api.today())
            return (self.T("text.no_tokens_before") + ("\n\n" + self.T("text.tokens_none_today") if later else ""),
                    keyboard([[(self.T("button.top_up"), "tok:req")]]))
        return None

    # --- экспорт и импорт (docs/EXPORT.md): через чат — только на ключ получателя, пароль в Telegram не вводится ---
    EXPORT_CONFIRM_TTL = 600  # с: столько ждёт подтверждения выгрузка на присланный ключ

    async def _export(self, arg: str) -> None:
        """/export VEILIMP…: сначала — что именно уйдёт и кому. Ключ VEILIMP мог прислать посторонний («пришлите файл»):
        файл откроет только тот, кто выдал ключ, поэтому выгрузка — только после кнопки владельца."""
        if not arg:
            await self._say(self.T("text.export_how"))
            return
        try:
            pk = ex.parse_import_key(arg)
            bundle = ex.collect(self.core.store, int(self.core.store.get("bot_id") or 0), self.cfg)
        except ex.ExportError as e:
            await self._say(self.T("text.export_failed", err=e))
            return
        self.core.store.put("export_pending", {"pk": b64.enc(pk), "at": int(time.time())})
        what = self.T("text.export_identity") if bundle.get("device") else self.T("text.export_no_identity")
        await self._say(self.T("text.export_confirm", identity=what, tokens=len(bundle["tokens"]),
                               posts=len(bundle["posts"]),
                               contacts=len(bundle["contacts"])),
                        keyboard([[(self.T("button.export_yes"), "ex:ok"), (self.T("button.cancel"), "ex:no")]]))
        del bundle

    async def _export_confirmed(self, msg: dict) -> None:
        pending = self.core.store.get("export_pending")
        self.core.store.put("export_pending", None)
        if not pending or time.time() - pending["at"] > self.EXPORT_CONFIRM_TTL:
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.export_expired"))
            return
        try:
            bundle = ex.collect(self.core.store, int(self.core.store.get("bot_id") or 0), self.cfg)
            data = ex.seal_recipient(bundle, b64.dec(pending["pk"]))
        except ex.ExportError as e:
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.export_failed", err=e))
            return
        del bundle
        await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.export_sending"))
        # Без protect_content: файл нужно переслать туда, куда переносите. Прочитать его может только место,
        # выдавшее ключ VEILIMP, — запрет пересылки ничего бы не защитил.
        sent = await self.bot.upload("sendDocument", "document", "veil-export.veilx", data, "application/octet-stream",
                                     chat_id=self.owner, caption=self.T("text.export_done"))
        self.schedule_wipe(self.owner, sent["message_id"], self.TRANSFER_TTL)

    async def _import_start(self) -> None:
        text, sk = ex.new_import_key()
        self.core.store.put("import_sk", b64.enc(sk))
        ask = await self._say(self.T("text.import_ready"), self._cancel_kb())
        self.core.store.put("await", {"what": "import", "ask": ask["message_id"] if ask else None})
        await self._say(text)  # отдельным сообщением — удобно скопировать целиком

    async def _import_file(self, m: dict) -> None:
        doc = m["document"]
        await self.bot.delete(m["chat"]["id"], m["message_id"])  # файл с секретами — из переписки сразу
        sk = self.core.store.get("import_sk")
        try:
            if int(doc.get("file_size") or 0) > ex.MAX_FILE:
                raise ex.ExportError("файл больше 8 МиБ")
            data = await self.bot.download(doc["file_id"], ex.MAX_FILE)
            bundle = ex.open_file(data, recipient_sk=b64.dec(sk) if sk else None)
            bot_id = int(self.core.store.get("bot_id") or 0)
            dev = ex.checked_device(bundle) if int(bundle.get("bot_id", 0)) == bot_id else None
            # Личность из файла — только если сервер подтвердит, что она уже привязана к этому боту (тот же бот на
            # новом месте). Чужой файл с подставленным ID бота так не пройдёт.
            confirmed = bool(dev) and not self.core.store.load_device() and await self.core.server_confirms(dev)
            report = ex.apply(self.core.store, bundle, bot_id=bot_id,
                              issuer_kid=(self.core.store.get("pinned_issuer") or {}).get("kid", ""),
                              accept_device=confirmed, current=self.cfg, locales=ex.available_locales())
        except ex.ExportError as e:
            await self._say(self.T("text.import_failed", err=e))
            return
        self.core.store.put("import_sk", None)
        self.core._device = None  # личность могла смениться — перечитать
        text = ex.format_report(report)
        if self.pool and callable(self.pool.get("restart")):
            # Бот в пуле: перезапуск сам — настройки применяются сразу (свою консоль владелец не видит).
            await self._say(text.replace(self.T("text.import_restart_note"), self.T("text.import_restarting")))
            await self.pool["restart"]()
            return
        await self._say(text)
        await self._sync_identity()

    WORDS_TTL = 3600  # с: сообщение с 12 словами удаляется само, если владелец не нажал «Я записал»

    async def _pool_identity(self, data: str, msg: dict) -> None:
        """Бот в пуле: личность кнопкой. Режим pool.identity:
        - "custodial" (по умолчанию) — слов нет совсем: личность держит пул, восстановить её нельзя (только перенести
          экспортом). Корень не существует нигде, и украсть его нельзя;
        - "words_once" — 12 слов одним сообщением с запретом пересылки и сохранения; после «Я записал» (или через
          час) оно удаляется. Слова проходят через Telegram и созданы сервером пула — это исключение из spec/02,
          поэтому только по явной настройке оператора и с предупреждением владельцу."""
        from veil import pool  # noqa: PLC0415 — слова только в модуле пула, не в интерфейсе (tests/test_cli.py)
        chat = msg["chat"]["id"]
        if data == "id:ok":
            mid = self.core.store.get("words_msg")
            self.core.store.put("words_msg", None)
            if mid:
                await self.bot.delete(chat, mid)
                self.unschedule_wipe(chat, mid)
            await self._say(self.T("text.pool_words_gone"))
            await self._sync_identity()
            await self._say(self.status_text(), self.status_keyboard())
            return
        if self.core.has_identity():
            await self.bot.edit(chat, msg["message_id"], self.T("text.welcome_back",
                                sign=self.core.nick() or f"·{self.core.device.tag}"))
            return
        mode = (self.pool or {}).get("identity", "custodial")
        d, grid = await asyncio.to_thread(pool.create_identity, self.core.store, mode)  # Argon2id — не в цикле событий
        self.core._device = d
        await self.bot.edit(chat, msg["message_id"], self.T("text.pool_identity_done", tag=d.tag))
        # Регистрация устройства на сервере стоит 1 токен; без токенов она пройдёт после /tokens.
        if grid is None:
            await self._sync_identity()
            return
        sent = await self.bot.call("sendMessage", chat_id=chat, text=self.T("text.pool_words", words=grid),
                                   entities=[{"type": "pre", "offset": _u16(self.T("text.pool_words", words="")),
                                              "length": _u16(grid)}],
                                   protect_content=True,
                                   reply_markup=keyboard([[(self.T("button.pool_words_ok"), "id:ok")]]))
        del grid
        self.core.store.put("words_msg", sent["message_id"])
        self.schedule_wipe(chat, sent["message_id"], self.WORDS_TTL)

    # --- удаление секретных сообщений по сроку, хранящемуся в базе ---
    # Слова, VEILTOK и файл экспорта удаляются из чата по сроку из базы, а не задачей в памяти: перезапуск бота не
    # оставит их в переписке. Удалять надо раньше 48 ч — потом Telegram не даст.
    def schedule_wipe(self, chat: int, mid: int, ttl: int) -> None:
        pending = self.core.store.get("wipe_at") or []
        pending.append([chat, mid, int(time.time()) + ttl])
        self.core.store.put("wipe_at", pending)

    def unschedule_wipe(self, chat: int, mid: int) -> None:
        self.core.store.put("wipe_at",
                            [w for w in self.core.store.get("wipe_at") or [] if w[:2] != [chat, mid]] or None)

    async def wipe_due(self) -> None:
        now = int(time.time())
        pending = self.core.store.get("wipe_at") or []
        due = [w for w in pending if w[2] <= now]
        if not due:
            return
        for chat, mid, _ in due:
            await self.bot.delete(chat, mid)
            if self.core.store.get("words_msg") == mid:
                self.core.store.put("words_msg", None)
        self.core.store.put("wipe_at", [w for w in pending if w[2] > now] or None)

    async def _wipe_loop(self) -> None:
        while True:
            try:
                await self.wipe_due()
            except Exception as e:  # noqa: BLE001 — сеть: попробуем через минуту
                log.info("wipe: %s", type(e).__name__)
            await asyncio.sleep(60)

    async def _send_draft(self, i: int, d: api.Draft, status: dict, delay: bool) -> None:
        """Отправка черновика. Черновик живёт до записи конверта в журнал: перезапуск во время случайной
        задержки не теряет пост — при старте он уйдёт в свой срок (_resume_scheduled)."""
        def scheduled(at: int) -> None:
            d.send_at, d.status = at, status
            self.core.store.save_draft(d.to_json(), i)

        def journaled() -> None:
            self.core.store.drop_draft(i)

        async def publish() -> dict:
            res = await self.core.create_post(d, on_journal=journaled)
            self.plugins.fire("post_published", plug.Published(res["n"], res.get("url", ""), d.anonymous, d.reply_to))
            return res

        await self._run(publish, lambda r: self.T("text.published", n=r["n"], url=r.get("url", "")), status=status,
                        delay=delay, scheduled=scheduled, name="post.create")
        # Итог (успех или отказ) владелец уже видит. При остановке (CancelledError) сюда не доходим: черновик со сроком
        # остаётся и уйдёт после перезапуска.
        self.core.store.drop_draft(i)

    async def _resume_scheduled(self) -> None:
        """После перезапуска: черновики, «Отправить» которых было нажато, уходят в свой срок; затем — дозапрос
        итога постов, конверт которых ушёл без ответа, и так раз в 5 минут."""
        for i, raw in self.core.store.scheduled_drafts():
            d = api.Draft.from_json(raw)
            wait = d.send_at - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            status = d.status or {}
            if not status.get("chat"):
                status = await self._say(self.T("text.sending")) or {}
            await self._send_draft(i, d, status, delay=False)
        while True:
            try:
                for what, res in await self.core.resume_pending():
                    if what == "published":
                        await self._say(self.T("text.published", n=res["n"], url=res.get("url", "")))
                        self.plugins.fire("post_published", plug.Published(res["n"], res.get("url", ""), None, None))
                    else:
                        await self._say(self.T("text.post_lost" if what == "lost" else "text.post_failed"))
            except Exception as e:
                log.info("resume pending: %s", type(e).__name__)
            await asyncio.sleep(300)

    async def _draft_action(self, i: int, action: str, msg: dict) -> None:
        raw = self.core.store.draft(i)
        if raw is None:
            return
        d = api.Draft.from_json(raw)
        if action == "x":
            self.core.store.drop_draft(i)
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.cancelled"))
            return
        if action == "send":
            if self.core.store.get("b2b_error"):
                await self.setup()  # владелец мог включить режим в @BotFather
            stop = self.blocker()
            if stop:  # черновик остаётся: после пополнения или включения связи «Отправить» нажимается снова
                await self._say(*stop)
                return
            if reason := await self.plugins.check_send(outgoing(d)):  # черновик остаётся
                await self._say(self.T("text.plugin_blocked", reason=reason))
                return
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], self.T("text.sending"))
            await self._send_draft(i, d, {"chat": msg["chat"], "message_id": msg["message_id"]}, delay=True)
            return
        if action == "anon":
            d.anonymous = not d.anonymous
        elif action == "hto":
            ask = await self._say(self.T("text.ask_recipient"), self._cancel_kb())
            self.core.store.put("await", {"what": "to_nick", "draft": i, "chat": msg["chat"]["id"],
                                          "mid": msg["message_id"], "ask": ask["message_id"] if ask else None})
            return
        elif action in ("hl", "hm", "h0"):
            d.hide = {"hl": "links", "hm": "message", "h0": ""}[action]
            d.to_label = d.to_pk = ""
        self.core.store.save_draft(d.to_json(), i)
        await self._show_draft(i, d, edit=msg)

    async def _post_action(self, n: int, action: str, msg: dict) -> None:
        """Меню поста одноразовое: после выбора кнопки убираются, повторное нажатие старого меню невозможно."""
        tr = self.T
        names = {"reply": tr("button.reply"), "append": tr("button.upd"), "replace": tr("button.fix"),
                 "del": tr("button.delete"), "delok": tr("button.delete_yes"), "none": tr("button.cancel")}
        if action == "none":
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], tr("text.cancelled"))
            return
        if action in names:
            await self.bot.edit(msg["chat"]["id"], msg["message_id"], tr("text.menu_used", n=n, action=names[action]))
        if action in ("reply", "append", "replace"):
            ask = await self._say(tr({"reply": "text.await_reply", "append": "text.await_append",
                                     "replace": "text.await_replace"}[action], n=n), self._cancel_kb())
            self.core.store.put("await", {"what": action, "n": n, "ask": ask["message_id"] if ask else None})
        elif action == "del":
            await self._say(tr("text.confirm_delete", n=n), keyboard([[(tr("button.delete_yes"), f"p:{n}:delok"),
                                                                       (tr("button.cancel"), f"p:{n}:none")]]))
        elif action == "delok":
            await self._run(lambda: self.core.delete_post(n),
                            lambda r: (tr("text.deleted_partly", n=n, left=r["left"]) if r.get("left")
                                       else tr("text.deleted", n=n)),
                            status=msg, name="post.delete")

    # --- токены, ник, лента ---
    async def _tokens(self) -> None:
        st = self.core.tokens_status()
        lines = "\n".join(self.T("text.tokens_line", day=d, count=c) for d, c in sorted(st.items()))
        rows = [[(self.T("button.top_up"), "tok:req")]]
        if st.get(api.today()):
            rows.append([(self.T("button.tokens_give"), "tok:give")])
        await self._say(self.T("text.tokens_status", lines=lines or self.T("text.tokens_none")) + "\n\n" +
                        self.T("text.tokens_explain"), keyboard(rows))

    async def _token_give(self, data: str) -> None:
        """Перенос сегодняшних токенов другому своему боту (квота эмитента — на человека, а не на бота)."""
        have = self.core.store.token_counts().get(api.today(), 0)
        if data == "tok:give":
            if not have:
                await self._say(self.T("text.tokens_give_none"))
                return
            opts = [n for n in (5, 10, 25) if n < have] + [have]
            await self._say(self.T("text.tokens_give_ask", n=have),
                            keyboard([[(str(n), f"tok:give:{n}") for n in opts], [(self.T("button.cancel"), "aw:x")]]))
            return
        n = int(data.rsplit(":", 1)[1])
        parts = self.core.export_tokens(api.today(), min(n, have))
        if not parts:
            await self._say(self.T("text.tokens_give_none"))
            return
        await self._say(self.T("text.tokens_give_send", n=min(n, have), parts=len(parts)))
        for p in parts:
            r = await self.bot.send(self.owner, p)
            self.schedule_wipe(self.owner, r["message_id"], self.TRANSFER_TTL)  # секрет на предъявителя
            await asyncio.sleep(1.1)

    TRANSFER_TTL = 3600

    async def _token_import(self, m: dict) -> None:
        await self.bot.delete(m["chat"]["id"], m["message_id"])  # пересланный секрет — из переписки сразу
        try:
            res = self.core.import_token_part(m.get("text", ""))
        except (IssueFormatError, ValueError) as e:
            await self._say(self.T("text.tokens_import_bad", err=e))
            return
        if isinstance(res, tuple):
            await self._say(self.T("text.tokens_import_wait", got=res[0], n=res[1]))
            return
        await self._say(self.T("text.tokens_imported", n=res) + "\n" + self._token_days())

    def _token_days(self) -> str:
        """Сколько токенов на какие дни и что делать, если на сегодня нет."""
        st = self.core.tokens_status()
        lines = "\n".join(self.T("text.tokens_line", day=d, count=c) for d, c in sorted(st.items()))
        out = self.T("text.tokens_status", lines=lines or self.T("text.tokens_none"))
        if not st.get(api.today()):
            out += "\n\n" + self.T("text.tokens_none_today")
        return out

    async def _top_up(self) -> None:
        if self.core.store.get("issuer_mismatch"):
            await self._say(self.T("text.issuer_mismatch"))  # закреплённый ключ всё равно проверит выдачу (spec/03)
        parts = self.core.make_token_request()
        if not parts:
            await self._say(self.T("text.tokens_full"))
            return
        await self._say(self.T("text.tokens_request", n=len(parts), issuer=self.issuer))
        for p in parts:
            await self.bot.send(self.owner, p)
            await asyncio.sleep(1.1)

    async def _token_part(self, text: str) -> None:
        try:
            added = self.core.accept_token_part(text)
        except api.UnknownTokenRequestError:
            await self._say(self.T("text.tokens_unknown_request"))
            return
        except (IssueFormatError, ValueError) as e:
            await self._say(self.T("text.tokens_bad", err=e))
            return
        if isinstance(added, tuple):
            await self._say(self.T("text.tokens_wait_parts", got=added[0], n=added[1]))
            return
        await self._say(self.T("text.tokens_added", n=added) + "\n" + self._token_days())

    async def _nick(self, arg: str) -> None:
        nick = None if arg in ("", "-") else arg
        await self._run(lambda: self.core.set_nick(nick),
                        lambda r: self.T("text.nick_set", nick=r["nick"], tag=r["tag"]) if r.get("nick")
                        else self.T("text.nick_removed"), name="nick.set")

    async def apply_feed(self, posts: list[dict], start: int, cursor: int) -> None:
        """Бот в пуле: лента, забранная пулом на всех (start — с какого номера есть записи, cursor — до какого).
        Новый бот начинает с текущего номера (своих постов в прошлом у него нет); бот, отставший дальше, чем помнит
        пул (например, после импорта), дочитывает ленту сам."""
        mine = self.core.store.get("feed_cursor")
        if mine is None:
            self.core.store.put("feed_cursor", cursor)
            return
        if mine < start:
            await self._sync_once()
            return
        await self._deliver_events(await self.core.process_feed(posts))

    async def _sync_once(self) -> None:
        await self._deliver_events(await self.core.sync_feed())

    async def _deliver_events(self, events) -> None:
        for ev in events:
            try:  # одно событие не должно отнимать остальные: курсор ленты уже сдвинут
                if ev.kind == "reply":
                    await self._say(self.T("text.reply_event", n=ev.n, to=ev.to, text=ev.text, url=ev.url))
                    self.plugins.fire("reply", plug.Reply(ev.n, ev.to, ev.text, ev.url))
                else:
                    await self._deliver_private(ev)
                    self.plugins.fire("hidden_for_me", plug.Private(ev.n, ev.url, ev.text, ev.sender, ev.file_count))
            except Exception as e:
                log.warning("feed event #%s: %s", ev.n, type(e).__name__)

    async def _deliver_private(self, ev) -> None:
        """«Лично для меня»: от кого (подпись поста или «без подписи»), текст с форматированием. Файлы прислал другой
        человек — бот их не выгружает сам, а предлагает кнопку: владелец решает, открывать ли файлы незнакомца."""
        who = ev.sender or self.T("text.hidden_sender_anon")
        head = self.T("text.hidden_event_head", n=ev.n, url=ev.url, who=who)
        text = head + ("\n" + ev.text if ev.text else "")
        shift = privacy.utf16(head + "\n")
        ents = [{**e, "offset": e["offset"] + shift} for e in (ev.entities or [])] if ev.text else None
        markup = (keyboard([[(self.T("button.private_files", n=ev.file_count), f"pf:{ev.n}")]])
                  if ev.file_count else None)
        await self.bot.send(self.owner, text, entities=ents or None, markup=markup)

    async def _private_files(self, n: int, msg: dict) -> None:
        """Кнопка «Файлы»: забрать контейнер, проверить и прислать файлы тем же видом, с безопасными именем и MIME."""
        try:
            files = await self.core.private_files(n)
        except KeyError:
            await self._say(self.T("text.private_files_gone"))
            return
        except Exception as e:  # контейнер не скачался или подделан
            log.warning("private file of #%s: %s", n, type(e).__name__)
            await self._say(self.T("text.private_file_failed"))
            return
        await self.bot.edit_markup(msg["chat"]["id"], msg["message_id"], None)  # кнопка одноразовая
        prepared = []
        for f in files:
            kind = f.kind if f.kind in MEDIA_SEND else "document"
            prepared.append((kind, safe_filename(f.name, kind), f.data, safe_mime(f.mime, MEDIA_MIME.get(kind))))
        kinds = {k for k, *_ in prepared}
        if len(prepared) > 1 and (kinds <= {"photo", "video"} or (len(kinds) == 1 and kinds & {"document", "audio"})):
            await self.bot.upload_group(self.owner, prepared)
            return
        for kind, name, data, mime in prepared:
            method, field = MEDIA_SEND[kind]
            try:
                await self.bot.upload(method, field, name, data, mime, chat_id=self.owner)
            except TelegramError:  # вид не подошёл Telegram (например, «фото» — не картинка): файлом
                await self.bot.upload("sendDocument", "document", name, data, mime, chat_id=self.owner)

    async def _feed_loop(self, every: int) -> None:
        await asyncio.sleep(5)
        while True:
            if self.core.store.get("b2b_error"):  # связи нет: лента подождёт, журнал не засоряется
                await asyncio.sleep(every)
                continue
            try:
                await self._sync_once()
            except (ServerError, NoReplyError, TelegramError) as e:
                log.info("feed sync: %s", e)
            except Exception as e:  # цикл ленты не должен умирать до перезапуска бота
                log.warning("feed sync: %s", type(e).__name__)
            await asyncio.sleep(every)
