"""Публичный API ядра (docs/ARCHITECTURE.md): единственная точка входа для интерфейса и плагинов.

Интерфейс (`veil/ui`) и плагины пользуются только этим модулем. Внутренности ядра могут меняться
между версиями, этот API — по семантическому версионированию.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from nacl.signing import SigningKey

from veil.core import privacy
from veil.core.crypto import keys, poprf
from veil.core.identity import nick as nickmod
from veil.core.protocol import b64, content as contentmod, hidden, keysdoc
from veil.core.store.db import Store
from veil.core.transport.exchange import Exchange, NoReply, ServerError
from veil.core.transport.telegram import Bot
from veil.core.wallet import issue

log = logging.getLogger("veil.core")
TOKENS_PER_DAY = 50
DAYS_AHEAD = 7
# Строка номера в шапке поста (spec/06): «№N» или «№N  >>> №M» — целиком, без текста вокруг.
_NUMBER_LINE = re.compile(r"№(\d+)(?:  >>> №\d+)?")
TOKEN_ERRORS = {"E_TOKEN_INVALID", "E_TOKEN_SPENT", "E_TOKEN_DAY"}
BAD_TOKEN_TRIES = 2 * 50  # подряд отвергнутых токенов на одну операцию: больше, чем бывает на день
PRIVATE_FILES_TTL = 7 * 86400  # с: столько бот помнит, у какого поста можно забрать файлы «лично для» по кнопке


def today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


class NoTokens(Exception):
    pass


class UnknownTokenRequest(Exception):
    """Ответ эмитента не на запрос этого бота: на запрос другого бота или на старый, уже принятый."""


class PostQueued(Exception):
    """Конверт поста отправлен, но итога нет (очередь публикации длиннее повторов или сервер не ответил). Секрет
    поста сохранён: Core.resume_pending дозапросит результат тем же конвертом."""


class NotMine(Exception):
    pass


class Ambiguous(Exception):
    """Под ником·меткой несколько проверенных личностей."""


class NoIdentity(Exception):
    """Личность ещё не создана: на машине бота нужно выполнить init или restore (spec/02)."""


class DeviceRevoked(Exception):
    """Сертификат этого устройства отозван: личность восстановлена по 12 словам на другом устройстве (E_STALE)."""


class OtherBot(Exception):
    """Личность привязана к другому боту (E_BOT_NOT_BOUND): перенос на этот бот — restore на его машине."""


@dataclass
class Draft:
    """Черновик: сообщения владельца (dict Bot API) и настройки публикации."""
    chat_id: int
    messages: list[dict]
    anonymous: bool = False
    hide: str = ""            # "" | "links" | "message"
    reply_to: int | None = None
    mode: str = "create"      # create | replace | append | media
    target: int | None = None  # номер поста для правки
    to_label: str = ""         # hide == "to": «Ник·метка» получателя
    to_pk: str = ""            # hide == "to": проверенный enc_pk получателя (b64url)
    send_at: int = 0           # «Отправить» нажато: не раньше этого времени (случайная задержка)
    status: dict | None = None  # сообщение «Отправлю через…», которое правится в итог

    def to_json(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_json(cls, d: dict) -> "Draft":
        return cls(**d)


@dataclass
class HiddenFile:
    kind: str     # photo | video | … — как отправлял автор
    name: str
    mime: str
    data: bytes


@dataclass
class FeedEvent:
    kind: str     # reply | hidden
    n: int
    to: int | None = None
    url: str = ""
    text: str = ""
    entities: list = field(default_factory=list)
    sender: str = ""      # «лично для»: подпись поста (ник·метка) или "" — пост без подписи
    file_count: int = 0   # «лично для» с медиа: сколько файлов можно забрать (Core.private_files, по кнопке)


def post_number(msg: dict) -> int | None:
    """№N из шапки пересланного поста (spec/06): строка «№N» — первая (пост без подписи) или вторая, если первая —
    ник·метка (жирный во всю строку). «№» в нике и в тексте поста номером не считается: иначе ник «№1» подменял бы
    номер, и ответ или удаление ушли бы на чужой пост."""
    text = msg.get("text") or msg.get("caption") or ""
    ents = msg.get("entities") or msg.get("caption_entities") or []
    lines = text.split("\n")
    if m := _NUMBER_LINE.fullmatch(lines[0]):
        return int(m.group(1))
    nick_line = any(e.get("type") == "bold" and e.get("offset") == 0 and e.get("length") == privacy.utf16(lines[0])
                    for e in ents)
    if nick_line and len(lines) > 1 and (m := _NUMBER_LINE.fullmatch(lines[1])):
        return int(m.group(1))
    return None


# Совместимость: эти помощники живут в privacy (единая таблица скрытия).
from veil.core.privacy import HIDDEN_LINK, HIDDEN_MESSAGE, has_links, hide_links  # noqa: E402,F401
from veil.core.privacy import text_of as _text_and_entities  # noqa: E402,F401


@dataclass
class Core:
    bot: Bot
    store: Store
    exchange: Exchange
    keys_doc: dict
    owner_id: int
    _device: keys.Device | None = field(default=None, repr=False)
    _state: dict | None = field(default=None, repr=False)  # личность на сервере после sync_device
    _inflight: set = field(default_factory=set, repr=False)  # id конвертов постов, ответ на которые ещё ждут

    # --- личность (spec/02): корня здесь нет, бот действует ключом устройства ---
    def has_identity(self) -> bool:
        return self.device_or_none() is not None

    def device_or_none(self) -> keys.Device | None:
        if self._device is None:
            self._device = self.store.load_device()
        return self._device

    @property
    def device(self) -> keys.Device:
        d = self.device_or_none()
        if d is None:
            raise NoIdentity()
        return d

    def _save_device(self) -> None:
        self.store.save_device(self.device)

    async def sync_device(self, force: bool = False) -> dict | None:
        """Сверяет регистрацию с сервером и чинит её: новое устройство или откат базы сервера — device.set
        (1 токен), ключ шифрования старше 7 дней — новый (enc.set, бесплатно). Возвращает состояние личности
        на сервере (None — личности нет). DeviceRevoked — устройство отозвано восстановлением на другом;
        OtherBot — личность привязана к другому боту; NoTokens — регистрации нужен токен."""
        d = self.device_or_none()
        if d is None:
            return None
        if self._state is not None and not force and not d.needs_rotation():
            return self._state
        if d.needs_rotation():
            d.new_enc()
        d.prune()
        self._save_device()
        try:
            st = await self.exchange.request("device.get", "identity", d.dev_sk)
        except ServerError as e:
            if e.code == "E_BOT_NOT_BOUND":
                raise OtherBot() from e
            if e.code != "E_DEVICE":
                raise
            st = await self._register()
        else:
            if st.get("enc_pk") != b64.enc(d.current.pk) and int(st.get("enc_exp", 0)) < d.current.exp:
                try:
                    await self.exchange.request("enc.set", "identity", d.dev_sk, body=d.enc_body())
                except ServerError as e:
                    if e.code not in ("E_RATE", "E_STALE"):
                        raise
        self.store.put("nick", st.get("nick"))
        self._state = st
        return st

    async def server_confirms(self, d: keys.Device) -> bool:
        """Личность из файла импорта — эта самая, уже зарегистрированная и привязанная к этому боту (device.get её
        ключом устройства с этого бота). Иначе файл мог собрать кто угодно."""
        try:
            st = await self.exchange.request("device.get", "identity", d.dev_sk)
        except (ServerError, NoReply):
            return False
        return st.get("id_pk") == b64.enc(d.id_pk) and int(st.get("seq", d.seq)) == d.seq

    async def _register(self) -> dict:
        """device.set своим сертификатом: первая регистрация или повтор после отката базы сервера."""
        d = self.device
        try:
            res = await self._paid("device.set", "identity", d.dev_sk, body=d.device_body())
        except ServerError as e:
            if e.code == "E_STALE":
                raise DeviceRevoked() from e
            if e.code == "E_BOT_NOT_BOUND":
                raise OtherBot() from e
            raise
        return {"tag": res.get("tag"), "nick": res.get("nick")}

    def tag_of(self, id_pk: bytes) -> str:
        """Медленная метка (~0,2 с) с кэшем: своя — из device.json, чужие — в meta."""
        d = self.device_or_none()
        if d is not None and id_pk == d.id_pk:
            return d.tag
        cache = self.store.get("tag_cache") or {}
        k = b64.enc(id_pk)
        if k not in cache:
            if len(cache) > 1000:
                cache.clear()
            cache[k] = keys.tag(id_pk)
            self.store.put("tag_cache", cache)
        return cache[k]

    # --- ключ эмитента: закреплён (spec/03) ---
    def issuer(self) -> tuple[str, bytes]:
        pin = self.store.get("pinned_issuer")
        if not pin:
            raise keysdoc.KeysError("ключ эмитента не закреплён")
        return pin["kid"], b64.dec(pin["pk"])

    # --- токены ---
    def tokens_status(self) -> dict[str, int]:
        self.store.drop_old_tokens(today())
        return self.store.token_counts()

    def make_token_request(self) -> list[str]:
        """Сообщения VEILREQ на дни сегодня…+6, на которые получено меньше 50. Пустой список — пополнять нечего.

        Просим 50 минус полученное (а не минус оставшееся): эмитент и так знает, сколько выдал, а число потраченных
        за день из формы запроса не узнает — иначе «добрал 3 токена в 14:05» сопоставлялось бы с тремя постами."""
        self.tokens_status()  # чистка прошедших дней
        have = self.store.token_received()
        start = datetime.now(timezone.utc).date()
        want = []
        for i in range(DAYS_AHEAD):
            day = (start + timedelta(days=i)).isoformat()
            need = TOKENS_PER_DAY - have.get(day, 0)
            if need > 0:
                want.append((day, self.issuer()[0], need))  # закреплённый ключ эмитента (spec/03)
        if not want:
            return []
        pending, parts = issue.make_request(want)
        state = {d: {"kid": k, "inputs": [s.input.hex() for s in st], "blinds": [s.blind for s in st],
                     "blinded": [s.blinded.hex() for s in st]} for d, (k, st) in pending.states.items()}
        self.store.save_issue_request(pending.req_id.hex(), state)
        return parts

    def accept_token_part(self, text: str) -> int | tuple[int, int]:
        """Часть VEILRES от владельца. Когда собраны все — проверяет ответ эмитента, сохраняет токены и возвращает
        их число; иначе — (принято частей, всего частей)."""
        m = re.fullmatch(r"VEILRES ([0-9a-f]{16}) ([0-9]{1,2})/([0-9]{1,2}) \S+", text.strip())
        if not m:
            raise issue.IssueFormatError("not a VEILRES part")
        req_id, i, n = m.group(1), int(m.group(2)), int(m.group(3))
        state = self.store.issue_request(req_id)
        if state is None:
            raise UnknownTokenRequest()
        parts = self.store.add_issue_part(req_id, i, n, text.strip())
        if parts is None:
            got = self.store.db.execute("SELECT count(*) FROM issue_parts WHERE req_id = ? AND n = ?", (req_id, n)).fetchone()[0]
            return got, n
        pending = issue.PendingRequest(bytes.fromhex(req_id), {
            d: (v["kid"], [poprf.BlindState(bytes.fromhex(a), b, bytes.fromhex(c))
                           for a, b, c in zip(v["inputs"], v["blinds"], v["blinded"])])
            for d, v in state.items()})
        kid, pk = self.issuer()  # доказательство DLEQ проверяется закреплённым ключом, а не ключом от сервера
        toks = issue.accept_response(pending, parts, {kid: pk})
        added = self.store.add_tokens(toks)
        self.store.forget_issue(req_id)
        return added

    # --- перенос токенов между своими ботами ---
    # Эмитент выдаёт 50 токенов в день на человека, а не на бота: второй бот того же человека на уже выданные дни
    # токенов не получит. Токены можно перенести: это не создаёт новых (квота та же), отправитель помечает их
    # потраченными, а сервер принимает каждый токен один раз. Сообщения VEILTOK — секрет на предъявителя: бот
    # удаляет их из чата после приёма.
    TRANSFER_PART = 3800

    def export_tokens(self, day: str, count: int) -> list[str]:
        toks = self.store.give_tokens(day, count)
        if not toks:
            return []
        data = b64.enc(json.dumps([[t.day, t.kid, b64.enc(t.input), b64.enc(t.output)] for t in toks],
                                  separators=(",", ":")).encode())
        tid = secrets.token_hex(4)
        self.store.put(f"tok_given:{tid}", [t.id for t in toks])  # перенос можно вернуть: те же VEILTOK сюда же
        chunks = [data[i:i + self.TRANSFER_PART] for i in range(0, len(data), self.TRANSFER_PART)]
        return [f"VEILTOK {tid} {i + 1}/{len(chunks)} {c}" for i, c in enumerate(chunks)]

    def import_token_part(self, text: str) -> int | tuple[int, int]:
        """Часть VEILTOK. Когда собраны все — проверка и сохранение; возвращает число новых токенов, иначе
        (принято частей, всего частей)."""
        m = re.fullmatch(r"VEILTOK ([0-9a-f]{8}) ([0-9]{1,2})/([0-9]{1,2}) ([A-Za-z0-9_-]+)", text.strip())
        if not m or not 1 <= int(m.group(2)) <= int(m.group(3)) <= 20:
            raise issue.IssueFormatError("not a VEILTOK part")
        tid, i, n = m.group(1), int(m.group(2)), int(m.group(3))
        key = f"tok_import:{tid}"
        got = self.store.get(key) or {}
        got[str(i)] = m.group(4)
        if len(got) < n:
            self.store.put(key, got)
            return len(got), n
        self.store.put(key, None)
        given = self.store.get(f"tok_given:{tid}")
        if given:  # эти VEILTOK отдал сам этот бот: перенос отменяется, токены снова его
            self.store.put(f"tok_given:{tid}", None)
            return self.store.revive_tokens(given)
        try:
            rows = json.loads(b64.dec("".join(got[str(k)] for k in range(1, n + 1))))
        except (ValueError, KeyError) as e:
            raise issue.IssueFormatError("bad VEILTOK") from e
        kid = self.issuer()[0]
        start = datetime.now(timezone.utc).date()
        days = {(start + timedelta(days=k)).isoformat() for k in range(DAYS_AHEAD + 1)}
        toks = []
        for r in rows if isinstance(rows, list) else []:
            if not (isinstance(r, list) and len(r) == 4 and all(isinstance(x, str) for x in r)):
                raise issue.IssueFormatError("bad VEILTOK token")
            day, k, inp, out = r
            if day not in days:  # прошедший день или слишком далеко
                continue
            # Ключ закреплённого эмитента или его прежний недельный ключ — только на дни своей недели (так же
            # принимает сервер). Иной ключ — чужой эмитент: его токены могли быть выданы, чтобы пометить вас (spec/03).
            if k != kid and not issue.week_kid_covers(k, day):
                raise issue.IssueFormatError("token of another issuer")
            inp_b, out_b = b64.dec(inp), b64.dec(out)
            if len(inp_b) != 32 or len(out_b) != 64:
                raise issue.IssueFormatError("bad VEILTOK token")
            toks.append(issue.Token(k, day, inp_b, out_b))
        if len(toks) > TOKENS_PER_DAY * (DAYS_AHEAD + 1):
            raise issue.IssueFormatError("too many tokens")
        # Чужие токены тратятся после своих: проверить их можно только тратой, а отдавший знает их значения.
        return self.store.add_tokens(toks, origin=tid)

    async def _paid(self, op: str, auth_mode: str, auth_key: SigningKey, **kw) -> dict:
        """Платная операция: берёт токен на сегодня, при ошибке токена — следующий, пока токены есть (переданные
        токены могли уже потратить другим ботом: сервер принимает каждый один раз, такой токен помечается bad). Если
        конверт записан в журнал (journal) и итога нет, токен считается потраченным: он закреплён за конвертом.
        E_PENDING (в том числе раньше на этот же конверт — e.accepted) значит, что действие принято и токен потрачен
        вместе с ним: новый токен и новый конверт дали бы второй пост."""
        for _ in range(BAD_TOKEN_TRIES):
            tok = self.store.take_token(today())
            if tok is None:
                raise NoTokens()
            journaled = []
            req = dict(kw)
            if kw.get("journal"):
                req["journal"] = lambda st, j=kw["journal"], mark=journaled: (j(st), mark.append(True))
            try:
                res = await self.exchange.request(op, auth_mode, auth_key, token=tok.envelope(), **req)
            except ServerError as e:
                if e.code == "E_PENDING" or e.accepted:
                    self.store.finish_token(tok, "spent")
                    raise
                self.store.finish_token(tok, "bad" if e.code in TOKEN_ERRORS else "ready")
                if e.code in TOKEN_ERRORS:
                    if tok.origin and (n := self.store.drop_transfer(tok.origin, tok.day)):
                        log.warning("transferred token rejected; %d more from the same transfer not used", n)
                    continue
                raise
            except NoReply:
                self.store.finish_token(tok, "spent" if journaled else "ready")
                raise
            except BaseException:
                self.store.finish_token(tok, "ready")
                raise
            self.store.finish_token(tok, "spent")
            return res
        raise NoTokens()

    # --- проверка черновика ---
    async def check_draft(self, d: Draft) -> list[tuple[str, dict]]:
        """Проблемы черновика до отправки: таблица скрытия (privacy.preview) и точный расчёт длины
        сервером (post.check, бесплатно). Пустой список — можно отправлять."""
        pv = privacy.preview(d, self.nick())
        problems = list(pv.problems)
        if pv.check is None or problems:
            return problems
        try:
            res = await self.exchange.request("post.check", "ephemeral", SigningKey.generate(), body=pv.check)
        except ServerError as e:
            if e.code == "E_UNSUPPORTED":
                return [("text.mode_unavailable", {})]
            return []  # сервер недоступен или занят: проверит при отправке
        except NoReply:
            return []
        if res.get("overflow", 0) > 0:
            problems.append(("text.too_long", {"n": res["overflow"]}))
        return problems

    # --- операции ---
    async def create_post(self, d: Draft, on_journal: Callable[[], None] | None = None) -> dict:
        """Публикует пост. Секрет и конверт записываются до отправки; on_journal — в этот момент (черновик
        больше не нужен: повтор возьмёт конверт из журнала)."""
        secret = secrets.token_bytes(32)
        post_pk = b64.enc(bytes(keys.post_signing_key(secret).verify_key))
        plan = await privacy.build(self, d, post_pk=post_pk)  # «лично для» привязывается к ключу поста (spec/07)
        body = {"post_pk": post_pk}
        if d.reply_to:
            body["reply_to"] = d.reply_to
        if plan.hidden:
            body["hidden"] = plan.hidden
        # С личностью — только пост с ником. Без ника пост выглядит так же, а одноразовый ключ не связывает его
        # с личностью на сервере (spec/02, «Ники»).
        signed = not d.anonymous and self.nick() is not None
        if signed:
            await self.sync_device()
        mode, key = ("identity", self.device.dev_sk) if signed else ("ephemeral", SigningKey.generate())
        content = contentmod.describe(plan.shown) if plan.shown else None  # файл: описание — после загрузки
        kind = privacy.kind(d.messages)
        ids: list[str] = []

        def journal(state: dict) -> None:
            for old in ids:  # прошлая попытка (ошибка токена, E_DEVICE) сервером отвергнута
                self.store.drop_pending_post(old)
            ids.append(state["id"])
            self._inflight.add(state["id"])
            self.store.save_pending_post(state["id"], secret, kind, state)
            if on_journal:
                on_journal()

        async def attempt() -> dict:
            return await self._paid("post.create", mode, key, body=body, content=content, deliver=plan.deliver,
                                    journal=journal)
        try:
            try:
                res = await attempt()
            except ServerError as e:
                if e.code != "E_DEVICE" or not signed:
                    raise
                await self.sync_device(force=True)  # база сервера откатилась или устройство отозвано
                res = await attempt()
        except (NoReply, ServerError) as e:
            if isinstance(e, NoReply) or e.code == "E_PENDING" or e.accepted:
                raise PostQueued() from e
            for old in ids:
                self.store.drop_pending_post(old)
            raise
        finally:
            self._inflight.difference_update(ids)
        self.store.add_post(res["n"], secret, res.get("url", ""), kind)
        for old in ids:
            self.store.drop_pending_post(old)
        return res

    # Дозапрос — час. Если конверт дошёл до сервера, ответ по его id сервер помнит сутки и вернёт его,
    # даже когда альбом уже забыл; если не дошёл — сервер ответит «нет контента», и владелец узнает, что пост не
    # ушёл. Дольше часа не дозапрашиваем: не дошедший конверт иначе опубликовал бы пост спустя часы после написания.
    PENDING_TTL = 3600

    async def resume_pending(self) -> list[tuple[str, dict | None]]:
        """Дозапросить итог постов, конверт которых ушёл без ответа. Возвращает события для владельца:
        ("published", result) | ("failed", None) | ("lost", None)."""
        out: list[tuple[str, dict | None]] = []
        for env_id, secret, kind, state, created in self.store.pending_posts():
            if env_id in self._inflight:
                continue  # ответ ещё ждёт исходный запрос
            if time.time() - created > self.PENDING_TTL:
                self.store.drop_pending_post(env_id)
                out.append(("lost", None))
                continue
            try:
                res = await self.exchange.resume(state, None if state.get("auth_seed") else self.device.dev_sk)
            except ServerError as e:
                if e.code == "E_PENDING" or e.accepted:
                    continue
                self.store.drop_pending_post(env_id)
                out.append(("failed", None))
                continue
            except NoReply:
                continue
            self.store.add_post(res["n"], secret, res.get("url", ""), kind)
            self.store.drop_pending_post(env_id)
            out.append(("published", res))
        return out

    def _post_key(self, n: int) -> SigningKey:
        secret = self.store.post_secret(n)
        if secret is None:
            raise NotMine(n)
        return keys.post_signing_key(secret)

    async def edit_post(self, d: Draft) -> dict:
        key = self._post_key(d.target)
        plan = await privacy.build(self, Draft(d.chat_id, d.messages))  # правка — без скрытия, как есть
        return await self._paid("post.edit", "post_secret", key, body={"n": d.target, "mode": d.mode},
                                content=contentmod.describe(plan.shown), deliver=plan.deliver)

    async def delete_post(self, n: int) -> dict:
        res = await self._paid("post.delete", "post_secret", self._post_key(n), body={"n": n})
        self.store.mark_deleted(n)
        return res

    async def set_nick(self, nick: str | None) -> dict:
        if nick is not None:
            nickmod.normalize(nick)  # NickError до траты токена
        await self.sync_device()  # новое устройство сначала регистрируется (device.set)
        res = await self._paid("nick.set", "identity", self.device.dev_sk, body={"nick": nick})
        self.store.put("nick", res.get("nick"))
        return res

    def nick(self) -> str | None:
        """Ник·метка, под которым выйдут неанонимные посты (None — ника нет, пост будет анонимным)."""
        n = self.store.get("nick")
        d = self.device_or_none()
        return keys.display_name(n, d.tag) if n and d else None

    def _private_payload(self, p: dict, enc_sk: bytes) -> dict | None:
        """Расшифрованное «лично для меня» из записи ленты, если оно настоящее: схема верна, и payload привязан к этому
        же посту (post_pk внутри совпадает с post_pk записи, spec/07). Иначе blob, скопированный из чужого поста, выдал
        бы чужое сообщение за сообщение автора этого поста. Чужое или испорченное — None (это не ошибка владельца)."""
        try:
            pl = hidden.open_to(b64.dec(p["hidden_blob"]), enc_sk)
        except Exception:
            return None
        if not valid_private(pl):  # содержимое пишет другой человек: без проверки схемы оно роняло бы доставку
            log.warning("private payload of #%s: bad schema", p.get("n"))
            return None
        if not isinstance(p.get("post_pk"), str) or pl.get("post_pk") != p["post_pk"]:
            log.warning("private payload of #%s: not bound to this post", p.get("n"))
            return None
        return pl

    def _open_private(self, p: dict, enc_sk: bytes) -> FeedEvent | None:
        """Скрытое «лично для меня»: текст — сразу; файлы — по кнопке владельца (private_files): их прислал другой
        человек, поэтому бот не выгружает их владельцу сам. Для этого запоминается запись ленты (шифротекст)."""
        pl = self._private_payload(p, enc_sk)
        if pl is None:
            return None
        sender = keys.display_name(p["nick"], p.get("tag", "")) if isinstance(p.get("nick"), str) else ""
        ev = FeedEvent("hidden", p["n"], None, p.get("url", ""), pl.get("text", ""), pl.get("entities", []), sender)
        files = pl.get("files") or []
        if p.get("hidden_file") and files:
            pending = {k: v for k, v in (self.store.get("private_files") or {}).items()
                       if time.time() - v.get("at", 0) < PRIVATE_FILES_TTL}
            pending[str(p["n"])] = {"entry": {k: p[k] for k in ("n", "hidden_for", "hidden_blob", "post_pk", "bot", "url")
                                              if k in p}, "at": int(time.time())}
            self.store.put("private_files", pending)
            ev.file_count = len(files)
        return ev

    async def private_files(self, n: int) -> list[HiddenFile]:
        """Файлы «лично для» поста n, когда владелец их попросил: контейнер — у приёмного бота, который его принял
        (hidden.file), проверка — тем же ключом из payload. KeyError — запись забыта или не для этого бота;
        ValueError и ошибки сети — контейнер не получен или подделан."""
        rec = (self.store.get("private_files") or {}).get(str(n))
        d = self.device_or_none()
        enc_sk = d.enc_secret(b64.dec(rec["entry"]["hidden_for"])) if rec and d else None
        pl = self._private_payload(rec["entry"], enc_sk) if enc_sk else None
        if pl is None:
            raise KeyError(n)
        files = pl.get("files") or []
        got: list[dict] = []
        bot_id = rec["entry"].get("bot")
        await self.exchange.request("hidden.file", "ephemeral", SigningKey.generate(), body={"n": n}, attachments=got,
                                    to=bot_id if isinstance(bot_id, int) else None)
        if not got:
            raise ValueError("no file attached")
        container = await self.bot.download(got[0]["document"]["file_id"], privacy.MAX_FILES + 64)
        parts = hidden.open_files(container, b64.dec(pl["file_key"]), [int(f["size"]) for f in files])
        pending = self.store.get("private_files") or {}
        pending.pop(str(n), None)
        self.store.put("private_files", pending or None)
        return [HiddenFile(str(f.get("kind")), str(f.get("name") or "file"), str(f.get("mime") or ""), data)
                for f, data in zip(files, parts)]

    async def find_recipient(self, nick: str, tag: str) -> dict:
        """Получатель «лично для»: запись nick.lookup, прошедшая проверку цепочки подписей и метки (spec/02).
        Возвращает {"nick", "id_pk", "enc_pk", "seq"} (b64url). Устройство старше уже виденного — отказ (сервер
        вернул отозванное). Несколько проверенных записей — Ambiguous: пара ник·метка уникальна, значит что-то не так."""
        res = await self.exchange.request("nick.lookup", "ephemeral", SigningKey.generate(),
                                          body={"nick": nick, "tag": tag})
        seen = self.store.get("contact_seq") or {}
        ok = []
        for m in res.get("matches", []):
            try:
                v = keys.verify_lookup_match(m, tag, tag_fn=self.tag_of)
            except keys.KeyMismatch:
                continue
            if seen.get(b64.enc(v.id_pk), 0) > v.seq:
                log.warning("nick.lookup returned a revoked device (rollback)")
                continue
            ok.append({"nick": v.nick or nick, "id_pk": b64.enc(v.id_pk), "enc_pk": b64.enc(v.enc_pk), "seq": v.seq})
        if not ok:
            raise keys.KeyMismatch("ни одна запись не прошла проверку")
        if len(ok) > 1:
            raise Ambiguous(keys.display_name(nick, tag))
        return ok[0]

    def known_recipient(self, label: str) -> str | None:
        """id_pk, с которым бот уже отправлял этому нику·метке (доверие при первом использовании)."""
        return (self.store.get("contacts") or {}).get(label.lower())

    def remember_recipient(self, label: str, id_pk: str, seq: int = 0) -> None:
        contacts = self.store.get("contacts") or {}
        contacts[label.lower()] = id_pk
        self.store.put("contacts", contacts)
        if seq:
            seen = self.store.get("contact_seq") or {}
            seen[id_pk] = max(int(seen.get(id_pk, 0)), int(seq))
            self.store.put("contact_seq", seen)

    async def refresh_keys(self) -> dict:
        """keys.get: по нему обновляются только ключи inbox_enc. Ключ эмитента закреплён и отсюда не меняется;
        если сервер предлагает другой — это либо смена ключа после компрометации (обновите keys.json из репозитория),
        либо попытка пометить вас отдельным ключом (spec/03). Флаг issuer_mismatch видит интерфейс."""
        doc = await self.exchange.request("keys.get", "ephemeral", SigningKey.generate())
        pinned = b64.enc(self.exchange.server_sig_pk)
        self.keys_doc = keysdoc.verify(doc, pinned)
        self.store.put("keys_doc", self.keys_doc)
        try:
            offered = keysdoc.issuer_key(self.keys_doc)
            mismatch = offered != self.issuer()
        except keysdoc.KeysError:
            mismatch = True
        if mismatch:
            log.warning("keys.get offers an issuer key different from the pinned one")
        self.store.put("issuer_mismatch", True if mismatch else None)
        return self.keys_doc

    async def sync_feed(self) -> list[FeedEvent]:
        """Читает ленту с курсора; находит ответы на свои посты и скрытое для себя (локально, spec/05)."""
        posts, _ = await self.fetch_feed(self.store.get("feed_cursor", 0))
        return await self.process_feed(posts)

    async def fetch_feed(self, since: int, pages: int = 5) -> tuple[list[dict], int]:
        """Записи ленты после номера since (до pages страниц) и номер, с которого читать дальше. Лента общая для всех
        (feed.get — без личности), поэтому пул забирает её один раз на всех своих ботов."""
        out: list[dict] = []
        for _ in range(pages):
            res = await self.exchange.request("feed.get", "ephemeral", SigningKey.generate(), body={"since": since})
            for p in res["posts"]:
                out.append(p)
                since = max(since, p["n"])
            if res.get("next") is None:
                break
            since = res["next"]
        return out, since

    async def process_feed(self, posts: list[dict]) -> list[FeedEvent]:
        """События для владельца из записей ленты новее своего курсора; курсор сдвигается."""
        events: list[FeedEvent] = []
        mine = self.store.my_numbers()
        d = self.device_or_none()
        my_enc = {b64.enc(k.pk): k.sk for k in d.enc} if d else {}  # текущий и прежние ключи шифрования
        since = self.store.get("feed_cursor", 0)
        for p in sorted(posts, key=lambda x: x["n"]):
            if p["n"] <= since:
                continue
            if p.get("reply_to") in mine and p["n"] not in mine:
                events.append(FeedEvent("reply", p["n"], p["reply_to"], p.get("url", ""), p.get("excerpt", "")))
            if p.get("hidden_for") in my_enc:
                ev = self._open_private(p, my_enc[p["hidden_for"]])
                if ev:
                    events.append(ev)
            since = p["n"]
        if since != self.store.get("feed_cursor", 0):
            self.store.put("feed_cursor", since)  # одной записью: у бота в пуле каждая запись — снимок базы на диск
        return events


def _int(v) -> bool:
    return type(v) is int  # bool — тоже int в Python, но не число в JSON


def valid_private(pl) -> bool:
    """Схема расшифрованного «лично для» (spec/07): text — строка до hidden.MAX_TEXT_UNITS UTF-16, entities — объекты
    с целыми offset/length в пределах текста, files — объекты с целым size и строками kind/name/mime разумной длины,
    file_key при файлах, post_pk — строка (с чем её сверять, решает вызывающий)."""
    if not isinstance(pl, dict):
        return False
    text = pl.get("text", "")
    if not isinstance(text, str) or privacy.utf16(text) > hidden.MAX_TEXT_UNITS:
        return False
    n = privacy.utf16(text)
    ents = pl.get("entities", [])
    if not isinstance(ents, list) or len(ents) > 100:
        return False
    for e in ents:
        if not (isinstance(e, dict) and isinstance(e.get("type"), str) and _int(e.get("offset"))
                and _int(e.get("length")) and 0 <= e["offset"] and 0 < e["length"] and e["offset"] + e["length"] <= n):
            return False
    files = pl.get("files") or []
    if not isinstance(files, list) or len(files) > 10:
        return False
    for f in files:
        if not (isinstance(f, dict) and _int(f.get("size")) and 0 <= f["size"] <= privacy.MAX_FILES
                and all(isinstance(f.get(k, ""), str) and len(f.get(k, "")) <= 255 for k in ("kind", "name", "mime"))):
            return False
    pad = pl.get("pad", "")
    if not isinstance(pad, str) or pad.strip(" ") or not isinstance(pl.get("post_pk", ""), str):
        return False
    return not files or isinstance(pl.get("file_key"), str)
