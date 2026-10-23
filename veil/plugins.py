"""Плагины бота (docs/PLUGINS.md, docs/MARKET.md): реестр, загрузка пакетов, события бота → плагинам.

Плагин — пакет `plugins/<id>/` (plugin.toml + *.py) из config.toml или из маркета. Его код исполняется в движке
(veil.plugin_engine): WebAssembly в отдельном процессе без ключей, сети и файлов бота. Здесь — сторона бота: какие
пакеты загружены, заместители их обработчиков, события и действия владельца в интерфейсе плагинов. SDK, который
импортирует код плагина (`from veil import plugins`), живёт внутри движка: engine/guest/veil/plugins.py.

Загружаются только пакеты из config.toml ([plugins] enabled), которые может менять один владелец машины, и
установленные из маркета; в пуле — только из маркета. Сбой плагина не останавливает бота: ошибка уходит в журнал и
коротко — владельцу. Исключение — before_send: если проверка упала или не ответила вовремя, пост не уходит (проверка,
которая молча пропускает, хуже, чем никакой).

Интерфейс плагина в чате — кнопки, а не команды с аргументами: в меню Telegram команду нажимают, и она уходит сразу.
Данные кнопок хранит бот: кнопки самого бота плагин подделать не может, нажатие приходит только своему плагину.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from veil import plugin_manifest as pm

log = logging.getLogger("veil.plugins")

NAME = pm.ID
COMMAND = re.compile(r"[a-z0-9_]{1,32}")  # имя команды Telegram (setMyCommands)
BUILTIN = frozenset({"start", "help", "tokens", "nick", "sync", "export", "import", "cancel", "leave", "market",
                     "plugins"})
EVENTS = tuple(pm.EVENT_PERMISSION)
EVENT_TIMEOUT = 30.0     # с: обработчик события
SEND_TIMEOUT = 10.0      # с: before_send — владелец ждёт отправки
COMMAND_TIMEOUT = 120.0  # с: команда плагина и действия владельца в его интерфейсе
REPORT_EVERY = 3600      # с: одна и та же ошибка плагина — владельцу не чаще раза в час
STORAGE_MAX = 1 << 20    # байт: своё хранилище плагина
ACTION = re.compile(r"[a-z0-9_]{1,32}")  # имя действия кнопки или вопроса
BUTTON_TEXT_MAX, BUTTON_DATA_MAX, BUTTONS_MAX = 64, 256, 24
LINK_LABEL = (3, 40)     # подпись кнопки плагина у черновика со ссылкой
LINK_HOSTS_MAX = 10
PER_BOT = 2              # событий одного бота в движке одновременно: в пуле один бот не занимает движок группы


class PluginError(Exception):
    """Плагин не загружен или не выполнил действие: имя, права файла, ошибка в коде, нет разрешения.
    log — что плагин напечатал до сбоя (для журнала бота)."""

    def __init__(self, message: str = "", log: list[str] | None = None):
        super().__init__(message)
        self.log = log or []


# --- что получают обработчики (тот же вид — в SDK движка) ---
@dataclass(frozen=True)
class Reply:
    """Ответ на ваш пост в группе."""
    n: int      # номер ответа
    to: int     # номер вашего поста
    text: str   # начало текста ответа (как в ленте сервера)
    url: str


@dataclass(frozen=True)
class Private:
    """«Лично для» вас (spec/07): текст уже расшифрован."""
    n: int
    url: str
    text: str
    sender: str      # подпись поста (ник·метка) или "" — пост без подписи
    file_count: int  # файлы забираются только кнопкой владельца


@dataclass(frozen=True)
class Published:
    n: int
    url: str
    anonymous: bool | None   # None — итог дозапрошен после перезапуска, черновика уже нет
    reply_to: int | None


@dataclass(frozen=True)
class Failure:
    op: str    # post.create | post.edit | post.delete | nick.set
    code: str  # код протокола (E_RATE…) или вид сбоя: no_tokens, no_reply, queued, internal


@dataclass(frozen=True)
class Outgoing:
    """Черновик перед отправкой — только для чтения: бот публикует ровно то, что прислал владелец (привязка
    контента к конверту, spec/04), поэтому плагин может отменить отправку, но не изменить пост."""
    kind: str               # text | photo | album | poll | … (privacy.kind)
    text: str               # текст или подпись
    anonymous: bool
    hide: str               # "" | links | message | to
    reply_to: int | None
    to: str                 # «лично для»: ник·метка получателя


@dataclass(frozen=True)
class Press:
    """Нажатие кнопки плагина."""
    action: str
    data: str
    message: int   # сообщение с кнопкой — плагин может его поправить


@dataclass(frozen=True)
class Link:
    """Ссылка из черновика владельца, под которым он нажал кнопку плагина (on_link)."""
    url: str


@dataclass(frozen=True)
class Response:
    """Ответ на http плагина."""
    status: int
    headers: dict
    body: bytes


def encode_event(args: tuple) -> Any:
    """Аргумент события — в JSON для движка."""
    if not args:
        return None
    a = args[0]
    return asdict(a) if hasattr(a, "__dataclass_fields__") else a


def check_rows(raw) -> list[list[list[str]]]:
    """Кнопки от плагина: [[[подпись, действие, данные], …], …] — формат и размеры. Кнопки собираются заново:
    в Telegram уходит только номер записи бота."""
    if not raw:
        return []
    if not isinstance(raw, list) or not all(isinstance(row, list) and row for row in raw):
        raise ValueError("rows")
    out = [[[str(t), str(a), str(d)] for t, a, d in row] for row in raw]
    flat = [b for row in out for b in row]
    if len(flat) > BUTTONS_MAX:
        raise PluginError(f"кнопок — не больше {BUTTONS_MAX}")
    for text, action, data in flat:
        if not 1 <= len(text) <= BUTTON_TEXT_MAX or not ACTION.fullmatch(action) or len(data) > BUTTON_DATA_MAX:
            raise PluginError(f"кнопка {text[:20]!r}: подпись 1–{BUTTON_TEXT_MAX} символов, действие a-z0-9_, "
                              f"данные до {BUTTON_DATA_MAX}")
    return out


def failure_kind(e: BaseException) -> str:
    """Вид сбоя плагина для владельца: KeyError, TimeoutError, «нет разрешения notify» — без текста из плагина."""
    if isinstance(e, asyncio.TimeoutError) or str(e) == "время вышло":
        return "TimeoutError"
    if isinstance(e, PluginError) and str(e):
        return str(e).split(":", 1)[0][:80]
    return type(e).__name__


def host_matches(url: str, hosts: tuple[str, ...]) -> bool:
    from urllib.parse import urlsplit  # noqa: PLC0415 — нужен только здесь
    try:
        host = (urlsplit(url if "://" in url else "https://" + url).hostname or "").lower()
    except ValueError:
        return False
    return any(host == h or host.endswith("." + h) for h in hosts)


@dataclass
class Loaded:
    name: str
    path: Path
    sha256: str
    manifest: pm.Manifest


Handler = Callable[..., Awaitable[Any]]


@dataclass
class Registry:
    """Плагины одного бота. Пустой реестр (плагинов нет) ничего не делает.

    host — исполнитель действий плагинов (сообщения владельцу, черновики, кнопки, хранилище) — интерфейс бота;
    engine — движок плагинов (veil.plugin_engine.Engine), в пуле общий для группы ботов."""
    tokens_low: int = 5
    handlers: dict[str, list[tuple[str, Handler]]] = field(default_factory=lambda: {e: [] for e in EVENTS})
    commands: dict[str, tuple[str, str, Handler]] = field(default_factory=dict)
    loaded: list[Loaded] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    packages: list[Loaded] = field(default_factory=list)  # проверенные пакеты: запускает start
    # Интерфейс: (плагин, действие) → обработчик; ссылки — (плагин, хосты, подпись, обработчик), по порядку объявления.
    buttons: dict[tuple[str, str], Handler] = field(default_factory=dict)
    inputs: dict[tuple[str, str], Handler] = field(default_factory=dict)
    links: list[tuple[str, tuple[str, ...], str, Handler]] = field(default_factory=list)
    pending: list[Loaded] = field(default_factory=list)   # пакеты, ждущие согласия владельца на разрешения
    settings: dict[str, dict] = field(default_factory=dict)
    tasks: set[asyncio.Task] = field(default_factory=set)
    runners: dict[str, Any] = field(default_factory=dict)
    host: Any = None
    engine: Any = None
    gate: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(PER_BOT))
    _reported: dict[tuple[str, str], float] = field(default_factory=dict)

    def menu(self) -> list[tuple[str, str]]:
        return [(name, desc) for name, (_, desc, _) in sorted(self.commands.items())]

    # --- пакеты в движке ---
    async def start(self, grants: dict | None) -> None:
        """Запустить пакеты, разрешения которых владелец уже одобрил; остальные ждут согласия (pending)."""
        for p in self.packages:
            if p.manifest.covered_by((grants or {}).get(p.name)):
                await self.start_package(p)
            else:
                self.pending.append(p)

    async def start_package(self, p: Loaded) -> bool:
        if p in self.pending:
            self.pending.remove(p)
        try:
            if self.engine is None:
                raise PluginError("движок плагинов не подключён")
            runner = self.engine.runner(self, p, self.settings.get(p.name, {}))
            self.runners[p.name] = runner
            await runner.start()
        except Exception as e:  # noqa: BLE001 — не запустился: бот работает без него
            log.error("plugin %s not started: %s", p.name, e)
            self.failed.append((p.name, str(e) or type(e).__name__))
            await self.remove(p.name, keep_package=True)
            return False
        self.loaded.append(p)
        return True

    async def stop(self) -> None:
        for runner in list(self.runners.values()):
            await runner.stop()
        self.runners.clear()

    async def remove(self, name: str, keep_package: bool = False) -> None:
        """Снять плагин на ходу (обновление, удаление, отзыв каталогом): обработчики и команды убираются."""
        runner = self.runners.pop(name, None)
        if runner:
            await runner.stop()
        self.handlers = {e: [(p, fn) for p, fn in hs if p != name] for e, hs in self.handlers.items()}
        self.commands = {c: v for c, v in self.commands.items() if v[0] != name}
        self.buttons = {k: v for k, v in self.buttons.items() if k[0] != name}
        self.inputs = {k: v for k, v in self.inputs.items() if k[0] != name}
        self.links = [x for x in self.links if x[0] != name]
        self.loaded = [p for p in self.loaded if p.name != name]
        self.pending = [p for p in self.pending if p.name != name]
        if not keep_package:
            self.packages = [p for p in self.packages if p.name != name]

    # --- события ---
    def fire(self, event: str, *args) -> None:
        """Событие для плагинов — фоном: бот не ждёт обработчиков."""
        for plugin, fn in self.handlers[event]:
            t = asyncio.get_running_loop().create_task(self._call(plugin, event, fn, args, EVENT_TIMEOUT + 2))
            self.tasks.add(t)
            t.add_done_callback(self.tasks.discard)

    async def check_send(self, out: Outgoing) -> str | None:
        """before_send: None — можно отправлять; иначе причина отказа для владельца. Обработчик возвращает None или
        True (можно), False (нельзя) или строку — причину. Упавшая или зависшая проверка — отказ."""
        for plugin, fn in self.handlers["before_send"]:
            try:
                verdict = await asyncio.wait_for(fn(out), SEND_TIMEOUT + 2)
            except Exception as e:  # noqa: BLE001 — проверка не прошла: пост не уходит
                self._log_failure(plugin, "before_send", e)
                return f"{plugin}: проверка не выполнилась ({failure_kind(e)})"
            if verdict is False:
                return plugin
            if isinstance(verdict, str):
                return f"{plugin}: {verdict[:300]}"
        return None

    async def run_command(self, name: str, arg: str) -> bool:
        """Команда плагина. False — такой команды нет."""
        if name not in self.commands:
            return False
        plugin, _, fn = self.commands[name]
        await self._call(plugin, f"/{name}", fn, (arg,), COMMAND_TIMEOUT + 2)
        return True

    # --- интерфейс: всё запускает нажатие владельца ---
    async def press(self, plugin: str, press: Press) -> bool:
        """Нажата кнопка плагина. False — плагина или действия больше нет."""
        fn = self.buttons.get((plugin, press.action))
        if fn is None:
            return False
        await self._call(plugin, f"кнопка {press.action}", fn, (press,), COMMAND_TIMEOUT + 2)
        return True

    async def answer(self, plugin: str, action: str, text: str) -> bool:
        """Ответ владельца на вопрос плагина (ask)."""
        fn = self.inputs.get((plugin, action))
        if fn is None:
            return False
        await self._call(plugin, f"ответ {action}", fn, (text,), COMMAND_TIMEOUT + 2)
        return True

    def link_buttons(self, urls: list[str]) -> list[tuple[str, int, str, str]]:
        """Кнопки плагинов к черновику со ссылками: (плагин, номер обработчика у плагина, подпись, ссылка) — первая
        подходящая ссылка на каждый обработчик, не больше трёх кнопок."""
        out = []
        per: dict[str, int] = {}
        for plugin, hosts, label, _ in self.links:
            k = per.get(plugin, 0)
            per[plugin] = k + 1
            url = next((u for u in urls if host_matches(u, hosts)), None)
            if url and len(out) < 3:
                out.append((plugin, k, label, url))
        return out

    async def open_link(self, plugin: str, k: int, url: str) -> bool:
        mine = [x for x in self.links if x[0] == plugin]
        if not 0 <= k < len(mine) or not host_matches(url, mine[k][1]):
            return False
        await self._call(plugin, "ссылка", mine[k][3], (Link(url),), COMMAND_TIMEOUT + 2)
        return True

    async def _call(self, plugin: str, event: str, fn: Handler, args: tuple, timeout: float) -> None:
        try:
            await asyncio.wait_for(fn(*args), timeout)
        except Exception as e:  # noqa: BLE001 — сбой плагина не должен ронять бота
            self._log_failure(plugin, event, e)
            await self.report(plugin, event, e)

    def _log_failure(self, plugin: str, event: str, e: BaseException) -> None:
        if isinstance(e, asyncio.TimeoutError):
            log.warning("plugin %s: %s timed out", plugin, event)
        elif isinstance(e, PluginError):
            log.warning("plugin %s: %s failed: %s", plugin, event, e)
        else:
            log.error("plugin %s: %s failed", plugin, event, exc_info=e)

    async def report(self, plugin: str, event: str, e: BaseException | str) -> None:
        """Владельцу — коротко, не чаще раза в час на одно и то же."""
        now = time.monotonic()
        if self.host is None or now - self._reported.get((plugin, event), -REPORT_EVERY) < REPORT_EVERY:
            return
        self._reported[(plugin, event)] = now
        try:
            await self.host.report(plugin, event, e if isinstance(e, str) else failure_kind(e))
        except Exception as err:  # noqa: BLE001 — сообщить не удалось: ошибка уже в журнале
            log.info("plugin error report: %s", type(err).__name__)


# --- загрузка ---
def _check_owner_only(path: Path, what: str) -> None:
    """Каталог и файлы плагинов — не ссылка, принадлежат пользователю бота, писать в них не может никто другой: иначе
    чужой пользователь машины подменил бы плагин (он работает с правами, которые ему дал владелец)."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise PluginError(f"{what} — символическая ссылка")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise PluginError(f"{what} принадлежит другому пользователю")
    if st.st_mode & 0o022:
        raise PluginError(f"{what} могут менять другие пользователи (chmod go-w)")


def load_package(pdir: Path, name: str) -> Loaded:
    """Пакет plugins/<id>/ с манифестом: проверить и посчитать; запускается позже, в движке (Registry.start)."""
    path = pdir / name
    _check_owner_only(path, f"каталог {name}/")
    try:
        files = pm.package_files(path)
        for f in files:
            _check_owner_only(f, f"{name}/{f.name}")
        m = pm.load(path)
        digest = pm.package_hash(path)
    except pm.ManifestError as e:
        raise PluginError(str(e)) from None
    return Loaded(name, path, digest, m)


def load(cfg: dict, base: Path, market: tuple | None = None, engine: Any = None) -> Registry:
    """Пакеты из config.toml ([plugins] enabled) и установленные из маркета (market = (каталог пакетов, установленные
    {id: {tree, …}}, отозванные {id: причина})). Не загрузившийся пакет попадает в failed, бот работает без него.
    Здесь пакеты только проверяются, запускаются они в движке — Registry.start. В пуле — только плагины из маркета:
    каталог plugins/ оператора пула не должен попадать ко всем ботам."""
    conf = cfg.get("plugins") or {}
    reg = Registry(tokens_low=int(conf.get("tokens_low", 5)), engine=engine)
    reg.settings = {str(k): dict(v) for k, v in (conf.get("settings") or {}).items() if isinstance(v, dict)}
    names = [str(n) for n in conf.get("enabled") or []]
    if cfg.get("pool") and names:
        log.warning("[plugins] enabled is ignored in a pool: only market plugins run there")
        names = []
    if market:
        _load_market(reg, names, *market)
    if not names:
        return reg
    pdir = base / conf.get("dir", "plugins")
    try:
        _check_owner_only(pdir, "каталог плагинов")
    except (PluginError, FileNotFoundError) as e:
        reg.failed += [(str(n), str(e) or "нет каталога плагинов") for n in names]
        return reg
    for name in names:
        try:
            if not NAME.fullmatch(name):
                raise PluginError("имя: a-z, 0-9, _ (до 32 символов, с буквы)")
            if not (pdir / name).is_dir() or (pdir / name).is_symlink():
                raise PluginError(f"нет пакета {name}/ (каталог с plugin.toml) в {pdir.name}/")
            reg.packages.append(load_package(pdir, name))
        except (PluginError, OSError) as e:
            log.error("plugin %s not loaded: %s", name, e)
            reg.failed.append((name, str(e)))
    return reg


def _load_market(reg: Registry, names: list[str], mdir: Path, installed: dict, revoked: dict) -> None:
    """Пакеты, поставленные из маркета: та же проверка, что у пакетов из config.toml, плюс — не отозваны каталогом и
    файлы не менялись после установки (хеш дерева пакета)."""
    for name in sorted(installed):
        try:
            if name in names:
                raise PluginError("такой плагин уже есть в [plugins] enabled — из маркета не запускаю")
            if name in revoked:
                raise PluginError(f"сборка отозвана каталогом: {revoked[name]}")
            p = load_package(mdir, name)
            if p.sha256 != installed[name].get("tree"):
                raise PluginError("файлы плагина изменены после установки из маркета")
            reg.packages.append(p)
        except (PluginError, OSError) as e:
            log.error("market plugin %s not loaded: %s", name, e)
            reg.failed.append((name, str(e)))


def changes(reg: Registry, seen: dict | None) -> tuple[dict, list[str]]:
    """Что изменилось с прошлого запуска: новые, изменённые и убранные плагины (по SHA-256 кода). Владелец узнаёт
    о каждой смене кода, работающего у него, — в том числе о подмене файла."""
    now = {p.name: p.sha256 for p in reg.loaded + reg.pending}
    seen = seen or {}
    lines = [f"+ {n} ({h[:12]})" for n, h in now.items() if n not in seen]
    lines += [f"~ {n} ({h[:12]})" for n, h in now.items() if n in seen and seen[n] != h]
    lines += [f"− {n}" for n in seen if n not in now]
    return now, lines


def storage_key(plugin: str) -> str:
    """Где у бота лежит хранилище плагина (данные бота; в пуле — зашифрованные)."""
    return f"plugin_storage:{plugin}"

