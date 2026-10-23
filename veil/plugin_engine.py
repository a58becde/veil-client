"""Движок плагинов — сторона бота (docs/PLUGINS.md, «Движок»; docs/MARKET.md, «Песочница»).

Код плагина исполняется в WASM-движке (engine/), движок — в процессе-хосте (veil.plugin_host): один на бота, в пуле —
один на группу ботов. Здесь то, что решает бот:
- Engine — файл движка (официальный: SHA-256 закреплён здесь; свой — только подтверждённый владельцем в терминале),
  его машинный код (.cwasm), процесс-хост и протокол с ним, перезапуск не чаще трёх раз в час;
- Runner — один пакет одного бота: что плагин объявил (describe) — по манифесту и разрешениям, заместители его
  обработчиков в реестре бота и каждое действие плагина: разрешение, лимит частоты, кнопки, сеть по списку хостов.
Хост бот не считает доверенным больше, чем нужно: он может сообщить только итог события и попросить действие — а
действие бот выполняет, только если его разрешил манифест и владелец.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import platform
import sys
import time
from importlib import metadata
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from veil import plugin_host, plugins
from veil import plugin_manifest as pm

log = logging.getLogger("veil.plugins")

ENGINE_SHA256 = "6814efbd5a3a6063e253a09494a988a4c6f075d036e23bbbc121658a1a85aea6"  # официальная сборка движка 1
ENGINE_URL = "https://github.com/a58becde/veil-client/releases/download/engine-1/veil-engine.wasm"
ENGINE_MAX = 64 << 20
APP_ROOT = Path(plugins.__file__).resolve().parent.parent
DEFAULT_ENGINE = APP_ROOT / "engine" / "dist" / "veil-engine.wasm"
BOOT = "import sys; sys.path.insert(0, sys.argv[1]); from veil import plugin_host; plugin_host.main()"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
MAX_LINE = 8 << 20
READY_TIMEOUT = 20.0
RESTARTS_PER_HOUR = 3
RATES = {"notify": 20, "propose": 10, "http": 60, "tokens_today": 60, "show": 20, "edit": 30, "ask": 10,
         "storage_get": 600, "storage_put": 120, "storage_delete": 120}  # в минуту, на плагин одного бота
STORAGE_CALLS = frozenset({"storage_get", "storage_put", "storage_delete"})  # без разрешения: своё хранилище
HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
HTTP_BODY_MAX, HTTP_RESPONSE_MAX = 1 << 20, 4 << 20
NET_PER_HOST = 120        # запросов в минуту к одному сайту от всех плагинов всех ботов процесса (пул — с IP сервера)
NET_PARALLEL = 4          # одновременных запросов к одному сайту


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def os_sandbox() -> str | None:
    """Защита ОС для хоста: None — будет (Linux с Landlock и известной архитектурой); иначе — почему её нет. В Linux
    без неё плагины не запускаются, в macOS работают только внутри WASM (владелец видит пометку)."""
    from veil import sandbox, seccomp  # noqa: PLC0415 — ctypes и Landlock только здесь
    if not sys.platform.startswith("linux"):
        return "нет seccomp и Landlock (только Linux)"
    if platform.machine() not in seccomp.ARCHES:
        return f"нет seccomp-фильтра для {platform.machine()}"
    if sandbox.abi() < 1:
        return "ядро без Landlock (нужен Linux 5.13+)"
    return None


def unsupported() -> str | None:
    """Почему плагины здесь не запустить; None — можно."""
    if sys.platform.startswith("linux"):
        why = os_sandbox()
        if why:
            return f"песочница ОС недоступна: {why}"
    elif sys.platform != "darwin":
        return "плагины работают в Linux и macOS"
    try:
        metadata.version("wasmtime")
    except metadata.PackageNotFoundError:
        return "не установлен wasmtime (pip install --require-hashes -r requirements.lock)"
    return None


# --- файл движка: официальный (из релиза, хеш закреплён здесь) или свой, подтверждённый владельцем ---
def engine_path(cfg: dict, base: Path) -> Path:
    """[plugins] engine в конфиге (путь от каталога конфига) или движок рядом с кодом бота."""
    p = (cfg.get("plugins") or {}).get("engine")
    return (base / p) if p else DEFAULT_ENGINE


async def fetch_engine(dest: Path, proxy: str | None = None, transport: httpx.AsyncBaseTransport | None = None) -> str:
    """Скачать официальный движок из релиза и сверить с ENGINE_SHA256; файл заменяется, только если хеш сошёлся."""
    async with httpx.AsyncClient(timeout=120, proxy=proxy, trust_env=proxy is None, follow_redirects=True,
                                 transport=transport) as c:
        async with c.stream("GET", ENGINE_URL) as r:
            if r.status_code != 200:
                raise plugins.PluginError(f"движок не скачался: HTTP {r.status_code}")
            data = bytearray()
            async for chunk in r.aiter_bytes():
                data += chunk
                if len(data) > ENGINE_MAX:
                    raise plugins.PluginError("движок больше ожидаемого — это не он")
    sha = hashlib.sha256(data).hexdigest()
    if sha != ENGINE_SHA256:
        raise plugins.PluginError(f"скачанный движок не совпал с официальной сборкой (SHA-256 {sha[:16]}…)")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_bytes(bytes(data))
    tmp.replace(dest)
    return sha


def make_engine(cfg: dict, base: Path, data_dir: Path, store) -> "Engine":
    """Движок своего бота: машинный код — в данных бота, своя сборка — только подтверждённая (engine trust)."""
    conf = cfg.get("plugins") or {}
    return Engine(engine_path(cfg, base), Path(data_dir) / "engine", set(store.get("engine_trusted") or []),
                  workers=int(conf.get("workers", 4)), memory_mb=int(conf.get("memory_mb", 64)))


def pool_engine(cfg: dict, base: Path) -> "Engine":
    """Движок группы пула: пул не компилирует движок сам (компиляция берёт ~350 МБ) — машинный код кладут заранее в
    precompiled_dir; своя сборка движка — только с хешем в конфиге пула ([plugins] engine_sha256)."""
    conf = cfg.get("plugins") or {}
    trusted = {conf["engine_sha256"]} if conf.get("engine_sha256") else set()
    return Engine(engine_path(cfg, base), base / conf.get("precompiled_dir", "engine"), trusted, compile_ok=False,
                  workers=int(conf.get("workers", 2)), memory_mb=int(conf.get("memory_mb", 64)))


# --- сеть плагинов ---
class NetGate:
    """Общий лимит запросов к одному сайту для всех плагинов процесса: в пуле все боты группы ходят с одного IP,
    и плагин одного бота не должен выбрать лимит сайта за всех (и сделать из сервера пула источник флуда)."""

    def __init__(self, per_minute: int = NET_PER_HOST, parallel: int = NET_PARALLEL):
        self.per_minute, self.parallel = per_minute, parallel
        self.hits: dict[str, list[float]] = {}
        self.slots: dict[str, asyncio.Semaphore] = {}

    def take(self, host: str) -> asyncio.Semaphore:
        now = time.monotonic()
        hits = [t for t in self.hits.get(host, []) if now - t < 60]
        if len(hits) >= self.per_minute:
            self.hits[host] = hits
            raise plugins.PluginError(f"{host}: слишком много запросов с этой машины, попробуйте через минуту")
        self.hits[host] = hits + [now]
        return self.slots.setdefault(host, asyncio.Semaphore(self.parallel))


NET = NetGate()


async def fetch(method: str, url: str, headers: dict, body: bytes, timeout: float, *, allowed: tuple[str, ...],
                proxy: str | None = None, transport: httpx.AsyncBaseTransport | None = None,
                gate: NetGate = NET) -> plugins.Response:
    """HTTPS-запрос от имени плагина: только хосты манифеста, без перехода по перенаправлениям (другой хост плагин
    запросит сам и упрётся в список), ответ до 4 МиБ."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443) or not host:
        raise plugins.PluginError("только https://хост/… без порта и учётных данных")
    if host not in allowed:
        raise plugins.PluginError(f"хоста {host} нет в network манифеста")
    if method not in HTTP_METHODS:
        raise plugins.PluginError(f"метод {method} не разрешён")
    if len(body) > HTTP_BODY_MAX:
        raise plugins.PluginError("тело запроса больше 1 МиБ")
    hdrs = {str(k)[:128]: str(v)[:4096] for k, v in list(headers.items())[:50]
            if str(k).lower() not in ("host", "content-length", "transfer-encoding", "connection")}
    async with gate.take(host):
        async with httpx.AsyncClient(timeout=min(max(timeout, 1.0), 60.0), proxy=proxy, trust_env=proxy is None,
                                     follow_redirects=False, transport=transport) as client:
            async with client.stream(method, url, headers=hdrs, content=body or None) as r:
                data = bytearray()
                async for chunk in r.aiter_bytes():
                    data += chunk
                    if len(data) > HTTP_RESPONSE_MAX:
                        raise plugins.PluginError("ответ больше 4 МиБ")
                return plugins.Response(r.status_code, {k.lower(): v[:4096] for k, v in list(r.headers.items())[:100]},
                                        bytes(data))


# --- движок ---
class Engine:
    """Процесс-хост движка и протокол с ним. Один на бота или на группу пула; пакеты с одинаковым кодом (хеш дерева)
    загружаются в хост один раз. Запускается при первом пакете."""

    def __init__(self, wasm: Path, cache: Path, trusted: set[str] | frozenset[str], *, compile_ok: bool = True,
                 workers: int = 4, memory_mb: int = 64, confine: bool | None = None, read: tuple[Path, ...] = ()):
        self.wasm, self.cache, self.trusted = Path(wasm), Path(cache), frozenset(trusted) | {ENGINE_SHA256}
        self.compile_ok, self.workers, self.memory_mb, self.read = compile_ok, workers, memory_mb, tuple(read)
        self.confine = sys.platform.startswith("linux") if confine is None else confine
        self.proc: asyncio.subprocess.Process | None = None
        self.ready: asyncio.Future | None = None
        self.os_sandbox: bool | None = None
        self.runs: dict[int, tuple[asyncio.Future, object]] = {}
        self.packages: dict[str, list] = {}   # ключ → [пакет, сколько ботов его держат]
        self.n = 0
        self.restarts: list[float] = []
        self.stopping = False
        self.lock = asyncio.Lock()
        self.tasks: set[asyncio.Task] = set()

    # --- файл движка ---
    def problem(self) -> str | None:
        """Почему движок не запустить: платформа, нет файла, файл не тот."""
        if why := unsupported():
            return why
        if not self.wasm.is_file():
            return (f"нет файла движка {self.wasm.name}: скачайте официальный — python -m veil <конфиг> engine fetch")
        if sha256_file(self.wasm) not in self.trusted:
            return ("файл движка не совпадает с официальной сборкой: python -m veil <конфиг> engine fetch, или, если "
                    "собрали сами, подтвердите — python -m veil <конфиг> engine trust")
        return None

    def cwasm(self) -> Path:
        return self.cache / plugin_host.cwasm_name(self.wasm)

    async def _compile(self, out: Path) -> None:
        """Скомпилировать отдельным процессом: компиляция берёт ~350 МБ, которые процесс потом не отдаёт."""
        out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        log.info("plugin engine: compiling %s (once per engine version, ~15 s)", out.name)
        p = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c",
                                                 "import sys; sys.path.insert(0, sys.argv[1]); from veil import "
                                                 "plugin_host; sys.exit(plugin_host.cli(sys.argv[2:]))",
                                                 str(APP_ROOT), "compile", str(self.wasm), str(out), env=ENV,
                                                 stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await p.communicate()
        if p.returncode != 0:
            raise plugins.PluginError(f"движок не скомпилировался: {err.decode('utf-8', 'replace').strip()[-300:]}")
        for old in out.parent.glob("veil-engine-*.cwasm"):  # машинный код прежних версий движка больше не нужен
            if old != out:
                old.unlink(missing_ok=True)

    # --- процесс ---
    async def _ensure(self) -> None:
        if self.proc is not None and self.proc.returncode is None:
            return
        async with self.lock:
            if self.proc is not None and self.proc.returncode is None:
                return
            if self.stopping:
                raise plugins.PluginError("движок плагинов остановлен")
            if why := self.problem():
                raise plugins.PluginError(why)
            if self.proc is not None:  # уже работал и упал
                now = time.monotonic()
                self.restarts = [t for t in self.restarts if now - t < 3600]
                if len(self.restarts) >= RESTARTS_PER_HOUR:
                    raise plugins.PluginError("движок плагинов падает слишком часто — выключен до перезапуска бота")
                self.restarts.append(now)
                log.warning("plugin engine: restarting")
            cw = self.cwasm()
            if not cw.is_file():
                if not self.compile_ok:
                    raise plugins.PluginError(f"нет скомпилированного движка {cw} (здесь не компилируется: "
                                              "python -m veil.plugin_host compile — docs/POOL.md)")
                await self._compile(cw)
            await self._spawn(cw)

    async def _spawn(self, cw: Path) -> None:
        self.proc = await asyncio.create_subprocess_exec(
            sys.executable, "-I", "-c", BOOT, str(APP_ROOT), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=ENV, limit=MAX_LINE)
        self.ready = asyncio.get_running_loop().create_future()
        self._track(self._read(self.proc))
        self._track(self._stderr(self.proc))
        self._send({"t": "hello", "cwasm": str(cw), "workers": self.workers, "memory_mb": self.memory_mb,
                    "read": [str(p) for p in (self.wasm.parent, cw.parent, *self.read)], "confine": self.confine})
        try:
            msg = await asyncio.wait_for(self.ready, READY_TIMEOUT)
        except asyncio.TimeoutError:
            self.proc.kill()
            raise plugins.PluginError("движок плагинов не ответил при запуске") from None
        self.os_sandbox = bool(msg.get("os_sandbox"))
        if self.confine and not self.os_sandbox:
            self.proc.kill()
            raise plugins.PluginError("движок запустился без защиты ОС")
        for key, (pkg, _) in self.packages.items():
            self._send({"t": "load", "key": key, "pkg": pkg})
        log.info("plugin engine started (%s)", "WASM + seccomp + Landlock" if self.os_sandbox else "WASM only")

    def _track(self, coro) -> None:
        t = asyncio.get_running_loop().create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    def _send(self, msg: dict) -> None:
        if self.proc is None or self.proc.returncode is not None:
            raise plugins.PluginError("движок плагинов не работает")
        self.proc.stdin.write((json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode())

    async def _read(self, proc) -> None:
        try:
            while line := await proc.stdout.readline():
                msg = json.loads(line)
                t = msg.get("t") if isinstance(msg, dict) else None
                if t in ("ready", "fail") and self.ready and not self.ready.done():
                    if t == "ready":
                        self.ready.set_result(msg)
                    else:
                        self.ready.set_exception(plugins.PluginError(str(msg.get("error", ""))[:300]))
                elif t == "done":
                    fut = self.runs.get(msg.get("id"), (None,))[0]
                    if fut and not fut.done():
                        fut.set_result(msg)
                elif t == "call":
                    self._track(self._serve_call(msg))
                else:
                    raise ValueError(f"unexpected {t}")
        except (ValueError, asyncio.LimitOverrunError) as e:  # хост нарушил протокол — остановить
            log.warning("plugin engine broke the protocol: %s", type(e).__name__)
            proc.kill()
        finally:
            await proc.wait()
            err = plugins.PluginError("движок плагинов завершился")
            for fut, _ in list(self.runs.values()):
                if not fut.done():
                    fut.set_exception(err)
            if self.ready and not self.ready.done():
                self.ready.set_exception(err)

    async def _stderr(self, proc) -> None:
        lines, since = 0, time.monotonic()
        while line := await proc.stderr.readline():
            if time.monotonic() - since > 60:
                lines, since = 0, time.monotonic()
            lines += 1
            if lines <= 100:
                log.info("plugin engine: %s", line.decode("utf-8", "replace").rstrip()[:500])

    async def _serve_call(self, msg: dict) -> None:
        run = self.runs.get(msg.get("run"))
        try:
            if run is None:
                raise plugins.PluginError("событие уже закончилось")
            value = await run[1](str(msg.get("fn")), msg.get("args") if isinstance(msg.get("args"), dict) else {})
            reply = {"t": "result", "id": msg.get("id"), "ok": True, "value": value}
        except Exception as e:  # noqa: BLE001 — отказ уходит плагину, бот работает дальше
            if not isinstance(e, plugins.PluginError):
                log.warning("plugin call failed: %s", type(e).__name__)
            reply = {"t": "result", "id": msg.get("id"), "ok": False, "error": str(e)[:300] or type(e).__name__}
        try:
            self._send(reply)
        except plugins.PluginError:
            pass

    # --- пакеты и события ---
    async def load(self, key: str, pkg: dict) -> None:
        if key in self.packages:
            self.packages[key][1] += 1
            return
        self.packages[key] = [pkg, 1]
        if self.proc is not None and self.proc.returncode is None:
            self._send({"t": "load", "key": key, "pkg": pkg})

    def release(self, key: str) -> None:
        entry = self.packages.get(key)
        if entry is None:
            return
        entry[1] -= 1
        if entry[1] <= 0:
            del self.packages[key]
            try:
                self._send({"t": "unload", "key": key})
            except plugins.PluginError:
                pass

    async def run(self, op: str, key: str, settings: dict, event: dict | None, timeout: float, on_call) -> dict:
        """describe или handle → ответ движка {"value"…, "log"}; сбой плагина — PluginError с причиной."""
        await self._ensure()
        self.n += 1
        rid = self.n
        fut = asyncio.get_running_loop().create_future()
        self.runs[rid] = (fut, on_call)
        try:
            self._send({"t": "run", "id": rid, "op": op, "key": key, "settings": settings, "event": event,
                        "timeout": timeout})
            msg = await fut
        finally:
            self.runs.pop(rid, None)
        if not msg.get("ok"):
            raise plugins.PluginError(str(msg.get("error", "сбой"))[:300], [str(x) for x in msg.get("log") or []])
        value = msg.get("value")
        if not isinstance(value, dict):
            raise plugins.PluginError("движок вернул не объект")
        return value

    async def stop(self) -> None:
        self.stopping = True
        proc, self.proc = self.proc, None
        if proc and proc.returncode is None:
            try:
                proc.stdin.write(b'{"t":"stop"}\n')
                await asyncio.wait_for(proc.wait(), 2)
            except (asyncio.TimeoutError, OSError, ConnectionError):
                proc.kill()
                await proc.wait()
        for t in list(self.tasks):
            t.cancel()

    def runner(self, reg: plugins.Registry, p: plugins.Loaded, settings: dict) -> "Runner":
        return Runner(reg, p, settings, self)


# --- пакет одного бота ---
class Runner:
    """Пакет одного бота в движке. Регистрирует в реестре бота заместителей своих обработчиков.

    События плагина у одного бота идут по очереди (lock): каждое — в новом экземпляре движка, и без очереди два
    одновременных обработчика прочитали бы хранилище одинаковым и один затёр бы запись другого."""

    def __init__(self, reg: plugins.Registry, p: plugins.Loaded, settings: dict, engine: Engine):
        self.reg, self.p, self.m, self.settings, self.engine = reg, p, p.manifest, settings, engine
        self.lock = asyncio.Lock()
        self.calls: dict[str, list[float]] = {}
        self.events: list[str] = []
        self.ui: dict = {"buttons": [], "inputs": [], "links": []}
        self.loaded = False

    async def start(self) -> None:
        files, digest = pm.read_package(self.p.path)
        if digest != self.p.sha256:
            raise plugins.PluginError("файлы пакета изменились после проверки")
        try:
            pkg = {"id": self.m.id, "entry": self.m.entry,
                   "files": {name: data.decode("utf-8") for name, data in files.items()}}
        except UnicodeDecodeError:
            raise plugins.PluginError("файлы пакета — не UTF-8") from None
        await self.engine.load(self.p.sha256, pkg)
        self.loaded = True
        d = await self._run("describe", None, READY_TIMEOUT)
        events, commands = d.get("events"), d.get("commands")
        self._check_ready(events, commands)
        self.events = list(events)
        self.ui = self._check_ui(d)
        for ev in self.events:
            self.reg.handlers[ev].append((self.m.id, self._event_proxy(ev)))
        for action in self.ui["buttons"]:
            self.reg.buttons[(self.m.id, action)] = self._ui_proxy("button", action)
        for action in self.ui["inputs"]:
            self.reg.inputs[(self.m.id, action)] = self._ui_proxy("input", action)
        for k, ln in enumerate(self.ui["links"]):
            self.reg.links.append((self.m.id, tuple(ln["hosts"]), ln["label"], self._ui_proxy("link", k)))
        for name, desc in commands:
            if name in self.reg.commands:
                raise plugins.PluginError(f"команда /{name} уже есть у плагина {self.reg.commands[name][0]}")
            self.reg.commands[name] = (self.m.id, desc, self._command_proxy(name))
        log.info("plugin %s %s started", self.m.id, self.m.version)

    async def stop(self) -> None:
        if self.loaded:
            self.loaded = False
            self.engine.release(self.p.sha256)

    def _check_ready(self, events, commands) -> None:
        """Плагин подписан только на то, что разрешено манифестом и владельцем."""
        if not isinstance(events, list) or not isinstance(commands, list):
            raise plugins.PluginError("неверный ответ describe")
        for ev in events:
            if ev not in pm.EVENT_PERMISSION:
                raise plugins.PluginError(f"неизвестное событие {ev}")
            need = pm.EVENT_PERMISSION[ev]
            if need and need not in self.m.permissions:
                raise plugins.PluginError(f"событие {ev} без разрешения {need}")
        if commands and "commands" not in self.m.permissions:
            raise plugins.PluginError("команды без разрешения commands")
        for c in commands:
            if not (isinstance(c, list) and len(c) == 2 and plugins.COMMAND.fullmatch(str(c[0]))
                    and str(c[0]) not in plugins.BUILTIN and 3 <= len(str(c[1])) <= 256):
                raise plugins.PluginError("неверная команда в describe")

    def _check_ui(self, msg: dict) -> dict:
        """Кнопки, вопросы и ссылки: формат, размеры и разрешение commands."""
        buttons, inputs, links = msg.get("buttons") or [], msg.get("inputs") or [], msg.get("links") or []
        if not all(isinstance(x, list) for x in (buttons, inputs, links)) or len(buttons) > 100 or len(inputs) > 100 \
                or len(links) > 10:
            raise plugins.PluginError("неверный ответ describe: интерфейс")
        for a in buttons + inputs:
            if not isinstance(a, str) or not plugins.ACTION.fullmatch(a):
                raise plugins.PluginError("неверное действие в describe")
        if len(set(buttons)) != len(buttons) or len(set(inputs)) != len(inputs):
            raise plugins.PluginError("действие объявлено дважды")
        for ln in links:
            hosts, label = (ln.get("hosts"), ln.get("label")) if isinstance(ln, dict) else (None, None)
            if not (isinstance(hosts, list) and 1 <= len(hosts) <= plugins.LINK_HOSTS_MAX
                    and all(isinstance(h, str) and pm.HOST.fullmatch(h) for h in hosts)
                    and isinstance(label, str) and plugins.LINK_LABEL[0] <= len(label) <= plugins.LINK_LABEL[1]):
                raise plugins.PluginError("неверная ссылка в describe")
        if (buttons or inputs or links) and pm.UI_PERMISSION not in self.m.permissions:
            raise plugins.PluginError("кнопки и вопросы без разрешения commands")
        return {"buttons": list(buttons), "inputs": list(inputs), "links": [dict(ln) for ln in links]}

    async def _run(self, op: str, event: dict | None, timeout: float):
        async with self.lock, self.reg.gate:
            try:
                d = await self.engine.run(op, self.p.sha256, self.settings, event, timeout, self._on_call)
            except plugins.PluginError as e:
                for line in e.log[:100]:
                    log.info("plugin %s: %s", self.m.id, line[:500])
                raise
        lines = d.pop("log", None)
        for line in lines[:100] if isinstance(lines, list) else []:
            log.info("plugin %s: %s", self.m.id, str(line)[:500])
        return d

    async def _request(self, event: dict, timeout: float):
        return (await self._run("handle", event, timeout)).get("value")

    def _event_proxy(self, ev: str):
        timeout = plugins.SEND_TIMEOUT if ev == "before_send" else plugins.EVENT_TIMEOUT

        async def proxy(*args):
            return await self._request({"t": "event", "ev": ev, "data": plugins.encode_event(args)}, timeout)
        return proxy

    def _ui_proxy(self, ev: str, key):
        async def proxy(arg):
            if ev == "button":
                data = {"action": arg.action, "data": arg.data, "message": arg.message}
            elif ev == "input":
                data = {"action": key, "text": arg}
            else:
                data = {"k": key, "url": arg.url}
            return await self._request({"t": "event", "ev": ev, "data": data}, plugins.COMMAND_TIMEOUT)
        return proxy

    def _command_proxy(self, name: str):
        async def proxy(arg: str):
            return await self._request({"t": "command", "name": name, "arg": arg}, plugins.COMMAND_TIMEOUT)
        return proxy

    # --- действия плагина ---
    def _rate_ok(self, fn: str) -> bool:
        now = time.monotonic()
        hits = [t for t in self.calls.get(fn, []) if now - t < 60]
        if len(hits) >= RATES.get(fn, 10):
            self.calls[fn] = hits
            return False
        self.calls[fn] = hits + [now]
        return True

    def _rows(self, raw) -> list:
        """Кнопки от плагина — заново собраны и проверены здесь: каждой нужен свой обработчик."""
        try:
            rows = plugins.check_rows(raw)
        except (TypeError, ValueError):
            raise plugins.PluginError("кнопки: [[[подпись, действие, данные], …], …]") from None
        if rows and pm.UI_PERMISSION not in self.m.permissions:
            raise plugins.PluginError("кнопки без разрешения commands")
        for row in rows:
            for _, action, _ in row:
                if action not in self.ui["buttons"]:
                    raise plugins.PluginError(f"кнопка без обработчика @on_button({action!r})")
        return rows

    async def _on_call(self, fn: str, args: dict):
        if fn not in pm.CALL_PERMISSION and fn not in STORAGE_CALLS:
            raise plugins.PluginError(f"нет действия {fn}")
        need = pm.CALL_PERMISSION.get(fn)
        if need and need not in self.m.permissions:
            raise plugins.PluginError(f"нет разрешения {need}")
        if not self._rate_ok(fn):
            raise plugins.PluginError(f"{fn}: слишком часто")
        host = self.reg.host
        if fn in STORAGE_CALLS:
            return await self._storage(fn, args)
        if fn == "notify":
            await host.notify(f"🧩 {self.m.name}: {str(args.get('text', ''))[:4000]}")
            return None
        if fn == "propose":
            reply_to = args.get("reply_to")
            await host.propose(str(args.get("text", ""))[:4096], reply_to if type(reply_to) is int else None,
                               source=self.m.name)
            return None
        if fn == "tokens_today":
            return int(await host.tokens_today())
        if fn in ("show", "edit"):
            rows = self._rows(args.get("buttons"))
            text = str(args.get("text", ""))[:4000]
            if fn == "show":
                return int(await host.show(self.m.id, text, rows))
            message = args.get("message")
            await host.edit(self.m.id, message if type(message) is int else 0, text, rows)
            return None
        if fn == "ask":
            action = str(args.get("action", ""))
            if action not in self.ui["inputs"]:
                raise plugins.PluginError(f"ask: нет обработчика @on_input({action!r})")
            await host.ask(self.m.id, str(args.get("prompt", ""))[:1000], action)
            return None
        try:
            body = base64.b64decode(str(args.get("body", "")), validate=True)
            timeout = float(args.get("timeout", 20))
        except (ValueError, TypeError):
            raise plugins.PluginError("http: неверные аргументы") from None
        headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}
        r = await fetch(str(args.get("method", "GET")).upper(), str(args.get("url", "")), headers, body, timeout,
                        allowed=self.m.network, proxy=getattr(host, "proxy", None),
                        transport=getattr(host, "http_transport", None))
        return {"status": r.status, "headers": r.headers, "body": base64.b64encode(r.body).decode()}

    async def _storage(self, fn: str, args: dict):
        """Своё хранилище плагина у бота: ключи — строки, значения — JSON, всего до 1 МиБ."""
        data = dict(self.reg.host.storage_load(self.m.id) or {})
        if fn == "storage_get":
            return data
        key = args.get("key")
        if not isinstance(key, str) or not 1 <= len(key) <= 256:
            raise plugins.PluginError("ключ хранилища — строка до 256 символов")
        if fn == "storage_put":
            data[key] = args.get("value")
        elif key in data:
            del data[key]
        else:
            return None
        if len(json.dumps(data, ensure_ascii=False).encode()) > plugins.STORAGE_MAX:
            raise plugins.PluginError("хранилище плагина больше 1 МиБ")
        self.reg.host.storage_save(self.m.id, data)
        return None


def main(argv: list[str]) -> int:
    """python -m veil.plugin_engine fetch [путь] — скачать официальный движок."""
    if argv[:1] != ["fetch"]:
        print(main.__doc__)
        return 2
    dest = Path(argv[1]) if len(argv) > 1 else DEFAULT_ENGINE
    try:
        sha = asyncio.run(fetch_engine(dest))
    except plugins.PluginError as e:
        print(f"Движок не скачан: {e}")
        return 1
    print(f"{dest}\nSHA-256 {sha} — официальная сборка")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
