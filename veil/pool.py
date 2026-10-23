"""Пул ботов Veil (docs/POOL.md): человек создаёт себе бота в пару нажатий, а работает бот здесь.

    python -m veil.pool pool.toml

Механизм Telegram «managed bots» (core.telegram.org/bots/features): у бота-менеджера в мини-приложении @BotFather
включён Bot Management Mode. Менеджер даёт ссылку https://t.me/newbot/<менеджер>/<username>?name=<имя>, человек
подтверждает создание, менеджер получает апдейт `managed_bot` и берёт токен `getManagedBotToken`.

Процессы. Менеджер (этот процесс) ведёт бота-менеджера, ограничения и список «бот → владелец, группа» и данных ботов
не держит. Боты работают в рабочих процессах группами по `group_size`: у каждой группы свой ключ (из главного ключа
пула), и рабочий процесс получает только его и токены своих ботов. Ошибка, через которую удалось бы выполнить код в
одном процессе, раскроет одну группу, а не весь пул. Связь менеджер ↔ группа — строки JSON по stdin/stdout.

Доверие: оператор пула видит, кто владелец бота и что он пишет боту, и держит ключ устройства. Для анонимности от
оператора — свой бот на своей машине (spec/02, «Бот в пуле»).

Плагины (docs/POOL.md, «Плагины»): только из маркета, по согласию владельца бота. Движок плагинов — один процесс на
группу, без ключей и сети; сеть плагинов — через бота, с общим на группу лимитом на сайт.
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import secrets
import shutil
import sys
import time
import urllib.parse
from pathlib import Path

import nacl.secret

from veil import sandbox
from veil.core.crypto import bip39, keys
from veil.core.store.db import Store, _shred, _write_private
from veil.core.transport.telegram import Bot, TelegramError

log = logging.getLogger("veil.pool")
_background: set[asyncio.Task] = set()


def background(coro) -> asyncio.Task:
    """Фоновая задача: ссылка хранится, пока задача идёт (иначе её мог бы собрать сборщик мусора), а исключение
    попадает в журнал, а не теряется."""
    t = asyncio.get_running_loop().create_task(coro)
    _background.add(t)

    def done(task: asyncio.Task) -> None:
        _background.discard(task)
        if not task.cancelled() and task.exception() is not None:
            log.error("background task failed: %s", type(task.exception()).__name__, exc_info=task.exception())
    t.add_done_callback(done)
    return t
RESTART_AFTER = 30       # с: бот пула упал — перезапуск
WORKER_RESTART = 10      # с: рабочий процесс упал — перезапуск
FEED_KEEP = 5000         # записей ленты в памяти группы: отставший сильнее бот дочитывает сам
FEED_MIN_GAP = 60        # с: обновление по действию владельца — не чаще
GONE_KEEP = 30 * 86400   # с: данные бота, удалённого владельцем в @BotFather, хранятся столько, затем стираются
CREATE_PER_DAY = 3       # новых ботов в пуле на человека за сутки (сверх предела max_bots_per_user)


def load_key(path: Path) -> bytes:
    """Главный ключ пула: 32 байта hex в файле с правами 600 вне каталога данных. Нет файла — создаётся."""
    if path.exists():
        if path.stat().st_mode & 0o077:
            raise SystemExit(f"{path}: права должны быть 600")
        key = bytes.fromhex(path.read_text().strip())
        if len(key) != 32:
            raise SystemExit(f"{path}: нужен ключ 32 байта (64 hex)")
        return key
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex() + "\n")
    log.warning("created pool key %s — сохраните его копию: без него данные пула не прочитать", path)
    return key


def group_key(master: bytes, group: int) -> bytes:
    return keys.hkdf_sha256(master, f"veil/pool/group/{group}".encode())


def index_key(master: bytes) -> bytes:
    return keys.hkdf_sha256(master, b"veil/pool/index")


def create_identity(store: Store, mode: str) -> tuple[keys.Device, str | None]:
    """Новая личность бота в пуле. Возвращает устройство и сетку 12 слов для показа (None в режиме custodial).
    Корень, как и в `init`, не сохраняется: на диске только ключ устройства."""
    mnemonic = bip39.generate()
    d = keys.issue_device(keys.root_from_seed(bip39.to_seed(mnemonic)))
    store.save_device(d)
    if mode == "custodial":
        return d, None
    words = mnemonic.split()
    rows = (len(words) + 2) // 3
    grid = "\n".join("".join(f"{i + 1:>2}. {words[i]:<12}" for i in (r, r + rows, r + 2 * rows) if i < len(words))
                     for r in range(rows))
    return d, grid


def text(key: str, **kw) -> str:
    t = POOL_TEXTS[key]
    for k, v in kw.items():
        t = t.replace("{" + k + "}", str(v))
    return t


# ============================================================ группа (рабочий процесс)
class Group:
    """Боты одной группы в одном процессе. emit — событие менеджеру (в рабочем процессе — строка JSON в stdout)."""

    def __init__(self, cfg: dict, base: Path, root: Path, key: bytes | None, emit):
        self.cfg, self.base, self.root, self.key, self.emit = cfg, base, root, key, emit
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.stores: dict[int, Store] = {}
        self.tasks: dict[int, asyncio.Task] = {}
        self.uis: dict[int, object] = {}
        self.feed: list[dict] = []
        self.feed_start, self.feed_cursor = 0, None
        self.feed_at = 0.0
        self.feed_lock = asyncio.Lock()
        from veil import plugin_engine  # noqa: PLC0415 — движок плагинов нужен процессу группы, не менеджеру
        self.engine = plugin_engine.pool_engine(cfg, base)

    def store(self, bot_id: int) -> Store:
        if bot_id not in self.stores:
            self.stores[bot_id] = Store(self.root / str(bot_id), key=self.key)
        return self.stores[bot_id]

    async def start_bot(self, bot_id: int, owner: int, token: str | None = None) -> dict | None:
        """Запустить (или перезапустить) бота. Токен приходит от менеджера и хранится в зашифрованной базе бота: если
        Telegram заблокирует менеджера, бот запустится со своим токеном."""
        from veil.__main__ import build  # noqa: PLC0415 — код бота грузит только процесс группы, не менеджер
        store = self.store(bot_id)
        if token and store.get("bot_token") != token:
            store.put("bot_token", token)
        token = token or store.get("bot_token")
        if not token:
            raise RuntimeError("no token")
        store.put("owner_id", owner)
        cfg = copy.deepcopy(self.cfg)
        cfg["telegram"]["owner_id"] = owner
        cfg["pool"]["leave"] = lambda: self.leave(bot_id)
        cfg["pool"]["restart"] = lambda: self._try_start(bot_id)  # после импорта настроек
        cfg["pool"]["feed_now"] = self.feed_soon
        cfg["privacy"]["auto_sync_feed_seconds"] = 0  # своей ленты у бота пула нет: общая на группу (feed_loop)
        ui, bot, core = await build(cfg, self.base, token, store, owner, engine=self.engine)
        me = await bot.get_me()
        store.put("bot_id", me["id"])
        self._stop(bot_id)
        self.tasks[bot_id] = asyncio.create_task(self._serve(bot_id, ui, bot, core))
        self.uis[bot_id] = ui
        log.info("pool bot @%s started", me.get("username"))
        return me

    async def _try_start(self, bot_id: int, owner: int | None = None, token: str | None = None) -> dict | None:
        owner = owner or self.store(bot_id).get("owner_id")
        try:
            me = await self.start_bot(bot_id, owner, token)
            await self.emit({"ev": "started", "bot": bot_id, "username": me.get("username")})
            return me
        except TelegramError as e:  # бот удалён владельцем, токен отозван и т. п.
            log.warning("pool bot %s not started: %s", bot_id, e.description)
            await self.emit({"ev": "failed", "bot": bot_id, "code": e.code})
        except Exception as e:  # noqa: BLE001
            log.warning("pool bot %s not started: %s", bot_id, type(e).__name__)
            await self.emit({"ev": "failed", "bot": bot_id, "code": 0})
        return None

    async def leave(self, bot_id: int) -> None:
        """Владелец отключает бота от пула: бот останавливается, его данные стираются, менеджер узнаёт об этом."""
        self.wipe(bot_id)
        log.info("pool bot %s left the pool", bot_id)
        await self.emit({"ev": "left", "bot": bot_id})
        self._stop(bot_id)  # последним: эта задача может быть задачей самого бота

    def wipe(self, bot_id: int) -> None:
        st = self.stores.pop(bot_id, None)
        if st:
            st.db.close()
        shutil.rmtree(self.root / str(bot_id), ignore_errors=True)

    async def check(self, bot_id: int) -> bool:
        ui = self.uis.get(bot_id)
        if ui is None:
            return False
        await ui.setup()
        return not ui.core.store.get("b2b_error")

    def status(self) -> dict:
        return {str(b): {"b2b": not ui.core.store.get("b2b_error")} for b, ui in self.uis.items()}

    # --- общая лента группы: один запрос вместо запроса от каждого бота ---
    async def feed_refresh(self) -> None:
        async with self.feed_lock:
            self.feed_at = asyncio.get_running_loop().time()
            via = next((ui for ui in self.uis.values() if not ui.core.store.get("b2b_error")), None)
            if via is None:
                return
            if self.feed_cursor is None:  # первый запуск: читать только новое
                known = [c for c in (ui.core.store.get("feed_cursor") for ui in self.uis.values()) if c is not None]
                self.feed_cursor = min(known, default=0)
                self.feed_start = self.feed_cursor
            posts, cursor = await via.core.fetch_feed(self.feed_cursor, pages=20)
            self.feed.extend(posts)
            if len(self.feed) > FEED_KEEP:
                self.feed = self.feed[-FEED_KEEP:]
                self.feed_start = self.feed[0]["n"] - 1
            self.feed_cursor = cursor
            feed, start = list(self.feed), self.feed_start
        for bot_id, ui in list(self.uis.items()):
            try:
                await ui.apply_feed(feed, start, cursor)
            except Exception as e:  # noqa: BLE001 — один бот не мешает остальным
                log.info("pool bot %s feed: %s", bot_id, type(e).__name__)

    async def feed_soon(self) -> None:
        """После действия владельца: обновить ленту группы, если с прошлого раза прошло больше FEED_MIN_GAP."""
        if asyncio.get_running_loop().time() - self.feed_at >= FEED_MIN_GAP and not self.feed_lock.locked():
            await asyncio.sleep(3)  # дать действию дойти до группы
            await self._feed_safe()

    async def _feed_safe(self) -> None:
        try:
            await self.feed_refresh()
        except Exception as e:  # noqa: BLE001 — сеть, сервер: попробуем в следующий раз
            log.info("pool feed: %s", type(e).__name__)

    async def feed_loop(self) -> None:
        every = int(self.cfg["pool"].get("feed_seconds", 3600))
        await asyncio.sleep(30)
        while True:
            await self._feed_safe()
            await asyncio.sleep(every)

    def _stop(self, bot_id: int) -> None:
        self.uis.pop(bot_id, None)
        t = self.tasks.pop(bot_id, None)
        if t:
            t.cancel()

    async def _serve(self, bot_id: int, ui, bot, core) -> None:
        from veil.__main__ import serve  # noqa: PLC0415 — см. start_bot
        try:
            await serve(ui, bot, core)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — один бот не роняет группу
            log.warning("pool bot %s stopped: %s; restart in %d s", bot_id, type(e).__name__, RESTART_AFTER)
            await asyncio.sleep(RESTART_AFTER)
            self.tasks.pop(bot_id, None)
            await self._try_start(bot_id)

    async def handle(self, msg: dict) -> None:
        op, b = msg.get("op"), msg.get("bot")
        if op == "start":
            await self._try_start(b, msg.get("owner"), msg.get("token"))
        elif op == "stop":
            self._stop(b)
        elif op == "wipe":
            self._stop(b)
            self.wipe(b)
        elif op == "check":
            await self.emit({"ev": "checked", "bot": b, "ok": await self.check(b)})
        elif op == "status":
            await self.emit({"ev": "status", "bots": self.status()})


def _proxy_ports(cfg: dict) -> list[int]:
    proxy = (cfg.get("telegram") or {}).get("proxy") or ""
    if proxy:
        return [urllib.parse.urlsplit(proxy).port or 1080]
    return [443]


def _sandbox(cfg: dict, base: Path, root: Path, group: int) -> None:
    """Landlock до обработки любых данных: процессу группы недоступны главный ключ, токен менеджера, индекс и
    другие группы (docs/POOL.md). Без Landlock группа не запускается, если pool.require_sandbox (по умолчанию да)."""
    import veil.__main__  # noqa: F401, PLC0415 — всё, что понадобится боту, загружается до песочницы
    import veil.ui.bot  # noqa: F401, PLC0415
    import veil.core.export  # noqa: F401, PLC0415
    from veil import plugin_engine  # noqa: PLC0415
    app = Path(__file__).resolve().parent.parent
    files = [base / cfg["server"].get("keys_file", "keys.json")]
    # Чтение сверх кода: движок плагинов и его машинный код, локальный каталог маркета (file:// в [market] urls).
    eng = plugin_engine.pool_engine(cfg, base)
    read = [eng.wasm.parent, eng.cache] + [Path(urllib.parse.unquote(u[len("file://"):]))
                                           for u in (cfg.get("market") or {}).get("urls") or [] if u.startswith("file://")]
    try:
        v = sandbox.restrict_group(root, app, files, _proxy_ports(cfg), read)
        log.info("group %d: sandbox on (Landlock ABI %d)", group, v)
    except sandbox.SandboxError as e:
        if cfg["pool"].get("require_sandbox", True):
            raise SystemExit(f"group {group}: песочница не включилась ({e}) — группа не запускается") from None
        log.warning("group %d: WITHOUT sandbox (%s)", group, e)


async def worker_main(cfg: dict, base: Path, group: int) -> None:
    """Рабочий процесс группы: первая строка stdin — ключ группы и каталог; дальше — команды менеджера."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    hello = json.loads(await reader.readline())
    out_lock = asyncio.Lock()

    async def emit(ev: dict) -> None:
        async with out_lock:
            sys.stdout.write(json.dumps(ev) + "\n")
            sys.stdout.flush()
    root = Path(hello["root"])
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    _sandbox(cfg, base, root, group)
    g = Group(cfg, base, root, bytes.fromhex(hello["key"]), emit)
    del hello
    background(g.feed_loop())
    while line := await reader.readline():
        try:
            background(g.handle(json.loads(line)))
        except ValueError:
            log.warning("group %d: bad command", group)
    os._exit(0)  # менеджер закрыл канал — процесс больше не нужен


# ============================================================ менеджер (главный процесс)
class Supervisor:
    def __init__(self, cfg: dict, base: Path, cfg_path: Path, manager_token: str, master: bytes | None):
        self.cfg, self.base, self.cfg_path, self.token, self.master = cfg, base, cfg_path, manager_token, master
        cfg["privacy"].setdefault("keep_posts_days", 7)  # в пуле — короче: меньше связей «человек → пост» на диске
        self.root = base / cfg["pool"].get("data_dir", "pool-data")
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.size = int(cfg["pool"].get("group_size", 25))
        self.index = Store(self.root / "index", key=index_key(master) if master else None)
        self.procs: dict[int, asyncio.subprocess.Process] = {}
        self.state: dict[int, dict] = {}            # бот → {"b2b": bool} по сводкам групп
        self.running: set[int] = set()
        self.checks: dict[int, int] = {}            # бот → владелец, запросивший проверку связи
        self.respawning: set[int] = set()           # группы, ждущие перезапуска процесса
        self.mgr = Bot(manager_token, proxy=cfg["telegram"].get("proxy") or None)
        self.me: dict = {}

    # --- список ботов: владелец, группа, имя, удалён ли (зашифрован ключом индекса) ---
    def bots(self) -> dict[int, dict]:
        return {int(k): v for k, v in (self.index.get("bots") or {}).items()}

    def save_bot(self, bot_id: int, **kw) -> None:
        bots = self.bots()
        bots.setdefault(bot_id, {}).update(kw)
        self.index.put("bots", {str(k): v for k, v in bots.items()})

    def drop_bot(self, bot_id: int) -> None:
        bots = self.bots()
        info = bots.pop(bot_id, None)
        self.index.put("bots", {str(k): v for k, v in bots.items()})
        if info and "group" in info:
            shutil.rmtree(self.root / f"g{info['group']}" / str(bot_id), ignore_errors=True)

    def owned_by(self, user_id: int) -> list[int]:
        return [b for b, v in self.bots().items() if v.get("owner") == user_id]

    def pick_group(self) -> int:
        load: dict[int, int] = {}
        for v in self.bots().values():
            if "group" in v:
                load[v["group"]] = load.get(v["group"], 0) + 1
        for g in sorted(load):
            if load[g] < self.size:
                return g
        return max(load, default=-1) + 1

    def _creation_allowed(self, user_id: int) -> bool:
        """Не больше CREATE_PER_DAY новых ботов на человека за сутки. Счётчик — в индексе на диске: перезапуск пула
        его не обнуляет."""
        now = time.time()
        created = self.index.get("created") or {}
        hits = [t for t in created.get(str(user_id), []) if now - t < 86400]
        return len(hits) < CREATE_PER_DAY

    def _note_created(self, user_id: int) -> None:
        now = time.time()
        created = {u: [t for t in ts if now - t < 86400] for u, ts in (self.index.get("created") or {}).items()}
        created = {u: ts for u, ts in created.items() if ts}
        created.setdefault(str(user_id), []).append(now)
        self.index.put("created", created)
        limit = int(self.cfg["pool"].get("max_bots", 100))
        if len(self.bots()) >= int(limit * 0.8):
            log.warning("pool is %d%% full (%d of %d bots)", 100 * len(self.bots()) // limit, len(self.bots()), limit)

    # --- перевод прежнего пула (один процесс, данные под главным ключом) ---
    def migrate_single(self) -> int:
        """bots.json + <id>/ под главным ключом → индекс + g<N>/<id>/ под ключом группы. Однократно при старте."""
        old = self.root / "bots.json"
        if not old.exists() or not self.master:
            return 0
        n = 0
        for b in json.loads(old.read_text()):
            src = self.root / str(b)
            if not src.exists():
                continue
            st = Store(src, key=self.master)
            g = self.pick_group()
            self.save_bot(b, owner=st.get("owner_id"), username=st.get("bot_username"), group=g,
                          gone_since=st.get("gone_since"))
            st.db.close()
            dst = self.root / f"g{g}" / str(b)
            dst.mkdir(parents=True, exist_ok=True)
            os.chmod(dst.parent, 0o700)
            os.chmod(dst, 0o700)
            old_box, new_box = nacl.secret.SecretBox(self.master), nacl.secret.SecretBox(group_key(self.master, g))
            for name in ("veil.db.enc", "device.json.enc"):
                if (src / name).exists():
                    _write_private(dst / name, new_box.encrypt(old_box.decrypt((src / name).read_bytes())))
            for f in src.iterdir():
                _shred(f)
            src.rmdir()
            n += 1
        _shred(old)
        log.info("pool migrated to groups: %d bots", n)
        return n

    # --- рабочие процессы ---
    async def spawn(self, g: int) -> None:
        if not self.master:  # без главного ключа данные группы шифровались бы нулевым ключом — лучше не запускать
            raise RuntimeError("pool master key is not loaded")
        p = await asyncio.create_subprocess_exec(
            sys.executable, "-W", "ignore", "-m", "veil.pool", "--group", str(g), str(self.cfg_path),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        key = group_key(self.master, g)
        p.stdin.write((json.dumps({"key": key.hex(), "root": str(self.root / f"g{g}")}) + "\n").encode())
        await p.stdin.drain()
        self.procs[g] = p
        background(self._read(g, p))
        for b, v in self.bots().items():
            if v.get("group") == g and not v.get("gone_since"):
                await self.start(b)

    async def send(self, g: int, msg: dict) -> None:
        if g in self.respawning:
            return  # процесс группы перезапускается: при запуске он сам поднимет всех своих ботов
        if g not in self.procs:
            await self.spawn(g)
            if msg.get("op") == "start":
                return  # spawn уже запустил ботов группы
        p = self.procs[g]
        p.stdin.write((json.dumps(msg) + "\n").encode())
        await p.stdin.drain()

    async def _read(self, g: int, p) -> None:
        while line := await p.stdout.readline():
            try:
                await self.on_event(g, json.loads(line))
            except Exception:  # noqa: BLE001
                log.exception("group %d event", g)
        await p.wait()
        if self.procs.get(g) is p:
            del self.procs[g]
            self.running -= {b for b, v in self.bots().items() if v.get("group") == g}
            log.warning("group %d exited (%s); restart in %d s", g, p.returncode, WORKER_RESTART)
            self.respawning.add(g)  # без этого команда во время ожидания запустила бы второй процесс той же группы
            try:
                await asyncio.sleep(WORKER_RESTART)
            finally:
                self.respawning.discard(g)
            if g not in self.procs and any(v.get("group") == g for v in self.bots().values()):
                await self.spawn(g)

    async def start(self, bot_id: int) -> None:
        """Взять токен у Telegram и отдать группе бота. Нет токена (менеджер заблокирован) — группа возьмёт свой."""
        info = self.bots().get(bot_id) or {}
        token = None
        try:
            token = await self.mgr.call("getManagedBotToken", user_id=bot_id)
        except TelegramError as e:
            if e.code in (400, 404) and "not found" in e.description.lower():
                self.mark_gone(bot_id)
                return
            log.warning("pool bot %s: manager cannot fetch token (%s), group uses the stored one", bot_id, e.description)
        # Доступ к боту не ограничивается: при is_access_restricted Telegram не пропускает и приёмного бота сервера
        # (BOT_ACCESS_RESTRICTED), а ID ботов в added_user_ids он молча отбрасывает. Посторонних бот и так не слушает.
        try:
            await self.mgr.call("setManagedBotAccessSettings", user_id=bot_id, is_access_restricted=False)
        except TelegramError as e:
            log.info("pool bot %s access settings: %s", bot_id, e.description)
        await self.send(info["group"], {"op": "start", "bot": bot_id, "owner": info.get("owner"), "token": token})

    def mark_gone(self, bot_id: int) -> None:
        if not (self.bots().get(bot_id) or {}).get("gone_since"):
            self.save_bot(bot_id, gone_since=int(time.time()))  # данные сотрутся через GONE_KEEP

    async def on_event(self, g: int, ev: dict) -> None:
        """Событие процесса группы g. Процессу группы не верим больше, чем нужно (он обрабатывает чужие данные):
        событие принимается только о боте этой же группы, ответ на проверку связи — только на запрос менеджера и
        только владельцу бота, сводка — только о своих ботах."""
        kind = ev.get("ev")
        if kind == "status":
            for k, v in (ev.get("bots") or {}).items():
                if str(k).isdigit() and (self.bots().get(int(k)) or {}).get("group") == g and isinstance(v, dict):
                    self.state[int(k)] = {"b2b": bool(v.get("b2b"))}
            return
        b = ev.get("bot")
        info = self.bots().get(b) if isinstance(b, int) else None
        if not info or info.get("group") != g:
            log.warning("group %d: event about a bot of another group ignored", g)
            return
        if kind == "started":
            self.running.add(b)
            self.save_bot(b, username=ev.get("username"), gone_since=None)
            pending = self.bots()[b].pop("notify_created", None) if b in self.bots() else None
            if pending:
                self.save_bot(b, notify_created=None)
                await self.mgr.send(pending, text("created", bot=ev.get("username")), markup={"inline_keyboard": [[
                    {"text": text("button_check"), "callback_data": f"chk:{b}"}]]})
        elif kind == "failed":
            self.running.discard(b)
            if ev.get("code") in (401, 403):
                self.mark_gone(b)
        elif kind == "left":
            owner = (self.bots().get(b) or {}).get("owner")
            self.running.discard(b)
            self.drop_bot(b)
            if owner:
                await self.mgr.send(owner, text("left"))
        elif kind == "checked":
            user = self.checks.pop(b, None)
            if user is None or user != info.get("owner"):
                return  # менеджер этой проверки не просил
            await self.mgr.send(user, text("check_ok" if ev.get("ok") else "check_fail", bot=info.get("username")))

    # --- бот-менеджер ---
    def create_link(self) -> str:
        suffix = secrets.token_hex(3)
        name = self.cfg["pool"].get("bot_name", "Мой Veil")
        return f"https://t.me/newbot/{self.me['username']}/veil_{suffix}_bot?name=" + urllib.parse.quote_plus(name)

    async def on_managed(self, bot_id: int, creator: int) -> None:
        """Создан бот, сменился его токен или владелец."""
        info = self.bots().get(bot_id)
        if info and info.get("owner") and info["owner"] != creator:
            # Бот передан другому человеку: личность, токены и секреты постов прежнего владельца новому не достаются —
            # они стираются вместе с ботом, а в пуле бот останавливается.
            log.warning("pool bot %s: owner changed, bot stopped and its data wiped", bot_id)
            if "group" in info:
                await self.send(info["group"], {"op": "wipe", "bot": bot_id})
            self.running.discard(bot_id)
            self.drop_bot(bot_id)
            await self.mgr.send(creator, text("owner_changed"))
            return
        if not info:
            limit = int(self.cfg["pool"].get("max_bots_per_user", 1))
            others = [b for b in self.owned_by(creator) if b != bot_id]
            if (len(others) >= limit or len(self.bots()) >= int(self.cfg["pool"].get("max_bots", 100))
                    or not self._creation_allowed(creator)):
                # Бот уже создан Telegram (удалить его через API нельзя), но в пуле не запускается.
                log.info("pool bot %s refused: limit", bot_id)
                await self.mgr.send(creator, text("limit", limit=limit))
                return
            self.save_bot(bot_id, owner=creator, group=self.pick_group(), notify_created=creator)
            self._note_created(creator)
        await self.start(bot_id)

    async def on_update(self, u: dict) -> None:
        if "managed_bot" in u:
            mb = u["managed_bot"]
            await self.on_managed(mb["bot"]["id"], mb["user"]["id"])
            return
        if "callback_query" in u:
            q = u["callback_query"]
            await self.mgr.answer(q["id"])
            data = q.get("data", "")
            if data.startswith("chk:"):
                b = int(data[4:])
                info = self.bots().get(b) or {}
                if info.get("owner") == q["from"]["id"] and "group" in info:
                    self.checks[b] = q["from"]["id"]
                    await self.send(info["group"], {"op": "check", "bot": b})
            return
        m = u.get("message")
        if not m or m["chat"]["type"] != "private" or (m.get("from") or {}).get("is_bot"):
            return
        if "managed_bot_created" in m:
            return  # то же событие, что апдейт managed_bot
        t = m.get("text", "")
        uid = m["from"]["id"]
        if t.startswith("/mybots"):
            await self.my_bots(uid)
        elif t.startswith("/help"):
            await self.mgr.send(uid, text("help"))
        elif t.startswith("/start"):
            if self.owned_by(uid):
                await self.my_bots(uid)
                return
            await self.mgr.send(m["chat"]["id"], text("welcome"), markup={"inline_keyboard": [[
                {"text": text("button_create"), "url": self.create_link()}]]})

    async def my_bots(self, uid: int) -> None:
        rows, lines = [], []
        for b in self.owned_by(uid):
            v = self.bots()[b]
            name = v.get("username") or f"id {b}"
            if v.get("gone_since"):
                left = max(0, int((v["gone_since"] + GONE_KEEP - time.time()) // 86400))
                lines.append(text("bot_gone", bot=name, days=left))
            elif b in self.running and not (self.state.get(b) or {}).get("b2b", True):
                lines.append(text("bot_no_b2b", bot=name))
                rows.append([{"text": text("button_check"), "callback_data": f"chk:{b}"}])
            elif b in self.running:
                lines.append(text("bot_ok", bot=name))
            else:
                lines.append(text("bot_stopped", bot=name))
        await self.mgr.send(uid, "\n".join(lines) or text("welcome"), markup={"inline_keyboard": rows} if rows else None)

    def status(self) -> dict:
        bots = self.bots()
        return {"bots": len(bots), "running": len(self.running), "groups": len(self.procs),
                "no_b2b": sum(1 for v in self.state.values() if not v.get("b2b", True)),
                "gone": sum(1 for v in bots.values() if v.get("gone_since"))}

    async def housekeeping_loop(self) -> None:
        """Раз в 5 минут — сводки групп; раз в час — сводка в журнал (без ID людей) и стирание ботов, удалённых в
        @BotFather больше GONE_KEEP назад. Простаивающие боты не трогаются: владелец может написать в любой момент."""
        tick = 0
        while True:
            await asyncio.sleep(300)
            for g in list(self.procs):
                await self.send(g, {"op": "status"})
            tick += 1
            if tick % 12:
                continue
            for b, v in self.bots().items():
                if v.get("gone_since") and time.time() - v["gone_since"] > GONE_KEEP:
                    log.info("pool bot %s wiped: deleted by owner %d days ago", b, GONE_KEEP // 86400)
                    if v.get("group") in self.procs:
                        await self.send(v["group"], {"op": "wipe", "bot": b})
                    self.drop_bot(b)
            log.info("pool status: %s", self.status())

    async def run(self) -> None:
        self.me = await self.mgr.get_me()
        if not self.me.get("can_manage_bots"):
            raise SystemExit(f"@{self.me.get('username')}: в @BotFather (мини-приложение) не включён Bot Management Mode")
        self.migrate_single()
        groups = sorted({v["group"] for v in self.bots().values() if "group" in v and not v.get("gone_since")})
        log.info("pool manager @%s, bots: %d, groups: %d", self.me["username"], len(self.bots()), len(groups))
        for g in groups:
            await self.spawn(g)
        background(self.housekeeping_loop())
        offset = 0
        while True:
            try:
                ups = await self.mgr.call("getUpdates", offset=offset, timeout=50,
                                          allowed_updates=["message", "managed_bot", "callback_query"])
            except TelegramError as e:
                log.warning("manager getUpdates: %s", e.description)
                await asyncio.sleep(max(e.retry_after, 3))
                continue
            for u in ups:
                offset = u["update_id"] + 1
                try:
                    await self.on_update(u)
                except Exception:  # noqa: BLE001
                    log.exception("manager update")


POOL_TEXTS = {
    "welcome": ("Здесь можно завести свой бот Veil без установки: нажмите кнопку, Telegram предложит создать бота, "
                "и он сразу заработает на общем сервере пула.\n\nВажно: оператор пула видит, кто вы и что вы пишете "
                "своему боту. Для полной анонимности заведите бот на своём компьютере (инструкция — в репозитории "
                "veil-client)."),
    "help": ("/start — завести бота или посмотреть свой; /mybots — мои боты и их состояние. Бот в пуле работает "
             "на общем сервере: оператор видит, кто вы и что вы пишете своему боту. В самом боте: /start — что нужно "
             "для публикации, /export — забрать бота к себе, /leave — отключить от пула."),
    "bot_ok": "@{bot} — работает.",
    "bot_no_b2b": ("@{bot} — нет связи с сервером: в @BotFather → /mybots → @{bot} → Bot Settings → Bot-to-Bot "
                   "Communication — включите и нажмите «Проверить связь»."),
    "bot_gone": "@{bot} — удалён в @BotFather; его данные в пуле сотрутся через {days} дн. Создайте нового: /start.",
    "bot_stopped": "@{bot} — не запущен (перезапуск через несколько минут).",
    "button_check": "Проверить связь",
    "check_ok": "@{bot}: связь с сервером есть. Откройте бота и нажмите «Старт».",
    "check_fail": "@{bot}: связи пока нет — bot-to-bot в @BotFather не включён или ещё не применился. Попробуйте через минуту.",
    "button_create": "Создать моего бота",
    "created": ("Готово: @{bot} создан и работает в пуле.\n\nОсталось одно действие в Telegram: откройте @BotFather → "
                "/mybots → @{bot} → Bot Settings → Bot-to-Bot Communication → включить. Без этого бот не может писать "
                "серверу. Затем нажмите «Проверить связь» и откройте @{bot}."),
    "limit": ("Этот бот не запущен: в пуле можно держать не больше {limit} бота на человека и создавать не больше "
              "3 в сутки. Удалите лишнего бота в @BotFather → /mybots."),
    "left": ("Бот отключён от пула, его данные на сервере пула стёрты. Если вы перенесли его к себе — запускайте. "
             "Токен бота: @BotFather → /mybots → бот → API Token."),
    "owner_changed": ("Бот передан вам, но данные прежнего владельца (личность, токены, посты) не передаются: они стёрты, "
                      "бот в пуле остановлен."),
}


def main() -> None:
    from veil import cli  # noqa: PLC0415 — менеджеру пула код бота не нужен (память, поверхность)
    from veil.__main__ import load_config  # noqa: PLC0415
    cli.harden()  # каждый процесс пула: без дампов памяти, чужой процесс того же пользователя не читает память
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # иначе в журнал попадёт URL с токеном
    args = sys.argv[1:]
    group = None
    if args[:1] == ["--group"]:
        group, args = int(args[1]), args[2:]
    path = Path(args[0] if args else "pool.toml").resolve()
    cfg = load_config(path)
    cfg.setdefault("pool", {})
    if group is not None:
        asyncio.run(worker_main(cfg, path.parent, group))
        return
    token = os.environ.get(cfg["pool"].get("manager_token_env", "VEIL_POOL_MANAGER_TOKEN"), "")
    if not token:
        raise SystemExit("нет токена бота-менеджера в переменной окружения")
    os.environ.pop(cfg["pool"].get("manager_token_env", "VEIL_POOL_MANAGER_TOKEN"), None)  # группам он не нужен
    key = load_key((path.parent / cfg["pool"].get("key_file", "pool.key")).resolve())
    asyncio.run(Supervisor(cfg, path.parent, path, token, key).run())


if __name__ == "__main__":
    main()
