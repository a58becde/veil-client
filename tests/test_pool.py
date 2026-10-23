"""Пул ботов (docs/POOL.md): владелец из апдейта managed_bot, личность кнопкой, 12 слов — один раз."""
import asyncio
from pathlib import Path

from veil import pool
from veil.core.crypto import bip39
from veil.core.store.db import Store
from veil.ui import bot as uibot

ROOT = Path(__file__).resolve().parent.parent


def test_create_identity_modes(tmp_path):
    d, grid = pool.create_identity(Store(tmp_path / "a"), "words_once")
    import re
    words = dict((int(n), w) for n, w in re.findall(r"(\d+)\. (\S+)", grid))
    assert sorted(words) == list(range(1, 13)) and bip39.validate(" ".join(words[i] for i in range(1, 13)))
    assert "mnemonic" not in (tmp_path / "a" / "device.json").read_text()
    d2, none = pool.create_identity(Store(tmp_path / "b"), "custodial")
    assert none is None and d2.tag != d.tag


class _Bot:
    def __init__(self):
        self.calls, self.deleted = [], []

    async def call(self, method, **kw):
        self.calls.append((method, kw))
        return {"message_id": 77}

    async def send(self, chat, text, **kw):
        self.calls.append(("send", {"text": text, **kw}))
        return {"message_id": 78}

    async def edit(self, chat, mid, text, **kw):
        self.calls.append(("edit", {"text": text}))

    async def delete(self, chat, mid):
        self.deleted.append(mid)

    async def answer(self, *a, **kw):
        pass


def _ui(tmp_path):
    ui = uibot.UI.__new__(uibot.UI)
    ui.bot, ui.owner, ui.config_name, ui.tasks = _Bot(), 1, "pool.toml", set()
    ui.T = uibot.Texts(ROOT / "locales" / "ru.toml", {})
    ui.pool = {"identity": "words_once"}
    ui.cfg = {"privacy": {"random_delay_seconds": [15, 90]}}
    ui.plugins = uibot.plug.Registry()  # UI собран без __init__: плагинов нет
    class Core:
        _device = None
        nick = staticmethod(lambda: None)

        def has_identity(self):
            return self.store.load_device() is not None

        @property
        def device(self):
            return self.store.load_device()
    ui.core = Core()
    ui.core.store = Store(tmp_path)
    synced = []

    async def sync(quiet=False):
        synced.append(True)
    ui._sync_identity = sync
    return ui, synced


def test_pool_identity_words_shown_once_and_deleted(tmp_path):
    ui, synced = _ui(tmp_path)
    msg = {"chat": {"id": 1}, "message_id": 5}

    async def flow():
        await ui._pool_identity("id:new", msg)
        sent = [kw for m, kw in ui.bot.calls if m == "sendMessage"]
        assert len(sent) == 1 and sent[0]["protect_content"] is True and sent[0]["entities"][0]["type"] == "pre"
        assert ui.core.store.get("words_msg") == 77 and ui.core.store.load_device() is not None
        await ui._pool_identity("id:ok", msg)
        for t in list(ui.tasks):
            t.cancel()
        await asyncio.gather(*ui.tasks, return_exceptions=True)
    asyncio.run(flow())
    assert ui.bot.deleted == [77] and ui.core.store.get("words_msg") is None and synced == [True]


def test_pool_words_expire_survives_restart(tmp_path, monkeypatch):
    """срок удаления слов — в базе; новый экземпляр бота (после перезапуска) удаляет их по сроку."""
    ui, _ = _ui(tmp_path)
    monkeypatch.setattr(uibot.UI, "WORDS_TTL", 0)
    asyncio.run(ui._pool_identity("id:new", {"chat": {"id": 1}, "message_id": 5}))
    assert ui.core.store.get("wipe_at") and ui.bot.deleted == []
    again, _ = _ui(tmp_path)  # «перезапуск»: в памяти ничего, срок — в базе
    asyncio.run(again.wipe_due())
    assert again.bot.deleted == [77] and again.core.store.get("words_msg") is None
    assert again.core.store.get("wipe_at") is None


def test_status_lists_everything_before_first_post(tmp_path):
    """/start сразу говорит всё: как публиковать, нет связи, нет токенов, личность необязательна, задержка."""
    ui, _ = _ui(tmp_path)
    ui.core.store.put("b2b_error", True)
    text = ui.status_text()
    for part in ("просто напишите", "❌ Нет связи", "❌ Токенов нет", "необязательно", "15–90 с", "оператор"):
        assert part in text, part
    kb = ui.status_keyboard()["inline_keyboard"]
    assert [b["callback_data"] for row in kb for b in row] == ["tok:req", "id:new"]


def test_send_blocked_before_delay(tmp_path, monkeypatch):
    """«Отправить» без токенов: отказ сразу, без случайной задержки; черновик остаётся."""
    from veil.core import api
    ui, _ = _ui(tmp_path)
    i = ui.core.store.save_draft(api.Draft(1, [{"message_id": 1, "text": "пост"}]).to_json())
    slept = []

    async def no_sleep(s):
        slept.append(s)
    monkeypatch.setattr(uibot.asyncio, "sleep", no_sleep)
    asyncio.run(ui._draft_action(i, "send", {"chat": {"id": 1}, "message_id": 5}))
    assert slept == [] and ui.core.store.draft(i) is not None
    assert any("токенов на сегодня нет" in kw.get("text", "") for m, kw in ui.bot.calls)


def test_ui_apply_feed_cursor_rules(tmp_path):
    ui, _ = _ui(tmp_path)
    got = []

    async def process(posts):
        got.append([x["n"] for x in posts])
        return []
    synced = []

    async def own():
        synced.append(True)
    ui.core.process_feed = process
    ui._sync_once = own
    asyncio.run(ui.apply_feed([{"n": 6}], 5, 6))  # новый бот: только запомнить номер
    assert ui.core.store.get("feed_cursor") == 6 and got == []
    asyncio.run(ui.apply_feed([{"n": 7}], 5, 7))
    assert got == [[7]]
    ui.core.store.put("feed_cursor", 2)
    asyncio.run(ui.apply_feed([{"n": 8}], 5, 8))  # отстал дальше, чем помнит пул — дочитывает сам
    assert synced == [True]


def test_load_key_permissions(tmp_path):
    import os

    import pytest
    k = pool.load_key(tmp_path / "pool.key")
    assert len(k) == 32 and (tmp_path / "pool.key").stat().st_mode & 0o077 == 0
    assert pool.load_key(tmp_path / "pool.key") == k
    os.chmod(tmp_path / "pool.key", 0o644)
    with pytest.raises(SystemExit):
        pool.load_key(tmp_path / "pool.key")


# --- менеджер (Supervisor) ---
def _sup(tmp_path, master=None, **pool_cfg):
    cfg = {"telegram": {}, "privacy": {}, "pool": {"max_bots_per_user": 1, "group_size": 2, **pool_cfg}}
    s = pool.Supervisor(cfg, tmp_path, tmp_path / "pool.toml", "1:x", master)
    s.mgr = _Bot()
    s.me = {"username": "mgr_bot"}
    sent = []

    async def send(g, msg):
        sent.append((g, msg))
    s.send = send
    return s, sent


def _texts(s):
    return [kw.get("text", "") for m, kw in s.mgr.calls if m == "send"]


def test_new_bot_owner_and_group(tmp_path):
    s, sent = _sup(tmp_path)

    async def call(method, **kw):
        return "900:tok" if method == "getManagedBotToken" else True
    s.mgr.call = call
    asyncio.run(s.on_update({"managed_bot": {"user": {"id": 42}, "bot": {"id": 900}}}))
    assert s.bots()[900]["owner"] == 42 and s.bots()[900]["group"] == 0
    assert sent == [(0, {"op": "start", "bot": 900, "owner": 42, "token": "900:tok"})]
    asyncio.run(s.on_event(0, {"ev": "started", "bot": 900, "username": "veil_x_bot"}))
    assert any("@veil_x_bot" in t and "Bot-to-Bot" in t for t in _texts(s))
    assert s.owned_by(42) == [900] and s.owned_by(7) == []


def test_groups_fill_by_size(tmp_path):
    s, _ = _sup(tmp_path, max_bots_per_user=10)
    for b in range(5):
        s.save_bot(b, owner=b, group=s.pick_group())
    assert [s.bots()[b]["group"] for b in range(5)] == [0, 0, 1, 1, 2]


def test_owner_change_wipes_bot(tmp_path):
    """Бот передан другому человеку: данные прежнего владельца (личность, токены, секреты постов) стираются, бот
    уходит из пула — новому они не достаются и на сервере пула не остаются."""
    s, sent = _sup(tmp_path)
    s.save_bot(900, owner=42, group=0)
    asyncio.run(s.on_managed(900, 43))
    assert sent == [(0, {"op": "wipe", "bot": 900})] and 900 not in s.bots()
    assert any("не передаются" in t and "стёрты" in t for t in _texts(s))


def test_one_bot_per_user_and_rate_limit(tmp_path):
    s, sent = _sup(tmp_path)
    s.save_bot(900, owner=42, group=0)
    asyncio.run(s.on_managed(901, 42))
    assert 901 not in s.bots() and sent == [] and any("не больше 1 бота" in t for t in _texts(s))
    s2, sent2 = _sup(tmp_path / "b", max_bots_per_user=10)
    s2.index.put("created", {"42": [__import__("time").time()] * pool.CREATE_PER_DAY})
    asyncio.run(s2.on_managed(950, 42))
    assert 950 not in s2.bots() and sent2 == []


def test_start_link_is_inline_url(tmp_path):
    s, _ = _sup(tmp_path)
    asyncio.run(s.on_update({"message": {"chat": {"id": 5, "type": "private"}, "from": {"id": 5}, "text": "/start"}}))
    [(m, kw)] = s.mgr.calls
    assert kw["markup"]["inline_keyboard"][0][0]["url"].startswith("https://t.me/newbot/mgr_bot/veil_")


def test_token_missing_and_gone(tmp_path):
    """Менеджер заблокирован — группа берёт свой токен (token=None); бот удалён в @BotFather — помечается, отчёт в
    /mybots, данные стираются через GONE_KEEP."""
    from veil.core.transport.telegram import TelegramError
    s, sent = _sup(tmp_path)
    s.save_bot(900, owner=42, group=0, username="veil_x_bot")

    async def blocked(method, **kw):
        raise TelegramError(method, 403, "Forbidden: bot was blocked")
    s.mgr.call = blocked
    asyncio.run(s.start(900))
    assert sent[-1] == (0, {"op": "start", "bot": 900, "owner": 42, "token": None})

    async def gone(method, **kw):
        raise TelegramError(method, 400, "Bad Request: bot not found")
    s.mgr.call = gone
    asyncio.run(s.start(900))
    assert s.bots()[900]["gone_since"]
    asyncio.run(s.my_bots(42))
    assert any("удалён в @BotFather" in t for t in _texts(s))
    (tmp_path / "pool-data" / "g0" / "900").mkdir(parents=True)
    s.save_bot(900, gone_since=int(__import__("time").time()) - pool.GONE_KEEP - 10)
    import veil.pool as vp
    n = {"i": 0}

    async def fake_sleep(sec):
        n["i"] += 1
        if n["i"] > 12:
            raise _Stop
    orig = vp.asyncio.sleep
    vp.asyncio.sleep = fake_sleep
    try:
        asyncio.run(s.housekeeping_loop())
    except _Stop:
        pass
    finally:
        vp.asyncio.sleep = orig
    assert 900 not in s.bots() and not (tmp_path / "pool-data" / "g0" / "900").exists()


class _Stop(Exception):
    pass


def test_check_only_for_owner(tmp_path):
    s, sent = _sup(tmp_path)
    s.save_bot(900, owner=42, group=0, username="veil_x_bot")
    cb = lambda uid: {"callback_query": {"id": "1", "from": {"id": uid}, "data": "chk:900"}}  # noqa: E731
    asyncio.run(s.on_update(cb(7)))
    assert sent == []
    asyncio.run(s.on_update(cb(42)))
    assert sent == [(0, {"op": "check", "bot": 900})]
    asyncio.run(s.on_event(0, {"ev": "checked", "bot": 900, "ok": True}))
    assert any("связь с сервером есть" in t for t in _texts(s))


def test_left_drops_bot_and_tells_owner(tmp_path):
    s, _ = _sup(tmp_path)
    s.save_bot(900, owner=42, group=0)
    (tmp_path / "pool-data" / "g0" / "900").mkdir(parents=True)
    asyncio.run(s.on_event(0, {"ev": "left", "bot": 900}))
    assert 900 not in s.bots() and any("отключён от пула" in t for t in _texts(s))
    assert not (tmp_path / "pool-data" / "g0" / "900").exists()


def test_group_keys_isolated():
    """У каждой группы свой ключ: процесс группы не расшифрует данные другой группы и индекс менеджера."""
    master = bytes(range(32))
    ks = {pool.group_key(master, g) for g in range(5)} | {pool.index_key(master), master}
    assert len(ks) == 7


def test_migrate_single_process_pool(tmp_path):
    """Прежний пул (один процесс, всё под главным ключом) переводится: индекс + данные под ключом группы,
    старые файлы затёрты; главный ключ данные бота больше не открывает."""
    import json
    import os

    import pytest
    from nacl.exceptions import CryptoError
    master = os.urandom(32)
    old = Store(tmp_path / "pool-data" / "900", key=master)
    old.put("owner_id", 42)
    old.put("bot_username", "veil_x_bot")
    old.add_post(7, b"\x01" * 32, "", "text")
    old.db._conn.close()
    (tmp_path / "pool-data" / "bots.json").write_text(json.dumps([900]))
    s, _ = _sup(tmp_path, master=master)
    assert s.migrate_single() == 1
    assert s.bots()[900] == {"owner": 42, "username": "veil_x_bot", "group": 0, "gone_since": None}
    assert not (tmp_path / "pool-data" / "900").exists() and not (tmp_path / "pool-data" / "bots.json").exists()
    moved = Store(tmp_path / "pool-data" / "g0" / "900", key=pool.group_key(master, 0))
    assert moved.post_secret(7) == b"\x01" * 32
    with pytest.raises(CryptoError):
        Store(tmp_path / "pool-data" / "g0" / "900", key=master)


# --- группа (рабочий процесс) ---
def _group(tmp_path):
    events = []

    async def emit(ev):
        events.append(ev)
    return pool.Group({"telegram": {}, "privacy": {}, "pool": {}}, tmp_path, tmp_path / "g0", None, emit), events


def test_group_feed_one_fetch_for_all_bots(tmp_path):
    g, _ = _group(tmp_path)
    fetched, applied = [], {}

    class Core:
        def __init__(self, cursor):
            self.store = Store(tmp_path / f"c{cursor}")
            if cursor is not None:
                self.store.put("feed_cursor", cursor)

        async def fetch_feed(self, since, pages=5):
            fetched.append(since)
            return [{"n": n} for n in range(since + 1, 13)], 12

    class UI:
        def __init__(self, i, cursor):
            self.i, self.core = i, Core(cursor)

        async def apply_feed(self, posts, start, cursor):
            applied[self.i] = (len(posts), start, cursor)
    g.uis = {1: UI(1, 5), 2: UI(2, 9), 3: UI(3, None)}
    asyncio.run(g.feed_refresh())
    assert fetched == [5] and applied == {1: (7, 5, 12), 2: (7, 5, 12), 3: (7, 5, 12)}


def test_group_uses_stored_token_and_reports(tmp_path, monkeypatch):
    g, events = _group(tmp_path)
    g.store(900).put("bot_token", "900:stored")
    used = []

    async def fake_build(cfg, base, token, store, owner, engine=None):
        used.append(token)
        from veil.core.transport.telegram import TelegramError
        raise TelegramError("getMe", 401, "Unauthorized")
    import veil.__main__ as main_mod
    monkeypatch.setattr(main_mod, "build", fake_build)
    asyncio.run(g.handle({"op": "start", "bot": 900, "owner": 42, "token": None}))
    assert used == ["900:stored"] and events == [{"ev": "failed", "bot": 900, "code": 401}]


def test_group_leave_wipes_and_reports(tmp_path):
    g, events = _group(tmp_path)
    g.store(900).put("owner_id", 42)
    asyncio.run(g.leave(900))
    assert not (tmp_path / "g0" / "900").exists() and events == [{"ev": "left", "bot": 900}]


def test_worker_process_protocol(tmp_path):
    """Настоящий рабочий процесс: ключ и каталог — первой строкой stdin, команда status — ответ в stdout."""
    import json
    import os
    import subprocess
    import sys
    cfg = tmp_path / "pool.toml"
    cfg.write_text('[server]\nserver_sig = "x"\n[pool]\n')
    p = subprocess.Popen([sys.executable, "-W", "ignore", "-m", "veil.pool", "--group", "0", str(cfg)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=ROOT, text=True)
    p.stdin.write(json.dumps({"key": os.urandom(32).hex(), "root": str(tmp_path / "g0")}) + "\n")
    p.stdin.write(json.dumps({"op": "status"}) + "\n")
    p.stdin.flush()
    line = p.stdout.readline()
    p.stdin.close()
    p.wait(timeout=10)
    assert json.loads(line) == {"ev": "status", "bots": {}}
    assert (tmp_path / "g0").stat().st_mode & 0o077 == 0
