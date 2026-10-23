"""Пул целиком: менеджер ↔ настоящий процесс группы, цикл менеджера, запуск бота в группе, логика песочницы."""
import asyncio
import json
import os
from pathlib import Path

import pytest

from veil import pool, sandbox
from veil.core.transport.telegram import TelegramError

ROOT = Path(__file__).resolve().parent.parent


class Mgr:
    def __init__(self, updates=None):
        self.sent, self.calls, self.updates = [], [], list(updates or [])

    async def send(self, chat, text, **kw):
        self.sent.append((chat, text))

    async def answer(self, *a, **kw):
        pass

    async def get_me(self):
        return {"id": 1, "username": "mgr_bot", "can_manage_bots": True}

    async def call(self, method, **kw):
        self.calls.append((method, kw))
        if method == "getUpdates":
            if self.updates:
                u = self.updates.pop(0)
                if isinstance(u, Exception):
                    raise u
                return u
            raise asyncio.CancelledError
        if method == "getManagedBotToken":
            return f"{kw['user_id']}:tok"
        return True


def config(tmp: Path) -> Path:
    p = tmp / "pool.toml"
    p.write_text('[server]\nserver_sig = "x"\n[pool]\ngroup_size = 2\nrequire_sandbox = true\n')
    return p


def sup(tmp: Path, master=None) -> pool.Supervisor:
    cfg = {"telegram": {}, "privacy": {}, "pool": {"group_size": 2}, "server": {"server_sig": "x"}}
    s = pool.Supervisor(cfg, tmp, config(tmp), "1:x", master)
    s.mgr = Mgr()
    return s


def test_supervisor_talks_to_real_group_process(tmp_path):
    """Настоящий процесс группы: получает ключ и каталог, отвечает сводкой; упал — менеджер перезапускает."""
    s = sup(tmp_path, master=os.urandom(32))

    async def go():
        await s.spawn(0)
        await s.send(0, {"op": "status"})
        for _ in range(100):
            await asyncio.sleep(0.05)
            if s.state is not None and s.procs.get(0) and getattr(s, "_got", False):
                break
        p = s.procs[0]
        p.kill()
        await p.wait()
        await asyncio.sleep(0.2)
        return p
    real_event = s.on_event

    async def on_event(g, ev):
        s._got = True
        await real_event(g, ev)
    s.on_event = on_event
    asyncio.run(go())
    assert getattr(s, "_got", False)  # сводка дошла по stdout
    assert (tmp_path / "pool-data" / "g0").stat().st_mode & 0o077 == 0


def test_supervisor_start_send_unknown_group_spawns(tmp_path, monkeypatch):
    s = sup(tmp_path)
    s.save_bot(900, owner=42, group=3)
    spawned, written = [], []

    async def spawn(g):
        spawned.append(g)

        class P:
            class stdin:
                @staticmethod
                def write(b):
                    written.append(json.loads(b))

                @staticmethod
                async def drain():
                    pass
        s.procs[g] = P()
    s.spawn = spawn
    asyncio.run(s.send(3, {"op": "start", "bot": 900}))
    assert spawned == [3] and written == []  # spawn сам запускает ботов группы
    asyncio.run(s.send(3, {"op": "status"}))
    assert written == [{"op": "status"}]


def test_supervisor_run_loop(tmp_path):
    s = sup(tmp_path)
    upd = [{"update_id": 1, "message": {"chat": {"id": 5, "type": "private"}, "from": {"id": 5}, "text": "/help"}},
           {"update_id": 2, "message": {"chat": {"id": 5, "type": "private"}, "from": {"id": 5}, "text": "/mybots"}},
           {"update_id": 3, "message": {"chat": {"id": 5, "type": "private"}, "from": {"id": 5},
                                        "managed_bot_created": {}}},
           {"update_id": 4, "message": {"chat": {"id": 5, "type": "group"}, "from": {"id": 5}, "text": "/start"}}]
    s.mgr = Mgr([upd, TelegramError("getUpdates", 502, "x")])
    real_sleep = asyncio.sleep

    async def fast(sec):
        await real_sleep(0)
    import veil.pool as vp
    vp.asyncio.sleep = fast
    try:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(s.run())
    finally:
        vp.asyncio.sleep = real_sleep
    texts = [t for _, t in s.mgr.sent]
    assert any("/mybots" in t for t in texts) and len(texts) == 2


def test_supervisor_refuses_without_management_mode(tmp_path):
    s = sup(tmp_path)

    async def no_mode():
        return {"username": "mgr_bot", "can_manage_bots": False}
    s.mgr.get_me = no_mode
    with pytest.raises(SystemExit):
        asyncio.run(s.run())


def test_status_summary(tmp_path):
    s = sup(tmp_path)
    s.save_bot(1, owner=1, group=0)
    s.save_bot(2, owner=2, group=0, gone_since=1)
    s.running.add(1)
    s.state[1] = {"b2b": False}
    assert s.status() == {"bots": 2, "running": 1, "groups": 0, "no_b2b": 1, "gone": 1}


def test_my_bots_states(tmp_path):
    s = sup(tmp_path)
    for b, kw in ((1, {}), (2, {}), (3, {})):
        s.save_bot(b, owner=42, group=0, username=f"b{b}", **kw)
    s.running |= {1, 2}
    s.state[2] = {"b2b": False}
    asyncio.run(s.my_bots(42))
    text = s.mgr.sent[-1][1]
    assert "@b1 — работает" in text and "@b2 — нет связи" in text and "@b3 — не запущен" in text


def test_group_start_bot_and_serve_restart(tmp_path, monkeypatch):
    events = []

    async def emit(ev):
        events.append(ev)
    g = pool.Group({"telegram": {}, "privacy": {}, "pool": {}}, tmp_path, tmp_path / "g0", os.urandom(32), emit)
    served = []

    class UI:
        def __init__(self):
            self.core = type("C", (), {"store": g.store(900)})()

        async def setup(self):
            self.core.store.put("b2b_error", None)

    class B:
        async def get_me(self):
            return {"id": 900, "username": "veil_x_bot"}

    async def fake_build(cfg, base, token, store, owner, engine=None):
        assert cfg["privacy"]["auto_sync_feed_seconds"] == 0 and callable(cfg["pool"]["leave"])
        assert engine is g.engine and not engine.compile_ok  # движок плагинов один на группу, в пуле не компилируется
        return UI(), B(), object()

    async def fake_serve(ui, bot, core):
        served.append(1)
        if len(served) == 1:
            raise RuntimeError("crash")
        await asyncio.sleep(3600)
    import veil.__main__ as main_mod
    monkeypatch.setattr(main_mod, "build", fake_build)
    monkeypatch.setattr(main_mod, "serve", fake_serve)
    monkeypatch.setattr(pool, "RESTART_AFTER", 0)

    async def go():
        await g.handle({"op": "start", "bot": 900, "owner": 42, "token": "900:t"})
        for _ in range(20):
            await asyncio.sleep(0.01)
        assert await g.check(900) is True and await g.check(901) is False
        await g.handle({"op": "check", "bot": 900})
        await g.handle({"op": "status"})
        await g.handle({"op": "stop", "bot": 900})
        await g.handle({"op": "wipe", "bot": 900})
    asyncio.run(go())
    kinds = [e["ev"] for e in events]
    assert kinds.count("started") == 2 and "checked" in kinds and "status" in kinds  # упал — перезапущен
    assert not (tmp_path / "g0" / "900").exists() and len(served) == 2


def test_group_start_without_token_fails(tmp_path):
    events = []

    async def emit(ev):
        events.append(ev)
    g = pool.Group({"telegram": {}, "privacy": {}, "pool": {}}, tmp_path, tmp_path / "g0", None, emit)
    asyncio.run(g.handle({"op": "start", "bot": 5, "owner": 1, "token": None}))
    assert events == [{"ev": "failed", "bot": 5, "code": 0}]


def test_feed_soon_and_loop(tmp_path, monkeypatch):
    async def emit(ev):
        pass
    g = pool.Group({"telegram": {}, "privacy": {}, "pool": {"feed_seconds": 1}}, tmp_path, tmp_path / "g0", None, emit)
    calls = []

    async def refresh():
        calls.append(1)
        if len(calls) == 3:
            raise RuntimeError("network")
    g.feed_refresh = refresh

    class Stop(Exception):
        pass
    n = {"i": 0}

    async def sleep(s):
        n["i"] += 1
        if n["i"] > 4:
            raise Stop
    monkeypatch.setattr(pool.asyncio, "sleep", sleep)
    asyncio.run(g.feed_soon())
    with pytest.raises(Stop):
        asyncio.run(g.feed_loop())
    assert len(calls) >= 3  # ошибка сети не роняет цикл


# --- песочница: логика вызовов без настоящего ограничения процесса ---
class FakeLibc:
    def __init__(self, abi=4, fail=None):
        self.abi_v, self.fail, self.calls = abi, fail or set(), []

        class S:
            restype = None

            def __call__(s, nr, *args):
                self.calls.append(nr)
                if nr == sandbox.SYS_CREATE and args[0] is None:
                    return self.abi_v
                return -1 if nr in self.fail else 3
        self.syscall = S()

    def prctl(self, *a):
        return -1 if "prctl" in self.fail else 0


@pytest.mark.parametrize("abi", [1, 3, 4])
def test_sandbox_rules(tmp_path, monkeypatch, abi):
    lib = FakeLibc(abi)
    monkeypatch.setattr(sandbox, "_libc", lambda: lib)
    monkeypatch.setattr(sandbox.os, "close", lambda fd: None)
    (tmp_path / "f").write_text("x")
    v = sandbox.restrict([tmp_path], [tmp_path], [tmp_path / "f", tmp_path / "missing"], [1080])
    assert v == abi
    adds = lib.calls.count(sandbox.SYS_ADD_RULE)
    assert adds == 3 + (1 if abi >= 4 else 0) and lib.calls[-1] == sandbox.SYS_RESTRICT


@pytest.mark.parametrize("fail", [{sandbox.SYS_ADD_RULE}, {sandbox.SYS_RESTRICT}, {"prctl"}])
def test_sandbox_errors(tmp_path, monkeypatch, fail):
    lib = FakeLibc(4, fail)
    monkeypatch.setattr(sandbox, "_libc", lambda: lib)
    monkeypatch.setattr(sandbox.os, "close", lambda fd: None)
    with pytest.raises(sandbox.SandboxError):
        sandbox.restrict([tmp_path], [], [], [443])


def test_sandbox_unavailable(monkeypatch):
    monkeypatch.setattr(sandbox, "_libc", lambda: FakeLibc(0))
    assert sandbox.abi() == 0
    with pytest.raises(sandbox.SandboxError):
        sandbox.restrict([], [], [], [])
    assert sandbox._fs_handled(1) < sandbox._fs_handled(2) < sandbox._fs_handled(3)


def test_main_entry_requires_token(tmp_path, monkeypatch):
    p = config(tmp_path)
    monkeypatch.setattr(pool.sys, "argv", ["veil.pool", str(p)])
    monkeypatch.delenv("VEIL_POOL_MANAGER_TOKEN", raising=False)
    import veil.cli as cli
    monkeypatch.setattr(cli, "harden", lambda: None)
    with pytest.raises(SystemExit, match="менеджера"):
        pool.main()
    monkeypatch.setenv("VEIL_POOL_MANAGER_TOKEN", "1:x")
    ran = []

    def fake_run(coro):
        ran.append(coro)
        coro.close()
    monkeypatch.setattr(pool.asyncio, "run", fake_run)
    pool.main()
    assert ran and "VEIL_POOL_MANAGER_TOKEN" not in os.environ  # группам токен менеджера не достаётся
    assert (tmp_path / "pool.key").stat().st_mode & 0o077 == 0


def test_no_second_process_while_group_restarts(tmp_path):
    """Группа упала и ждёт перезапуска: команда в это время не запускает второй процесс той же группы."""
    s = sup(tmp_path)
    s.save_bot(900, owner=42, group=0)
    spawned = []

    async def spawn(g):
        spawned.append(g)
    s.spawn = spawn
    s.respawning.add(0)
    asyncio.run(s.send(0, {"op": "status"}))
    assert spawned == []
