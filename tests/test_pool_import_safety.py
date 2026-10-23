"""Недоверенный ввод в пуле и при импорте: подложенный файл экспорта, чужая личность, события чужой группы,
песочница процессов групп, сроки удаления секретных сообщений, окно дозапроса, сбой записи снимка."""
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from veil import pool, sandbox
from veil.core import api
from veil.core import export as ex
from veil.core.crypto import keys
from veil.core.store.db import Store
from veil.ui import bot as uibot

ROOT = Path(__file__).resolve().parent.parent
SIG = "server-sig-pinned"
VICTIM_BOT = 7000001


def victim(tmp, name):
    s = Store(tmp / name)
    s.put("pinned_server_sig", SIG)
    s.put("pinned_issuer", {"kid": "t1", "pk": "x"})
    s.put("owner_id", 111)
    return s


# --- подложенный файл не меняет подписи кнопок и не ослабляет приватность ---
def test_planted_labels_and_weaker_privacy_rejected(tmp_path):
    planted = {"v": 1, "server_sig": SIG, "settings": {
        "privacy": {"random_delay_seconds": [0, 0], "keep_posts_days": 3650},
        "ui": {"labels": {"button": {"anon_on": "Анонимно: нет", "anon_off": "Анонимно: да"}}}}}
    st = victim(tmp_path, "labels")
    current = {"privacy": {"random_delay_seconds": [15, 90], "keep_posts_days": 30}, "ui": {}}
    r = ex.apply(st, planted, bot_id=VICTIM_BOT, issuer_kid="t1", current=current, locales=ex.available_locales())
    assert r["settings"] == {}
    assert set(r["skipped_settings"]) == {"privacy.random_delay_seconds", "privacy.keep_posts_days", "ui.labels"}
    # и при запуске бота подписи из импорта не применяются, даже если когда-то сохранились
    st.put("imported_settings", {"ui": {"labels": {"button": {"anon_off": "Анонимно: да"}}}})
    cfg = {"privacy": {}, "ui": {}}
    for sec in ("privacy", "ui"):
        for k, v in (st.get("imported_settings") or {}).get(sec, {}).items():
            if k != "labels":
                cfg[sec][k] = v
    assert "labels" not in cfg["ui"]
    src = (ROOT / "veil" / "__main__.py").read_text()
    assert 'if k != "labels"' in src


def test_stricter_privacy_accepted(tmp_path):
    st = victim(tmp_path, "strict")
    current = {"privacy": {"random_delay_seconds": [15, 90], "keep_posts_days": 30}}
    r = ex.apply(st, {"v": 1, "server_sig": SIG, "settings": {"privacy": {"random_delay_seconds": [30, 120],
                                                                           "keep_posts_days": 7}}},
                 bot_id=1, issuer_kid="t1", current=current)
    assert r["settings"] == {"privacy": {"random_delay_seconds": [30, 120], "keep_posts_days": 7}}
    # 0 — «хранить всегда» — слабее любого срока
    r = ex.apply(st, {"v": 1, "server_sig": SIG, "settings": {"privacy": {"keep_posts_days": 0}}},
                 bot_id=1, issuer_kid="t1", current=current)
    assert r["skipped_settings"] == ["privacy.keep_posts_days"]


# --- чужая личность из файла с подставленным ID бота ---
def test_planted_identity_not_accepted_without_confirmation(tmp_path):
    dev = keys.issue_device(SigningKey.generate())
    fresh = victim(tmp_path, "fresh")
    r = ex.apply(fresh, {"v": 1, "server_sig": SIG, "bot_id": VICTIM_BOT, "device": dev.to_json()},
                 bot_id=VICTIM_BOT, issuer_kid="t1")
    assert fresh.load_device() is None and "подтверждённой" in r["device"]


class _Bot:
    def __init__(self):
        self.said, self.deleted, self.files = [], [], {}

    async def send(self, chat, text, **kw):
        self.said.append(text)
        return {"message_id": len(self.said)}

    async def upload(self, *a, **kw):
        return {"message_id": 500}

    async def edit(self, chat, mid, text, **kw):
        self.said.append(text)

    async def delete(self, chat, mid):
        self.deleted.append(mid)

    async def download(self, file_id, max_bytes):
        return self.files[file_id]


def _ui(store, confirms):
    class Core:
        _device = None

        def __init__(self):
            self.store = store

        async def server_confirms(self, d):
            return confirms
    ui = uibot.UI.__new__(uibot.UI)
    ui.bot, ui.owner, ui.tasks, ui.cfg, ui.pool = _Bot(), 1, set(), {"privacy": {}, "ui": {}}, None
    ui.plugins = uibot.plug.Registry()  # UI собран без __init__: плагинов нет
    ui.T = uibot.Texts(ROOT / "locales" / "ru.toml", {})
    ui.core = Core()

    async def sync(quiet=False):
        pass
    ui._sync_identity = sync
    return ui


@pytest.mark.parametrize("confirms", [False, True])
def test_chat_import_identity_only_if_server_confirms(tmp_path, confirms):
    dev = keys.issue_device(SigningKey.generate())
    st = victim(tmp_path, f"c{confirms}")
    st.put("bot_id", VICTIM_BOT)
    ui = _ui(st, confirms)
    asyncio.run(ui._import_start())
    key = ui.bot.said[-1]
    data = ex.seal_recipient({"v": 1, "server_sig": SIG, "bot_id": VICTIM_BOT, "device": dev.to_json()},
                             ex.parse_import_key(key))
    ui.bot.files["F"] = data
    asyncio.run(ui._import_file({"chat": {"id": 1}, "message_id": 9, "document": {"file_id": "F", "file_size": 1}}))
    assert (st.load_device() is not None) is confirms


# --- менеджер не верит событиям группы о чужих ботах ---
def _sup(tmp_path):
    s = pool.Supervisor({"telegram": {}, "privacy": {}, "pool": {"group_size": 2}}, tmp_path, tmp_path / "p.toml",
                        "1:x", None)
    sent = []

    class Mgr:
        async def send(self, chat, text, **kw):
            sent.append((chat, text))
    s.mgr = Mgr()
    return s, sent


def test_group_cannot_touch_other_groups_bots(tmp_path):
    s, sent = _sup(tmp_path)
    s.save_bot(900, owner=42, group=0)
    s.save_bot(901, owner=43, group=1, username="v")
    victim_dir = s.root / "g1" / "901"
    victim_dir.mkdir(parents=True)
    asyncio.run(s.on_event(0, {"ev": "left", "bot": 901}))
    asyncio.run(s.on_event(0, {"ev": "started", "bot": 901, "username": "evil"}))
    asyncio.run(s.on_event(0, {"ev": "status", "bots": {"901": {"b2b": False}}}))
    assert 901 in s.bots() and victim_dir.exists() and s.bots()[901]["username"] == "v" and 901 not in s.state
    asyncio.run(s.on_event(0, {"ev": "checked", "bot": 900, "user": 555, "ok": True}))  # проверки не просили
    asyncio.run(s.on_event(0, {"ev": "checked", "bot": "900", "ok": True}))
    assert sent == []


def test_sandbox_blocks_master_key_other_groups_and_ports(tmp_path):
    """Настоящая песочница Landlock в отдельном процессе: главный ключ, индекс, чужая группа и сторонний порт
    недоступны; свой каталог и keys.json — доступны."""
    if sandbox.abi() < 1:
        pytest.skip("Landlock недоступен в этом ядре")
    (tmp_path / "pool.key").write_text("00" * 32)
    (tmp_path / "keys.json").write_text("{}")
    (tmp_path / "data" / "g0").mkdir(parents=True)
    (tmp_path / "data" / "g1").mkdir()
    (tmp_path / "data" / "g1" / "veil.db.enc").write_text("other")
    (tmp_path / "data" / "index").mkdir()
    code = f"""
import json, socket, sys
from pathlib import Path
from veil import sandbox
t = Path({str(tmp_path)!r})
v = sandbox.restrict_group(t / "data" / "g0", Path({str(ROOT)!r}), [t / "keys.json"], [1080])
out = {{"abi": v}}
def tryread(p):
    try:
        open(p).read(); return "ok"
    except PermissionError:
        return "denied"
out["pool.key"] = tryread(t / "pool.key")
out["other_group"] = tryread(t / "data" / "g1" / "veil.db.enc")
out["keys.json"] = tryread(t / "keys.json")
(t / "data" / "g0" / "x").write_text("w"); out["own_write"] = "ok"
try:
    (t / "data" / "index" / "y").write_text("w"); out["index_write"] = "ok"
except PermissionError:
    out["index_write"] = "denied"
if v >= 4:
    s = socket.socket(); s.settimeout(1)
    try:
        s.connect(("127.0.0.1", 9)); out["port9"] = "ok"
    except PermissionError:
        out["port9"] = "denied"
    except OSError:
        out["port9"] = "refused"
import nacl.secret, base64, json as j2
out["imports"] = "ok"
print(json.dumps(out))
"""
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, timeout=60)
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["pool.key"] == "denied" and out["other_group"] == "denied" and out["index_write"] == "denied"
    assert out["keys.json"] == "ok" and out["own_write"] == "ok" and out["imports"] == "ok"
    if out["abi"] >= 4:
        assert out["port9"] == "denied"


def test_group_refuses_to_start_without_sandbox(tmp_path, monkeypatch):
    def fail(*a, **kw):
        raise sandbox.SandboxError("нет Landlock")
    monkeypatch.setattr(sandbox, "restrict_group", fail)
    cfg = {"server": {}, "pool": {}, "telegram": {}}
    with pytest.raises(SystemExit):
        pool._sandbox(cfg, tmp_path, tmp_path / "g0", 0)
    cfg["pool"]["require_sandbox"] = False
    pool._sandbox(cfg, tmp_path, tmp_path / "g0", 0)  # явно разрешено — только предупреждение


def test_proxy_ports():
    assert pool._proxy_ports({"telegram": {"proxy": "socks5://127.0.0.1:1080"}}) == [1080]
    assert pool._proxy_ports({"telegram": {}}) == [443]


# --- счётчик «3 в сутки» переживает перезапуск ---
def test_creation_counter_on_disk(tmp_path):
    s, _ = _sup(tmp_path)
    for _ in range(pool.CREATE_PER_DAY):
        s._note_created(42)
    s2, _ = _sup(tmp_path)  # перезапуск: новый менеджер, тот же индекс
    assert not s2._creation_allowed(42) and s2._creation_allowed(43)


# --- VEILTOK и файл экспорта удаляются по сроку из базы ---
def test_veiltok_and_export_scheduled_for_wipe(tmp_path, monkeypatch):
    from veil.core.wallet.issue import Token
    st = victim(tmp_path, "w")
    st.put("bot_id", 1)
    st.add_tokens([Token("t1", api.today(), bytes([i]) * 32, bytes(64)) for i in range(3)])
    ui = _ui(st, False)
    ui.core.export_tokens = lambda day, n: ["VEILTOK 01234567 1/1 AAAA"]

    async def no_sleep(s):
        pass
    monkeypatch.setattr(uibot.asyncio, "sleep", no_sleep)
    asyncio.run(ui._token_give("tok:give:2"))
    text, sk = ex.new_import_key()
    asyncio.run(ui._export(text))
    asyncio.run(ui._export_confirmed({"chat": {"id": 1}, "message_id": 3}))  # владелец нажал «Выгрузить»
    pending = st.get("wipe_at")
    assert len(pending) == 2 and all(w[2] > time.time() + 3000 for w in pending)


# --- окно дозапроса — час ---
def test_resume_window_one_hour():
    assert api.Core.PENDING_TTL == 3600


# --- снимок не записался — ошибка наружу, при следующей записи снимок догоняет ---
def test_flush_failure_retried(tmp_path, monkeypatch):
    import veil.core.store.db as dbmod
    key = os.urandom(32)
    s = Store(tmp_path, key=key)
    real = dbmod._write_private
    calls = {"n": 0}

    def flaky(path, data):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("No space left on device")
        return real(path, data)
    monkeypatch.setattr(dbmod, "_write_private", flaky)
    with pytest.raises(OSError):
        s.put("a", 1)
    s.put("b", 2)  # следующая запись пишет полный снимок
    s2 = Store(tmp_path, key=key)
    assert s2.get("a") == 1 and s2.get("b") == 2


def test_sandbox_scopes_signals_and_abstract_sockets(tmp_path):
    """Landlock ABI 6: процесс группы не посылает сигналы процессам вне своей песочницы (менеджеру, другим группам) и не
    подключается к абстрактным UNIX-сокетам снаружи; себе — может."""
    import secrets
    import socket
    if sandbox.abi() < 6:
        pytest.skip("нужен Landlock ABI 6 (Linux 6.12+)")
    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    name = "\0veil-test-" + secrets.token_hex(4)
    srv.bind(name)
    srv.listen(1)
    code = f"""
import json, os, signal, socket
from pathlib import Path
from veil import sandbox
sandbox.restrict_group(Path({str(tmp_path)!r}), Path({str(ROOT)!r}), [], [1080])
out = {{}}
try:
    os.kill({victim.pid}, signal.SIGTERM); out["kill"] = "ok"
except PermissionError:
    out["kill"] = "denied"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect({name!r}); out["abstract"] = "ok"
except PermissionError:
    out["abstract"] = "denied"
os.kill(os.getpid(), 0)
out["self"] = "ok"
print(json.dumps(out))
"""
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, timeout=60)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        assert out == {"kill": "denied", "abstract": "denied", "self": "ok"} and victim.poll() is None, (out, r.stderr)
    finally:
        victim.kill()
        srv.close()
