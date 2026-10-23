"""Экспорт и импорт бота (docs/EXPORT.md): что переносится, что нет, и подложенные файлы."""
import asyncio
import hashlib
import io
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from nacl.public import PrivateKey, SealedBox
from nacl.signing import SigningKey

from veil import cli
from veil.core import export as ex
from veil.core.crypto import keys
from veil.core.protocol import b64
from veil.core.store.db import Store
from veil.core.wallet.issue import Token

ROOT = Path(__file__).resolve().parent.parent
TODAY = datetime.now(timezone.utc).date().isoformat()
SIG = "server-sig-pinned"
PASS = "correct horse battery"


def bot_store(tmp, name, *, device=True, tokens=5, posts=2):
    s = Store(tmp / name)
    s.put("pinned_server_sig", SIG)
    s.put("pinned_issuer", {"kid": "t1", "pk": "x"})
    s.put("owner_id", 111)
    if device:
        s.save_device(keys.issue_device(SigningKey.generate()))
    s.add_tokens([Token("t1", TODAY, hashlib.sha256(f"{name}{i}".encode()).digest(), bytes([i]) * 64) for i in range(tokens)])
    for n in range(1, posts + 1):
        s.add_post(n, bytes([n]) * 32, f"https://t.me/c/1/{n}", "text")
    s.put("contacts", {"ромашка·k7m2qa": b64.enc(bytes(32))})
    return s


CFG = {"telegram": {}, "privacy": {"random_delay_seconds": [10, 20], "keep_posts_days": 7}, "ui": {"locale": "ru"}}


def roundtrip(bundle, password=PASS):
    return ex.open_file(ex.seal_password(bundle, password), password=password)


def test_same_bot_new_machine_moves_everything(tmp_path):
    src = bot_store(tmp_path, "src")
    dev = src.load_device()
    bundle = roundtrip(ex.collect(src, 42, CFG))
    dst = Store(tmp_path / "dst")
    dst.put("pinned_server_sig", SIG)
    r = ex.apply(dst, bundle, bot_id=42, issuer_kid="t1", accept_device=True)
    assert r["device"].startswith("перенесён") and dst.load_device().to_json() == dev.to_json()
    assert r["tokens"] == 5 and dst.token_counts()[TODAY] == 5
    assert r["posts"] == 2 and dst.post_secret(1) == bytes([1]) * 32
    assert r["contacts"] == 1 and dst.get("contacts") == {"ромашка·k7m2qa": b64.enc(bytes(32))}
    # задержка [10, 20] короче текущей [15, 90] — из чужого файла не ослабляется
    assert r["settings"] == {"privacy": {"keep_posts_days": 7}, "ui": {"locale": "ru"}}
    assert r["skipped_settings"] == ["privacy.random_delay_seconds"]
    # владелец и закрепления сервера и эмитента из файла не берутся никогда
    assert dst.get("owner_id") is None and dst.get("pinned_issuer") is None


def test_other_bot_gets_data_but_not_identity(tmp_path):
    src = bot_store(tmp_path, "src")
    dst = bot_store(tmp_path, "dst", device=False, tokens=0, posts=0)
    r = ex.apply(dst, roundtrip(ex.collect(src, 42, CFG)), bot_id=99, issuer_kid="t1")
    assert "restore" in r["device"] and dst.load_device() is None  # личность — только по 12 словам
    assert r["tokens"] == 5 and r["posts"] == 2


def test_existing_identity_needs_force(tmp_path):
    src = bot_store(tmp_path, "src")
    dst = bot_store(tmp_path, "dst")
    mine = dst.load_device().to_json()
    bundle = roundtrip(ex.collect(src, 42, CFG))
    r = ex.apply(dst, bundle, bot_id=42, issuer_kid="t1", accept_device=True)
    assert "--force" in r["device"] and dst.load_device().to_json() == mine
    ex.apply(dst, bundle, bot_id=42, issuer_kid="t1", accept_device=True, force=True)
    assert dst.load_device().to_json() == src.load_device().to_json()


def test_wrong_password_tamper_and_wrong_key(tmp_path):
    src = bot_store(tmp_path, "src")
    data = ex.seal_password(ex.collect(src, 42, CFG), PASS)
    with pytest.raises(ex.ExportError, match="неверный пароль"):
        ex.open_file(data, password="wrong password!!")
    bad = bytearray(data)
    bad[-5] ^= 1
    with pytest.raises(ex.ExportError):
        ex.open_file(bytes(bad), password=PASS)
    with pytest.raises(ex.ExportError, match="короче"):
        ex.seal_password({}, "short")
    text, sk = ex.new_import_key()
    sealed = ex.seal_recipient(ex.collect(src, 42, CFG), ex.parse_import_key(text))
    assert ex.open_file(sealed, recipient_sk=sk)["bot_id"] == 42
    with pytest.raises(ex.ExportError):
        ex.open_file(sealed, recipient_sk=ex.new_import_key()[1])
    with pytest.raises(ex.ExportError, match="другой машины"):
        ex.open_file(sealed)


def test_argon_params_bounded(tmp_path):
    """Параметры Argon2id из файла: не ниже минимума (слабый пароль) и не выше предела (взрыв памяти)."""
    data = bytearray(ex.seal_password({"v": 1}, PASS))
    hdr = len(ex.MAGIC) + 1 + 16
    for ops, mem in ((1, ex.MEM_MIN), (ex.OPS_MIN, ex.MEM_MAX * 4)):
        d = bytearray(data)
        d[hdr:hdr + 8], d[hdr + 8:hdr + 16] = ops.to_bytes(8, "big"), mem.to_bytes(8, "big")
        with pytest.raises(ex.ExportError, match="параметры"):
            ex.open_file(bytes(d), password=PASS)


def test_planted_file_cannot_take_over(tmp_path):
    """Подложенный файл («импортируй мои настройки»): чужой сервер, чужой эмитент, владелец, журнал постов."""
    dst = bot_store(tmp_path, "dst", tokens=0, posts=0)
    base = ex.collect(bot_store(tmp_path, "src"), 42, CFG)
    with pytest.raises(ex.ExportError, match="другого сервера"):
        ex.apply(dst, dict(base, server_sig="evil"), bot_id=42, issuer_kid="t1")
    evil_tok = dict(base, tokens=[[TODAY, "evil", b64.enc(bytes(32)), b64.enc(bytes(64))]])
    with pytest.raises(ex.ExportError, match="другого эмитента"):
        ex.apply(dst, evil_tok, bot_id=42, issuer_kid="t1")
    planted = dict(base, owner_id=666, pinned_server_sig="evil", pinned_issuer={"kid": "evil"}, keys_doc={},
                   pending_posts=[["id", "s", "text", {"op": "post.create"}, 0]], claim_code="x")
    ex.apply(dst, planted, bot_id=42, issuer_kid="t1")
    assert dst.get("owner_id") == 111 and dst.get("pinned_server_sig") == SIG
    assert dst.get("pinned_issuer") == {"kid": "t1", "pk": "x"} and dst.pending_posts() == []
    # свой пост и своё закрепление не перезаписываются пришедшими
    dst.add_post(7, bytes([9]) * 32, "", "text")
    dst.put("contacts", {"ромашка·k7m2qa": "MINE"})
    ex.apply(dst, dict(base, posts=[[7, b64.enc(bytes(32)), "", "text", 0, 0]]), bot_id=42, issuer_kid="t1")
    assert dst.post_secret(7) == bytes([9]) * 32 and dst.get("contacts")["ромашка·k7m2qa"] == "MINE"


def test_forged_device_rejected(tmp_path):
    src = bot_store(tmp_path, "src")
    b = ex.collect(src, 42, CFG)
    dev = dict(b["device"], dev_sig=b64.enc(bytes(64)))
    with pytest.raises(ex.ExportError, match="сертификат"):
        ex.apply(Store(tmp_path / "d1"), dict(b, device=dev), bot_id=42, issuer_kid="t1")
    enc = [dict(b["device"]["enc"][0], sk=b64.enc(bytes(32)))]
    with pytest.raises(ex.ExportError):
        ex.apply(Store(tmp_path / "d2"), dict(b, device=dict(b["device"], enc=enc)), bot_id=42, issuer_kid="t1")


def test_settings_whitelist_and_limits(tmp_path):
    dst = Store(tmp_path / "d")
    settings = {"privacy": {"random_delay_seconds": [0, 99999], "keep_posts_days": 5, "evil": 1},
                "ui": {"locale": "zz", "labels": {"button": {"send": "Опубликовать", "nonexistent": "x"},
                                                  "text": {"help": "x" * 500}}},
                "telegram": {"owner_id": 666}, "server": {"server_sig": "evil"}}
    r = ex.apply(dst, {"v": 1, "settings": settings}, bot_id=1, issuer_kid="t1",
                 locales={"ru"})
    # подписи кнопок не принимаются никогда; keep_posts_days 5 — строже текущих 30, принимается
    assert r["settings"] == {"privacy": {"keep_posts_days": 5}} and "ui.labels" in r["skipped_settings"]


def test_limits_and_format(tmp_path):
    dst = Store(tmp_path / "d")
    with pytest.raises(ex.ExportError, match="слишком много"):
        ex.apply(dst, {"v": 1, "posts": [[1, "x", "", "", 0, 0]] * (ex.LIMITS["posts"] + 1)}, bot_id=1, issuer_kid="t1")
    for bad in (b"garbage", ex.MAGIC + b"\x09xxxx", b"x" * (ex.MAX_FILE + 1)):
        with pytest.raises(ex.ExportError):
            ex.open_file(bad, password=PASS)
    with pytest.raises(ex.ExportError, match="версия"):
        roundtrip({"v": 2})
    with pytest.raises(ex.ExportError):
        ex.parse_import_key("VEILIMP short")


def test_export_refused_while_posts_pending(tmp_path):
    src = bot_store(tmp_path, "src")
    src.save_pending_post("01JA", bytes(32), "text", {"id": "01JA"})
    with pytest.raises(ex.ExportError, match="итог"):
        ex.collect(src, 42, CFG)


def test_cli_export_import_batch(tmp_path, monkeypatch):
    src = bot_store(tmp_path, "src")
    out = tmp_path / "bot.veilx"
    monkeypatch.setenv("VEIL_BOT_TOKEN", "42:x")
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASS + "\n"))
    cli.export(src, CFG, str(out), batch=True)
    assert out.stat().st_mode & 0o077 == 0
    assert b"post_secret" not in out.read_bytes() and b"tokens" not in out.read_bytes()  # на диске только шифротекст
    dst = Store(tmp_path / "dst")
    monkeypatch.setattr(cli, "_pins", lambda store, cfg, base: (store.put("pinned_server_sig", SIG), "t1")[1])
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASS + "\n"))
    r = cli.import_(dst, CFG, tmp_path, str(out), batch=True, with_identity=True)
    assert r["tokens"] == 5 and dst.load_device() is not None


def test_cli_import_via_recipient_key(tmp_path, monkeypatch, capsys):
    src = bot_store(tmp_path, "src")
    dst = Store(tmp_path / "dst")
    key = cli.import_key(dst)
    out = tmp_path / "chat.veilx"
    monkeypatch.setenv("VEIL_BOT_TOKEN", "42:x")
    cli.export(src, CFG, str(out), to_key=key)
    monkeypatch.setattr(cli, "_pins", lambda store, cfg, base: (store.put("pinned_server_sig", SIG), "t1")[1])
    assert cli.import_(dst, CFG, tmp_path, str(out))["posts"] == 2
    assert dst.get("import_sk") is None  # ключ одноразовый


# --- в боте ---
class _Bot:
    def __init__(self, files=None):
        self.said, self.uploads, self.deleted, self.files, self.edits = [], [], [], files or {}, []

    async def send(self, chat, text, **kw):
        self.said.append(text)
        return {"message_id": len(self.said)}

    async def edit(self, chat, mid, text, **kw):
        self.edits.append(text)

    async def answer(self, callback_id, text=None, alert=False):
        pass

    async def upload(self, method, field, name, data, mime, **kw):
        self.uploads.append((method, name, data, kw))
        return {"message_id": 500}

    async def delete(self, chat, mid):
        self.deleted.append(mid)

    async def download(self, file_id, max_bytes):
        return self.files[file_id]


def _ui(store, bot):
    from veil.ui import bot as uibot

    class Core:
        _device = None
        confirms = True

        def __init__(self):
            self.store = store

        async def server_confirms(self, d):
            return self.confirms
    ui = uibot.UI.__new__(uibot.UI)
    ui.bot, ui.owner, ui.tasks, ui.cfg, ui.pool = bot, 1, set(), CFG, None
    ui.plugins = uibot.plug.Registry()  # UI собран без __init__: плагинов нет
    ui.T = uibot.Texts(ROOT / "locales" / "ru.toml", {})
    ui.core = Core()

    async def sync(quiet=False):
        pass
    ui._sync_identity = sync
    return ui


def test_bot_export_import_through_chat(tmp_path):
    src = bot_store(tmp_path, "src")
    src.put("bot_id", 42)
    dst = Store(tmp_path / "dst")
    dst.put("pinned_server_sig", SIG)
    dst.put("pinned_issuer", {"kid": "t1", "pk": "x"})
    dst.put("bot_id", 42)
    b_dst = _Bot()
    u_dst = _ui(dst, b_dst)
    asyncio.run(u_dst._import_start())
    key = b_dst.said[-1]
    assert key.startswith("VEILIMP ") and dst.get("await")["what"] == "import"
    b_src = _Bot()
    u_src = _ui(src, b_src)
    asyncio.run(u_src._export(""))
    assert "import-key" in b_src.said[-1]
    asyncio.run(u_src._export(key))
    # Сначала — что уйдёт и предупреждение (ключ мог прислать посторонний); файла ещё нет.
    assert b_src.uploads == [] and "Выгрузить" in b_src.said[-1] and "токенов: 5" in b_src.said[-1]
    msg = {"chat": {"id": 1}, "message_id": 9}
    asyncio.run(u_src._callback({"id": "q", "data": "ex:ok", "message": msg}))
    [(method, name, data, kw)] = b_src.uploads
    # файл пересылается туда, куда переносят: запрета пересылки нет (прочитать его может только владелец ключа)
    assert method == "sendDocument" and "protect_content" not in kw and data.startswith(ex.MAGIC)
    b_dst.files["F"] = data
    asyncio.run(u_dst._import_file({"chat": {"id": 1}, "message_id": 77,
                                    "document": {"file_id": "F", "file_size": len(data)}}))
    assert b_dst.deleted == [77] and dst.get("import_sk") is None
    assert dst.token_counts()[TODAY] == 5 and dst.load_device() is not None
    assert "личность — перенесён" in b_dst.said[-1]


def test_chat_export_needs_confirmation(tmp_path):
    """/export с чужим ключом: без нажатия «Выгрузить» файла нет; «Отмена» и устаревшее подтверждение — тоже нет."""
    src = bot_store(tmp_path, "src")
    src.put("bot_id", 42)
    b = _Bot()
    u = _ui(src, b)
    key, _ = ex.new_import_key()
    msg = {"chat": {"id": 1}, "message_id": 9}
    asyncio.run(u._export(key))
    asyncio.run(u._callback({"id": "q", "data": "ex:no", "message": msg}))
    asyncio.run(u._callback({"id": "q", "data": "ex:ok", "message": msg}))  # после отмены подтверждать нечего
    assert b.uploads == [] and src.get("export_pending") is None
    asyncio.run(u._export(key))
    pending = src.get("export_pending")
    src.put("export_pending", dict(pending, at=pending["at"] - u.EXPORT_CONFIRM_TTL - 1))
    asyncio.run(u._callback({"id": "q", "data": "ex:ok", "message": msg}))
    assert b.uploads == [] and "устарело" in b.edits[-1]


def test_pool_bot_restarts_after_import(tmp_path):
    src = bot_store(tmp_path, "src")
    dst = Store(tmp_path / "dst")
    for k, v in (("pinned_server_sig", SIG), ("pinned_issuer", {"kid": "t1", "pk": "x"}), ("bot_id", 7)):
        dst.put(k, v)
    b = _Bot()
    u = _ui(dst, b)
    restarted = []

    async def restart():
        restarted.append(True)
    u.pool = {"restart": restart}
    asyncio.run(u._import_start())
    key = b.said[-1]
    data = ex.seal_recipient(ex.collect(src, 42, CFG), ex.parse_import_key(key))
    b.files["F"] = data
    asyncio.run(u._import_file({"chat": {"id": 1}, "message_id": 5, "document": {"file_id": "F", "file_size": 1}}))
    assert restarted == [True] and "перезапускается" in b.said[-1]


def test_pool_leave_wipes_data(tmp_path):
    from veil import pool
    events = []

    async def emit(ev):
        events.append(ev)
    g = pool.Group({"telegram": {}, "privacy": {}, "pool": {}}, tmp_path, tmp_path / "g0", None, emit)
    g.store(900).put("owner_id", 5)
    asyncio.run(g.leave(900))
    assert not (tmp_path / "g0" / "900").exists() and events == [{"ev": "left", "bot": 900}]


def test_export_without_pins_refused(tmp_path):
    """Бот ни разу не запускался — ключ сервера не закреплён: файл никто бы не принял, экспорт отказывает."""
    st = Store(tmp_path / "s")
    with pytest.raises(ex.ExportError, match="запустите бота"):
        ex.collect(st, 1, CFG)


def test_import_is_all_or_nothing(tmp_path):
    """Ошибка в середине файла (испорченный пост после хороших токенов) — ничего не записано: ни токены, ни посты."""
    src = bot_store(tmp_path, "src")
    bundle = ex.collect(src, 42, CFG)
    bundle["posts"].append([99, "не base64", "", "text", 0, 0])
    dst = Store(tmp_path / "dst")
    dst.put("pinned_server_sig", SIG)
    with pytest.raises(ValueError):
        ex.apply(dst, bundle, bot_id=42, issuer_kid="t1")
    assert dst.token_counts() == {} and dst.my_numbers() == set() and dst.get("contacts") is None


def test_import_contact_seq_bounded(tmp_path):
    """seq — время выпуска сертификата: значение из будущего (дальше суток) из файла не принимается, иначе подложенный
    файл навсегда объявил бы настоящее устройство контакта «отозванным»."""
    dst = Store(tmp_path / "dst")
    far, ok = b64.enc(bytes([1]) * 32), b64.enc(bytes([2]) * 32)
    seqs = {far: int(time.time()) + 10 * 86400, ok: int(time.time()) - 60, b64.enc(bytes([3]) * 32): True}
    ex.apply(dst, {"v": 1, "contact_seq": seqs}, bot_id=1, issuer_kid="t1")
    assert dst.get("contact_seq") == {ok: seqs[ok]}


@pytest.mark.parametrize("plain", [b'{"v":1,"v":1}', b'{"v":1,"tokens":[1.5]}', b'{"v":1,"created":123456789012345678901234567890}'])
def test_import_parses_json_strictly(tmp_path, plain):
    """Файл экспорта разбирается тем же строгим JSON, что и протокол (docs/EXPORT.md): дубли ключей, дробные и
    огромные числа — «файл повреждён»."""
    sk = PrivateKey.generate()
    data = ex.MAGIC + bytes([ex.MODE_RECIPIENT]) + SealedBox(sk.public_key).encrypt(plain)
    with pytest.raises(ex.ExportError, match="повреждён"):
        ex.open_file(data, recipient_sk=bytes(sk))


def lic(cert=True):
    return {"kid": "s1", "input": b64.enc(bytes(range(32))), "output": b64.enc(bytes(64)),
            "lic_sk": b64.enc(bytes(SigningKey.generate())), "cert": b64.enc(bytes(64)) if cert else None}


def test_licenses_move_with_the_bot(tmp_path):
    """Купленные плагины переезжают: лицензия (и её сертификат) — в файле экспорта; своя лицензия не заменяется."""
    src = bot_store(tmp_path, "src")
    src.put("market_licenses", {"pro": lic(), "fresh": lic(cert=False)})
    dst = bot_store(tmp_path, "dst", device=False, tokens=0, posts=0)
    mine = lic()
    dst.put("market_licenses", {"pro": mine})
    r = ex.apply(dst, roundtrip(ex.collect(src, 42, CFG)), bot_id=42, issuer_kid="t1")
    assert r["licenses"] == 1 and dst.get("market_licenses") == {"pro": mine, "fresh": src.get("market_licenses")["fresh"]}
    assert "лицензий 1" in ex.format_report(r)


def test_unfinished_purchase_moves(tmp_path):
    """Оплатил в старом боте, ответ магазина ещё не переслал: новый бот примет его, ослепление переехало."""
    order = {"kid": "s1", "pk": b64.enc(bytes(32)), "input": b64.enc(bytes(range(32))), "blind": "1f", "at": 1}
    src = bot_store(tmp_path, "src")
    src.put("market_orders", {"pro": order})
    dst = bot_store(tmp_path, "dst", device=False, tokens=0, posts=0)
    ex.apply(dst, roundtrip(ex.collect(src, 42, CFG)), bot_id=42, issuer_kid="t1")
    assert dst.get("market_orders") == {"pro": order}
    bundle = roundtrip(ex.collect(src, 42, CFG))
    with pytest.raises(ex.ExportError, match="лицензии"):
        ex.apply(dst, {**bundle, "license_orders": {"pro": {**order, "blind": "xyz"}}}, bot_id=42, issuer_kid="t1")


@pytest.mark.parametrize("bad", [
    {"Pro": None}, {"pro": {**lic(), "extra": 1}}, {"pro": {**lic(), "output": b64.enc(bytes(32))}},
    {"pro": {**lic(), "kid": "s 1"}}, {"pro": {**lic(), "cert": 5}}, ["pro"],
])
def test_licenses_checked_on_import(tmp_path, bad):
    dst = bot_store(tmp_path, "dst", device=False, tokens=0, posts=0)
    bundle = roundtrip(ex.collect(bot_store(tmp_path, "src"), 42, CFG))
    with pytest.raises(ex.ExportError, match="лицензии"):
        ex.apply(dst, {**bundle, "licenses": bad}, bot_id=42, issuer_kid="t1")
    assert dst.get("market_licenses") is None and dst.token_counts().get(TODAY, 0) == 0
