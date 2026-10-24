"""Пути доставки поста (privacy.build), обмен с сервером (Exchange) и редкие ветки ядра (Core)."""
import asyncio

import pytest
from harness import Env, person
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core import api, privacy
from veil.core.crypto import keys
from veil.core.protocol import b64, envelope, hidden
from veil.core.transport import exchange as exmod
from veil.core.transport.exchange import Exchange, NoReplyError, ServerError

PHOTO = lambda mid, cap=None, g=None: dict(  # noqa: E731
    {"message_id": mid, "chat": {"id": 111}, "photo": [{"file_id": f"p{mid}", "file_unique_id": f"u{mid}"}]},
    **({"caption": cap} if cap else {}), **({"media_group_id": g} if g else {}))
TEXT = {"message_id": 1, "chat": {"id": 111}, "text": "смотри https://e.com",
        "entities": [{"type": "url", "offset": 7, "length": 13}]}
NOTE = {"message_id": 3, "chat": {"id": 111}, "video_note": {"file_id": "vn", "file_unique_id": "uvn"}}


def deliver(env, d):
    async def go():
        plan = await privacy.build(env.core, d)
        got = await plan.deliver()
        return plan, got
    return asyncio.run(go())


@pytest.mark.parametrize("msgs,hide,method", [
    ([TEXT], "", "copyMessage"),
    ([PHOTO(2, cap="фото https://e.com", g="g"), PHOTO(3, g="g")], "", "copyMessages"),
    ([TEXT], "links", "sendMessage"),
    ([PHOTO(2, cap="фото https://e.com")], "links", "sendPhoto"),
    ([PHOTO(2, cap="a https://e.com", g="g"), PHOTO(3, g="g")], "links", "sendMediaGroup"),
    ([TEXT], "message", "sendMessage"),
    ([PHOTO(2, cap="секрет")], "message", "sendPhoto"),
    ([PHOTO(2, cap="секрет", g="g"), PHOTO(3, g="g")], "message", "copyMessages"),
    ([NOTE], "message", "copyMessage"),
])
def test_build_delivery_paths(tmp_path, msgs, hide, method):
    e = Env(tmp_path)
    for m in msgs:
        if "caption" in m and "https" in m["caption"]:
            m["caption_entities"] = [{"type": "url", "offset": m["caption"].index("https"), "length": 13}]
    assert hide in privacy.modes(msgs)
    plan, got = deliver(e, api.Draft(111, msgs, hide=hide))
    assert method in e.tg.methods()
    if hide in ("links", "message"):
        assert plan.hidden and plan.hidden["mode"] == "all"


def test_build_private_files(tmp_path):
    e = Env(tmp_path)
    rose, _ = person("Роза")
    e.tg.files["p2"] = b"jpegbytes"
    d = api.Draft(111, [PHOTO(2, cap="тебе")], hide="to", to_pk=b64.enc(rose.current.pk), to_label="Роза·x")
    plan, got = deliver(e, d)
    assert plan.shown == [] and plan.hidden["mode"] == "to" and plan.hidden["file"] is True
    pl = hidden.open_to(b64.dec(plan.hidden["blob"]), rose.current.sk)
    assert pl["text"] == "тебе" and pl["files"][0]["size"] == 9
    assert "sendDocument" in e.tg.methods() and "getFile" in e.tg.methods()
    with pytest.raises(ValueError):
        asyncio.run(privacy.build(e.core, api.Draft(111, [TEXT], hide="nonsense")))


# --- Exchange с «сервером», который читает конверт и отвечает ---
class Wire:
    def __init__(self):
        self.sent, self.uploads = [], []

    async def send(self, chat, text, **kw):
        self.sent.append((chat, text, kw))
        return {"message_id": 100 + len(self.sent)}

    async def upload(self, method, field, name, data, mime, **kw):
        self.uploads.append((method, kw.get("caption"), data.decode()))
        self.sent.append((kw.get("chat_id"), data.decode(), kw))
        return {"message_id": 100 + len(self.sent)}


INBOX_FROM = {"is_bot": True, "username": "inbox_bot"}  # отправитель сообщений приёмного бота ("@Inbox_Bot")


def make_ex(ids=None):
    inbox, server = PrivateKey.generate(), SigningKey.generate()
    w = Wire()
    ex = Exchange(w, "@Inbox_Bot", bytes(server.verify_key), lambda: ("i1", bytes(inbox.public_key)),
                  lambda: ids or [])
    return ex, w, inbox, server


def reply_to(ex, w, inbox, server, result=None, error=None, mid=None):
    text = w.sent[-1][1]
    env = envelope.open_envelope(text, inbox, max_plain=envelope.MAX_DOC_PLAINTEXT)  # конверт мог уйти документом
    resp = envelope.build_response(env["id"], server, result=result, error=error)
    ex.on_inbox_message({"from": INBOX_FROM, "text": envelope.seal_response(resp, b64.dec(env["resp_pk"])),
                         "reply_to_message": {"message_id": mid or 100 + len(w.sent)}})
    return env


@pytest.fixture
def fast(monkeypatch):
    real = asyncio.sleep

    async def quick(s):
        await real(0)
    monkeypatch.setattr(exmod.asyncio, "sleep", quick)


def test_pending_then_result_same_envelope(fast):
    ex, w, inbox, server = make_ex()
    states = []

    async def go():
        t = asyncio.create_task(ex.request("post.create", "ephemeral", SigningKey.generate(), body={},
                                           journal=states.append))
        await asyncio.sleep(0.01)
        e1 = reply_to(ex, w, inbox, server, error={"code": "E_PENDING", "retry_after": 1})
        for _ in range(20):
            await asyncio.sleep(0)
        e2 = reply_to(ex, w, inbox, server, result={"n": 7})
        r = await t
        return e1, e2, r
    e1, e2, r = asyncio.run(go())
    assert r == {"n": 7} and e1["id"] == e2["id"] == states[0]["id"] and e1["resp_pk"] == e2["resp_pk"]


def test_no_reply_after_two_waits(monkeypatch):
    monkeypatch.setattr(exmod, "WAIT", 0.01)
    ex, w, *_ = make_ex()
    with pytest.raises(NoReplyError):
        asyncio.run(ex.request("ping", "ephemeral", SigningKey.generate()))
    assert len(w.sent) == 2  # тот же конверт отправлен второй раз


def test_big_envelope_goes_as_document():
    ex, w, inbox, server = make_ex()

    async def go():
        t = asyncio.create_task(ex.request("post.create", "ephemeral", SigningKey.generate(),
                                           body={"x": "я" * 3000}))
        await asyncio.sleep(0.01)
        reply_to(ex, w, inbox, server, result={"ok": 1})
        return await t
    assert asyncio.run(go()) == {"ok": 1} and w.uploads[0][1] == envelope.DOC_CAPTION


def test_attachments_hint_and_forgery():
    ex, w, inbox, server = make_ex()
    got = []

    async def go():
        t = asyncio.create_task(ex.request("hidden.file", "ephemeral", SigningKey.generate(), attachments=got))
        await asyncio.sleep(0.01)
        ex.on_inbox_message({"from": INBOX_FROM, "document": {"file_id": "D"}, "reply_to_message": {"message_id": 101}})
        ex.on_inbox_message({"from": INBOX_FROM, "text": "просто текст", "reply_to_message": {"message_id": 101}})
        ex.on_inbox_message({"from": INBOX_FROM, "text": "VEIL1R x", "reply_to_message": {"message_id": 999}})  # чужой
        reply_to(ex, w, inbox, server, result={}, mid=101)
        return await t
    asyncio.run(go())
    assert got and got[0]["document"]["file_id"] == "D"

    async def hint():
        t = asyncio.create_task(ex.request("ping", "ephemeral", SigningKey.generate()))
        await asyncio.sleep(0.01)
        ex.on_inbox_message({"from": INBOX_FROM, "text": "VEIL1E E_CLOCK",
                             "reply_to_message": {"message_id": 100 + len(w.sent)}})
        return await t
    with pytest.raises(ServerError) as e:
        asyncio.run(hint())
    assert e.value.hint and e.value.code == "E_CLOCK"


def test_resume_and_inbox_address():
    ex, w, inbox, server = make_ex()
    seed = SigningKey.generate()
    state = {"op": "post.create", "auth_mode": "ephemeral", "id": envelope.new_ulid(),
             "resp_sk": b64.enc(bytes(PrivateKey.generate())), "auth_seed": b64.enc(bytes(seed)), "body": {}}

    async def go():
        t = asyncio.create_task(ex.resume(state))
        await asyncio.sleep(0.01)
        env = reply_to(ex, w, inbox, server, result={"n": 3})
        return env, await t
    env, r = asyncio.run(go())
    assert r == {"n": 3} and env["id"] == state["id"]
    with pytest.raises(ValueError):
        asyncio.run(ex.resume(dict(state, auth_seed=None)))
    assert ex.inbox == "@inbox_bot" and ex.is_inbox({"is_bot": True, "username": "INBOX_bot"})
    assert not ex.is_inbox({"is_bot": False, "username": "inbox_bot"})
    ex2, *_ = make_ex(ids=[42])
    assert ex2.inbox == 42 and ex2.is_inbox({"is_bot": True, "id": 42}) and not ex2.is_inbox({"is_bot": True, "id": 7})


# --- редкие ветки ядра ---
def test_sync_device_rotation_and_enc_set(tmp_path):
    e = Env(tmp_path, identity=True)
    asyncio.run(e.core.sync_device())  # регистрация
    d = e.store.load_device()
    st = e.server.registered[d.dev_pk]
    st["enc_pk"], st["enc_exp"] = "old", 0  # на сервере старый ключ шифрования
    asyncio.run(e.core.sync_device(force=True))
    assert any(op == "enc.set" for op, _ in e.server.ops)
    e.server.fail("enc.set", "E_RATE")
    asyncio.run(e.core.sync_device(force=True))  # занято — не ошибка
    e.server.fail("device.get", "E_BOT_NOT_BOUND")
    with pytest.raises(api.OtherBotError):
        asyncio.run(e.core.sync_device(force=True))
    e.server.fail("device.get", "E_INTERNAL")
    with pytest.raises(ServerError):
        asyncio.run(e.core.sync_device(force=True))
    assert asyncio.run(e.core.server_confirms(d)) is True
    assert asyncio.run(e.core.server_confirms(keys.issue_device(SigningKey.generate()))) is False


def test_open_private_with_files(tmp_path):
    """«Лично для» с файлами: текст — сразу, файлы — только по запросу владельца (Core.private_files) и у того
    приёмного бота, который держит контейнер; payload привязан к post_pk поста."""
    e = Env(tmp_path, identity=True)
    me = e.store.load_device()
    container, key = hidden.seal_files([b"abc"])
    post_pk = b64.enc(bytes(range(32)))
    pl = hidden.payload("тебе", files=[{"kind": "photo", "name": "a.jpg", "mime": "image/jpeg", "size": 3}],
                        file_key=key, post_pk=post_pk)
    blob = b64.enc(hidden.seal_to(hidden.padded(pl), me.current.pk))
    post = {"n": 5, "hidden_for": b64.enc(me.current.pk), "hidden_blob": blob, "hidden_file": True, "url": "u",
            "post_pk": post_pk, "bot": 4242, "nick": "Аня", "tag": "k2m9xq"}
    ev = e.core._open_private(post, me.current.sk)
    assert ev.text == "тебе" and ev.file_count == 1 and ev.sender == "Аня·k2m9xq"
    assert [op for op, _ in e.server.ops] == []  # файл сам не скачивается
    e.tg.files["C"] = container
    e.server.attach = [{"document": {"file_id": "C"}}]
    files = asyncio.run(e.core.private_files(5))
    assert files[0].data == b"abc" and e.server.last_to == 4242
    with pytest.raises(KeyError):  # уже прислан — запись забыта
        asyncio.run(e.core.private_files(5))
    e.core._open_private(post, me.current.sk)
    e.server.attach = []
    with pytest.raises(ValueError):
        asyncio.run(e.core.private_files(5))
    bad = hidden.seal_to(hidden.jcs.canonicalize({"text": 5}), me.current.pk)  # текст не строка — схема не та
    assert e.core._open_private(dict(post, hidden_blob=b64.enc(bad)), me.current.sk) is None


def test_private_payload_bound_to_post(tmp_path):
    """Blob «лично для», скопированный из чужого поста (другой post_pk), не выдаётся за сообщение этого поста."""
    e = Env(tmp_path, identity=True)
    me = e.store.load_device()
    alice_pk, mallory_pk = b64.enc(bytes(32)), b64.enc(bytes([1]) * 32)
    blob = b64.enc(hidden.seal_to(hidden.padded(hidden.payload("от Алисы", post_pk=alice_pk)), me.current.pk))
    entry = {"n": 7, "hidden_for": b64.enc(me.current.pk), "hidden_blob": blob, "url": "u"}
    assert e.core._open_private(dict(entry, post_pk=alice_pk), me.current.sk).text == "от Алисы"
    assert e.core._open_private(dict(entry, n=8, post_pk=mallory_pk), me.current.sk) is None
    assert e.core._open_private(entry, me.current.sk) is None  # запись ленты без post_pk — не проверить
    legacy = b64.enc(hidden.seal_to(hidden.padded(hidden.payload("старый формат")), me.current.pk))
    assert e.core._open_private(dict(entry, hidden_blob=legacy, post_pk=alice_pk), me.current.sk) is None


def test_resume_pending_paths(tmp_path):
    e = Env(tmp_path)
    e.store.save_pending_post("a", bytes(32), "text", {"id": "a", "auth_mode": "ephemeral"})
    e.store.save_pending_post("b", bytes(32), "text", {"id": "b", "auth_mode": "ephemeral"})

    async def fail_then(state, auth_key=None, resp_sk=None):
        if state["id"] == "a":
            raise ServerError("E_PENDING")
        raise ServerError("E_TOO_LONG")
    e.server.resume = fail_then
    assert asyncio.run(e.core.resume_pending()) == [("failed", None)]
    assert [p[0] for p in e.store.pending_posts()] == ["a"]

    async def silent(state, auth_key=None, resp_sk=None):
        raise NoReplyError("x")
    e.server.resume = silent
    assert asyncio.run(e.core.resume_pending()) == []
    e.core._inflight.add("a")
    assert asyncio.run(e.core.resume_pending()) == []


def test_create_post_retries_after_device_reset(tmp_path):
    e = Env(tmp_path, identity=True)
    asyncio.run(e.core.sync_device())
    e.server.registered[e.store.load_device().dev_pk]["nick"] = "Роза"  # ник — на сервере (бот берёт его оттуда)
    asyncio.run(e.core.sync_device(force=True))
    assert e.core.nick()
    e.server.fail("post.create", "E_DEVICE")  # база сервера откатилась: устройство перерегистрируется, пост повторяется
    d = api.Draft(111, [{"message_id": 1, "chat": {"id": 111}, "text": "пост"}])
    r = asyncio.run(e.core.create_post(d))
    assert r["n"] and sum(op == "device.set" for op, _ in e.server.ops) >= 1
    e.server.fail("post.create", "E_TOO_LONG")
    with pytest.raises(ServerError):
        asyncio.run(e.core.create_post(d))
    assert e.store.pending_posts() == []  # отказ сервера — журнал не держит
