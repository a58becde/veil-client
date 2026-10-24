"""Журнал клиента без ключей, приём ответов приёмного бота и «принято» после E_PENDING (spec/02, 04, 05, 09):
ключи журнала выводятся из post_secret, отправитель проверяется самим обменом, части ответа собираются по группам,
срок операции общий, а после E_PENDING наружу выходит только итог или «принято»."""
import asyncio
import time
from types import SimpleNamespace

import pytest
from harness import Env
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core import api, privacy
from veil.core.crypto import keys
from veil.core.protocol import b64, envelope, keysdoc
from veil.core.store.db import Store
from veil.core.transport import exchange as exmod
from veil.core.transport.exchange import Exchange, NoReplyError, PartBuffer, ServerError
from veil.core.transport.telegram import TelegramError
from veil.core.wallet.issue import Token as IssuedToken

REAL_SLEEP = asyncio.sleep  # до подмены в fast
FROM = {"is_bot": True, "username": "inbox"}  # отправитель сообщений приёмного бота ("@inbox")


class Wire:
    """Bot API приёмного бота: записывает отправленное; boom — номера отправок (с 1), на которых Telegram отказывает."""

    def __init__(self, boom=()):
        self.sent, self.boom = [], set(boom)

    async def send(self, chat, text, **kw):
        if len(self.sent) + 1 in self.boom:
            raise TelegramError("sendMessage", 500, "boom")
        self.sent.append(text)
        return {"message_id": 100 + len(self.sent)}


class Rig:
    def __init__(self, wire=None, ids=None, same_keys_as: "Rig | None" = None):
        self.inbox, self.server = ((same_keys_as.inbox, same_keys_as.server) if same_keys_as
                                   else (PrivateKey.generate(), SigningKey.generate()))
        self.wire = wire or Wire()
        self.ex = Exchange(self.wire, "@inbox", bytes(self.server.verify_key),
                           lambda: ("i1", bytes(self.inbox.public_key)), (lambda: ids) if ids else (lambda: []))

    def env(self, n: int = -1) -> dict:
        return envelope.open_envelope(self.wire.sent[n], self.inbox)

    def sealed(self, env: dict, result=None, error=None, re=None) -> str:
        resp = envelope.build_response(re or env["id"], self.server, result=result, error=error)
        return envelope.seal_response(resp, b64.dec(env["resp_pk"]))

    def feed(self, text: str, mid: int | None = None, **extra) -> None:
        self.ex.on_inbox_message({"from": FROM, "text": text,
                                  "reply_to_message": {"message_id": mid or 100 + len(self.wire.sent)}, **extra})

    def answer(self, result=None, error=None, mid: int | None = None) -> dict:
        env = self.env(-1 if mid is None else mid - 101)
        self.feed(self.sealed(env, result=result, error=error), mid)
        return env

    async def sent(self, n: int) -> None:
        for _ in range(500):
            if len(self.wire.sent) >= n:
                return
            await REAL_SLEEP(0.002)
        raise AssertionError("конверт не отправлен")


@pytest.fixture
def fast(monkeypatch):
    async def quick(s):
        await REAL_SLEEP(0)
    monkeypatch.setattr(exmod.asyncio, "sleep", quick)
    monkeypatch.setattr(exmod, "WAIT", 0.02)


def req(r: Rig, **kw):
    return asyncio.create_task(r.ex.request("post.create", "ephemeral", SigningKey.generate(), body={"x": 1}, **kw))


# --- ключи журнала ---
def test_journal_keys_deterministic_and_separate():
    secret = bytes(range(32))
    a1, r1 = keys.journal_keys(secret)
    a2, r2 = keys.journal_keys(secret)
    assert bytes(a1) == bytes(a2) and bytes(r1) == bytes(r2)
    assert bytes(a1) != bytes(r1) != bytes(keys.post_signing_key(secret))
    assert bytes(a1) != bytes(keys.post_signing_key(secret))
    assert bytes(a1) == keys.hkdf_sha256(secret, b"veil/v1/journal/auth")
    assert bytes(r1) == keys.hkdf_sha256(secret, b"veil/v1/journal/resp")
    assert bytes(keys.journal_keys(bytes(32))[0]) != bytes(a1)
    for bad in (b"", bytes(31), bytes(33)):
        with pytest.raises(ValueError):
            keys.journal_keys(bad)


def test_request_journal_has_no_keys_and_uses_given_resp_sk():
    r, states = Rig(), []
    rsk = PrivateKey.generate()

    async def go():
        t = req(r, journal=states.append, resp_sk=rsk)
        await r.sent(1)
        r.answer(result={"n": 1})
        return await t
    assert asyncio.run(go()) == {"n": 1}
    assert "resp_sk" not in states[0] and "auth_seed" not in states[0]
    assert set(states[0]) == {"op", "auth_mode", "body", "token", "content", "reply_to", "id", "inbox"}
    assert r.env()["resp_pk"] == b64.enc(bytes(rsk.public_key))


def test_request_without_resp_sk_is_random():
    r = Rig()

    async def go():
        for _ in range(2):
            t = req(r)
            await r.sent(len(r.wire.sent) + 1)
            r.answer(result={})
            await t
    asyncio.run(go())
    assert r.env(0)["resp_pk"] != r.env(1)["resp_pk"]


# --- resume ---
def test_resume_new_and_legacy_rows():
    r = Rig()
    auth, rsk = SigningKey.generate(), PrivateKey.generate()
    state = {"op": "post.create", "auth_mode": "ephemeral", "id": envelope.new_ulid(), "body": {}}

    async def go(st, **kw):
        n = len(r.wire.sent)
        t = asyncio.create_task(r.ex.resume(st, **kw))
        await r.sent(n + 1)
        r.answer(result={"n": 3})
        return await t
    assert asyncio.run(go(state, auth_key=auth, resp_sk=rsk)) == {"n": 3}
    env = r.env()
    assert env["id"] == state["id"] and env["resp_pk"] == b64.enc(bytes(rsk.public_key))
    assert env["auth"]["pk"] == b64.enc(bytes(auth.verify_key))
    with pytest.raises(ValueError):
        asyncio.run(r.ex.resume(state, auth_key=auth))  # нет ключа ответа
    with pytest.raises(ValueError):
        asyncio.run(r.ex.resume(state, resp_sk=rsk))  # нет ключа подписи
    # старая строка: свои поля главнее параметров
    old_auth, old_rsk = SigningKey.generate(), PrivateKey.generate()
    legacy = dict(state, auth_seed=b64.enc(bytes(old_auth)), resp_sk=b64.enc(bytes(old_rsk)))
    assert asyncio.run(go(legacy, auth_key=auth, resp_sk=rsk)) == {"n": 3}
    env = r.env()
    assert env["resp_pk"] == b64.enc(bytes(old_rsk.public_key))
    assert env["auth"]["pk"] == b64.enc(bytes(old_auth.verify_key))
    assert asyncio.run(go(legacy)) == {"n": 3}  # без параметров тоже


def _core(tmp_path, monkeypatch, ex):
    async def build(core, d, post_pk=None):
        return SimpleNamespace(hidden=None, shown=None, deliver=None)
    monkeypatch.setattr(privacy, "build", build)
    monkeypatch.setattr(api, "today", lambda: "2026-10-17")
    store = Store(tmp_path)
    store.add_tokens([IssuedToken("t1", "2026-10-17", bytes([1]) * 32, bytes(64))])
    core = api.Core(bot=None, store=store, exchange=ex, keys_doc={}, owner_id=1)
    monkeypatch.setattr(core, "nick", lambda: None)
    return core


def test_row_written_before_restart_is_read_by_new_core(tmp_path, monkeypatch, fast):
    """Пост без ответа → PostQueuedError, в строке журнала ключей нет. «Перезапуск»: новый обмен и новый Core над той
    же базой дозапрашивают итог тем же конвертом: тот же id, auth.pk, resp_pk, токен и тело."""
    r1 = Rig()
    core1 = _core(tmp_path, monkeypatch, r1.ex)
    d = api.Draft(1, [{"message_id": 1, "text": "пост"}], anonymous=True)
    with pytest.raises(api.PostQueuedError):
        asyncio.run(core1.create_post(d))
    first = r1.env(0)
    assert len(r1.wire.sent) == 2 and r1.env(1)["id"] == first["id"]
    [(env_id, secret, _, state, _)] = core1.store.pending_posts()
    assert "resp_sk" not in state and "auth_seed" not in state and env_id == first["id"]
    eph, rsk = keys.journal_keys(secret)
    assert first["resp_pk"] == b64.enc(bytes(rsk.public_key)) and first["auth"]["pk"] == b64.enc(bytes(eph.verify_key))

    r2 = Rig(same_keys_as=r1)
    core2 = api.Core(bot=None, store=core1.store, exchange=r2.ex, keys_doc={}, owner_id=1)

    async def go():
        t = asyncio.create_task(core2.resume_pending())
        await r2.sent(1)
        r2.answer(result={"n": 42, "url": "u"})
        return await t
    assert asyncio.run(go()) == [("published", {"n": 42, "url": "u"})]
    again = r2.env()
    for k in ("id", "resp_pk", "token", "body"):
        assert again[k] == first[k]
    assert again["auth"] == first["auth"]
    assert core2.store.post_secret(42) == secret and core2.store.pending_posts() == []


def test_legacy_row_with_keys_still_resumes(tmp_path, monkeypatch):
    r = Rig()
    core = _core(tmp_path, monkeypatch, r.ex)
    a, rs = SigningKey.generate(), PrivateKey.generate()
    old_id = envelope.new_ulid()
    core.store.save_pending_post(old_id, bytes(32), "text", {
        "op": "post.create", "auth_mode": "ephemeral", "id": old_id, "body": {},
        "auth_seed": b64.enc(bytes(a)), "resp_sk": b64.enc(bytes(rs))})

    async def go():
        t = asyncio.create_task(core.resume_pending())
        await r.sent(1)
        r.answer(result={"n": 5})
        return await t
    assert asyncio.run(go()) == [("published", {"n": 5})]
    assert r.env()["resp_pk"] == b64.enc(bytes(rs.public_key))


# --- is_inbox ---
def test_is_inbox_never_raises_and_warns_once(caplog):
    def broken():
        raise keysdoc.KeysError("испорчен")
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), broken)
    assert ex.is_inbox({"is_bot": True, "username": "inbox"}) is False
    assert ex.is_inbox({"is_bot": True, "id": 1}) is False
    assert ex.is_inbox("не словарь") is False  # type: ignore[arg-type]
    exmod._warned_username = False
    plain = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)))
    with caplog.at_level("WARNING", logger="veil.exchange"):
        assert plain.is_inbox({"is_bot": True, "username": "Inbox"})
        assert plain.is_inbox({"is_bot": True, "username": "inbox"})
        assert not plain.is_inbox({"is_bot": True, "username": 5})
    assert sum("using @username" in m for m in caplog.messages) == 1


# --- отправитель, вложения, исключения, первый итог ---
def test_stranger_message_is_ignored_without_effects():
    r = Rig(ids=[42])

    async def go():
        got = []
        t = req(r, attachments=got)
        await r.sent(1)
        env = r.env()
        good = r.sealed(env, result={"n": 1})
        for sender in (None, {}, {"id": 42}, {"is_bot": False, "id": 42}, {"is_bot": True, "id": 7},
                       {"is_bot": True, "username": "inbox"}):
            msg = {"text": good, "reply_to_message": {"message_id": 101}}
            if sender is not None:
                msg["from"] = sender
            r.ex.on_inbox_message(msg)
            r.ex.on_inbox_message(dict(msg, text=None, document={"file_id": "D"}))
        pending = next(iter(r.ex._pending.values()))
        assert not pending.future.done() and pending.attachments == []
        r.ex.on_inbox_message({"from": {"is_bot": True, "id": 42}, "text": good,
                               "reply_to_message": {"message_id": 101}})
        return await t, got
    res, got = asyncio.run(go())
    assert res == {"n": 1}


def test_attachments_only_if_requested_and_at_most_four():
    r = Rig()

    async def go():
        t = req(r)  # attachments=None: документы не нужны
        await r.sent(1)
        r.ex.on_inbox_message({"from": FROM, "document": {"file_id": "X"}, "reply_to_message": {"message_id": 101}})
        assert next(iter(r.ex._pending.values())).attachments == []
        r.answer(result={})
        await t
        got = []
        t = req(r, attachments=got)
        await r.sent(2)
        for i in range(7):
            r.ex.on_inbox_message({"from": FROM, "document": {"file_id": str(i)},
                                   "reply_to_message": {"message_id": 102}})
        r.answer(result={})
        await t
        return got
    got = asyncio.run(go())
    assert [m["document"]["file_id"] for m in got] == ["0", "1", "2", "3"]


def test_never_raises_and_first_outcome_wins():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        junk = [None, [], "x", {}, {"from": FROM}, {"from": "bot"}, {"from": FROM, "chat": "x"},
                {"from": FROM, "text": None, "reply_to_message": {"message_id": 101}},
                {"from": FROM, "text": 5, "reply_to_message": {"message_id": 101}},
                {"from": FROM, "text": b"VEIL1R x", "reply_to_message": {"message_id": 101}},
                {"from": FROM, "text": "VEIL1R x", "reply_to_message": "101"},
                {"from": FROM, "text": "VEIL1R x", "chat": {"id": []}, "reply_to_message": {"message_id": []}}]
        for m in junk:
            r.ex.on_inbox_message(m)  # type: ignore[arg-type]
        assert not next(iter(r.ex._pending.values())).future.done()
        # синхронно, без await между вызовами: два правильных ответа, подсказка, часть
        r.feed(r.sealed(env, result={"n": 1}), 101)
        r.feed(r.sealed(env, result={"n": 2}), 101)
        r.feed("VEIL1E E_RATE", 101)
        r.feed("VEIL1R 1/2 AAAA", 101)
        r.feed(r.sealed(env, error={"code": "E_INTERNAL"}), 101)
        return await t
    assert asyncio.run(go()) == {"n": 1}


# --- подсказка VEIL1E ---
@pytest.mark.parametrize("hint", ["VEIL1E hello", "VEIL1E e_rate", "VEIL1E E_", "VEIL1E E_" + "A" * 33,
                                  "VEIL1E E_RATE extra", "VEIL1E E_1", "VEIL1E "])
def test_hint_with_bad_code_is_ignored(hint):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(hint, 101)
        await REAL_SLEEP(0.01)
        assert not t.done()
        r.answer(result={"n": 1})
        return await t
    assert asyncio.run(go()) == {"n": 1}


@pytest.mark.parametrize("code", ["E_RATE", "E_A", "E_" + "A" * 32, "E_TOKEN_DAY"])
def test_hint_with_valid_code_ends_request(code):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(f"VEIL1E {code}", 101)
        return await t
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.hint and ei.value.code == code and not ei.value.accepted


# --- PartBuffer ---
def _chunks(body: str):
    return envelope.split_response("VEIL1R " + body)


def test_part_buffer_group_replace_and_foreign():
    body = "A" * 4000 + "B" * 4000 + "C" * 10
    p1, p2, p3 = _chunks(body)
    buf = PartBuffer()
    assert len(buf) == 0
    assert buf.add(p3) is None and buf.add(p1) is None
    assert buf.add("VEIL1R 1/2 xx") is None and buf.add("VEIL1R 2/2 yy") == "VEIL1R xxyy"  # другая группа независима
    assert buf.add(p2) == "VEIL1R " + body and len(buf) == 5
    # замена той же пары: последний побеждает; полная группа возвращается при каждом приходе
    assert buf.add("VEIL1R 3/3 Z") == "VEIL1R " + "A" * 4000 + "B" * 4000 + "Z"
    assert buf.add(p3) == "VEIL1R " + body and len(buf) == 5
    assert buf.add("VEIL1R 1/2 qq") == "VEIL1R qqyy"


@pytest.mark.parametrize("text", ["VEIL1R 01/02 x", "VEIL1R 17/17 x", "VEIL1R 0/2 x", "VEIL1R 3/2 x", "VEIL1R abc",
                                  "VEIL1R 1/2", "VEIL1R 1/2 ", "VEIL1R 1/2 x y", "VEIL1E E_RATE", "", "1/2 x",
                                  "VEIL1R -1/2 x", "VEIL1R 1/+2 x"])
def test_part_buffer_ignores_non_parts(text):
    buf = PartBuffer()
    buf.add("VEIL1R 1/2 aa")
    assert buf.add(text) is None and len(buf) == 1


def test_part_buffer_is_bounded():
    buf = PartBuffer()
    for n in range(1, 17):
        for i in range(1, n + 1):
            buf.add(f"VEIL1R {i}/{n} {'a' * i}")
    assert len(buf) == 136
    for n in range(1, 17):
        for i in range(1, n + 1):
            buf.add(f"VEIL1R {i}/{n} b")
    assert len(buf) == 136


def test_foreign_parts_do_not_break_real_answer():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        big = envelope.build_response(env["id"], r.server, result={"posts": ["я" * 100] * 50})
        parts = envelope.split_response(envelope.seal_response(big, b64.dec(env["resp_pk"])))
        n = len(parts)
        assert n > 1
        r.feed("VEIL1R 1/16 junk", 101)  # посторонняя часть с другим n
        r.feed("VEIL1R 01/02 junk", 101)
        r.feed("VEIL1R 17/17 junk", 101)
        for i in range(1, n + 1):  # полная группа того же n из мусора: расшифровать нечем — игнорируется
            r.feed(f"VEIL1R {i}/{n} AAAA", 101)
        await REAL_SLEEP(0.01)
        assert not t.done()
        for p in reversed(parts):
            r.feed(p, 101)
        return await t
    assert len(asyncio.run(go())["posts"]) == 50


def test_signed_malformed_assembled_response_ends_request():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        bad = envelope.build_response("other-id", r.server, result={"posts": ["я" * 100] * 50})
        for p in envelope.split_response(envelope.seal_response(bad, b64.dec(env["resp_pk"]))):
            r.feed(p, 101)
        return await asyncio.wait_for(t, 1)
    with pytest.raises(exmod.ProtocolError) as ei:
        asyncio.run(go())
    assert ei.value.signed and ei.value.code == "E_MALFORMED"


def test_replaced_part_completes_answer():
    """Подмена куска (та же пара) не мешает: настоящий кусок позже заменяет подложный."""
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        big = envelope.build_response(env["id"], r.server, result={"posts": ["я" * 100] * 50})
        parts = envelope.split_response(envelope.seal_response(big, b64.dec(env["resp_pk"])))
        r.feed(parts[0][: parts[0].index(" ", 7) + 1] + "AAAA", 101)  # подложный кусок 1
        for p in parts[1:]:
            r.feed(p, 101)  # группа полна, но не расшифровывается: игнорируется
        await REAL_SLEEP(0.01)
        assert not t.done()
        r.feed(parts[0], 101)  # настоящий кусок заменяет подложный
        return await t
    assert len(asyncio.run(go())["posts"]) == 50


# --- «принято» после E_PENDING и общий срок ---
def _pending_then(r: Rig, after):
    """E_PENDING на первый конверт; after(r) — что происходит с повтором."""
    async def go():
        t = req(r)
        await r.sent(1)
        r.answer(error={"code": "E_PENDING", "retry_after": 1})
        await r.sent(2)
        after(r)
        return await t
    return go


def test_two_timeouts_after_pending_are_accepted_not_no_reply(fast):
    r = Rig()
    with pytest.raises(ServerError) as ei:
        asyncio.run(_pending_then(r, lambda r: None)())
    assert ei.value.code == "E_PENDING" and ei.value.accepted
    assert len(r.wire.sent) == 3  # первая, повтор, ещё повтор — тот же конверт
    assert r.env(0)["id"] == r.env(1)["id"] == r.env(2)["id"]


def test_no_reply_without_pending_stays_no_reply(fast):
    r = Rig()
    with pytest.raises(NoReplyError):
        asyncio.run(req_wait(r))


async def req_wait(r: Rig):
    return await req(r)


def test_telegram_error_on_resend_after_pending_is_accepted(fast):
    r = Rig(Wire(boom={2}))

    async def go():
        t = req(r)
        await r.sent(1)
        r.answer(error={"code": "E_PENDING", "retry_after": 1})
        return await t
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.code == "E_PENDING" and ei.value.accepted
    assert len(r.wire.sent) == 1  # без вращения в цикле


def test_telegram_error_before_pending_is_raised_as_is(fast):
    r = Rig(Wire(boom={1}))
    with pytest.raises(TelegramError):
        asyncio.run(req_wait(r))


def test_hint_after_pending_keeps_accepted(fast):
    r = Rig()
    with pytest.raises(ServerError) as ei:
        asyncio.run(_pending_then(r, lambda r: r.feed("VEIL1E E_RATE", 102))())
    assert ei.value.code == "E_RATE" and ei.value.accepted


def test_signed_malformed_after_pending_keeps_accepted(fast):
    r = Rig()

    def bad(r):
        r.feed(r.sealed(r.env(), result={"n": 1}, re="other-id"), 102)
    with pytest.raises(ServerError) as ei:
        asyncio.run(_pending_then(r, bad)())
    assert ei.value.code == "E_MALFORMED" and ei.value.accepted


def test_server_error_after_pending_keeps_accepted(fast):
    r = Rig()
    with pytest.raises(ServerError) as ei:
        asyncio.run(_pending_then(r, lambda r: r.answer(error={"code": "E_TOKEN_DAY"}, mid=102))())
    assert ei.value.code == "E_TOKEN_DAY" and ei.value.accepted


def test_pending_retries_exhausted_is_accepted(fast, monkeypatch):
    monkeypatch.setattr(exmod, "PENDING_RETRIES", 1)
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.answer(error={"code": "E_PENDING", "retry_after": 1})
        await r.sent(2)
        r.answer(error={"code": "E_PENDING", "retry_after": 1}, mid=102)
        return await t
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.code == "E_PENDING" and ei.value.accepted and len(r.wire.sent) == 2


def test_deadline_bounds_wait_without_pending(monkeypatch):
    monkeypatch.setattr(exmod, "WAIT", 30.0)
    monkeypatch.setattr(exmod, "DEADLINE", 0.1)
    r = Rig()
    t0 = time.monotonic()
    with pytest.raises(NoReplyError):
        asyncio.run(req_wait(r))
    assert time.monotonic() - t0 < 5 and len(r.wire.sent) <= 2  # по сроку новых отправок нет (допуск на таймер)


def test_deadline_bounds_pause_after_pending(monkeypatch):
    monkeypatch.setattr(exmod, "WAIT", 30.0)
    monkeypatch.setattr(exmod, "DEADLINE", 0.3)
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.answer(error={"code": "E_PENDING", "retry_after": 60})
        return await t
    t0 = time.monotonic()
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert time.monotonic() - t0 < 5 and ei.value.accepted and ei.value.code == "E_PENDING"
    assert len(r.wire.sent) <= 2  # срок вышел в паузе: повтор не отправляется (допуск на таймер)


def test_deadline_applies_to_resume(monkeypatch):
    monkeypatch.setattr(exmod, "WAIT", 30.0)
    monkeypatch.setattr(exmod, "DEADLINE", 0.1)
    r = Rig()
    state = {"op": "post.create", "auth_mode": "ephemeral", "id": envelope.new_ulid()}
    t0 = time.monotonic()
    with pytest.raises(NoReplyError):
        asyncio.run(r.ex.resume(state, SigningKey.generate(), PrivateKey.generate()))
    assert time.monotonic() - t0 < 5


def test_constants_defaults():
    assert exmod.DEADLINE == 600.0 and exmod.MAX_ATTACHMENTS == 4 and exmod.WAIT == 125.0


# --- Core: E_DEVICE при accepted, refresh_keys ---
def test_create_post_no_device_retry_when_accepted(tmp_path):
    e = Env(tmp_path, identity=True)
    asyncio.run(e.core.sync_device())
    e.server.registered[e.store.load_device().dev_pk]["nick"] = "Роза"
    asyncio.run(e.core.sync_device(force=True))
    e.server.fail("post.create", "E_DEVICE", accepted=True)
    d = api.Draft(111, [{"message_id": 1, "chat": {"id": 111}, "text": "пост"}])
    with pytest.raises(api.PostQueuedError):
        asyncio.run(e.core.create_post(d))
    assert sum(op == "post.create" for op, _ in e.server.ops) == 1
    assert len(e.store.pending_posts()) == 1  # журнал держит пост для дозапроса


def test_create_post_passes_derived_resp_key(tmp_path):
    e = Env(tmp_path)
    d = api.Draft(111, [{"message_id": 1, "chat": {"id": 111}, "text": "пост"}], anonymous=True)
    asyncio.run(e.core.create_post(d))
    secret = e.store.post_secret(e.server.n)
    assert bytes(e.server.last_resp_sk) == bytes(keys.journal_keys(secret)[1])


def _signed_doc(sk: SigningKey, **extra) -> dict:
    doc = {"inbox_enc": [{"kid": "i1", "pk": b64.enc(bytes(32))}],
           "issuer_poprf": [{"kid": "t1", "pk": b64.enc(bytes(range(32)))}],
           "server_sig": b64.enc(bytes(sk.verify_key)), **extra}
    doc["sig"] = b64.enc(sk.sign(envelope.signing_input(doc, keysdoc.CTX_KEYS)).signature)
    return doc


def _refresh_core(tmp_path, old: dict, new: dict, sk: SigningKey):
    class Ex:
        server_sig_pk = bytes(sk.verify_key)

        async def request(self, *a, **kw):
            return new
    store = Store(tmp_path)
    return api.Core(bot=None, store=store, exchange=Ex(), keys_doc=old, owner_id=1)


@pytest.mark.parametrize("new_extra", [{}, {"inbox_bots": []}, {"inbox_bots": [0]}, {"inbox_bots": "x"},
                                       {"inbox_bots": [True]}, {"inbox_bots": [1, -2]}])
def test_refresh_keys_rejects_rollback_and_corrupt_inbox_bots(tmp_path, new_extra):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[5, 6])
    core = _refresh_core(tmp_path, old, _signed_doc(sk, **new_extra), sk)
    with pytest.raises(keysdoc.KeysError):
        asyncio.run(core.refresh_keys())
    assert core.keys_doc is old and core.store.get("keys_doc") is None


def test_refresh_keys_accepts_new_ids_and_first_publication(tmp_path):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[5, 6])
    new = _signed_doc(sk, inbox_bots=[7])
    core = _refresh_core(tmp_path, old, new, sk)
    assert asyncio.run(core.refresh_keys()) == new and core.store.get("keys_doc") == new
    plain_old = _signed_doc(sk)  # у клиента ID ещё не было: документ без них допустим (spec/02)
    (tmp_path / "b").mkdir()
    core =_refresh_core(tmp_path / "b", plain_old, _signed_doc(sk), sk)
    assert asyncio.run(core.refresh_keys())["server_sig"] == plain_old["server_sig"]


# --- интерфейс ---
def test_explain_accepted_says_pending_for_any_code(tmp_path):
    e = Env(tmp_path)
    pending = e.ui.explain(ServerError("E_PENDING"))
    for code in ("E_TOKEN_DAY", "E_RATE", "E_UNKNOWN_X", "E_PENDING"):
        assert e.ui.explain(ServerError(code, accepted=True)) == pending
    assert e.ui.explain(ServerError("E_RATE")) != pending
    assert "не выполнено" not in e.ui.T("text.no_reply")
    assert "группе" in e.ui.T("text.no_reply")


# --- ожидание на всю операцию: ответ на любой конверт (spec/09) ---
def test_all_keys_of_operation_are_released_after_outcome(fast):
    async def go(outcome):
        r = Rig()
        t = req(r)
        await r.sent(1)
        if outcome == "timeout":
            await r.sent(2)
        elif outcome == "error":
            r.answer(error={"code": "E_RATE"})
        else:
            r.answer(result={})
        try:
            await t
        except (ServerError, NoReplyError):
            pass
        return r.ex._pending
    for outcome in ("ok", "error", "timeout"):
        assert asyncio.run(go(outcome)) == {}


def test_answer_to_first_envelope_after_resend_and_pending_retry(fast):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(2)  # таймаут первого ожидания — тот же конверт отправлен повторно
        assert len(r.ex._pending) == 2
        r.answer(error={"code": "E_PENDING", "retry_after": 1}, mid=101)  # ответ на первый конверт
        await r.sent(3)
        r.answer(result={"n": 3}, mid=101)  # итог снова на первый конверт
        return await t
    assert asyncio.run(go()) == {"n": 3}


def test_parts_on_different_envelopes_of_one_operation_are_joined(fast):
    r = Rig()
    parts = [f"VEIL1R {i}/2 x" for i in (1, 2)]
    assert envelope.is_response_part(parts[0]) == (1, 2)

    async def go():
        t = req(r)
        await r.sent(2)
        env = r.env()
        # настоящие части одного ответа, но склеенные из шаблонных кусков, не откроются; проверяем лишь,
        # что обе доходят до одного буфера: части с разных конвертов лежат вместе
        r.feed(parts[0], 101)
        r.feed(parts[1], 102)
        pending = next(iter(r.ex._pending.values()))
        assert len(pending.parts) == 2
        r.feed(r.sealed(env, result={"ok": 1}), 101)
        return await t
    assert asyncio.run(go()) == {"ok": 1}


def test_old_key_stays_valid_after_inbox_bot_switch(fast):
    r = Rig(ids=[1, 2])

    async def go():
        t = req(r)
        await r.sent(2)  # первый конверт без ответа, повтор ушёл тому же боту
        r.ex.switch_from(1)
        r.ex.on_inbox_message({"from": {"is_bot": True, "id": 1}, "text": r.sealed(r.env(), result={"s": 1}),
                               "reply_to_message": {"message_id": 101}})
        return await t
    assert asyncio.run(go()) == {"s": 1}
