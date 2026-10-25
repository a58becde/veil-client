"""Тесты-противник к обмену с сервером (spec/02, 04, 05, 09): ключи журнала, проверка отправителя, части ответа,
«принято» после E_PENDING, общий срок. Написаны от правил spec, а не от устройства реализации."""
import asyncio
import base64
import hashlib
import hmac
import json
import time

import pytest
from harness import Env
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core import api
from veil.core.crypto import keys
from veil.core.protocol import b64, envelope, keysdoc
from veil.core.store.db import Store
from veil.core.transport import exchange as exmod
from veil.core.transport.exchange import Exchange, NoReplyError, PartBuffer, ServerError
from veil.core.transport.telegram import TelegramError

REAL_SLEEP = asyncio.sleep
FROM = {"is_bot": True, "username": "inbox"}
B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
PROP = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])


class Wire:
    """boom — номера отправок (с 1), на которых Telegram отказывает; dead — чаты, куда писать нельзя (403);
    calls — (чат, reply_to) каждой попытки; uploads — документы."""

    def __init__(self, boom=(), on_send=None, dead=(), dead_code=403, dead_text="Forbidden: bot was blocked"):
        self.sent, self.boom, self.on_send = [], set(boom), on_send
        self.dead, self.dead_err = set(dead), (dead_code, dead_text)
        self.calls, self.uploads = [], []

    async def send(self, chat, text, **kw):
        self.calls.append((chat, kw.get("reply_to")))
        if self.on_send:
            self.on_send(len(self.sent))
        if chat in self.dead:
            raise TelegramError("sendMessage", *self.dead_err)
        if len(self.sent) + 1 in self.boom:
            raise TelegramError("sendMessage", 500, "boom")
        self.sent.append(text)
        return {"message_id": 100 + len(self.sent)}

    async def upload(self, method, field, filename, data, mime, **params):
        self.uploads.append((method, field, filename, mime, params))
        self.calls.append((params.get("chat_id"), (params.get("reply_parameters") or {}).get("message_id")))
        self.sent.append(data.decode())
        return {"message_id": 100 + len(self.sent)}


class Rig:
    def __init__(self, wire=None, ids=None):
        self.inbox, self.server = PrivateKey.generate(), SigningKey.generate()
        self.ids = ids
        self.wire = wire or Wire()
        self.ex = Exchange(self.wire, "@inbox", bytes(self.server.verify_key),
                           lambda: ("i1", bytes(self.inbox.public_key)), (lambda: ids) if ids else (lambda: []))

    def env(self, n: int = -1) -> dict:
        return envelope.open_envelope(self.wire.sent[n], self.inbox, max_plain=envelope.MAX_DOC_PLAINTEXT)

    def sealed(self, env: dict, result=None, error=None, re=None, signer=None) -> str:
        resp = envelope.build_response(re or env["id"], signer or self.server, result=result, error=error)
        return envelope.seal_response(resp, b64.dec(env["resp_pk"]))

    def feed(self, text: str, mid: int, sender=None) -> None:
        if sender is None:
            sender = {"is_bot": True, "id": self.ids[-1]} if self.ids else FROM
        self.ex.on_inbox_message({"from": sender, "text": text, "reply_to_message": {"message_id": mid}})

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


def hkdf(ikm: bytes, info: bytes, salt: bytes = b"veil/v1") -> bytes:
    """Независимая реализация RFC 5869 (HKDF-SHA256, 32 байта)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


# --- ключи журнала ---
@given(st.binary(min_size=32, max_size=32))
@PROP
def test_journal_keys_match_independent_hkdf(secret):
    a, r = keys.journal_keys(secret)
    assert bytes(a) == hkdf(secret, b"veil/v1/journal/auth")
    assert bytes(r) == hkdf(secret, b"veil/v1/journal/resp")
    assert bytes(a) != bytes(r) and bytes(a) != secret and bytes(r) != secret
    assert bytes(a) != bytes(keys.post_signing_key(secret))
    assert bytes(a.verify_key) != bytes(r.public_key)
    assert [bytes(k) for k in keys.journal_keys(secret)] == [bytes(a), bytes(r)]


@given(st.binary(min_size=32, max_size=32), st.integers(0, 255))
@PROP
def test_journal_keys_every_bit_matters(secret, bit):
    other = bytearray(secret)
    other[bit // 8] ^= 1 << (bit % 8)
    a1, r1 = keys.journal_keys(secret)
    a2, r2 = keys.journal_keys(bytes(other))
    assert bytes(a1) != bytes(a2) and bytes(r1) != bytes(r2)


@given(st.integers(0, 100).filter(lambda n: n != 32))
@PROP
def test_journal_keys_reject_wrong_length(n):
    with pytest.raises(ValueError, match="^post_secret must be 32 bytes$"):
        keys.journal_keys(bytes(n))


@pytest.mark.parametrize("bad", [None, "a" * 32, 32, [0] * 32])
def test_journal_keys_reject_non_bytes(bad):
    with pytest.raises((ValueError, TypeError)):
        keys.journal_keys(bad)  # type: ignore[arg-type]


# --- журнал после request ---
def test_journal_never_contains_keys_in_any_encoding():
    auth, rsk = SigningKey.generate(), PrivateKey.generate()
    states, order = [], []
    r = Rig(Wire(on_send=lambda n: order.append(len(states))))

    async def go():
        t = asyncio.create_task(r.ex.request("post.create", "ephemeral", auth, body={"x": 1},
                                             journal=states.append, resp_sk=rsk))
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={"n": 1}), 101)
        return await t
    assert asyncio.run(go()) == {"n": 1}
    assert order == [1]  # запись в журнал — до первой отправки
    dump = json.dumps(states[0], default=lambda o: o.hex() if isinstance(o, bytes) else str(o))
    for secret in (bytes(auth), bytes(rsk)):
        std, url = base64.b64encode(secret).decode(), base64.urlsafe_b64encode(secret).decode()
        forms = {secret.hex(), secret.hex().upper(), std, url, std.rstrip("="), url.rstrip("="),
                 repr(secret), str(list(secret))}
        assert not any(f in dump for f in forms)


def test_journal_called_exactly_once_per_request(fast):
    states = []
    r = Rig()

    async def go():
        t = req(r, journal=states.append)
        await r.sent(1)
        r.feed(r.sealed(r.env(), error={"code": "E_PENDING", "retry_after": 0}), 101)
        await r.sent(2)
        r.feed(r.sealed(r.env(), result={}), 102)
        return await t
    asyncio.run(go())
    assert len(states) == 1


def test_resume_legacy_row_with_one_key_only():
    """Старая строка с одним из двух полей: недостающий ключ берётся из параметра, имеющийся — из строки."""
    r = Rig()
    old_auth, old_rsk = SigningKey.generate(), PrivateKey.generate()
    new_auth, new_rsk = SigningKey.generate(), PrivateKey.generate()
    base = {"op": "post.create", "auth_mode": "ephemeral", "id": envelope.new_ulid(), "body": {}}

    async def go(state, **kw):
        n = len(r.wire.sent)
        t = asyncio.create_task(r.ex.resume(state, **kw))
        await r.sent(n + 1)
        r.feed(r.sealed(r.env(), result={"n": 1}), 100 + n + 1)
        await t
        return r.env()
    env = asyncio.run(go(dict(base, auth_seed=b64.enc(bytes(old_auth))), resp_sk=new_rsk))
    assert env["auth"]["pk"] == b64.enc(bytes(old_auth.verify_key))
    assert env["resp_pk"] == b64.enc(bytes(new_rsk.public_key))
    env = asyncio.run(go(dict(base, resp_sk=b64.enc(bytes(old_rsk))), auth_key=new_auth))
    assert env["auth"]["pk"] == b64.enc(bytes(new_auth.verify_key))
    assert env["resp_pk"] == b64.enc(bytes(old_rsk.public_key))


# --- core: ключи анонимного поста и поста с личностью ---
def _identity_env(tmp_path):
    e = Env(tmp_path, identity=True)
    asyncio.run(e.core.sync_device())
    e.server.registered[e.store.load_device().dev_pk]["nick"] = "Роза"
    asyncio.run(e.core.sync_device(force=True))
    seen = {}
    orig = e.server.request

    async def spy(op, auth_mode, auth_key, **kw):
        if op == "post.create":
            seen["auth"], seen["resp"], seen["mode"] = auth_key, kw.get("resp_sk"), auth_mode
        return await orig(op, auth_mode, auth_key, **kw)
    e.server.request = spy
    resumed = {}

    async def resume(state, auth_key=None, resp_sk=None):
        resumed.update(state=state, auth=auth_key, resp=resp_sk)
        return {"n": 7, "url": "u"}
    e.server.resume = resume
    return e, seen, resumed


@pytest.mark.parametrize("anonymous", [True, False])
def test_create_and_resume_use_matching_keys(tmp_path, anonymous):
    e, seen, resumed = _identity_env(tmp_path)
    e.server.fail("post.create", "E_PENDING", accepted=True)
    d = api.Draft(111, [{"message_id": 1, "chat": {"id": 111}, "text": "пост"}], anonymous=anonymous)
    with pytest.raises(api.PostQueuedError):
        asyncio.run(e.core.create_post(d))
    [(_, secret, _, _, _)] = e.store.pending_posts()
    jk_auth, jk_resp = keys.journal_keys(secret)
    dev = e.store.load_device().dev_sk
    expect_auth = jk_auth if anonymous else dev
    assert bytes(seen["auth"]) == bytes(expect_auth) and bytes(seen["resp"]) == bytes(jk_resp)
    assert seen["mode"] == ("ephemeral" if anonymous else "identity")
    assert asyncio.run(e.core.resume_pending()) == [("published", {"n": 7, "url": "u"})]
    assert bytes(resumed["auth"]) == bytes(expect_auth) and bytes(resumed["resp"]) == bytes(jk_resp)
    assert "resp_sk" not in resumed["state"] and "auth_seed" not in resumed["state"]


def test_create_post_retries_e_device_once_when_not_accepted(tmp_path):
    e = Env(tmp_path, identity=True)
    asyncio.run(e.core.sync_device())
    e.server.registered[e.store.load_device().dev_pk]["nick"] = "Роза"
    asyncio.run(e.core.sync_device(force=True))
    e.server.fail("post.create", "E_DEVICE")
    d = api.Draft(111, [{"message_id": 1, "chat": {"id": 111}, "text": "пост"}])
    asyncio.run(e.core.create_post(d))
    assert sum(op == "post.create" for op, _ in e.server.ops) == 2


# --- is_inbox / отправитель ---
@pytest.mark.parametrize("ids", [None, ["x"], [[1]], {"a": 1}, [float("nan")], "abc", 5])
def test_is_inbox_tolerates_garbage_id_list(ids):
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: ids)
    for sender in ({"is_bot": True, "id": 5}, {"is_bot": True, "username": "inbox"}, {}, {"id": None}):
        assert isinstance(ex.is_inbox(sender), bool)


def test_is_inbox_sender_without_id_is_not_matched_by_none_in_list():
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: [None])
    assert ex.is_inbox({"is_bot": True, "username": "inbox"}) is False


def test_is_inbox_unexpected_exception_is_untrusted():
    def boom():
        raise RuntimeError("x")
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), boom)
    assert ex.is_inbox({"is_bot": True, "username": "inbox", "id": 5}) is False


@pytest.mark.parametrize("sid", ["42", None, 0, -42, 2 ** 70, [42]])
def test_is_inbox_by_id_is_strict(sid):
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: [1, 42])
    assert ex.is_inbox({"is_bot": True, "id": sid, "username": "inbox"}) is False


@pytest.mark.parametrize("sid", [True, 42.0])
def test_is_inbox_by_id_is_not_loose_on_types(sid):
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: [1, 42])
    assert ex.is_inbox({"is_bot": True, "id": sid}) is False


def test_is_inbox_by_id_accepts_listed_and_requires_bot_flag():
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: [1, 42])
    assert ex.is_inbox({"is_bot": True, "id": 42}) and ex.is_inbox({"is_bot": True, "id": 1})
    for s in ({"id": 42}, {"is_bot": False, "id": 42}):
        assert not ex.is_inbox(s)


@pytest.mark.parametrize("flag", ["yes", 1, [True]])
def test_is_inbox_requires_boolean_bot_flag(flag):
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: [1, 42])
    assert not ex.is_inbox({"is_bot": flag, "id": 42})


@pytest.mark.parametrize("name", ["inbox ", " inbox", "inbox​", "іnbox", "ınbox", "INBOX\n", "inbox@", "@inbox",
                                  "", None, 7])
def test_is_inbox_by_username_exact(name):
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)))
    assert not ex.is_inbox({"is_bot": True, "username": name})


def test_is_inbox_username_is_ascii_only():
    """Имена ботов в Telegram — латиница; знак Кельвина при понижении регистра не должен подменять «k»."""
    ex = Exchange(None, "@kbot", bytes(32), lambda: ("i1", bytes(32)))
    assert not ex.is_inbox({"is_bot": True, "username": "Kbot"})


class _Boom(dict):
    def get(self, *a, **k):
        raise RuntimeError("boom")


def test_on_inbox_message_swallows_internal_failures(monkeypatch):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.ex.on_inbox_message(_Boom())  # type: ignore[arg-type]
        r.ex.on_inbox_message({"from": _Boom(), "text": "x", "reply_to_message": {"message_id": 101}})
        good = r.sealed(r.env(), result={"n": 9})

        def broken(*a, **k):
            raise RuntimeError("internal")
        monkeypatch.setattr(envelope, "open_response", broken)
        r.feed(good, 101)
        r.feed("VEIL1R 1/2 aaaa", 101)
        r.feed("VEIL1R 2/2 aaaa", 101)
        monkeypatch.undo()
        await REAL_SLEEP(0.01)
        r.feed(good, 101)
        return await asyncio.wait_for(t, 2)
    assert asyncio.run(go()) == {"n": 9}


def test_stranger_hint_and_parts_are_ignored():
    r = Rig(ids=[42])

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        for stranger in ({"is_bot": True, "id": 7}, {"is_bot": True, "username": "inbox"}, {}):
            r.feed("VEIL1E E_RATE", 101, stranger)
            r.feed(r.sealed(env, error={"code": "E_INTERNAL"}), 101, stranger)
        await REAL_SLEEP(0.01)
        assert not t.done()
        r.feed(r.sealed(env, result={"ok": 1}), 101, {"is_bot": True, "id": 42})
        return await t
    assert asyncio.run(go()) == {"ok": 1}


def test_message_for_other_envelope_is_ignored():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        for mid in (0, 100, 102, 10 ** 9, -1):
            r.feed(r.sealed(env, result={"bad": 1}), mid)
        r.ex.on_inbox_message({"from": FROM, "text": r.sealed(env, result={"bad": 1})})
        await REAL_SLEEP(0.01)
        assert not t.done()
        r.feed(r.sealed(env, result={"ok": 1}), 101)
        return await t
    assert asyncio.run(go()) == {"ok": 1}


def test_concurrent_requests_get_own_answers_out_of_order():
    r = Rig()

    async def go():
        t1 = req(r)
        await r.sent(1)
        t2 = req(r)
        await r.sent(2)
        e1, e2 = r.env(0), r.env(1)
        r.feed(r.sealed(e2, result={"who": 2}), 102)
        r.feed(r.sealed(e1, result={"who": 1}), 101)
        return await t1, await t2
    assert asyncio.run(go()) == ({"who": 1}, {"who": 2})


def test_pending_registry_is_cleaned(fast):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={}), 101)
        await t
        assert not r.ex._pending
        r.feed(r.sealed(r.env(), result={"late": 1}), 101)  # поздний дубль не бросает
        with pytest.raises(NoReplyError):
            await req(r)
        assert not r.ex._pending
        t = req(r)
        await r.sent(len(r.wire.sent) + 1)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        assert not r.ex._pending
    asyncio.run(go())


def test_cancel_after_pending_is_not_turned_into_accepted(fast, monkeypatch):
    monkeypatch.setattr(exmod, "WAIT", 30.0)
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), error={"code": "E_PENDING", "retry_after": 0}), 101)
        await r.sent(2)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        assert not r.ex._pending
    asyncio.run(go())


# --- ответы: подпись, ключ, группы ---
def test_response_from_wrong_signer_or_key_is_ignored():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        r.feed(r.sealed(env, result={"evil": 1}, signer=SigningKey.generate()), 101)
        other = envelope.build_response(env["id"], r.server, result={"evil": 2})
        r.feed(envelope.seal_response(other, bytes(PrivateKey.generate().public_key)), 101)
        await REAL_SLEEP(0.01)
        assert not t.done()
        r.feed(r.sealed(env, result={"ok": 1}), 101)
        return await t
    assert asyncio.run(go()) == {"ok": 1}


def test_signed_response_for_other_id_ends_single_request_with_signed_error():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={}, re="not-this-id"), 101)
        return await asyncio.wait_for(t, 2)
    with pytest.raises(exmod.ProtocolError) as ei:
        asyncio.run(go())
    assert ei.value.signed


def test_junk_group_then_real_group_with_same_n():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        big = envelope.build_response(env["id"], r.server, result={"posts": ["я" * 100] * 50})
        parts = envelope.split_response(envelope.seal_response(big, b64.dec(env["resp_pk"])))
        n = len(parts)
        for i in range(1, n + 1):
            r.feed(f"VEIL1R {i}/{n} {'A' * 40}", 101)
        await REAL_SLEEP(0.01)
        assert not t.done()
        for p in parts:
            r.feed(p, 101)
        return await t
    assert len(asyncio.run(go())["posts"]) == 50


def test_real_group_split_in_parts_then_duplicates_and_late_hint():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        big = envelope.build_response(env["id"], r.server, result={"posts": ["я" * 100] * 50})
        parts = envelope.split_response(envelope.seal_response(big, b64.dec(env["resp_pk"])))
        for p in parts + parts:
            r.feed(p, 101)
        r.feed("VEIL1E E_RATE", 101)
        return await t
    assert len(asyncio.run(go())["posts"]) == 50


@pytest.mark.parametrize("hint", ["VEIL1E E_RATЕ", "VEIL1E E_ＲＡＴＥ", "VEIL1E e_rate", "veil1e E_RATE",
                                  "VEIL1E\tE_RATE", "VEIL1E E_RATE​", " VEIL1E E_RATE"])
def test_hint_lookalikes_are_ignored(hint):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(hint, 101)
        await REAL_SLEEP(0.01)
        assert not t.done()
        r.feed(r.sealed(r.env(), result={"n": 1}), 101)
        return await t
    assert asyncio.run(go()) == {"n": 1}


# --- PartBuffer ---
def _part(n, i, chunk):
    return f"VEIL1R {i}/{n} {chunk}"


def _is_part(n, i):
    return 1 <= i <= n <= 16


@given(st.integers(1, 16).flatmap(lambda n: st.tuples(
    st.lists(st.text(B64URL, min_size=1, max_size=12), min_size=n, max_size=n),
    st.permutations(list(range(1, n + 1))))))
@PROP
def test_part_buffer_any_order_assembles_once_complete(case):
    chunks, order = case
    n, buf, outs = len(chunks), PartBuffer(), []
    for i in order:
        outs.append(buf.add(_part(n, i, chunks[i - 1])))
    assert outs[:-1] == [None] * (n - 1) and outs[-1] == "VEIL1R " + "".join(chunks)
    assert len(buf) == n


@given(st.lists(st.one_of(
    st.tuples(st.integers(0, 18), st.integers(0, 18), st.text("abXY_-", min_size=1, max_size=3)),
    st.sampled_from([(-1, 0, "x"), (1, 1, "")])), max_size=60))
@PROP
def test_part_buffer_matches_reference_model(events):
    buf, model = PartBuffer(), {}
    for n, i, chunk in events:
        text = _part(n, i, chunk)
        got = buf.add(text)
        if not _is_part(n, i) or not chunk:
            assert got is None
        else:
            model[(n, i)] = chunk
            full = all((n, k) in model for k in range(1, n + 1))
            expect = "VEIL1R " + "".join(model[(n, k)] for k in range(1, n + 1)) if full else None
            assert got == expect
        assert len(buf) == len(model) <= 136


@pytest.mark.parametrize("text", ["VEIL1R ١/٢ x", "VEIL1R １/２ x", "VEIL1R 1/2 x\n", "VEIL1R 1/2 x\ny", "VEIL1R 1/2 я",
                                  "VEIL1R 1/2 x​", " VEIL1R 1/2 x", "veil1r 1/2 x", "VEIL1R  1/2 x", "VEIL1R 1 /2 x",
                                  "VEIL1R 1/ 2 x", "VEIL1R 1/2\tx", "VEIL1R 1/2  x", "VEIL1R 17/16 x", "VEIL1R 16/17 x",
                                  "VEIL1R 1/17 x", "VEIL1R 0/1 x", "VEIL1R 1/0 x", "VEIL1R 10/9 x", "VEIL1R 1/002 x",
                                  "VEIL1R 1/99999999999999999999999 x", "VEIL1R 1.0/2 x", "VEIL1R 0x1/2 x",
                                  "VEIL1R 1_0/16 x"])
def test_part_buffer_rejects_lookalike_parts(text):
    buf = PartBuffer()
    assert buf.add(text) is None and len(buf) == 0


@pytest.mark.parametrize("n,i", [(1, 1), (16, 16), (16, 1), (2, 2)])
def test_part_buffer_accepts_boundaries(n, i):
    buf = PartBuffer()
    buf.add(_part(n, i, "z"))
    assert len(buf) == 1


def test_part_buffer_single_part_group():
    assert PartBuffer().add("VEIL1R 1/1 abc") == "VEIL1R abc"


@given(st.lists(st.text(max_size=30), max_size=40))
@PROP
def test_part_buffer_never_raises_on_arbitrary_text(texts):
    buf = PartBuffer()
    for t in texts:
        buf.add(t)
    assert len(buf) <= 136


def test_part_buffer_flood_is_bounded():
    buf = PartBuffer()
    for rnd in range(3):
        for n in range(0, 40):
            for i in range(0, 40):
                buf.add(_part(n, i, f"{rnd}"))
    assert len(buf) == 136


# --- E_PENDING / срок ---
def _pending(r: Rig, retry_after=0):
    r.feed(r.sealed(r.env(), error={"code": "E_PENDING", "retry_after": retry_after}), 100 + len(r.wire.sent))


def test_late_answer_to_first_envelope_after_resend_is_accepted(fast):
    """spec/09: пока первая копия выполняется, повтор остаётся без ответа — ответ приходит на первый конверт."""
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env0 = r.env()
        await r.sent(2)  # ответа за срок ожидания нет — тот же конверт отправлен повторно
        r.feed(r.sealed(env0, result={"n": 5}), 101)
        return await asyncio.wait_for(t, 2)
    assert asyncio.run(go()) == {"n": 5}


@pytest.mark.parametrize("retries", [0, 1, 3])
def test_pending_retries_count_exact(fast, monkeypatch, retries):
    monkeypatch.setattr(exmod, "PENDING_RETRIES", retries)
    r = Rig()

    async def go():
        t = req(r)
        for k in range(retries + 1):
            await r.sent(k + 1)
            _pending(r)
        return await asyncio.wait_for(t, 2)
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.code == "E_PENDING" and ei.value.accepted
    assert len(r.wire.sent) == retries + 1
    assert len({r.env(k)["id"] for k in range(len(r.wire.sent))}) == 1


@pytest.mark.parametrize("retry_after", [10 ** 6, 0])
def test_pending_with_extreme_retry_after_ends_as_accepted(monkeypatch, retry_after):
    monkeypatch.setattr(exmod, "WAIT", 0.05)
    monkeypatch.setattr(exmod, "DEADLINE", 0.5)
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        _pending(r, retry_after)
        return await asyncio.wait_for(t, 5)
    t0 = time.monotonic()
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.accepted and ei.value.code == "E_PENDING" and time.monotonic() - t0 < 4


def test_deadline_cuts_wait_after_pending(monkeypatch):
    monkeypatch.setattr(exmod, "WAIT", 30.0)
    monkeypatch.setattr(exmod, "DEADLINE", 0.3)
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        _pending(r, 0)
        return await asyncio.wait_for(t, 5)
    t0 = time.monotonic()
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.accepted and time.monotonic() - t0 < 4
    assert len(r.wire.sent) <= 2


def test_deadline_is_one_for_all_waits(monkeypatch):
    """Ожидания по 0,2 с при сроке 0,3 с укладываются в срок, а не в сумму ожиданий (6 повторов × 0,2 с)."""
    monkeypatch.setattr(exmod, "WAIT", 0.2)
    monkeypatch.setattr(exmod, "DEADLINE", 0.3)
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        _pending(r, 0)
        return await asyncio.wait_for(t, 5)
    t0 = time.monotonic()
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.accepted and time.monotonic() - t0 < 0.6


def test_telegram_error_on_first_send_without_pending_is_not_accepted(fast):
    r = Rig(Wire(boom={1}))
    with pytest.raises(TelegramError):
        asyncio.run(req_wait(r))


async def req_wait(r: Rig):
    return await req(r)


def test_pending_then_result_returns_result(fast):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        _pending(r)
        await r.sent(2)
        r.feed(r.sealed(r.env(), result={"n": 3}), 102)
        return await t
    assert asyncio.run(go()) == {"n": 3}


@pytest.mark.parametrize("after", ["timeout", "tg", "hint", "signed_bad", "err"])
def test_nothing_but_result_or_accepted_after_pending(fast, after):
    r = Rig(Wire(boom={2} if after == "tg" else ()))

    async def go():
        t = req(r)
        await r.sent(1)
        _pending(r)
        if after == "hint":
            await r.sent(2)
            r.feed("VEIL1E E_RATE", 102)
        elif after == "signed_bad":
            await r.sent(2)
            r.feed(r.sealed(r.env(), result={}, re="zzz"), 102)
        elif after == "err":
            await r.sent(2)
            r.feed(r.sealed(r.env(), error={"code": "E_TOKEN_DAY"}), 102)
        return await asyncio.wait_for(t, 5)
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.accepted


# --- refresh_keys ---
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

        async def ensure_known(self):
            pass
    return api.Core(bot=None, store=Store(tmp_path), exchange=Ex(), keys_doc=old, owner_id=1)


@pytest.mark.parametrize("bad", [[0], "x", [True], [1, -2], [None], {"a": 1}, 5, [1, 1]])
def test_refresh_keys_corrupt_inbox_bots_never_saved_even_first_time(tmp_path, bad):
    sk = SigningKey.generate()
    old = _signed_doc(sk)
    core = _refresh_core(tmp_path, old, _signed_doc(sk, inbox_bots=bad), sk)
    try:
        asyncio.run(core.refresh_keys())
    except keysdoc.KeysError:
        pass
    # если испорченный список всё же принят, он обязан читаться без исключений
    keysdoc.inbox_bots(core.keys_doc)
    stored = core.store.get("keys_doc")
    assert stored is None or keysdoc.inbox_bots(stored) is not None


def test_refresh_keys_allows_shrinking_but_not_emptying(tmp_path):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[5, 6])
    new = _signed_doc(sk, inbox_bots=[6])
    core = _refresh_core(tmp_path, old, new, sk)
    assert asyncio.run(core.refresh_keys()) == new
    (tmp_path / "x").mkdir()
    core = _refresh_core(tmp_path / "x", new, _signed_doc(sk), sk)
    with pytest.raises(keysdoc.KeysError):
        asyncio.run(core.refresh_keys())
    assert core.keys_doc is new


def test_refresh_keys_signature_by_other_key_rejected(tmp_path):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[5])
    forged = _signed_doc(SigningKey.generate(), inbox_bots=[5, 9])

    class Ex:
        server_sig_pk = bytes(sk.verify_key)

        async def request(self, *a, **kw):
            return forged
    core = api.Core(bot=None, store=Store(tmp_path), exchange=Ex(), keys_doc=old, owner_id=1)
    with pytest.raises(Exception):
        asyncio.run(core.refresh_keys())
    assert core.keys_doc is old and core.store.get("keys_doc") is None


# --- поля ошибок и мелкие значения по умолчанию ---
def test_server_error_defaults_and_no_reply_text():
    e = ServerError("E_X")
    assert (e.code, e.overflow, e.retry_after, e.hint, e.accepted) == ("E_X", 0, 0, False, False)
    assert str(e) == "E_X"
    e = ServerError("E_Y", 3, 7, True, True)
    assert (e.code, e.overflow, e.retry_after, e.hint, e.accepted) == ("E_Y", 3, 7, True, True)
    assert str(NoReplyError("post.create")) == "post.create"


@pytest.mark.parametrize("code,desc,expect", [
    (403, "Forbidden: bot was blocked by the user", True), (403, "", True),
    (400, "Bad Request: chat not found", True), (400, "Bad Request: CHAT NOT FOUND", True),
    (400, "Bad Request: message is too long", False), (400, "", False),
    (404, "chat not found", False), (500, "chat not found", False), (429, "Too Many Requests", False),
    (0, "", False)])
def test_unreachable_classification(code, desc, expect):
    assert exmod.unreachable(TelegramError("sendMessage", code, desc)) is expect


@pytest.mark.parametrize("code,fields", [
    ({"code": "E_TOKEN_DAY", "overflow": 3, "retry_after": 7}, (3, 7)), ({"code": "E_TOKEN_DAY"}, (0, 0))])
def test_server_error_carries_response_fields(code, fields):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), error=code), 101)
        return await t
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    e = ei.value
    assert (e.code, e.overflow, e.retry_after, e.hint, e.accepted) == ("E_TOKEN_DAY", *fields, False, False)


@pytest.mark.parametrize("ra,expect", [(7, 7), (1, 1), (1000, 60), (60, 60), (None, 5)])
def test_pending_pause_follows_retry_after_within_bounds(monkeypatch, ra, expect):
    sleeps = []

    async def rec(s):
        sleeps.append(s)
        await REAL_SLEEP(0)
    monkeypatch.setattr(exmod.asyncio, "sleep", rec)
    monkeypatch.setattr(exmod, "WAIT", 0.05)
    r = Rig()
    err = {"code": "E_PENDING"} if ra is None else {"code": "E_PENDING", "retry_after": ra}

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), error=err), 101)
        await r.sent(2)
        r.feed(r.sealed(r.env(), result={"ok": 1}), 102)
        return await t
    assert asyncio.run(go()) == {"ok": 1}
    assert sleeps and sleeps[0] == expect


# --- форма отправки, повтор и журнал ---
def test_resend_keeps_envelope_and_refreshes_ts(fast, monkeypatch):
    now = int(time.time())
    clock = iter(range(now, now + 100))
    monkeypatch.setattr(envelope, "now_ts", lambda: next(clock))
    r = Rig()
    tok, content = {"kid": "t1", "day": "2026-10-24", "n": "x"}, {"kind": "text", "n": 1}

    async def go():
        t = asyncio.create_task(r.ex.request("post.create", "ephemeral", SigningKey.generate(), body={"b": [1, 2]},
                                             token=tok, content=content))
        await r.sent(1)
        r.feed(r.sealed(r.env(), error={"code": "E_PENDING", "retry_after": 1}), 101)
        await r.sent(2)
        r.feed(r.sealed(r.env(), result={}), 102)
        return await t
    asyncio.run(go())
    a, b = r.env(0), r.env(1)
    for k in ("id", "op", "kid", "resp_pk", "auth", "token", "body", "content"):
        assert a[k] == b[k], k
    assert a["token"] == tok and a["content"] == content and a["body"] == {"b": [1, 2]}
    assert b["ts"] > a["ts"] and a["sig"] != b["sig"]


@pytest.mark.parametrize("ret,content_in,reply,content_out", [
    (777, {"k": 2}, 777, {"k": 2}), ((777, {"c": 1}), {"k": 2}, 777, {"c": 1}), ((777, {"c": 1}), None, 777, {"c": 1}),
    (777, None, 777, None)])
def test_deliver_result_sets_reply_and_content_for_every_send(fast, ret, content_in, reply, content_out):
    r, states = Rig(ids=[10, 20]), []

    async def deliver():
        return ret

    async def go():
        t = asyncio.create_task(r.ex.request("post.create", "ephemeral", SigningKey.generate(), body={},
                                             deliver=deliver, content=content_in, journal=states.append))
        await r.sent(1)
        r.feed(r.sealed(r.env(), error={"code": "E_PENDING", "retry_after": 1}), 101)
        await r.sent(2)
        r.feed(r.sealed(r.env(), result={}), 102)
        return await t
    asyncio.run(go())
    assert r.wire.calls == [(10, reply), (10, reply)]
    assert r.env(0).get("content") == content_out == r.env(1).get("content")
    assert states[0]["reply_to"] == reply and states[0]["content"] == content_out and states[0]["inbox"] == 10


def test_no_deliver_means_no_reply_target_and_username_chat_is_not_journaled():
    r, states = Rig(), []

    async def go():
        t = req(r, journal=states.append)
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={}), 101)
        return await t
    asyncio.run(go())
    assert r.wire.calls == [("@inbox", None)]
    assert states[0]["reply_to"] is None and states[0]["inbox"] is None


def test_big_envelope_goes_as_document_with_reply_parameters():
    r = Rig(ids=[10])

    async def deliver():
        return 777

    async def go():
        t = asyncio.create_task(r.ex.request("post.create", "ephemeral", SigningKey.generate(),
                                             body={"b": "я" * 2000}, deliver=deliver))
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={"ok": 1}), 101)
        return await t
    assert asyncio.run(go()) == {"ok": 1}
    [(method, field, filename, mime, params)] = r.wire.uploads
    assert (method, field, filename, mime) == ("sendDocument", "document", "veil.txt", "text/plain")
    assert params["chat_id"] == 10 and params["caption"] == envelope.DOC_CAPTION
    assert params["reply_parameters"] == {"message_id": 777, "allow_sending_without_reply": True}
    assert r.env()["body"] == {"b": "я" * 2000}


def test_big_envelope_without_reply_target_has_no_reply_parameters():
    r = Rig()

    async def go():
        t = asyncio.create_task(r.ex.request("post.create", "ephemeral", SigningKey.generate(), body={"b": "я" * 2000}))
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={}), 101)
        await t
    asyncio.run(go())
    assert r.wire.uploads[0][4].get("reply_parameters") is None


# --- несколько приёмных ботов ---
def test_switch_from_and_inbox_for(caplog):
    ids = [1, 2, 3]
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: ids)
    assert ex.inbox == 1 and ex.inbox_for(None) == 1 and ex.inbox_for(3) == 3 and ex.inbox_for(99) == 1
    with caplog.at_level("WARNING", logger="veil.exchange"):
        assert ex.switch_from(1) is True and ex.inbox == 2
        assert ex.switch_from(2) and ex.inbox == 3 and ex.switch_from(3) and ex.inbox == 1  # по кругу
    assert "inbox bot 1 does not accept messages, switching to 2" in caplog.messages
    assert ex.switch_from(99) is False and ex.inbox == 1
    solo = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: [5])
    assert solo.switch_from(5) is False and solo.inbox == 5
    none = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)))
    assert none.switch_from(1) is False and none.inbox == "@inbox"
    stale = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: ids)
    stale.switch_from(2)
    ids[:] = [7, 8]  # список обновился по keys.get: прежний выбор недействителен
    assert stale.inbox == 7


def test_unreachable_inbox_switches_through_all_ids_once():
    r = Rig(Wire(dead={10, 20}), ids=[10, 20, 30])

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={"ok": 1}), 101)
        return await t
    assert asyncio.run(go()) == {"ok": 1}
    assert [c for c, _ in r.wire.calls] == [10, 20, 30] and r.ex.inbox == 30


def test_all_inbox_bots_unreachable_stops_after_one_round():
    r = Rig(Wire(dead={10, 20, 30}), ids=[10, 20, 30])
    with pytest.raises(TelegramError):
        asyncio.run(req_wait(r))
    assert [c for c, _ in r.wire.calls] == [10, 20, 30]


def test_chat_not_found_switches_but_other_400_and_500_do_not():
    r = Rig(Wire(dead={10}, dead_code=400, dead_text="Bad Request: chat not found"), ids=[10, 20])

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={}), 101)
        await t
    asyncio.run(go())
    assert [c for c, _ in r.wire.calls] == [10, 20]
    for code, text in ((400, "Bad Request: message is too long"), (500, "Internal")):
        r = Rig(Wire(dead={10}, dead_code=code, dead_text=text), ids=[10, 20])
        with pytest.raises(TelegramError):
            asyncio.run(req_wait(r))
        assert [c for c, _ in r.wire.calls] == [10]


def test_no_switch_when_content_was_delivered_or_target_fixed():
    async def deliver():
        return 5
    r = Rig(Wire(dead={10}), ids=[10, 20])
    with pytest.raises(TelegramError):
        asyncio.run(r.ex.request("post.create", "ephemeral", SigningKey.generate(), body={}, deliver=deliver))
    assert [c for c, _ in r.wire.calls] == [10]
    r = Rig(Wire(dead={20}), ids=[10, 20])
    with pytest.raises(TelegramError):
        asyncio.run(r.ex.request("post.create", "ephemeral", SigningKey.generate(), body={}, to=20))
    assert [c for c, _ in r.wire.calls] == [20]


def test_switch_does_not_use_up_a_wait_attempt(fast):
    r = Rig(Wire(dead={10}), ids=[10, 20])
    with pytest.raises(NoReplyError):
        asyncio.run(req_wait(r))
    assert [c for c, _ in r.wire.calls] == [10, 20, 20]


# --- адрес по имени и журнал предупреждений ---
def test_username_comparison_edges(caplog):
    ex = Exchange(None, "@Xbot", bytes(32), lambda: ("i1", bytes(32)))
    assert ex.is_inbox({"is_bot": True, "username": "xbot"}) and ex.is_inbox({"is_bot": True, "username": "XBOT"})
    ex = Exchange(None, "@xxxx", bytes(32), lambda: ("i1", bytes(32)))
    assert not ex.is_inbox({"is_bot": True}) and not ex.is_inbox({"is_bot": True, "username": None})
    assert ex.is_inbox({"is_bot": True, "username": "xxxx"})
    bad = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: 1 / 0)
    with caplog.at_level("WARNING", logger="veil.exchange"):
        assert bad.is_inbox({"is_bot": True, "id": 1}) is False
    assert "inbox bot ids unreadable (ZeroDivisionError), sender rejected" in caplog.messages


def test_swallowed_failure_is_logged_with_type(caplog):
    r = Rig()
    with caplog.at_level("WARNING", logger="veil.exchange"):
        r.ex.on_inbox_message(_Boom())  # type: ignore[arg-type]
    assert "inbox message ignored: RuntimeError" in caplog.messages


def test_username_warning_text(caplog):
    exmod._warned_username = False
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)))
    with caplog.at_level("WARNING", logger="veil.exchange"):
        ex.is_inbox({"is_bot": True, "username": "inbox"})
    assert [m for m in caplog.messages if "not published" in m] == ["inbox bots not published, using @username"]


# --- resume: содержимое строки журнала и ошибки ---
def test_resume_resends_content_and_reply_target_from_row():
    r = Rig(ids=[10, 20])
    state = {"op": "post.create", "auth_mode": "ephemeral", "id": envelope.new_ulid(), "body": {"b": 1},
             "token": {"kid": "t1", "n": "x"}, "content": {"c": 1}, "reply_to": 55, "inbox": 20}

    async def go():
        t = asyncio.create_task(r.ex.resume(state, SigningKey.generate(), PrivateKey.generate()))
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={"n": 1}), 101)
        return await t
    assert asyncio.run(go()) == {"n": 1}
    env = r.env()
    assert env["content"] == {"c": 1} and env["token"] == {"kid": "t1", "n": "x"} and env["body"] == {"b": 1}
    assert env["id"] == state["id"]
    assert r.wire.calls == [(20, 55)]


def test_resume_without_keys_says_which_is_missing():
    r = Rig()
    state = {"op": "post.create", "auth_mode": "ephemeral", "id": envelope.new_ulid()}
    with pytest.raises(ValueError, match="^resp key required$"):
        asyncio.run(r.ex.resume(state, SigningKey.generate()))
    with pytest.raises(ValueError, match="^auth key required$"):
        asyncio.run(r.ex.resume(state, None, PrivateKey.generate()))
    assert not r.wire.sent


# --- вложения: документ может прийти чуть позже ответа ---
def _doc(mid=101, fid="D"):
    return {"from": FROM, "document": {"file_id": fid}, "reply_to_message": {"message_id": mid}}


def test_late_attachment_after_ok_response_is_waited_for():
    r = Rig()
    got = []

    async def go():
        t = req(r, attachments=got)
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={"ok": 1}), 101)
        await REAL_SLEEP(0.3)
        assert not t.done()  # ждёт документ
        r.ex.on_inbox_message(_doc())
        return await asyncio.wait_for(t, 3)
    assert asyncio.run(go()) == {"ok": 1}
    assert [m["document"]["file_id"] for m in got] == ["D"]


def test_attachment_wait_is_polled_quickly_and_bounded(monkeypatch):
    """Документ ждут короткими шагами и не дольше нескольких секунд (всего 25 × 0,2 с)."""
    sleeps = []

    async def rec(s):
        sleeps.append(s)
        await REAL_SLEEP(0)
    r = Rig()

    async def go():
        t = req(r, attachments=[])
        await r.sent(1)
        monkeypatch.setattr(exmod.asyncio, "sleep", rec)
        r.feed(r.sealed(r.env(), result={"ok": 1}), 101)
        return await asyncio.wait_for(t, 3)
    assert asyncio.run(go()) == {"ok": 1}
    assert sleeps == [0.2] * 25


def test_late_attachment_is_noticed_within_a_poll_step():
    r = Rig()
    got = []

    async def go():
        t = req(r, attachments=got)
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={"ok": 1}), 101)
        await REAL_SLEEP(0.3)
        r.ex.on_inbox_message(_doc())
        t1 = time.monotonic()
        await asyncio.wait_for(t, 3)
        return time.monotonic() - t1
    assert asyncio.run(go()) < 0.6


def test_response_without_error_code_is_server_error_or_signed_malformed():
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), error={"overflow": 1}), 101)
        return await asyncio.wait_for(t, 2)
    try:
        asyncio.run(go())
    except ServerError as e:
        assert e.code == "E_INTERNAL"
    except exmod.ProtocolError as e:
        assert e.signed


def test_no_attachment_wait_when_not_requested_or_on_error():
    r = Rig()

    async def go():
        t0 = time.monotonic()
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), result={}), 101)
        await t
        t = req(r, attachments=[])
        await r.sent(2)
        r.feed(r.sealed(r.env(), error={"code": "E_RATE"}), 102)
        with pytest.raises(ServerError):
            await t
        got = []
        t = req(r, attachments=got)
        await r.sent(3)
        r.ex.on_inbox_message(_doc(103))
        r.feed(r.sealed(r.env(), result={}), 103)
        await t
        assert got
        return time.monotonic() - t0
    assert asyncio.run(go()) < 1.0


def test_deadline_does_not_overshoot_by_a_floor(monkeypatch):
    """Остаток срока меньше секунды: ожидание не растягивается до секунды."""
    monkeypatch.setattr(exmod, "WAIT", 30.0)
    monkeypatch.setattr(exmod, "DEADLINE", 0.2)
    r = Rig()
    t0 = time.monotonic()
    with pytest.raises(NoReplyError) as ei:
        asyncio.run(req_wait(r))
    assert str(ei.value) == "post.create"
    assert time.monotonic() - t0 < 0.8



# --- ошибка сервера без кода ---
@pytest.mark.parametrize("error", [{"overflow": 1}, {"message": "x"}, {"retry_after": 3}])
def test_error_without_code_is_e_internal_exactly(monkeypatch, error):
    """Ответ ok=false, где у error нет code: клиент поднимает ServerError ровно с E_INTERNAL. Разбор конверта такой
    ответ отвергает сам (E_MALFORMED, spec/04), поэтому разобранный ответ подставляем: это защитная ветка обмена."""
    r = Rig()
    monkeypatch.setattr(exmod.envelope, "open_response",
                        lambda text, sk, pk, env_id: {"v": 1, "re": env_id, "ok": False, "error": dict(error)})

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed("VEIL1R junk", 101)
        r.feed(r.sealed(r.env(), result={}), 101)
        return await asyncio.wait_for(t, 2)
    with pytest.raises(ServerError) as ei:
        asyncio.run(go())
    assert ei.value.code == "E_INTERNAL" and type(ei.value.code) is str


# --- E_PENDING, затем многочастный итог (spec/04, VEIL1R) ---
def _split(r: Rig, env: dict, ch: str):
    big = envelope.build_response(env["id"], r.server, result={"posts": [ch * 100] * 50})
    return envelope.split_response(envelope.seal_response(big, b64.dec(env["resp_pk"])))


def test_pending_then_multipart_result_is_assembled(fast):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        _pending(r)
        await r.sent(2)
        parts = _split(r, r.env(), "я")
        assert len(parts) > 1
        for p in parts:
            r.feed(p, 102)
        return await asyncio.wait_for(t, 3)
    assert asyncio.run(go())["posts"] == ["я" * 100] * 50


def test_part_before_pending_is_not_mixed_with_parts_of_result(fast):
    """Часть группы, пришедшая до E_PENDING, не склеивается с частями итога той же длины."""
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        old = _split(r, env, "ю")
        new = _split(r, env, "я")
        assert len(old) == len(new) > 1
        r.feed(old[0], 101)
        _pending(r)
        await r.sent(2)
        for p in new:
            r.feed(p, 102)
        return await asyncio.wait_for(t, 3)
    assert asyncio.run(go())["posts"] == ["я" * 100] * 50


# --- resume и request не переключают приёмного бота, когда адрес закреплён ---
def _row(**kw):
    return {"op": "post.create", "auth_mode": "ephemeral", "id": envelope.new_ulid(), "body": {}, **kw}


@pytest.mark.parametrize("extra", [{"inbox": 10}, {"inbox": 10, "content": {"c": 1}, "reply_to": 5},
                                   {"inbox": 10, "reply_to": 5}])
def test_resume_does_not_switch_inbox_bot(extra):
    r = Rig(Wire(dead={10}), ids=[10, 20])
    with pytest.raises(TelegramError):
        asyncio.run(r.ex.resume(_row(**extra), SigningKey.generate(), PrivateKey.generate()))
    assert [c for c, _ in r.wire.calls] == [10]
    assert not r.wire.sent and r.ex.inbox == 10


def test_resume_dead_bot_never_sends_envelope_to_other_bot():
    r = Rig(Wire(dead={20}), ids=[10, 20])
    with pytest.raises(TelegramError):
        asyncio.run(r.ex.resume(_row(inbox=20), SigningKey.generate(), PrivateKey.generate()))
    assert 10 not in [c for c, _ in r.wire.calls]


def test_request_with_deliver_or_to_does_not_switch_and_keeps_inbox():
    async def deliver():
        return 5
    for kw, dead in (({"deliver": deliver}, 10), ({"to": 10}, 10)):
        r = Rig(Wire(dead={dead}), ids=[10, 20])
        with pytest.raises(TelegramError):
            asyncio.run(r.ex.request("post.create", "ephemeral", SigningKey.generate(), body={}, **kw))
        assert [c for c, _ in r.wire.calls] == [10] and not r.wire.sent and r.ex.inbox == 10


# --- сообщение приёмного бота без текста не завершает ожидание ---
@pytest.mark.parametrize("text", [None, 5, {}, [], {"a": 1}, 1.5, True, b"VEIL1E E_RATE"])
def test_inbox_message_with_non_string_text_is_ignored(text):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.ex.on_inbox_message({"from": FROM, "text": text, "reply_to_message": {"message_id": 101}})
        r.ex.on_inbox_message({"from": FROM, "document": {"file_id": "D"}, "reply_to_message": {"message_id": 101}})
        r.ex.on_inbox_message({"from": FROM, "reply_to_message": {"message_id": 101}})
        await REAL_SLEEP(0.05)
        assert not t.done()
        r.feed(r.sealed(r.env(), result={"n": 7}), 101)
        return await asyncio.wait_for(t, 2)
    assert asyncio.run(go()) == {"n": 7}


def test_signed_error_without_code_never_becomes_server_error():
    """Настоящий разбор: error без code — подписанный E_MALFORMED, а не ServerError (spec/04)."""
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), error={"overflow": 1}), 101)
        return await asyncio.wait_for(t, 2)
    with pytest.raises(exmod.ProtocolError) as ei:
        asyncio.run(go())
    assert ei.value.signed


@pytest.mark.parametrize("text", [None, 5, {}, ["VEIL1R 1/1 x"]])
def test_non_string_text_is_dropped_quietly_not_by_exception(caplog, text):
    """Сообщение без текста отбрасывается проверкой типа, а не срабатыванием общей защиты от исключений."""
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        with caplog.at_level("WARNING", logger="veil.exchange"):
            r.ex.on_inbox_message({"from": FROM, "text": text, "reply_to_message": {"message_id": 101}})
        r.feed(r.sealed(r.env(), result={}), 101)
        await asyncio.wait_for(t, 2)
    asyncio.run(go())
    assert not [m for m in caplog.messages if "ignored" in m]
