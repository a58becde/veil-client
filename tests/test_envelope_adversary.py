"""Тесты-противник на envelope.py (spec/04, spec/09).

Написаны по spec, векторам и сигнатурам, без чтения реализации. Конверты и ответы собираются здесь вручную и
подписываются заново, чтобы проверять разбор после подписи и порядок проверок.
"""

import random

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey

from veil.core.protocol import b64, envelope, jcs
from veil.core.protocol.errors import ProtocolError

SERVER = SigningKey.generate()
SERVER_PK = bytes(SERVER.verify_key)
RESP_SK = PrivateKey.generate()
RESP_PK = bytes(RESP_SK.public_key)
INBOX_SK = PrivateKey.generate()
INBOX_PK = bytes(INBOX_SK.public_key)
EID = "01K7ZZ0000000000000000TEST"
B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
NOW = 1_792_000_000


def raw_seal(pt: bytes, pk: bytes, prefix: str, frame: bytes = b"\x00") -> str:
    return prefix + b64.enc(SealedBox(PublicKey(pk)).encrypt(frame + pt))


def sign_resp(obj: dict) -> dict:
    obj = {k: v for k, v in obj.items() if k != "sig"}
    obj["sig"] = b64.enc(SERVER.sign(envelope.CTX_RESPONSE + jcs.canonicalize(obj)).signature)
    return obj


def resp_text(obj: dict, *, sign: bool = True) -> str:
    if sign:
        obj = sign_resp(obj)
    return raw_seal(jcs.canonicalize(obj), RESP_PK, envelope.RESP_PREFIX)


def good_resp(**over) -> dict:
    r = {"v": 1, "re": EID, "ok": True, "result": {"n": 1}}
    r.update(over)
    return {k: v for k, v in r.items() if v is not ...}


def open_resp(text: str) -> dict:
    return envelope.open_response(text, RESP_SK, SERVER_PK, EID)


def code_of(fn, *a, **kw) -> str:
    with pytest.raises(ProtocolError) as ex:
        fn(*a, **kw)
    return ex.value.code


# ───────────────────────── open_response: состав ответа (spec/09) ─────────────────────────


def test_response_ok_roundtrip_and_null_result():
    assert open_resp(resp_text(good_resp()))["result"] == {"n": 1}
    for res in (None, 0, False, [], "", {}, [None]):
        got = open_resp(resp_text(good_resp(result=res)))
        assert got["ok"] is True and got["result"] == res


def test_response_error_forms_ok():
    for err in (
        {"code": "E_A"},
        {"code": "E_" + "A" * 32},
        {"code": "E__"},
        {"code": "E_NEW_CODE", "x": [1, {"y": 2}]},
        {"code": "E_RATE", "retry_after": 0},
        {"code": "E_RATE", "retry_after": 2**53 - 1},
        {"code": "E_TOO_LONG", "overflow": 0, "retry_after": 7, "future": None},
    ):
        r = {"v": 1, "re": EID, "ok": False, "error": err}
        assert open_resp(resp_text(r))["error"] == err


@pytest.mark.parametrize(
    "obj",
    [
        {"v": 1, "re": EID, "ok": True},  # нет result
        {"v": 1, "re": EID, "ok": False},  # нет error
        {"v": 1, "re": EID, "ok": True, "result": 1, "error": {"code": "E_X"}},
        {"v": 1, "re": EID, "ok": False, "result": 1, "error": {"code": "E_X"}},
        {"v": 1, "re": EID, "ok": True, "result": 1, "extra": 1},
        {"v": 1, "re": EID, "ok": False, "error": {"code": "E_X"}, "extra": None},
        {"v": 1, "re": EID, "ok": 1, "result": 1},
        {"v": 1, "re": EID, "ok": 0, "error": {"code": "E_X"}},
        {"v": 1, "re": EID, "ok": "true", "result": 1},
        {"v": 1, "re": EID, "ok": None, "result": 1},
        {"v": 1, "ok": True, "result": 1},  # нет re
        {"re": EID, "ok": True, "result": 1},  # нет v → это тоже состав, v отсутствует
        {"v": 1, "re": EID, "result": 1},  # нет ok
        {"v": 1, "re": "01K7ZZ0000000000000000TESX", "ok": True, "result": 1},
        {"v": 1, "re": EID.lower(), "ok": True, "result": 1},
        {"v": 1, "re": EID + " ", "ok": True, "result": 1},
        {"v": 1, "re": 5, "ok": True, "result": 1},
        {"v": 1, "re": None, "ok": True, "result": 1},
        {"v": 1, "re": EID, "ok": False, "error": "E_X"},
        {"v": 1, "re": EID, "ok": False, "error": ["E_X"]},
        {"v": 1, "re": EID, "ok": False, "error": None},
        {"v": 1, "re": EID, "ok": False, "error": 5},
        {"v": 1, "re": EID, "ok": False, "error": {}},
        {"v": 1, "re": EID, "ok": False, "error": {"message": "x"}},
    ],
)
def test_response_composition_malformed(obj):
    code = code_of(open_resp, resp_text(obj))
    # «нет v» — на усмотрение: v не int → E_VERSION по контракту («v не int») или состав → E_MALFORMED
    if "v" not in obj:
        assert code in ("E_VERSION", "E_MALFORMED")
    else:
        assert code == "E_MALFORMED"


@pytest.mark.parametrize(
    "code",
    [
        "",
        "E_",
        "e_FOO",
        "E_foo",
        "E_FOO1",
        "E_FOO BAR",
        "E_FOO\n",
        "E_" + "A" * 33,
        "EFOO",
        "X_FOO",
        "E_ФОО",
        "E_FOO-BAR",
        " E_FOO",
        "E_FOO ",
        5,
        None,
        True,
        ["E_X"],
        {"a": 1},
    ],
)
def test_response_error_code_format(code):
    r = {"v": 1, "re": EID, "ok": False, "error": {"code": code}}
    assert code_of(open_resp, resp_text(r)) == "E_MALFORMED"


@pytest.mark.parametrize("field", ["overflow", "retry_after"])
@pytest.mark.parametrize("val", [True, False, "5", "", -1, -(2**53 - 1), None, [1], {"a": 1}, [], "1.5"])
def test_response_error_numbers(field, val):
    r = {"v": 1, "re": EID, "ok": False, "error": {"code": "E_RATE", field: val}}
    assert code_of(open_resp, resp_text(r)) == "E_MALFORMED"


@pytest.mark.parametrize("v", [True, False, 2, 0, -1, "1", None, [1], {"v": 1}, 10**12])
def test_response_version(v):
    assert code_of(open_resp, resp_text(good_resp(v=v))) == "E_VERSION"


def test_response_version_checked_before_composition():
    # v плохой и состав плохой: порядок по spec/09 — сначала v
    assert code_of(open_resp, resp_text(good_resp(v=True, extra=1))) == "E_VERSION"
    assert code_of(open_resp, resp_text(good_resp(v=2, re="other"))) == "E_VERSION"
    assert code_of(open_resp, resp_text(good_resp(v=2, ok="x"))) == "E_VERSION"


def test_response_signature_checked_before_everything_after():
    bad_sig = good_resp(v=2, extra=1, re="zzz")
    bad_sig["sig"] = b64.enc(bytes(64))
    assert code_of(open_resp, resp_text(bad_sig, sign=False)) == "E_SIG"
    ok_but_unsigned = good_resp()
    ok_but_unsigned["sig"] = b64.enc(bytes(64))
    assert code_of(open_resp, resp_text(ok_but_unsigned, sign=False)) == "E_SIG"
    # подпись другим ключом
    other = SigningKey.generate()
    o = {k: v for k, v in good_resp().items()}
    o["sig"] = b64.enc(other.sign(envelope.CTX_RESPONSE + jcs.canonicalize(o)).signature)
    assert code_of(open_resp, resp_text(o, sign=False)) == "E_SIG"
    # подпись с контекстом конверта, а не ответа
    o = good_resp()
    o["sig"] = b64.enc(SERVER.sign(envelope.CTX_ENVELOPE + jcs.canonicalize(o)).signature)
    assert code_of(open_resp, resp_text(o, sign=False)) == "E_SIG"
    # подпись без контекста
    o = good_resp()
    o["sig"] = b64.enc(SERVER.sign(jcs.canonicalize(o)).signature)
    assert code_of(open_resp, resp_text(o, sign=False)) == "E_SIG"


@pytest.mark.parametrize("sig", [b"", bytes(63), bytes(65), bytes(32)])
def test_response_sig_wrong_length(sig):
    o = good_resp()
    o["sig"] = b64.enc(sig)
    assert code_of(open_resp, resp_text(o, sign=False)) == "E_SIG"


@pytest.mark.parametrize("sig", [5, None, ["x"], "!!!", "A" * 85, True])
def test_response_sig_garbage_is_protocol_error(sig):
    o = good_resp()
    o["sig"] = sig
    assert code_of(open_resp, resp_text(o, sign=False)) in ("E_SIG", "E_MALFORMED")


def test_response_signature_covers_body():
    o = sign_resp(good_resp(result={"n": 1}))
    o["result"] = {"n": 2}
    assert code_of(open_resp, resp_text(o, sign=False)) == "E_SIG"
    o = sign_resp(good_resp())
    o["re"] = "01K7ZZ0000000000000000TESX"
    assert code_of(open_resp, resp_text(o, sign=False)) == "E_SIG"  # сначала подпись, потом re


def test_response_no_missing_sig_key():
    o = good_resp()
    assert code_of(open_resp, resp_text(o, sign=False)) in ("E_SIG", "E_MALFORMED")


def test_response_wrong_expect_id_and_wrong_key():
    t = resp_text(good_resp())
    assert code_of(envelope.open_response, t, RESP_SK, SERVER_PK, "01K7ZZ0000000000000000TESX") == "E_MALFORMED"
    assert code_of(envelope.open_response, t, PrivateKey.generate(), SERVER_PK, EID) == "E_DECRYPT"
    assert code_of(envelope.open_response, t, RESP_SK, bytes(SigningKey.generate().verify_key), EID) == "E_SIG"
    assert code_of(envelope.open_response, t, RESP_SK, bytes(32), EID) in ("E_SIG", "E_MALFORMED")


# ───────────────────────── open_response: кадр, префикс, JSON ─────────────────────────


def test_response_prefix():
    body = resp_text(good_resp())[len(envelope.RESP_PREFIX) :]
    for t in (
        "",
        "VEIL1R",
        "VEIL1R" + body,
        "VEIL1 " + body,
        " VEIL1R " + body,
        "veil1r " + body,
        "VEIL1E " + body,
        "VEIL1R\t" + body,
        "xVEIL1R " + body,
        body,
    ):
        assert code_of(open_resp, t) == "E_NOT_ENVELOPE", t[:20]
    assert code_of(open_resp, "VEIL1R ") == "E_DECRYPT"


def test_response_frames_and_json_garbage():
    pk = RESP_PK
    pfx = envelope.RESP_PREFIX
    assert code_of(open_resp, raw_seal(b"", pk, pfx, frame=b"")) == "E_DECRYPT"  # шифртекст 48 байт: короче 49
    assert code_of(open_resp, raw_seal(b"", pk, pfx)) == "E_MALFORMED"  # 49 байт, кадр 0, JSON пуст
    assert code_of(open_resp, raw_seal(b"{}", pk, pfx, frame=b"\x01")) == "E_DECRYPT"
    assert code_of(open_resp, raw_seal(b"{}", pk, pfx, frame=b"\xff")) == "E_DECRYPT"
    assert code_of(open_resp, raw_seal(b"{}", pk, pfx, frame=b"\x02")) == "E_DECRYPT"
    for pt in (
        b"[]",
        b"null",
        b"1",
        b'"x"',
        b"true",
        b"{",
        b"\xff\xfe{}",
        b'{"a":1,"a":2}',
        b'{"v":1.0}',
        b'{"v":1e0}',
        b'{"a":"\\ud800"}',
        b"\xef\xbb\xbf{}",
        b"{} x",
        b"\xc3\x28",
    ):
        assert code_of(open_resp, raw_seal(pt, pk, pfx)) == "E_MALFORMED", pt
    # пустой объект: формат строгий, но подписи нет
    assert code_of(open_resp, raw_seal(b"{}", pk, pfx)) in ("E_SIG", "E_MALFORMED")


def test_response_junk_base64_is_decrypt():
    body = resp_text(good_resp())[len(envelope.RESP_PREFIX) :]
    for t in (
        body + "=",
        body + "\n",
        body + " ",
        body[:-1],
        "!" + body[1:],
        body[:10] + "+" + body[11:],
        body[:10] + "/" + body[11:],
        "A" * 64,
        "A" * 65,
        "я" * 100,
        "١" * 100,
        body + "A",
    ):
        assert code_of(open_resp, "VEIL1R " + t) == "E_DECRYPT", t[-5:]
    # флип одного бита шифртекста
    ct = bytearray(b64.dec(body))
    ct[40] ^= 1
    assert code_of(open_resp, "VEIL1R " + b64.enc(bytes(ct))) == "E_DECRYPT"


# ───────────────────────── границы размера ответа ─────────────────────────


def _padded_signed_resp(total: int, ch: str = "a") -> dict:
    """Подписанный ответ, у которого канонический JSON (с sig) ровно total байт."""
    base = len(jcs.canonicalize(sign_resp(good_resp(result={"pad": ""}))))
    unit = len(ch.encode())
    extra = total - base
    assert extra >= 0 and extra % unit == 0
    r = sign_resp(good_resp(result={"pad": ch * (extra // unit)}))
    assert len(jcs.canonicalize(r)) == total
    return r


def test_response_exact_limit_roundtrip_and_parts():
    assert envelope.MAX_RESPONSE == 47951
    r = _padded_signed_resp(envelope.MAX_RESPONSE)
    text = envelope.seal_response(r, RESP_PK)
    assert len(text) - len(envelope.RESP_PREFIX) == 64000
    assert open_resp(text)["result"]["pad"] == r["result"]["pad"]
    parts = envelope.split_response(text)
    assert len(parts) == 16
    assert all(len(p) <= 4096 for p in parts)
    random.Random(1).shuffle(parts)
    joined = envelope.join_response(parts)
    assert joined == text
    assert open_resp(joined) == r


def test_response_one_over_is_rejected_everywhere():
    over = sign_resp(
        good_resp(
            result={
                "pad": "a"
                * (envelope.MAX_RESPONSE + 1 - len(jcs.canonicalize(sign_resp(good_resp(result={"pad": ""})))))
            }
        )
    )
    assert len(jcs.canonicalize(over)) == envelope.MAX_RESPONSE + 1
    with pytest.raises(ValueError):
        envelope.seal_response(over, RESP_PK)
    text = raw_seal(jcs.canonicalize(over), RESP_PK, envelope.RESP_PREFIX)
    assert len(text) - len(envelope.RESP_PREFIX) == 64002
    assert code_of(open_resp, text) == "E_DECRYPT"


def test_response_limit_counts_bytes_not_chars():
    # «я» — 2 байта: символов меньше, чем байт; предел в байтах
    base = len(jcs.canonicalize(sign_resp(good_resp(result={"pad": ""}))))
    n_ok = (envelope.MAX_RESPONSE - base) // 2  # base чётность: добьём ascii
    r = sign_resp(good_resp(result={"pad": "я" * n_ok + "a" * (envelope.MAX_RESPONSE - base - 2 * n_ok)}))
    assert len(jcs.canonicalize(r)) == envelope.MAX_RESPONSE
    assert len(jcs.canonicalize(r).decode()) < envelope.MAX_RESPONSE
    text = envelope.seal_response(r, RESP_PK)
    assert open_resp(text)["ok"] is True
    r2 = sign_resp(good_resp(result={"pad": "я" * n_ok + "a" * (envelope.MAX_RESPONSE + 1 - base - 2 * n_ok)}))
    assert len(jcs.canonicalize(r2)) == envelope.MAX_RESPONSE + 1
    with pytest.raises(ValueError):
        envelope.seal_response(r2, RESP_PK)
    # один «я» вместо двух ascii: те же байты, на единицу меньше символов
    r3 = sign_resp(
        good_resp(result={"pad": "я" * (n_ok + 1) + "a" * (envelope.MAX_RESPONSE - base - 2 * n_ok - 2 + 1 - 1)})
    )
    assert len(jcs.canonicalize(r3)) <= envelope.MAX_RESPONSE + 1


def test_response_body_over_char_limit_is_rejected_without_decoding(monkeypatch):
    calls = []
    real = envelope.b64.dec

    def spy(s):
        calls.append(len(s))
        return real(s)

    monkeypatch.setattr(envelope.b64, "dec", spy)
    limit = -(-(envelope.MAX_RESPONSE + 49) * 4 // 3)
    assert limit == 64000
    assert code_of(open_resp, "VEIL1R " + "A" * (limit + 1)) == "E_DECRYPT"
    assert calls == []
    assert code_of(open_resp, "VEIL1R " + "A" * (limit + 5000)) == "E_DECRYPT"
    assert calls == []
    # ровно на пределе — декодирование происходит (и дальше E_DECRYPT от расшифровки)
    assert code_of(open_resp, "VEIL1R " + "A" * limit) == "E_DECRYPT"
    assert calls == [limit]
    # то же — для мусора, который не base64: длинный не декодируется
    assert code_of(open_resp, "VEIL1R " + "!" * (limit + 1)) == "E_DECRYPT"
    assert calls == [limit]


# ───────────────────────── split_response / join_response / is_response_part ─────────────────────────


def test_split_boundaries():
    pfx = envelope.RESP_PREFIX
    assert envelope.split_response("x" * 4096) == ["x" * 4096]  # ≤4096 — как есть, даже без префикса
    assert envelope.split_response("") == [""]
    with pytest.raises(ValueError):
        envelope.split_response("x" * 4097)
    for body_len in (4090, 4091, 4092, 8000, 8001, 4000 * 16 - 1, 4000 * 16):
        text = pfx + "A" * body_len
        parts = envelope.split_response(text)
        n = -(-body_len // 4000) if len(text) > 4096 else 1
        if len(text) > 4096:
            assert len(parts) == n
            assert all(len(p) <= 4096 for p in parts)
            assert [envelope.is_response_part(p) for p in parts] == [(i + 1, n) for i in range(n)]
            assert envelope.join_response(parts) == text
    with pytest.raises(ValueError):
        envelope.split_response(pfx + "A" * (4000 * 16 + 1))
    with pytest.raises(ValueError):
        envelope.split_response(pfx + "A" * 200000)
    # 4097 символов без префикса — ValueError, не молчаливое «как есть»
    with pytest.raises(ValueError):
        envelope.split_response("VEIL1 " + "A" * 5000)
    with pytest.raises(ValueError):
        envelope.split_response(" " + pfx + "A" * 5000)


def test_split_part_layout():
    body = (B64URL * 200)[:9001]
    parts = envelope.split_response("VEIL1R " + body)
    assert len(parts) == 3
    assert parts[0] == "VEIL1R 1/3 " + body[:4000]
    assert parts[1] == "VEIL1R 2/3 " + body[4000:8000]
    assert parts[2] == "VEIL1R 3/3 " + body[8000:]


@pytest.mark.parametrize(
    "text,want",
    [
        ("VEIL1R 1/1 A", (1, 1)),
        ("VEIL1R 1/2 AAAA", (1, 2)),
        ("VEIL1R 2/2 A-_", (2, 2)),
        ("VEIL1R 16/16 AAAA", (16, 16)),
        ("VEIL1R 9/10 AAAA", (9, 10)),
        ("VEIL1R 10/10 AAAA", (10, 10)),
        ("VEIL1R 15/16 AAAA", (15, 16)),
        ("VEIL1R 0/1 AAAA", None),
        ("VEIL1R 1/0 AAAA", None),
        ("VEIL1R 0/0 AAAA", None),
        ("VEIL1R 2/1 AAAA", None),
        ("VEIL1R 17/17 AAAA", None),
        ("VEIL1R 1/17 AAAA", None),
        ("VEIL1R 16/17 AAAA", None),
        ("VEIL1R 17/16 AAAA", None),
        ("VEIL1R 01/02 AAAA", None),
        ("VEIL1R 1/02 AAAA", None),
        ("VEIL1R 01/2 AAAA", None),
        ("VEIL1R 00/2 AAAA", None),
        ("VEIL1R 001/002 AAAA", None),
        ("VEIL1R +1/2 AAAA", None),
        ("VEIL1R 1/+2 AAAA", None),
        ("VEIL1R -1/2 AAAA", None),
        ("VEIL1R 1/-2 AAAA", None),
        ("VEIL1R  1/2 AAAA", None),
        ("VEIL1R 1 /2 AAAA", None),
        ("VEIL1R 1/ 2 AAAA", None),
        ("VEIL1R 1/2AAAA", None),
        ("VEIL1R 1/2  AAAA", None),
        ("VEIL1R 1/2 AAAA ", None),
        ("VEIL1R 1/2 AAAA\n", None),
        ("VEIL1R 1/2 AA\nAA", None),
        ("VEIL1R 1/2 AA AA", None),
        ("VEIL1R 1/2 AA/AA", None),
        ("VEIL1R 1/2 AA=", None),
        ("VEIL1R 1/2 AAA+", None),
        ("VEIL1R 1/2 ÄÄÄÄ", None),
        ("VEIL1R 1/2 яяяя", None),
        ("VEIL1R 1/2 AAAA​", None),
        ("VEIL1R 1/2 ١٢", None),
        ("VEIL1R ١/٢ AAAA", None),
        ("VEIL1R １/２ AAAA", None),
        ("VEIL1R 1/2 ", None),
        ("VEIL1R 1/2", None),
        ("VEIL1R 1/", None),
        ("VEIL1R /2 AAAA", None),
        ("VEIL1R 1 2 AAAA", None),
        ("VEIL1R 1\\2 AAAA", None),
        ("VEIL1R 1.0/2 AAAA", None),
        ("VEIL1R 1e0/2 AAAA", None),
        ("VEIL1R 0x1/2 AAAA", None),
        ("VEIL1R 1_0/16 AAAA", None),
        ("VEIL1R AAAA", None),
        ("VEIL1R ", None),
        ("", None),
        ("VEIL1 1/2 AAAA", None),
        ("VEIL1E 1/2 AAAA", None),
        ("veil1r 1/2 AAAA", None),
        (" VEIL1R 1/2 AAAA", None),
        ("VEIL1R\t1/2 AAAA", None),
        ("VEIL1R1/2 AAAA", None),
        ("1/2 AAAA", None),
    ],
)
def test_is_response_part_table(text, want):
    assert envelope.is_response_part(text) == want


def test_is_response_part_huge_numbers_do_not_raise():
    for digits in (30, 500, 5000, 100000):
        n = "9" * digits
        assert envelope.is_response_part(f"VEIL1R {n}/2 AAAA") is None
        assert envelope.is_response_part(f"VEIL1R 1/{n} AAAA") is None
        assert envelope.is_response_part(f"VEIL1R {n}/{n} AAAA") is None
        assert code_of(envelope.join_response, [f"VEIL1R {n}/{n} AAAA"]) == "E_MALFORMED"
        assert code_of(envelope.join_response, ["VEIL1R 1/2 AAAA", f"VEIL1R {n}/2 AAAA"]) == "E_MALFORMED"


def test_is_response_part_long_body_ok_and_non_str():
    assert envelope.is_response_part("VEIL1R 1/2 " + "A" * 4000) == (1, 2)


@pytest.mark.parametrize(
    "parts,code",
    [
        ([], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA"], "E_MALFORMED"),  # нет части 2
        (["VEIL1R 2/2 AAAA"], "E_MALFORMED"),  # нет части 1
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/3 BBBB"], "E_MALFORMED"),  # разные n
        (["VEIL1R 1/3 AAAA", "VEIL1R 2/3 BBBB"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 1/2 BBBB"], "E_MALFORMED"),  # дубль индекса, нет 2
        (["VEIL1R 1/2 AAAA", "VEIL1R 02/02 BBBB"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 BB BB"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 BB/B"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 BBB="], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 BBBB\n"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 "], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 яяяя"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 ١٢"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1 2/2 BBBB"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R BBBB"], "E_MALFORMED"),
        (["VEIL1R 17/17 AAAA"], "E_MALFORMED"),
        (["VEIL1R 0/1 AAAA"], "E_MALFORMED"),
        (["VEIL1R 1/17 AAAA"] + [f"VEIL1R {i}/17 AAAA" for i in range(2, 18)], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA ", "VEIL1R 2/2 BBBB"], "E_MALFORMED"),
        ([" VEIL1R 1/2 AAAA", "VEIL1R 2/2 BBBB"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 BBBB", "VEIL1R 3/2 CCCC"], "E_MALFORMED"),
        (["VEIL1R 1/2 AAAA", "VEIL1R 2/2 BBBB", "VEIL1R 3/3 CCCC"], "E_MALFORMED"),
    ],
)
def test_join_response_rejects(parts, code):
    assert code_of(envelope.join_response, parts) == code


@pytest.mark.parametrize(
    "parts,want",
    [
        (["VEIL1R 1/1 AAAA"], "VEIL1R AAAA"),
        (["VEIL1R 2/2 BBBB", "VEIL1R 1/2 AAAA"], "VEIL1R AAAABBBB"),
        (["VEIL1R 1/3 A", "VEIL1R 2/3 B", "VEIL1R 3/3 C"], "VEIL1R ABC"),
        (["VEIL1R 3/3 C", "VEIL1R 1/3 A", "VEIL1R 2/3 B"], "VEIL1R ABC"),
        (["VEIL1R 1/2 a-_Z", "VEIL1R 2/2 09"], "VEIL1R a-_Z09"),
        ([f"VEIL1R {i}/16 {chr(65 + i - 1)}" for i in range(16, 0, -1)], "VEIL1R ABCDEFGHIJKLMNOP"),
    ],
)
def test_join_response_ok(parts, want):
    assert envelope.join_response(parts) == want


# ───────────────────────── property ─────────────────────────

b64_chunk = st.text(alphabet=B64URL, min_size=1, max_size=4000)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(st.text(alphabet=B64URL, min_size=4090, max_size=64000), st.randoms())
def test_prop_join_split_roundtrip(body, rnd):
    text = envelope.RESP_PREFIX + body
    parts = envelope.split_response(text)
    assert 1 <= len(parts) <= envelope.MAX_RESP_PARTS
    assert all(len(p) <= 4096 for p in parts)
    n = len(parts)
    assert sorted(envelope.is_response_part(p) for p in parts) == [(i, n) for i in range(1, n + 1)]
    rnd.shuffle(parts)
    assert envelope.join_response(parts) == text


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet=B64URL, min_size=0, max_size=4089))
def test_prop_short_is_identity(body):
    text = envelope.RESP_PREFIX + body
    assert envelope.split_response(text) == [text]


@settings(max_examples=100, deadline=None)
@given(st.text(max_size=5000))
def test_prop_split_total(text):
    try:
        parts = envelope.split_response(text)
    except ValueError:
        return
    assert parts == [text] if len(text) <= 4096 else all(len(p) <= 4096 for p in parts)


_PIECE = st.sampled_from(
    [
        "",
        "0",
        "1",
        "2",
        "9",
        "16",
        "17",
        "01",
        "+1",
        "-1",
        "١",
        "٣",
        "２",
        " ",
        "\n",
        "/",
        "A",
        "-",
        "_",
        "=",
        "я",
        "VEIL1R ",
        "VEIL1R",
        "\x00",
        "9" * 5000,
    ]
)


def _candidate():
    num = st.builds("".join, st.lists(_PIECE, max_size=3))
    body = st.builds("".join, st.lists(_PIECE, max_size=4))
    return st.builds(lambda a, b, c: f"VEIL1R {a}/{b} {c}", num, num, body) | st.builds(
        "".join, st.lists(_PIECE, max_size=6)
    )


@settings(max_examples=400, deadline=None)
@given(st.lists(_candidate(), max_size=4))
def test_prop_garbage_parts_never_raise_other_than_malformed(parts):
    for p in parts:
        r = envelope.is_response_part(p)
        assert r is None or (1 <= r[0] <= r[1] <= 16)
    try:
        out = envelope.join_response(parts)
    except ProtocolError as e:
        assert e.code == "E_MALFORMED"
        return
    # если собралось — каждая часть была настоящей, а тело — base64url
    assert out.startswith("VEIL1R ")
    assert len(parts) == 1 or all(envelope.is_response_part(p) for p in parts)
    assert all(c in B64URL for c in out[len("VEIL1R ") :])


@settings(max_examples=200, deadline=None)
@given(st.lists(st.sampled_from(B64URL), min_size=1, max_size=40), st.integers(1, 16), st.randoms())
def test_prop_hand_made_parts_join(chars, n, rnd):
    chunks = [str(c) for c in chars][:n]
    n = len(chunks)
    parts = [f"VEIL1R {i}/{n} {c}" for i, c in enumerate(chunks, 1)]
    rnd.shuffle(parts)
    assert envelope.join_response(parts) == "VEIL1R " + "".join(chunks)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=300))
def test_prop_open_response_random_bytes_only_protocol_errors(blob):
    for text in ("VEIL1R " + b64.enc(blob), "VEIL1R " + blob.decode("latin-1")):
        try:
            open_resp(text)
        except ProtocolError as e:
            assert e.code in ("E_DECRYPT", "E_NOT_ENVELOPE", "E_MALFORMED", "E_SIG")
        else:
            raise AssertionError("мусор принят")


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=200), st.sampled_from([b"\x00", b"\x01", b"\x7f", b"\xff", b""]))
def test_prop_open_response_sealed_garbage_only_protocol_errors(pt, frame):
    for pre, pk, fn in (
        (envelope.RESP_PREFIX, RESP_PK, open_resp),
        (envelope.PREFIX, INBOX_PK, lambda t: envelope.open_envelope(t, INBOX_SK, now=NOW)),
    ):
        try:
            fn(raw_seal(pt, pk, pre, frame=frame))
        except ProtocolError as e:
            assert e.code in ("E_DECRYPT", "E_MALFORMED", "E_SIG", "E_VERSION")
        else:
            raise AssertionError("мусор принят")


# ───────────────────────── open_envelope ─────────────────────────

AUTH = SigningKey.generate()
GOOD_ID = "01K7ZZ0000000000000000TEST"


def good_env(**over) -> dict:
    e = {
        "v": 1,
        "op": "post.create",
        "id": GOOD_ID,
        "ts": NOW,
        "kid": "i1",
        "resp_pk": b64.enc(RESP_PK),
        "auth": {"mode": "ephemeral", "pk": b64.enc(bytes(AUTH.verify_key))},
        "body": {"x": 1},
    }
    e.update(over)
    return {k: v for k, v in e.items() if v is not ...}


def sign_env(e: dict, key: SigningKey = AUTH) -> dict:
    e = {k: v for k, v in e.items() if k != "sig"}
    e["sig"] = b64.enc(key.sign(envelope.CTX_ENVELOPE + jcs.canonicalize(e)).signature)
    return e


def env_text(e: dict, *, sign: bool = True, prefix: str = envelope.PREFIX) -> str:
    if sign:
        e = sign_env(e)
    return raw_seal(jcs.canonicalize(e), INBOX_PK, prefix)


def open_env(text: str, now: int = NOW, **kw) -> dict:
    return envelope.open_envelope(text, INBOX_SK, now=now, **kw)


def test_envelope_ok_variants():
    assert open_env(env_text(good_env()))["op"] == "post.create"
    for op in ("ping", "a", "a.b.c", "zzz.zzz"):
        open_env(env_text(good_env(op=op)))
    for mode in envelope.AUTH_MODES:
        open_env(env_text(good_env(auth={"mode": mode, "pk": b64.enc(bytes(AUTH.verify_key))})))
    open_env(env_text(good_env(token={"a": 1}, content={"b": 2})))
    for kid in ("a", "x" * 32, "A.b_c-9", ".", ".."):
        open_env(env_text(good_env(kid=kid)))
    open_env(env_text(good_env(id="7ZZZZZZZZZZZZZZZZZZZZZZZZZ")))
    open_env(env_text(good_env(id="00000000000000000000000000")))
    open_env(env_text(good_env(body=None)))


@pytest.mark.parametrize(
    "delta,ok",
    [
        (0, True),
        (300, True),
        (-300, True),
        (299, True),
        (-299, True),
        (301, False),
        (-301, False),
        (10**6, False),
        (-(10**6), False),
    ],
)
def test_envelope_clock_boundaries(delta, ok):
    t = env_text(good_env(ts=NOW + delta))
    if ok:
        open_env(t)
    else:
        assert code_of(open_env, t) == "E_CLOCK"
    # симметрия: сдвигаем «сейчас» вместо ts
    t = env_text(good_env())
    if ok:
        open_env(t, now=NOW + delta)
    else:
        assert code_of(open_env, t, now=NOW + delta) == "E_CLOCK"


def test_envelope_clock_default_now_uses_real_time():
    import time

    t = env_text(good_env(ts=int(time.time())))
    open_env(t, now=None)
    t = env_text(good_env(ts=int(time.time()) - 1000))
    assert code_of(envelope.open_envelope, t, INBOX_SK) == "E_CLOCK"


@pytest.mark.parametrize("v", [True, False, 2, 0, -1, 1 << 40, "1", None, [1], {}])
def test_envelope_version(v):
    assert code_of(open_env, env_text(good_env(v=v))) == "E_VERSION"


def test_envelope_version_before_fields_and_formats_and_sig():
    assert code_of(open_env, env_text(good_env(v=True, extra=1))) == "E_VERSION"
    assert code_of(open_env, env_text(good_env(v=2, op="BAD"))) == "E_VERSION"
    assert code_of(open_env, env_text(good_env(v=True, ts=True))) == "E_VERSION"
    assert code_of(open_env, env_text(good_env(v=2), sign=False)) == "E_VERSION"  # подписи нет вовсе
    e = good_env(v=True)
    e["sig"] = b64.enc(bytes(64))
    assert code_of(open_env, env_text(e, sign=False)) == "E_VERSION"


@pytest.mark.parametrize("name", sorted(envelope.FIELDS_REQUIRED))
def test_envelope_missing_required(name):
    e = sign_env(good_env())
    del e[name]
    code = code_of(open_env, env_text(e, sign=False))
    assert code == ("E_VERSION" if name == "v" else "E_MALFORMED")


@pytest.mark.parametrize(
    "extra", [{"x": 1}, {"Token": {}}, {"sig2": "a"}, {"": 1}, {"re": EID}, {"ok": True}, {"error": None}]
)
def test_envelope_extra_top_level(extra):
    assert code_of(open_env, env_text(good_env(**extra))) == "E_MALFORMED"


@pytest.mark.parametrize(
    "field,val",
    [
        ("op", "Post.create"),
        ("op", "post.Create"),
        ("op", "post."),
        ("op", ".post"),
        ("op", "post..create"),
        ("op", ""),
        ("op", "post create"),
        ("op", "post1"),
        ("op", "post_create"),
        ("op", "post-create"),
        ("op", "post.create\n"),
        ("op", "post.crеate"),
        ("op", "post.create​"),
        ("op", 5),
        ("op", None),
        ("op", ["post"]),
        ("op", True),
        ("id", GOOD_ID.lower()),
        ("id", "8" + GOOD_ID[1:]),
        ("id", "I" + GOOD_ID[1:]),
        ("id", "0" + "L" + GOOD_ID[2:]),
        ("id", "0" + "O" + GOOD_ID[2:]),
        ("id", "0" + "U" + GOOD_ID[2:]),
        ("id", GOOD_ID[:-1]),
        ("id", GOOD_ID + "0"),
        ("id", GOOD_ID + "\n"),
        ("id", " " + GOOD_ID),
        ("id", ""),
        ("id", 5),
        ("id", None),
        ("id", "01K7ZZ000000000000000000ТЕ"),
        ("kid", ""),
        ("kid", "a/b"),
        ("kid", "a b"),
        ("kid", "x" * 33),
        ("kid", "i1\n"),
        ("kid", "ё"),
        ("kid", "a\u0000"),
        ("kid", 1),
        ("kid", None),
        ("kid", ["i1"]),
        ("ts", True),
        ("ts", False),
        ("ts", "1792000000"),
        ("ts", None),
        ("ts", [NOW]),
        ("ts", {"a": 1}),
        ("resp_pk", b64.enc(bytes(31))),
        ("resp_pk", b64.enc(bytes(33))),
        ("resp_pk", b64.enc(bytes(RESP_PK)) + "="),
        ("resp_pk", ""),
        ("resp_pk", 5),
        ("resp_pk", None),
        ("resp_pk", "!" * 43),
        ("resp_pk", b64.enc(RESP_PK) + "\n"),
        ("resp_pk", b64.enc(RESP_PK)[:-1] + "B"),  # неканоническая кодировка: лишние младшие биты
        ("auth", None),
        ("auth", []),
        ("auth", "x"),
        ("auth", {}),
        ("auth", {"mode": "identity"}),
        ("auth", {"pk": "A" * 43}),
        ("auth", {"mode": "x", "pk": "A" * 43}),
        ("auth", {"mode": 1, "pk": "A" * 43}),
        ("auth", {"mode": "Identity", "pk": b64.enc(bytes(AUTH.verify_key))}),
        ("auth", {"mode": "ephemeral", "pk": b64.enc(bytes(AUTH.verify_key)), "extra": 1}),
        ("auth", {"mode": "ephemeral", "pk": b64.enc(bytes(31))}),
        ("auth", {"mode": "ephemeral", "pk": b64.enc(bytes(33))}),
        ("auth", {"mode": "ephemeral", "pk": 5}),
        ("auth", {"mode": "ephemeral", "pk": None}),
        ("auth", {"mode": "ephemeral", "pk": b64.enc(bytes(AUTH.verify_key)) + "="}),
        ("token", []),
        ("token", "x"),
        ("token", 1),
        ("token", None),
        ("token", True),
        ("content", []),
        ("content", "x"),
        ("content", 1),
        ("content", None),
        ("content", False),
    ],
)
def test_envelope_field_formats_signed(field, val):
    assert code_of(open_env, env_text(good_env(**{field: val}))) == "E_MALFORMED"


def test_envelope_format_checked_before_signature():
    # испорчено поле без переподписи: формат раньше подписи
    for field, val in (
        ("op", "BAD"),
        ("id", "bad"),
        ("kid", "a/b"),
        ("ts", True),
        ("resp_pk", "AA"),
        ("auth", {"mode": "x", "pk": "A"}),
    ):
        e = sign_env(good_env())
        e[field] = val
        assert code_of(open_env, env_text(e, sign=False)) == "E_MALFORMED", field
    # неверная подпись при корректных форматах — E_SIG
    e = sign_env(good_env())
    e["body"] = {"x": 2}
    assert code_of(open_env, env_text(e, sign=False)) == "E_SIG"
    # неверная подпись и просроченный ts: сначала E_SIG
    e = sign_env(good_env(ts=NOW + 10000))
    e["body"] = {"x": 2}
    assert code_of(open_env, env_text(e, sign=False)) == "E_SIG"
    # корректная подпись и просроченный ts: E_CLOCK
    assert code_of(open_env, env_text(good_env(ts=NOW + 10000))) == "E_CLOCK"
    # формат плохой и ts просрочен: сначала формат
    assert code_of(open_env, env_text(good_env(ts=NOW + 10000, op="BAD"))) == "E_MALFORMED"


@pytest.mark.parametrize("sig", [b"", bytes(63), bytes(65), bytes(128)])
def test_envelope_sig_wrong_length(sig):
    e = good_env()
    e["sig"] = b64.enc(sig)
    assert code_of(open_env, env_text(e, sign=False)) == "E_SIG"


@pytest.mark.parametrize("sig", [5, None, True, ["x"], {"a": 1}, "!!!"])
def test_envelope_sig_garbage_is_protocol_error(sig):
    e = good_env()
    e["sig"] = sig
    assert code_of(open_env, env_text(e, sign=False)) in ("E_SIG", "E_MALFORMED")


def test_envelope_sig_other_key_or_context():
    e = good_env()
    e["sig"] = b64.enc(SigningKey.generate().sign(envelope.CTX_ENVELOPE + jcs.canonicalize(e)).signature)
    assert code_of(open_env, env_text(e, sign=False)) == "E_SIG"
    e = good_env()
    e["sig"] = b64.enc(AUTH.sign(envelope.CTX_RESPONSE + jcs.canonicalize(e)).signature)
    assert code_of(open_env, env_text(e, sign=False)) == "E_SIG"
    e = good_env()
    e["sig"] = b64.enc(AUTH.sign(jcs.canonicalize(e)).signature)
    assert code_of(open_env, env_text(e, sign=False)) == "E_SIG"


SMALL_ORDER = [
    bytes(32),
    b"\x01" + bytes(31),
    bytes.fromhex("ec" + "ff" * 30 + "7f"),
    b"\x00" * 31 + b"\x80",
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    bytes.fromhex("ed" + "ff" * 30 + "7f"),
    bytes.fromhex("ee" + "ff" * 30 + "7f"),
    b"\x01" + bytes(30) + b"\x80",
    bytes.fromhex("02" + "00" * 31),
]


@pytest.mark.parametrize("pk", SMALL_ORDER, ids=lambda b: b.hex()[:12])
def test_envelope_small_order_or_noncanonical_pk_is_malformed_even_with_forged_sig(pk):
    e = good_env(auth={"mode": "ephemeral", "pk": b64.enc(pk)})
    e["sig"] = b64.enc(b"\x01" + bytes(63))  # R = нейтральная, S = 0
    assert code_of(open_env, env_text(e, sign=False)) == "E_MALFORMED"
    e["sig"] = b64.enc(bytes(64))
    assert code_of(open_env, env_text(e, sign=False)) == "E_MALFORMED"


def test_envelope_mixed_order_pk_passes_format_then_fails_signature():
    base = bytes.fromhex("58" + "66" * 31)
    mixed = envelope._add(envelope._decompress(base), (0, envelope._P - 1))
    mixed_pk = (mixed[1] | (mixed[0] & 1) << 255).to_bytes(32, "little")
    e = good_env(auth={"mode": "ephemeral", "pk": b64.enc(mixed_pk)})
    e["sig"] = b64.enc(bytes(64))
    assert code_of(open_env, env_text(e, sign=False)) == "E_SIG"


# размер и кадр


def _env_with_json_size(total: int) -> dict:
    base = len(jcs.canonicalize(sign_env(good_env(body={"p": ""}))))
    assert total >= base
    e = sign_env(good_env(body={"p": "a" * (total - base)}))
    assert len(jcs.canonicalize(e)) == total
    return e


def test_envelope_text_limit_exact_and_over():
    assert envelope.MAX_PLAINTEXT == 3000
    e = _env_with_json_size(3000)
    t = env_text(e, sign=False)
    assert envelope.needs_document(e) is False
    assert open_env(t)["body"] == e["body"]
    over = _env_with_json_size(3001)
    assert envelope.needs_document(over) is True
    assert code_of(open_env, env_text(over, sign=False)) == "E_DECRYPT"


def test_envelope_doc_limit_exact_and_over():
    e = _env_with_json_size(65536)
    t = env_text(e, sign=False)
    assert open_env(t, max_plain=envelope.MAX_DOC_PLAINTEXT)["body"] == e["body"]
    assert code_of(open_env, t) == "E_DECRYPT"  # как текстовый — нельзя
    over = _env_with_json_size(65537)
    assert code_of(open_env, env_text(over, sign=False), max_plain=envelope.MAX_DOC_PLAINTEXT) == "E_DECRYPT"
    with pytest.raises(Exception):
        envelope.seal(over, INBOX_PK)
    assert envelope.seal(e, INBOX_PK).startswith(envelope.PREFIX)


def test_needs_document_counts_bytes():
    base = len(jcs.canonicalize(sign_env(good_env(body={"p": ""}))))
    n = (3000 - base) // 2
    pad = "я" * n + "a" * (3000 - base - 2 * n)
    e = sign_env(good_env(body={"p": pad}))
    assert len(jcs.canonicalize(e)) == 3000 and len(jcs.canonicalize(e).decode()) < 3000
    assert envelope.needs_document(e) is False
    e = sign_env(good_env(body={"p": pad + "a"}))
    assert envelope.needs_document(e) is True


def test_envelope_body_over_char_limit_rejected_without_decoding(monkeypatch):
    calls = []
    real = envelope.b64.dec

    def spy(s):
        calls.append(len(s))
        return real(s)

    monkeypatch.setattr(envelope.b64, "dec", spy)
    lim = -(-(3000 + 49) * 4 // 3)
    assert lim == 4066
    assert code_of(open_env, "VEIL1 " + "A" * (lim + 1)) == "E_DECRYPT"
    assert calls == []
    assert code_of(open_env, "VEIL1 " + "A" * 10**6) == "E_DECRYPT"
    assert calls == []
    assert code_of(open_env, "VEIL1 " + "A" * lim) == "E_DECRYPT"
    assert calls == [lim]
    dlim = -(-(65536 + 49) * 4 // 3)
    assert code_of(open_env, "VEIL1 " + "A" * (dlim + 1), max_plain=65536) == "E_DECRYPT"
    assert calls == [lim]
    assert code_of(open_env, "VEIL1 " + "A" * dlim, max_plain=65536) == "E_DECRYPT"
    assert calls == [lim, dlim]
    # произвольный max_plain
    assert code_of(open_env, "VEIL1 " + "A" * (-(-(100 + 49) * 4 // 3) + 1), max_plain=100) == "E_DECRYPT"
    assert calls == [lim, dlim]


def test_envelope_prefix_frame_and_json():
    body = env_text(good_env())[len(envelope.PREFIX) :]
    for t in (
        "",
        "VEIL1",
        "VEIL1" + body,
        "VEIL1R " + body,
        " VEIL1 " + body,
        "veil1 " + body,
        "VEIL1\t" + body,
        body,
        "VEIL1D " + body,
    ):
        assert code_of(open_env, t) == "E_NOT_ENVELOPE", t[:12]
    assert code_of(open_env, "VEIL1 ") == "E_DECRYPT"
    pfx = envelope.PREFIX
    assert code_of(open_env, raw_seal(b"", INBOX_PK, pfx, frame=b"")) == "E_DECRYPT"
    assert code_of(open_env, raw_seal(b"", INBOX_PK, pfx)) == "E_MALFORMED"
    for fr in (b"\x01", b"\x02", b"\xff"):
        assert (
            code_of(open_env, raw_seal(jcs.canonicalize(sign_env(good_env())), INBOX_PK, pfx, frame=fr)) == "E_DECRYPT"
        )
    for pt in (
        b"[]",
        b"null",
        b"3",
        b'"x"',
        b"{",
        b'{"v":1,"v":1}',
        b'{"v":1.5}',
        b"\xff",
        b'{"v":1}\n{"v":1}',
        b'{"a":"\\udc00"}',
        b"\xef\xbb\xbf" + jcs.canonicalize(sign_env(good_env())),
    ):
        assert code_of(open_env, raw_seal(pt, INBOX_PK, pfx)) == "E_MALFORMED", pt
    # чужой ключ
    assert code_of(envelope.open_envelope, env_text(good_env()), PrivateKey.generate(), NOW) == "E_DECRYPT"
    # неканонический base64 / мусор
    for t in (body + "=", body + "\n", body[:-1] + ("A" if body[-1] != "A" else "B"), body + "A", "!" * 50, body[:-2]):
        assert code_of(open_env, "VEIL1 " + t) == "E_DECRYPT", t[-5:]


def test_envelope_json_formats_not_canonical_but_valid():
    # пробелы и произвольный порядок ключей допустимы: подпись считается по JCS
    e = sign_env(good_env())
    import json as _json

    pt = _json.dumps(e, ensure_ascii=False, indent=2, sort_keys=False).encode()
    assert open_env(raw_seal(pt, INBOX_PK, envelope.PREFIX))["id"] == GOOD_ID


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    st.sampled_from(["v", "op", "id", "ts", "kid", "resp_pk", "auth", "token", "content", "body", "extra"]),
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(-10, 10**12),
        st.text(max_size=40),
        st.lists(st.integers(-10, 10), max_size=3),
        st.dictionaries(st.text(max_size=5), st.integers(-10, 10), max_size=3),
    ),
)
def test_prop_envelope_mutations_only_protocol_errors(field, val):
    e = good_env()
    e[field] = val
    try:
        out = open_env(env_text(e))
    except ProtocolError as ex:
        assert ex.code in ("E_VERSION", "E_MALFORMED", "E_SIG", "E_CLOCK", "E_DECRYPT")
    else:
        # принято: значит, подмена не нарушила контракт полей
        assert field in ("token", "content", "body") or out[field] == val
        assert field != "extra"


@pytest.mark.parametrize("s", ["VEIL1R 0", "VEIL1R AAAA", "VEIL1R a-_Z"])
def test_join_single_ok(s):
    assert envelope.join_response([s]) == s


@pytest.mark.parametrize(
    "s",
    [
        "VEIL1R AAA=",
        "VEIL1R !!!",
        "VEIL1R ",
        "xxx",
        "VEIL1R a/b",
        "VEIL1R AA\n",
        "VEIL1R яя",
        "VEIL1R A A",
        " VEIL1R A",
        "VEIL1R1 A",
        "",
    ],
)
def test_join_single_rejects(s):
    assert code_of(envelope.join_response, [s]) == "E_MALFORMED"


# ───────────────────────── по выжившим мутациям (build, new_ulid, арифметика ключей, join) ─────────────────────────


def test_new_ulid_is_crockford_of_128_bits(monkeypatch):
    """id — 128 случайных бит (spec/04), закодированные Crockford Base32 по 5 бит: все биты на месте."""
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    for value in (0, 1, 2**127, 2**128 - 1, 0x0123456789ABCDEF0123456789ABCDEF, 31, 32, 1 << 64):
        monkeypatch.setattr(envelope.os, "urandom", lambda n, v=value: v.to_bytes(n, "big"))
        got = envelope.new_ulid()
        want = "".join(alphabet[(value >> (5 * i)) & 31] for i in range(25, -1, -1))
        assert got == want, value
        assert len(got) == 26
    monkeypatch.setattr(envelope.os, "urandom", lambda n: b"\xff" * n)
    assert envelope.new_ulid() == "7" + "Z" * 25


def test_new_ulid_random_pattern_and_entropy():
    import re

    ids = [envelope.new_ulid() for _ in range(300)]
    assert all(re.fullmatch(envelope.ULID_PATTERN, i) for i in ids)
    assert len(set(ids)) == len(ids)
    # старшие символы тоже случайны (не нулевая «метка времени»): в 300 id первые 4 символа не постоянны
    assert len({i[:4] for i in ids}) > 100
    assert len({i[1] for i in ids}) > 8


def test_now_ts_rounds_down_to_ten(monkeypatch):
    for t, want in (
        (1_792_000_009.99, 1_792_000_000),
        (1_792_000_010.0, 1_792_000_010),
        (1_792_000_019.5, 1_792_000_010),
        (1_792_000_000.0, 1_792_000_000),
    ):
        monkeypatch.setattr(envelope.time, "time", lambda t=t: t)
        assert envelope.now_ts() == want
        assert type(envelope.now_ts()) is int


def test_build_includes_all_given_parts_and_signs():
    import re

    from nacl.signing import VerifyKey

    sk = SigningKey.generate()
    tok, cont, body = {"scheme": "x"}, {"kind": "text", "files": []}, {"a": [1, 2]}
    env, rsk = envelope.build(
        "post.create", "identity", sk, "i1", body=body, token=tok, content=cont, ts=1234, id_=GOOD_ID
    )
    assert env["token"] == tok and env["content"] == cont and env["body"] == body
    assert (
        env["ts"] == 1234
        and env["id"] == GOOD_ID
        and env["kid"] == "i1"
        and env["op"] == "post.create"
        and env["v"] == 1
    )
    assert env["auth"] == {"mode": "identity", "pk": b64.enc(bytes(sk.verify_key))}
    assert env["resp_pk"] == b64.enc(bytes(rsk.public_key))
    unsigned = {k: v for k, v in env.items() if k != "sig"}
    VerifyKey(bytes(sk.verify_key)).verify(envelope.CTX_ENVELOPE + jcs.canonicalize(unsigned), b64.dec(env["sig"]))
    # без token/content ключей нет вовсе (а не null)
    env2, _ = envelope.build("ping", "ephemeral", sk, "i1", ts=0)
    assert "token" not in env2 and "content" not in env2
    assert env2["ts"] == 0  # 0 — явное значение, а не «не задано»
    assert re.fullmatch(envelope.ULID_PATTERN, env2["id"])
    # свой resp_sk используется
    mine = PrivateKey.generate()
    env3, rsk3 = envelope.build("ping", "ephemeral", sk, "i1", resp_sk=mine, ts=5)
    assert rsk3 == mine and env3["resp_pk"] == b64.enc(bytes(mine.public_key))
    # и весь конверт открывается зеркалом
    got = envelope.open_envelope(envelope.seal(env, INBOX_PK), INBOX_SK, now=1234)
    assert got == env


def test_build_ts_default_is_now_rounded(monkeypatch):
    sk = SigningKey.generate()
    monkeypatch.setattr(envelope.time, "time", lambda: 1_792_000_019.9)
    env, _ = envelope.build("ping", "ephemeral", sk, "i1")
    assert env["ts"] == 1_792_000_010
    env, _ = envelope.build("ping", "ephemeral", sk, "i1", ts=1_792_000_019)  # явный ts не округляется
    assert env["ts"] == 1_792_000_019


def test_strong_key_non_bytes_is_false_without_exception():
    good = bytes(SigningKey.generate().verify_key)
    for bad in (None, 5, "x" * 32, "", [], bytearray(good), memoryview(good), 3.5, {"a": 1}):
        assert envelope.strong_key(bad) is False, bad
    assert envelope.strong_key(good) is True


def _compress(pt):
    return (pt[1] | (pt[0] & 1) << 255).to_bytes(32, "little")


def test_curve_arithmetic_matches_libsodium():
    """_decompress/_add — собственная арифметика Ed25519 (нужна для правила [8]P ≠ 0): сверка с libsodium."""
    from nacl.bindings import (
        crypto_core_ed25519_add,
        crypto_core_ed25519_is_valid_point,
        crypto_scalarmult_ed25519_base_noclamp,
    )

    rnd = random.Random(7)
    pts = [crypto_scalarmult_ed25519_base_noclamp(rnd.randrange(1, 2**250).to_bytes(32, "little")) for _ in range(12)]
    for p in pts:
        assert crypto_core_ed25519_is_valid_point(p)
        assert _compress(envelope._decompress(p)) == p
    for a, b in zip(pts, pts[1:] + pts[:1]):
        s = envelope._add(envelope._decompress(a), envelope._decompress(b))
        assert _compress(s) == crypto_core_ed25519_add(a, b)
        d = envelope._add(envelope._decompress(a), envelope._decompress(a))
        assert _compress(d) == crypto_core_ed25519_add(a, a)
    # нейтральный элемент и противоположная точка
    p0 = envelope._decompress(pts[0])
    assert envelope._add(p0, (0, 1)) == p0
    neg = ((-p0[0]) % envelope._P, p0[1])
    assert envelope._add(p0, neg) == (0, 1)
    # точка порядка 2 (0, -1): P + T2 = (−x, −y)
    t2 = envelope._add(p0, (0, envelope._P - 1))
    assert t2 == ((-p0[0]) % envelope._P, (-p0[1]) % envelope._P)


def test_decompress_rejects_noncanonical_y():
    p = envelope._P
    for y in (p, p + 1, p + 2, 2**255 - 1):
        assert envelope._decompress(y.to_bytes(32, "little")) is None, y
    # y = p − 1 (−1) канонична и принимается
    assert envelope._decompress((p - 1).to_bytes(32, "little")) == (0, p - 1)


def test_join_two_plain_singles_is_not_a_response():
    for parts in (
        ["VEIL1R AAAA", "VEIL1R BBBB"],
        ["VEIL1R AAAA", "VEIL1R 1/2 BBBB"],
        ["VEIL1R 1/2 AAAA", "VEIL1R BBBB"],
        ["VEIL1R AAAA"] * 3,
        ["VEIL1R AAAA", "VEIL1R AAAA"],
    ):
        assert code_of(envelope.join_response, parts) == "E_MALFORMED", parts
