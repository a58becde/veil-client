"""Конверт VEIL1 и ответ VEIL1R (spec/04)."""
from __future__ import annotations

import os
import re
import time
from typing import Any

from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from . import b64, jcs
from .errors import E_CLOCK, E_DECRYPT, E_MALFORMED, E_NOT_ENVELOPE, E_SIG, E_VERSION, ProtocolError

VERSION = 1
PREFIX = "VEIL1 "
RESP_PREFIX = "VEIL1R "
CTX_ENVELOPE = b"veil/v1/envelope\n"
CTX_RESPONSE = b"veil/v1/response\n"
FRAME_PLAIN = 0x00
MAX_PLAINTEXT = 3000  # байт JSON: чтобы "VEIL1 " + base64url влезало в 4096 символов
# Конверт больше MAX_PLAINTEXT (длинный скрытый текст) уходит документом с подписью DOC_CAPTION ответом на контент;
# внутри — тот же текст «VEIL1 …» (spec/04, «Большой конверт»).
MAX_DOC_PLAINTEXT = 64 * 1024
DOC_CAPTION = "VEIL1D"
CLOCK_SKEW = 300
# ts конверта округляется вниз до TS_STEP секунд, а id — 128 случайных бит без метки времени: по точным часам клиента
# сервер мог бы различать устройства (сдвиг часов — их отпечаток) и связывать посты разных ботов одной машины.
TS_STEP = 10

# Формат kid ключей сервера (spec/04): один для конвертов, keys.json и запросов эмитента. Тот же у сервера —
# сверяется общим вектором formats.kid.
KID_PATTERN = r"^[A-Za-z0-9._-]{1,32}$"
# Операция и id конверта (spec/04, «Прочие форматы»): сверяются общими векторами formats.op и formats.id.
OP_PATTERN = r"^[a-z]+(\.[a-z]+)*$"
ULID_PATTERN = r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
AUTH_MODES = ("identity", "ephemeral", "post_secret")
FIELDS_REQUIRED = {"v", "op", "id", "ts", "kid", "resp_pk", "auth", "sig"}
FIELDS_OPTIONAL = {"token", "content", "body"}
_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SEALED_OVERHEAD = 48  # sealed box: эфемерный ключ X25519 (32) + MAC (16)
RESP_PART_CHARS = 4000
MAX_RESP_PARTS = 16
# Наибольший JSON ответа: 16 частей по 4000 символов base64url минус накладные расходы и байт кадра (spec/04).
MAX_RESPONSE = MAX_RESP_PARTS * RESP_PART_CHARS * 3 // 4 - SEALED_OVERHEAD - 1
_CODE_RE = re.compile(r"E_[A-Z_]{1,32}")
_FIELD_RES = {name: re.compile(p) for name, p in (("op", OP_PATTERN), ("id", ULID_PATTERN), ("kid", KID_PATTERN))}


def new_ulid() -> str:
    """id конверта в записи ULID (26 символов Crockford Base32): 128 случайных бит, время в id не кладётся."""
    v = int.from_bytes(os.urandom(16), "big")
    return "".join(_ULID_ALPHABET[(v >> (5 * i)) & 31] for i in range(25, -1, -1))


def now_ts() -> int:
    return int(time.time()) // TS_STEP * TS_STEP


def signing_input(obj: dict, ctx: bytes = CTX_ENVELOPE) -> bytes:
    return ctx + jcs.canonicalize({k: v for k, v in obj.items() if k != "sig"})


def _is_int(x: Any) -> bool:
    """Целое число JSON: bool в Python — подкласс int, но в протоколе это другой тип."""
    return isinstance(x, int) and not isinstance(x, bool)


def _fmt_ok(name: str, value: Any) -> bool:
    return isinstance(value, str) and _FIELD_RES[name].fullmatch(value) is not None


# Ed25519 (RFC 8032): поле p = 2^255 - 19, d = -121665/121666. Нужно только для проверки ключа конверта.
_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1)


def _decompress(b: bytes) -> tuple[int, int] | None:
    """Точка Ed25519 из 32 байт (RFC 8032, 5.1.3) или None, если это не точка кривой."""
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    u, w = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x2 = u * pow(w, -1, _P) % _P  # w ≠ 0: d не квадрат
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = -x % _P
    return x, y


def _add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    """Сложение на кривой -x² + y² = 1 + d·x²·y² (полная формула, нейтральная точка — (0, 1))."""
    (x1, y1), (x2, y2) = a, b
    t = _D * x1 * x2 * y1 * y2 % _P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, _P) % _P, (y1 * y2 + x1 * x2) * pow(1 - t, -1, _P) % _P)


def strong_key(pk: bytes) -> bool:
    """Ключ Ed25519 в канонической кодировке и не малого порядка (spec/04): точка декодируется, кодируется обратно теми
    же байтами, и [8]P не нейтральная точка. Это не `crypto_core_ed25519_is_valid_point` libsodium: та отвергает ещё и
    точки смешанного порядка, которые правило протокола допускает."""
    if not isinstance(pk, bytes) or len(pk) != 32:
        return False
    pt = _decompress(pk)
    if pt is None or ((pt[1] | (pt[0] & 1) << 255).to_bytes(32, "little") != pk):
        return False
    for _ in range(3):
        pt = _add(pt, pt)
    return pt != (0, 1)


def build(op: str, auth_mode: str, auth_key: SigningKey, kid: str, *, body: Any = None,
          token: dict | None = None, content: dict | None = None, ts: int | None = None,
          id_: str | None = None, resp_sk: PrivateKey | None = None) -> tuple[dict, PrivateKey]:
    """Собирает и подписывает конверт. Возвращает (конверт, одноразовый ключ для расшифровки ответа).

    Ошибку вызывающего (неверный режим, формат op/kid/id, ts) выбрасывает как ValueError: в сеть такое не уходит."""
    if auth_mode not in AUTH_MODES:
        raise ValueError(auth_mode)
    if not _fmt_ok("op", op):
        raise ValueError(f"bad op: {op!r}")
    if not _fmt_ok("kid", kid):
        raise ValueError(f"bad kid: {kid!r}")
    if id_ is not None and not _fmt_ok("id", id_):
        raise ValueError(f"bad id: {id_!r}")
    if ts is not None and (not _is_int(ts) or ts < 0):
        raise ValueError(f"bad ts: {ts!r}")
    resp_sk = resp_sk or PrivateKey.generate()
    env: dict[str, Any] = {
        "v": VERSION, "op": op, "id": id_ or new_ulid(), "ts": now_ts() if ts is None else ts,
        "kid": kid, "resp_pk": b64.enc(bytes(resp_sk.public_key)),
        "auth": {"mode": auth_mode, "pk": b64.enc(bytes(auth_key.verify_key))},
    }
    if token is not None:
        env["token"] = token
    if content is not None:
        env["content"] = content
    if body is not None:
        env["body"] = body
    env["sig"] = b64.enc(auth_key.sign(signing_input(env)).signature)
    return env, resp_sk


def needs_document(env: dict) -> bool:
    """Конверт не помещается в текстовое сообщение — отправлять документом (DOC_CAPTION)."""
    return len(jcs.canonicalize(env)) > MAX_PLAINTEXT


def seal(env: dict, inbox_pk: bytes) -> str:
    pt = jcs.canonicalize(env)
    if len(pt) > MAX_DOC_PLAINTEXT:
        raise ValueError(f"envelope too large: {len(pt)} > {MAX_DOC_PLAINTEXT}")
    return PREFIX + b64.enc(SealedBox(PublicKey(inbox_pk)).encrypt(bytes([FRAME_PLAIN]) + pt))


def _b64_len(n: int) -> int:
    """Длина base64url без '=' для n байт."""
    return -(-n * 4 // 3)


def _unseal(text: str, prefix: str, sk: PrivateKey, max_plain: int) -> dict:
    """Расшифровывает и разбирает JSON. Длина проверяется до декодирования base64 (spec/04): шифртекст — это JSON
    (до max_plain байт), байт кадра и SEALED_OVERHEAD."""
    if not text.startswith(prefix):
        raise ProtocolError(E_NOT_ENVELOPE)
    body = text[len(prefix):]
    if len(body) > _b64_len(max_plain + 1 + SEALED_OVERHEAD):
        raise ProtocolError(E_DECRYPT, "too long")
    try:
        sealed = b64.dec(body)
        if not 1 + SEALED_OVERHEAD <= len(sealed) <= max_plain + 1 + SEALED_OVERHEAD:
            raise ValueError("bad length")
        frame = SealedBox(sk).decrypt(sealed)
    except (ValueError, CryptoError) as e:
        raise ProtocolError(E_DECRYPT) from e
    if not frame or frame[0] != FRAME_PLAIN:
        raise ProtocolError(E_DECRYPT, "unknown frame")
    try:
        obj = jcs.strict_loads(frame[1:].decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ProtocolError(E_MALFORMED, str(e)) from e
    if not isinstance(obj, dict):
        raise ProtocolError(E_MALFORMED, "not an object")
    return obj


def _verify(obj: dict, pk: bytes, ctx: bytes) -> None:
    try:
        VerifyKey(pk).verify(signing_input(obj, ctx), b64.dec(obj["sig"]))
    except (BadSignatureError, ValueError, KeyError, TypeError) as e:
        raise ProtocolError(E_SIG) from e


def _b64_field(value: Any, size: int) -> bytes | None:
    try:
        raw = b64.dec(value)
    except ValueError:
        return None
    return raw if len(raw) == size else None


def open_envelope(text: str, inbox_sk: PrivateKey, now: int | None = None, *,
                  max_plain: int = MAX_PLAINTEXT) -> dict:
    """Серверная сторона — для тестов и тестовых векторов клиента. Порядок проверок — как в spec/04: префикс,
    расшифровка, JSON, v, поля, форматы, подпись, ts. Конверт-документ открывается с max_plain=MAX_DOC_PLAINTEXT."""
    env = _unseal(text, PREFIX, inbox_sk, max_plain)
    if not _is_int(env.get("v")) or env["v"] != VERSION:
        raise ProtocolError(E_VERSION)
    keys = set(env)
    if not FIELDS_REQUIRED <= keys or keys - FIELDS_REQUIRED - FIELDS_OPTIONAL:
        raise ProtocolError(E_MALFORMED, "fields")
    if not (_fmt_ok("op", env["op"]) and _fmt_ok("id", env["id"]) and _fmt_ok("kid", env["kid"])):
        raise ProtocolError(E_MALFORMED, "op/id/kid")
    if not _is_int(env["ts"]):
        raise ProtocolError(E_MALFORMED, "ts")
    if _b64_field(env["resp_pk"], 32) is None:
        raise ProtocolError(E_MALFORMED, "resp_pk")
    auth = env["auth"]
    if not isinstance(auth, dict) or set(auth) != {"mode", "pk"} or auth["mode"] not in AUTH_MODES:
        raise ProtocolError(E_MALFORMED, "auth")
    pk = _b64_field(auth["pk"], 32)
    if pk is None or not strong_key(pk):
        raise ProtocolError(E_MALFORMED, "auth.pk")
    if any(k in env and not isinstance(env[k], dict) for k in ("token", "content")):
        raise ProtocolError(E_MALFORMED, "token/content")
    _verify(env, pk, CTX_ENVELOPE)
    now = int(time.time()) if now is None else now
    if abs(env["ts"] - now) > CLOCK_SKEW:
        raise ProtocolError(E_CLOCK)
    return env


def build_response(env_id: str, server_sig: SigningKey, *, result: Any = None,
                   error: dict | None = None) -> dict:
    resp: dict[str, Any] = {"v": VERSION, "re": env_id, "ok": error is None}
    if error is None:
        resp["result"] = result
    else:
        resp["error"] = error
    resp["sig"] = b64.enc(server_sig.sign(signing_input(resp, CTX_RESPONSE)).signature)
    return resp


def seal_response(resp: dict, resp_pk: bytes) -> str:
    """Запечатывает ответ на resp_pk. JSON длиннее MAX_RESPONSE не поместился бы в MAX_RESP_PARTS частей."""
    pt = jcs.canonicalize(resp)
    if len(pt) > MAX_RESPONSE:
        raise ValueError(f"response too large: {len(pt)} > {MAX_RESPONSE}")
    return RESP_PREFIX + b64.enc(SealedBox(PublicKey(resp_pk)).encrypt(bytes([FRAME_PLAIN]) + pt))


MESSAGE_CHARS = 4096  # предел текста сообщения Telegram
# Части ответа: десятичные i и n без ведущих нулей, 1 ≤ i ≤ n ≤ MAX_RESP_PARTS (проверяется в _part_numbers).
_RESP_PART = re.compile(r"VEIL1R ([1-9][0-9]?)/([1-9][0-9]?) ([A-Za-z0-9_-]+)")
_RESP_SINGLE = re.compile(r"VEIL1R [A-Za-z0-9_-]+")


def split_response(text: str) -> list[str]:
    """Ответ длиннее 4096 символов уходит частями "VEIL1R <i>/<n> <часть>" (spec/04)."""
    if len(text) <= MESSAGE_CHARS:
        return [text]
    if not text.startswith(RESP_PREFIX):
        raise ValueError("not a response")
    body = text[len(RESP_PREFIX):]
    n = -(-len(body) // RESP_PART_CHARS)
    if n > MAX_RESP_PARTS:
        raise ValueError(f"response needs {n} parts, at most {MAX_RESP_PARTS}")
    return [f"{RESP_PREFIX}{i + 1}/{n} {body[i * RESP_PART_CHARS:(i + 1) * RESP_PART_CHARS]}" for i in range(n)]


def _part_numbers(m: re.Match | None) -> tuple[int, int] | None:
    if m is None:
        return None
    i, n = int(m.group(1)), int(m.group(2))
    return (i, n) if 1 <= i <= n <= MAX_RESP_PARTS else None


def is_response_part(text: str) -> tuple[int, int] | None:
    """(i, n) для части многочастного ответа, None во всех остальных случаях (в том числе при i или n вне 1 ≤ i ≤ n ≤ 16
    и числах с ведущими нулями)."""
    return _part_numbers(_RESP_PART.fullmatch(text))


def join_response(parts: list[str]) -> str:
    """Склеивает части в любом порядке. Одиночный ответ возвращается как есть."""
    if len(parts) == 1 and _RESP_SINGLE.fullmatch(parts[0]):
        return parts[0]
    got: dict[int, str] = {}
    n = None
    for p in parts:
        m = _RESP_PART.fullmatch(p)
        nums = _part_numbers(m)
        if m is None or nums is None or n not in (None, nums[1]):
            raise ProtocolError(E_MALFORMED, "bad response part")
        n, got[nums[0]] = nums[1], m.group(3)
    if n is None or sorted(got) != list(range(1, n + 1)):
        raise ProtocolError(E_MALFORMED, "missing response parts")
    return RESP_PREFIX + "".join(got[i] for i in range(1, n + 1))


def _check_response(resp: dict, expect_id: str) -> None:
    """Состав подписанного ответа (spec/09): v, ровно допустимый набор полей, re, ok, форма error."""
    if not _is_int(resp.get("v")) or resp["v"] != VERSION:
        raise ProtocolError(E_VERSION)
    ok = resp.get("ok")
    if not isinstance(ok, bool) or set(resp) != {"v", "re", "ok", "sig", "result" if ok else "error"}:
        raise ProtocolError(E_MALFORMED, "response fields")
    if resp["re"] != expect_id:
        raise ProtocolError(E_MALFORMED, "response does not match request")
    if ok:
        return
    err = resp["error"]
    if not isinstance(err, dict) or not isinstance(err.get("code"), str) or not _CODE_RE.fullmatch(err["code"]):
        raise ProtocolError(E_MALFORMED, "error")
    for k in ("overflow", "retry_after"):
        if k in err and (not _is_int(err[k]) or err[k] < 0):
            raise ProtocolError(E_MALFORMED, k)


def open_response(text: str, resp_sk: PrivateKey, server_sig_pk: bytes, expect_id: str) -> dict:
    """Открывает ответ сервера: префикс, длина и расшифровка, JSON, подпись, затем состав ответа (spec/09)."""
    resp = _unseal(text, RESP_PREFIX, resp_sk, MAX_RESPONSE)
    _verify(resp, server_sig_pk, CTX_RESPONSE)
    try:
        _check_response(resp, expect_id)
    except ProtocolError as e:
        e.signed = True  # подпись сервера верна: это его испорченный ответ, а не подделка
        raise
    return resp
