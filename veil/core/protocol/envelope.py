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
from .errors import (E_CLOCK, E_DECRYPT, E_MALFORMED, E_NOT_ENVELOPE, E_SIG, E_VERSION,
                     ProtocolError)

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

# Формат kid ключей сервера (spec/04): один для конвертов, keys.json и запросов эмитента. Тот же у сервера
# (protocol.KidPattern) — сверяется общим вектором formats.kid.
KID_PATTERN = r"^[A-Za-z0-9._-]{1,32}$"
AUTH_MODES = ("identity", "ephemeral", "post_secret")
FIELDS_REQUIRED = {"v", "op", "id", "ts", "kid", "resp_pk", "auth", "sig"}
FIELDS_OPTIONAL = {"token", "content", "body"}
_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    """id конверта в записи ULID (26 символов Crockford Base32): 128 случайных бит, время в id не кладётся."""
    v = int.from_bytes(os.urandom(16), "big")
    return "".join(_ULID_ALPHABET[(v >> (5 * i)) & 31] for i in range(25, -1, -1))


def now_ts() -> int:
    return int(time.time()) // TS_STEP * TS_STEP


def signing_input(obj: dict, ctx: bytes = CTX_ENVELOPE) -> bytes:
    return ctx + jcs.canonicalize({k: v for k, v in obj.items() if k != "sig"})


def build(op: str, auth_mode: str, auth_key: SigningKey, kid: str, *, body: Any = None,
          token: dict | None = None, content: dict | None = None, ts: int | None = None,
          id_: str | None = None, resp_sk: PrivateKey | None = None) -> tuple[dict, PrivateKey]:
    """Собирает и подписывает конверт. Возвращает (конверт, одноразовый ключ для расшифровки ответа)."""
    if auth_mode not in AUTH_MODES:
        raise ValueError(auth_mode)
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


def _unseal(text: str, prefix: str, sk: PrivateKey) -> dict:
    if not text.startswith(prefix):
        raise ProtocolError(E_NOT_ENVELOPE)
    try:
        frame = SealedBox(sk).decrypt(b64.dec(text[len(prefix):]))
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


def open_envelope(text: str, inbox_sk: PrivateKey, now: int | None = None) -> dict:
    """Серверная сторона — для тестов и тестовых векторов клиента."""
    env = _unseal(text, PREFIX, inbox_sk)
    if env.get("v") != VERSION:
        raise ProtocolError(E_VERSION)
    keys = set(env)
    if not FIELDS_REQUIRED <= keys or keys - FIELDS_REQUIRED - FIELDS_OPTIONAL:
        raise ProtocolError(E_MALFORMED, "fields")
    auth = env["auth"]
    if not isinstance(auth, dict) or set(auth) != {"mode", "pk"} or auth["mode"] not in AUTH_MODES:
        raise ProtocolError(E_MALFORMED, "auth")
    try:
        pk = b64.dec(auth["pk"])
    except ValueError as e:
        raise ProtocolError(E_MALFORMED, "auth.pk") from e
    _verify(env, pk, CTX_ENVELOPE)
    now = int(time.time()) if now is None else now
    if not isinstance(env["ts"], int) or abs(env["ts"] - now) > CLOCK_SKEW:
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
    return RESP_PREFIX + b64.enc(SealedBox(PublicKey(resp_pk)).encrypt(bytes([FRAME_PLAIN]) + jcs.canonicalize(resp)))


RESP_PART_CHARS = 4000
MAX_RESP_PARTS = 16
_RESP_PART = re.compile(r"VEIL1R ([0-9]{1,2})/([0-9]{1,2}) ([A-Za-z0-9_-]+)")


def split_response(text: str) -> list[str]:
    """Ответ длиннее 4096 символов уходит частями "VEIL1R <i>/<n> <часть>" (spec/04)."""
    if len(text) <= 4096:
        return [text]
    body = text[len(RESP_PREFIX):]
    n = -(-len(body) // RESP_PART_CHARS)
    return [f"{RESP_PREFIX}{i + 1}/{n} {body[i * RESP_PART_CHARS:(i + 1) * RESP_PART_CHARS]}" for i in range(n)]


def is_response_part(text: str) -> tuple[int, int] | None:
    """(i, n) для части многочастного ответа, None для обычного ответа."""
    m = _RESP_PART.fullmatch(text)
    return (int(m.group(1)), int(m.group(2))) if m else None


def join_response(parts: list[str]) -> str:
    """Склеивает части в любом порядке. Одиночный ответ возвращается как есть."""
    if len(parts) == 1 and is_response_part(parts[0]) is None:
        return parts[0]
    got, n = {}, None
    for p in parts:
        m = _RESP_PART.fullmatch(p)
        if not m:
            raise ProtocolError(E_MALFORMED, "bad response part")
        i, k = int(m.group(1)), int(m.group(2))
        if not 1 <= i <= k <= MAX_RESP_PARTS or n not in (None, k):
            raise ProtocolError(E_MALFORMED, "bad response part")
        n, got[i] = k, m.group(3)
    if sorted(got) != list(range(1, n + 1)):
        raise ProtocolError(E_MALFORMED, "missing response parts")
    return RESP_PREFIX + "".join(got[i] for i in range(1, n + 1))


def open_response(text: str, resp_sk: PrivateKey, server_sig_pk: bytes, expect_id: str) -> dict:
    resp = _unseal(text, RESP_PREFIX, resp_sk)
    _verify(resp, server_sig_pk, CTX_RESPONSE)
    if resp.get("re") != expect_id or not isinstance(resp.get("ok"), bool):
        raise ProtocolError(E_MALFORMED, "response does not match request")
    return resp

