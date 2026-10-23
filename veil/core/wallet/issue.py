"""Обмен с ботом-эмитентом (veil-protocol/spec/03, «Формат запроса и ответа»).

IssueRequest  = "VQ1" | req_id[8] | n_days[1] | n_days × Day
IssueResponse = "VS1" | req_id[8] | n_days[1] | n_days × (Day | proof[64])
Day           = day[10] | kid_len[1] | kid | count[1] | count × element[32]

Сообщения: "VEILREQ <req_id hex> <i>/<n> <часть base64url>", до 3800 символов части.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import date

from veil.core.crypto import poprf
from veil.core.protocol import b64
from veil.core.protocol.envelope import KID_PATTERN

REQ_MAGIC = b"VQ1"
RESP_MAGIC = b"VS1"
REQ_PREFIX = "VEILREQ"
RESP_PREFIX = "VEILRES"
MAX_PER_DAY = 50
MAX_DAYS = 8
PART_CHARS = 3800
MAX_PARTS = 16
SCHEME = "poprf-r255-v1"

_KID = re.compile(KID_PATTERN.strip("^$"))
_WEEK_KID = re.compile(r"([0-9]{4})-W([0-9]{2})")
_PART = re.compile(r"(VEILREQ|VEILRES) ([0-9a-f]{16}) ([0-9]{1,2})/([0-9]{1,2}) ([A-Za-z0-9_-]+)")


class IssueFormatError(ValueError):
    pass


@dataclass
class Day:
    day: str
    kid: str
    elements: list[bytes]
    proof: bytes = b""


@dataclass
class IssueMessage:
    req_id: bytes
    days: list[Day] = field(default_factory=list)


@dataclass
class Token:
    """Готовый токен для поля token конверта."""
    kid: str
    day: str
    input: bytes
    output: bytes


@dataclass
class PendingRequest:
    """Что клиент хранит до прихода ответа: req_id и состояние ослепления по дням."""
    req_id: bytes
    states: dict[str, tuple[str, list[poprf.BlindState]]]  # day → (kid, states)


def week_kid_covers(kid: str, day: str) -> bool:
    """kid прежней недельной схемы ключа эмитента («YYYY-Www») покрывает этот день: ISO-неделя дня та же. Так же решает
    сервер (TokenChecker): токены недельного ключа истекают вместе с его неделей, даже пока файл ключа не удалён."""
    m = _WEEK_KID.fullmatch(kid)
    if not m:
        return False
    try:
        y, w, _ = date.fromisoformat(day).isocalendar()
    except ValueError:
        return False
    return (y, w) == (int(m.group(1)), int(m.group(2)))


def _check_day(s: str) -> None:
    try:
        if date.fromisoformat(s).isoformat() != s:
            raise ValueError
    except ValueError:
        raise IssueFormatError(f"bad day {s!r}") from None


def encode(msg: IssueMessage, response: bool) -> bytes:
    if not 1 <= len(msg.days) <= MAX_DAYS or len(msg.req_id) != 8:
        raise IssueFormatError("days/req_id")
    out = bytearray(RESP_MAGIC if response else REQ_MAGIC)
    out += msg.req_id
    out.append(len(msg.days))
    for d in msg.days:
        _check_day(d.day)
        if not _KID.fullmatch(d.kid) or not 1 <= len(d.elements) <= MAX_PER_DAY:
            raise IssueFormatError("kid/count")
        out += d.day.encode()
        out.append(len(d.kid))
        out += d.kid.encode()
        out.append(len(d.elements))
        for e in d.elements:
            if len(e) != 32:
                raise IssueFormatError("element size")
            out += e
        if response:
            if len(d.proof) != 64:
                raise IssueFormatError("proof size")
            out += d.proof
    return bytes(out)


def decode(b: bytes, response: bool) -> IssueMessage:
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(b):
            raise IssueFormatError("truncated")
        pos += n
        return b[pos - n:pos]

    if take(3) != (RESP_MAGIC if response else REQ_MAGIC):
        raise IssueFormatError("magic")
    msg = IssueMessage(req_id=take(8))
    n_days = take(1)[0]
    if not 1 <= n_days <= MAX_DAYS:
        raise IssueFormatError("n_days")
    seen = set()
    for _ in range(n_days):
        try:
            day = take(10).decode("ascii")
        except UnicodeDecodeError:
            raise IssueFormatError("day") from None
        _check_day(day)
        if day in seen:
            raise IssueFormatError("duplicate day")
        seen.add(day)
        kid_b = take(take(1)[0])
        kid = kid_b.decode("ascii", "replace")
        if not _KID.fullmatch(kid):
            raise IssueFormatError("kid")
        count = take(1)[0]
        if not 1 <= count <= MAX_PER_DAY:
            raise IssueFormatError("count")
        elems = [take(32) for _ in range(count)]
        proof = take(64) if response else b""
        msg.days.append(Day(day, kid, elems, proof))
    if pos != len(b):
        raise IssueFormatError("trailing bytes")
    return msg


def split(prefix: str, req_id: bytes, payload: bytes) -> list[str]:
    s = b64.enc(payload)
    n = -(-len(s) // PART_CHARS)
    return [f"{prefix} {req_id.hex()} {i + 1}/{n} {s[i * PART_CHARS:(i + 1) * PART_CHARS]}" for i in range(n)]


def join(prefix: str, texts: list[str]) -> tuple[bytes, bytes]:
    """Склеивает части (в любом порядке, дубли допустимы). Возвращает (req_id, payload)."""
    req_id, n, parts = None, None, {}
    for t in texts:
        m = _PART.fullmatch(t.strip())
        if not m or m.group(1) != prefix:
            raise IssueFormatError("not a part")
        i, k = int(m.group(3)), int(m.group(4))
        if not 1 <= i <= k <= MAX_PARTS or len(m.group(5)) > PART_CHARS:
            raise IssueFormatError("part index")
        if req_id not in (None, m.group(2)) or n not in (None, k):
            raise IssueFormatError("parts of different requests")
        req_id, n = m.group(2), k
        parts[i] = m.group(5)
    if n is None or sorted(parts) != list(range(1, n + 1)):
        raise IssueFormatError("missing parts")
    try:
        payload = b64.dec("".join(parts[i] for i in range(1, n + 1)))
    except ValueError:
        raise IssueFormatError("base64") from None
    return bytes.fromhex(req_id), payload


def make_request(want: list[tuple[str, str, int]], req_id: bytes | None = None,
                 inputs: dict[str, list[bytes]] | None = None,
                 blinds: dict[str, list[int]] | None = None) -> tuple[PendingRequest, list[str]]:
    """want: [(day, kid, count)]. inputs/blinds — только для детерминированных тестов."""
    req_id = req_id or secrets.token_bytes(8)
    msg = IssueMessage(req_id)
    pending = PendingRequest(req_id, {})
    for day, kid, count in want:
        ins = (inputs or {}).get(day) or [secrets.token_bytes(32) for _ in range(count)]
        bl = (blinds or {}).get(day) or [None] * count
        states = [poprf.blind(i, b) for i, b in zip(ins, bl)]
        pending.states[day] = (kid, states)
        msg.days.append(Day(day, kid, [s.blinded for s in states]))
    return pending, split(REQ_PREFIX, req_id, encode(msg, response=False))


def accept_response(pending: PendingRequest, texts: list[str], issuer_pk: dict[str, bytes]) -> list[Token]:
    """Проверяет ответ эмитента (DLEQ на каждый день) и возвращает готовые токены.

    issuer_pk: kid → публичный ключ из проверенного keys.json. Ответ может содержать меньше дней
    и меньше элементов, чем запрошено (лимит уже частично выдан): берутся первые count ослеплений.
    """
    req_id, payload = join(RESP_PREFIX, texts)
    msg = decode(payload, response=True)
    if req_id != pending.req_id or msg.req_id != pending.req_id:
        raise IssueFormatError("response for another request")
    tokens: list[Token] = []
    for d in msg.days:
        if d.day not in pending.states:
            raise IssueFormatError(f"unrequested day {d.day}")
        kid, states = pending.states[d.day]
        if d.kid != kid or kid not in issuer_pk or len(d.elements) > len(states):
            raise IssueFormatError("kid/count mismatch")
        used = states[:len(d.elements)]
        outs = poprf.finalize_batch(used, d.elements, d.proof, issuer_pk[kid], b"veil/v1/day/" + d.day.encode())
        tokens += [Token(kid, d.day, s.input, o) for s, o in zip(used, outs)]
    return tokens
