"""Клиентская часть RFC 9497 POPRF, набор ristretto255-SHA512 (режим 0x02).

Реализованы только операции клиента: Blind, проверка DLEQ-доказательства, Finalize.
Совместимость проверяется векторами RFC 9497 (Appendix A.1.3) и кросс-векторами эмитента сервера
(test-vectors/poprf-cross.json).
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from . import ristretto as r255

MODE_POPRF = 0x02
SUITE = b"ristretto255-SHA512"
CONTEXT = b"OPRFV1-" + bytes([MODE_POPRF]) + b"-" + SUITE


def _i2osp2(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _lp(b: bytes) -> bytes:
    return _i2osp2(len(b)) + b


def expand_message_xmd(msg: bytes, dst: bytes, length: int = 64) -> bytes:
    """RFC 9380, expand_message_xmd с SHA-512 (b_in_bytes=64, s_in_bytes=128)."""
    if len(dst) > 255:
        raise ValueError("DST too long")
    ell = -(-length // 64)
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha512(bytes(128) + msg + _i2osp2(length) + b"\x00" + dst_prime).digest()
    b = [hashlib.sha512(b0 + b"\x01" + dst_prime).digest()]
    for i in range(2, ell + 1):
        prev = bytes(x ^ y for x, y in zip(b0, b[-1]))
        b.append(hashlib.sha512(prev + bytes([i]) + dst_prime).digest())
    return b"".join(b)[:length]


def hash_to_group(msg: bytes) -> bytes:
    return r255.from_uniform(expand_message_xmd(msg, b"HashToGroup-" + CONTEXT))


def hash_to_scalar(msg: bytes, dst: bytes | None = None) -> int:
    u = expand_message_xmd(msg, dst or (b"HashToScalar-" + CONTEXT))
    return int.from_bytes(u, "little") % r255.L


def _info_scalar(info: bytes) -> int:
    return hash_to_scalar(b"Info" + _lp(info))


class ProofError(ValueError):
    pass


@dataclass
class BlindState:
    input: bytes
    blind: int
    blinded: bytes


def tweaked_key(pk: bytes, info: bytes) -> bytes:
    """T = G*m + pkS. Нейтральный элемент означает невалидный ключ."""
    t = r255.add(r255.mul_base(_info_scalar(info)), r255.check(pk))
    if t == r255.IDENTITY:
        raise ValueError("invalid tweaked key")
    return t


def blind(inp: bytes, blind_scalar: int | None = None) -> BlindState:
    if blind_scalar is None:
        blind_scalar = 0
        while blind_scalar == 0:
            blind_scalar = int.from_bytes(secrets.token_bytes(64), "little") % r255.L
    p = hash_to_group(inp)
    if p == r255.IDENTITY:
        raise ValueError("input maps to identity")
    return BlindState(inp, blind_scalar, r255.mul(blind_scalar, p))


def _composites(B: bytes, C: list[bytes], D: list[bytes]) -> tuple[bytes, bytes]:
    seed_dst = b"Seed-" + CONTEXT
    seed = hashlib.sha512(_lp(B) + _lp(seed_dst)).digest()
    M = Z = None
    for i, (c, d) in enumerate(zip(C, D)):
        di = hash_to_scalar(_lp(seed) + _i2osp2(i) + _lp(c) + _lp(d) + b"Composite")
        mc, md = r255.mul(di, c), r255.mul(di, d)
        M = mc if M is None else r255.add(M, mc)
        Z = md if Z is None else r255.add(Z, md)
    if M is None or Z is None:  # не assert: при python -O проверка исчезла бы
        raise ValueError("empty batch")
    return M, Z


def verify_proof(A: bytes, B: bytes, C: list[bytes], D: list[bytes], proof: bytes) -> bool:
    if len(proof) != 64 or not C or len(C) != len(D):
        return False
    try:
        c = r255.scalar_from_bytes(proof[:32])
        s = r255.scalar_from_bytes(proof[32:])
        M, Z = _composites(B, C, D)
        t2 = r255.add(r255.mul(s, A) if s else r255.IDENTITY, r255.mul(c, B) if c else r255.IDENTITY)
        t3 = r255.add(r255.mul(s, M) if s else r255.IDENTITY, r255.mul(c, Z) if c else r255.IDENTITY)
    except (ValueError, r255.InvalidElement):
        return False
    expected = hash_to_scalar(_lp(B) + _lp(M) + _lp(Z) + _lp(t2) + _lp(t3) + b"Challenge")
    return expected == c


def finalize_batch(states: list[BlindState], evaluated: list[bytes], proof: bytes,
                   pk: bytes, info: bytes) -> list[bytes]:
    """Проверяет пакетное доказательство эмитента и возвращает выходы PRF (64 байта каждый)."""
    if len(states) != len(evaluated):
        raise ProofError("batch size mismatch")
    for e in evaluated:
        r255.check(e)
    T = tweaked_key(pk, info)
    G = r255.mul_base(1)
    if not verify_proof(G, T, evaluated, [s.blinded for s in states], proof):
        raise ProofError("DLEQ proof verification failed")
    out = []
    for s, e in zip(states, evaluated):
        n = r255.mul(r255.scalar_invert(s.blind), e)
        out.append(hashlib.sha512(_lp(s.input) + _lp(info) + _lp(n) + b"Finalize").digest())
    return out
