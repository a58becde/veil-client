"""ristretto255 через libsodium (ctypes).

PyNaCl не экспортирует функции ristretto255, поэтому они берутся из системной libsodium (>= 1.0.18, см. _load).
Скаляры здесь — обычные int по модулю L, точки — 32 байта в канонической кодировке.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os

L = 2**252 + 27742317777372353535851937790883648493
ELEMENT_BYTES = 32
SCALAR_BYTES = 32


MIN_VERSION = (1, 0, 18)  # первая версия с ristretto255
# Каталоги системных библиотек: libsodium грузится по абсолютному пути из них (они принадлежат root), а не поиском
# по имени — тот зависит от LD_LIBRARY_PATH и подобных переменных окружения.
SYSTEM_LIB_DIRS = ("/usr/lib64", "/usr/lib", "/lib64", "/lib", "/usr/lib/x86_64-linux-gnu",
                   "/usr/lib/aarch64-linux-gnu", "/usr/local/lib", "/opt/homebrew/lib")
LIB_NAMES = ("libsodium.so.26", "libsodium.so.23", "libsodium.so", "libsodium.26.dylib", "libsodium.23.dylib",
             "libsodium.dylib")


def _version(lib: ctypes.CDLL) -> tuple[int, ...]:
    lib.sodium_version_string.restype = ctypes.c_char_p
    return tuple(int(x) for x in lib.sodium_version_string().decode().split(".")[:3])


def _candidates() -> list[str]:
    """Абсолютные пути в системных каталогах; имя для системного поиска — только если их нет (другая ОС)."""
    paths = [os.path.join(d, n) for d in SYSTEM_LIB_DIRS for n in LIB_NAMES if os.path.isfile(os.path.join(d, n))]
    return paths or list(filter(None, [ctypes.util.find_library("sodium")]))


def _load() -> ctypes.CDLL:
    """Системная libsodium: PyNaCl функций ristretto255 не экспортирует. Уязвимость CVE-2025-69277 касается
    crypto_core_ed25519_is_valid_point — Veil её не вызывает, а дистрибутивы исправляют её в своих сборках, не меняя
    номер версии (Ubuntu 24.04: 1.0.18-1ubuntu0.24.04.1), поэтому по номеру о ней не судим и не пугаем владельца."""
    for candidate in _candidates():
        try:
            lib = ctypes.CDLL(candidate)
        except OSError:
            continue
        if (hasattr(lib, "crypto_core_ristretto255_from_hash") and lib.sodium_init() >= 0
                and _version(lib) >= MIN_VERSION):
            return lib
    raise RuntimeError("нужна системная libsodium >= 1.0.18 с поддержкой ristretto255")


_lib = _load()


class InvalidElementError(ValueError):
    pass


def scalar_to_bytes(s: int) -> bytes:
    return (s % L).to_bytes(SCALAR_BYTES, "little")


def scalar_from_bytes(b: bytes) -> int:
    if len(b) != SCALAR_BYTES:
        raise ValueError("scalar length")
    s = int.from_bytes(b, "little")
    if s >= L:
        raise ValueError("non-canonical scalar")
    return s


def is_valid(p: bytes) -> bool:
    return len(p) == ELEMENT_BYTES and _lib.crypto_core_ristretto255_is_valid_point(p) == 1


def check(p: bytes) -> bytes:
    """Проверка десериализованной точки: каноничная и не нейтральная (RFC 9497, DeserializeElement)."""
    if not is_valid(p):
        raise InvalidElementError("invalid ristretto255 element")
    if p == IDENTITY:
        raise InvalidElementError("identity element")
    return p


def from_uniform(h64: bytes) -> bytes:
    if len(h64) != 64:
        raise ValueError("from_uniform needs 64 bytes")
    out = ctypes.create_string_buffer(ELEMENT_BYTES)
    _lib.crypto_core_ristretto255_from_hash(out, h64)
    return out.raw


def scalar_invert(s: int) -> int:
    """1/s по модулю L за постоянное время (libsodium): обращение ослепляющего скаляра в Finalize. pow(s, -1, L) —
    алгоритм Евклида, его время зависит от значения."""
    out = ctypes.create_string_buffer(SCALAR_BYTES)
    if _lib.crypto_core_ristretto255_scalar_invert(out, scalar_to_bytes(s)) != 0:
        raise ValueError("zero scalar has no inverse")
    return int.from_bytes(out.raw, "little")


def mul(s: int, p: bytes) -> bytes:
    out = ctypes.create_string_buffer(ELEMENT_BYTES)
    if _lib.crypto_scalarmult_ristretto255(out, scalar_to_bytes(s), p) != 0:
        raise InvalidElementError("scalar multiplication gave identity")
    return out.raw


def mul_base(s: int) -> bytes:
    out = ctypes.create_string_buffer(ELEMENT_BYTES)
    if _lib.crypto_scalarmult_ristretto255_base(out, scalar_to_bytes(s)) != 0:
        raise InvalidElementError("scalar multiplication gave identity")
    return out.raw


def add(p: bytes, q: bytes) -> bytes:
    out = ctypes.create_string_buffer(ELEMENT_BYTES)
    if _lib.crypto_core_ristretto255_add(out, p, q) != 0:
        raise InvalidElementError("invalid point in addition")
    return out.raw


IDENTITY = bytes(32)
