"""BIP-39: 12 слов (128 бит) и seed — эталонная реализация `python-mnemonic` (Trezor, авторы стандарта).

Своё здесь только приведение ввода (регистр, лишние пробелы) и понятные ошибки. Проверка: официальные векторы
Trezor (слова и seed с паролем «TREZOR») в tests/test_vectors.py.
"""
from __future__ import annotations

import unicodedata

from mnemonic import Mnemonic

_M = Mnemonic("english")
_WORDS = set(_M.wordlist)


class MnemonicError(ValueError):
    pass


def generate() -> str:
    """Новая мнемоника: 128 бит из secrets.token_bytes (генератор ОС)."""
    return _M.generate(strength=128)


def from_entropy(entropy: bytes) -> str:
    return _M.to_mnemonic(entropy)


def normalize(mnemonic: str) -> str:
    return " ".join(unicodedata.normalize("NFKD", mnemonic).lower().split())


def validate(mnemonic: str) -> str:
    """Возвращает нормализованную мнемонику или бросает MnemonicError (неизвестное слово, контрольная сумма)."""
    words = normalize(mnemonic).split(" ")
    if len(words) != 12:
        raise MnemonicError("нужно 12 слов")
    for w in words:
        if w not in _WORDS:
            raise MnemonicError(f"неизвестное слово: {w}")
    m = " ".join(words)
    if not _M.check(m):
        raise MnemonicError("неверная контрольная сумма (слово введено с ошибкой или не на своём месте)")
    return m


def to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return Mnemonic.to_seed(mnemonic, passphrase)
