"""Ники (spec/02): NFC, 2–32 графемы (≤128 кодовых точек, ≤3 знака на графему), без управляющих, bidi, zero-width, невидимых заполнителей и «точек-разделителей»."""
from __future__ import annotations

import unicodedata

import regex

MIN_GRAPHEMES = 2
MAX_GRAPHEMES = 32
# Против «Zalgo» и раздутой шапки: кодовых точек в нике и комбинирующих знаков на графему.
# Селекторы вида U+FE0E/U+FE0F в знаки не считаются (часть эмодзи). Так же проверяет сервер (identity.NormalizeNick).
MAX_CODEPOINTS = 128
MAX_MARKS = 3

# Символы, похожие на разделитель метки «·»: иначе можно нарисовать «Вася·7f3a9c» внутри ника.
_DOTS = {0x00B7, 0x0387, 0x16EB, 0x2022, 0x2027, 0x2219, 0x22C5, 0x30FB, 0xFF65}
# U+2800 (пустой символ Брайля) выглядит как пробел — из него складывался «пустой» ник; «№» путался бы с номером поста
# в шапке, по которому бот находит пересланный пост. Так же проверяет сервер (identity.forbidden).
_LOOKALIKE = {0x2800, 0x2116}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
_ZERO_WIDTH = {0x200B, 0x200C, 0x2060, 0xFEFF, 0x180E}
ZWJ = "\u200d"
_EMOJI_TAIL = {"\ufe0f"} | {chr(c) for c in range(0x1F3FB, 0x1F400)}  # VS16 и модификаторы кожи
_PRESENTATION = {"\ufe0e", "\ufe0f"}  # селекторы текстового/эмодзи-вида — только как часть эмодзи (_selector_ok)
# Невидимые заполнители (U+3164 HANGUL FILLER, U+034F …) и прочие селекторы вариантов: из них складывается
# «пустой» ник (spec/02, 2026-10-16). Так же проверяет сервер (identity.forbidden).
_INVISIBLE = regex.compile(r"[\p{Other_Default_Ignorable_Code_Point}\p{Variation_Selector}]")


def _zwj_ok(n: str, i: int) -> bool:
    """ZWJ разрешён только внутри эмодзи-последовательности: символ So (+VS16/модификатор) ZWJ символ So."""
    j = i - 1
    while j >= 0 and n[j] in _EMOJI_TAIL:
        j -= 1
    return j >= 0 and i + 1 < len(n) and unicodedata.category(n[j]) == "So" \
        and unicodedata.category(n[i + 1]) == "So"


def _selector_ok(n: str, i: int) -> bool:
    """Селектор вида стоит там, где он часть эмодзи: сразу после символа So («❤️», «☺︎») или в keycap «1️⃣»
    ([0-9#*] U+FE0F U+20E3). Между буквами он невидим и только множит написания ника. Так же — сервер (selectorOK)."""
    if i == 0:
        return False
    if unicodedata.category(n[i - 1]) == "So":
        return True
    return n[i] == "\ufe0f" and n[i - 1] in "0123456789#*" and i + 1 < len(n) and n[i + 1] == "\u20e3"


class NickError(ValueError):
    """Причина — понятным текстом для владельца (без кодов): что именно не так и как исправить."""


def _describe(ch: str) -> str:
    cp = ord(ch)
    if cp == 0x00A0 or (unicodedata.category(ch) == "Zs" and ch != " "):
        return "в нике неразрывный или особый пробел (часто появляется при копировании) — наберите пробел заново"
    if cp in _DOTS:
        return f"в нике точка «{ch}», похожая на разделитель метки — её использовать нельзя"
    if cp == 0x2116:
        return "в нике знак «№»: его не отличить от номера поста — напишите «N» или «No»"
    if cp == 0x2800 or ch in _PRESENTATION:
        return "в нике невидимый символ (часто появляется при копировании) — наберите ник вручную"
    if cp in _BIDI or cp in _ZERO_WIDTH or ch == ZWJ or _INVISIBLE.match(ch) or unicodedata.category(ch) == "Cf":
        return "в нике невидимый служебный символ (часто появляется при копировании) — наберите ник вручную"
    if unicodedata.category(ch) in ("Zl", "Zp") or ch in "\n\r":
        return "ник должен быть в одну строку"
    return f"в нике недопустимый символ U+{cp:04X}"


def normalize(nick: str) -> str:
    """Нормализует ник или бросает NickError. Пробелы по краям отрезаются, внутренние не схлопываются."""
    n = unicodedata.normalize("NFC", nick).strip()
    for i, ch in enumerate(n):
        cp = ord(ch)
        if ch == ZWJ:
            if not _zwj_ok(n, i):
                raise NickError(_describe(ch))
            continue
        if ch in _PRESENTATION:
            if not _selector_ok(n, i):
                raise NickError(_describe(ch))
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp") or cp in _DOTS or cp in _BIDI or cp in _ZERO_WIDTH \
                or cp in _LOOKALIKE or _INVISIBLE.match(ch):
            raise NickError(_describe(ch))
        if cat == "Zs" and ch != " ":
            raise NickError(_describe(ch))
    if "  " in n:
        raise NickError("в нике два пробела подряд — оставьте один")
    g = len(regex.findall(r"\X", n))
    if not MIN_GRAPHEMES <= g <= MAX_GRAPHEMES:
        raise NickError(f"длина ника {g} символ(ов), нужно от {MIN_GRAPHEMES} до {MAX_GRAPHEMES}")
    if len(n) > MAX_CODEPOINTS:
        raise NickError(f"в нике слишком много составных символов ({len(n)} кодовых точек, можно до {MAX_CODEPOINTS}) "
                        "— уберите часть эмодзи или значков")
    for gr in regex.findall(r"\X", n):
        if sum(1 for ch in gr if unicodedata.category(ch).startswith("M") and ch not in _PRESENTATION) > MAX_MARKS:
            raise NickError(f"над буквой «{gr[0]}» слишком много надстрочных знаков (можно до {MAX_MARKS})")
    return n
