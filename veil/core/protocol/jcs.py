"""RFC 8785 (JCS) для подмножества JSON, которое использует протокол.

Допустимы: объекты, массивы, строки, bool, null, целые числа в диапазоне ±(2^53-1).
Дробные числа протоколом запрещены, поэтому сериализация чисел ES6 не нужна.
"""
from __future__ import annotations

import json
from typing import Any

MAX_SAFE_INT = 2**53 - 1


class JCSError(ValueError):
    pass


def _str(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as e:
        raise JCSError("lone surrogate in string") from e
    # json.dumps с ensure_ascii=False экранирует ровно то, что требует JCS:
    # " \\ \b \f \n \r \t и прочие U+0000..U+001F как \u00xx (строчные hex).
    return json.dumps(s, ensure_ascii=False)


def _enc(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise JCSError("integer out of safe range")
        out.append(str(v))
    elif isinstance(v, str):
        out.append(_str(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _enc(x, out)
        out.append("]")
    elif isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise JCSError("object key must be string")
        out.append("{")
        for i, k in enumerate(sorted(v, key=lambda k: k.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(_str(k))
            out.append(":")
            _enc(v[k], out)
        out.append("}")
    else:
        raise JCSError(f"unsupported type {type(v).__name__}")


def canonicalize(v: Any) -> bytes:
    out: list[str] = []
    _enc(v, out)
    return "".join(out).encode("utf-8")


def _no_dups(pairs: list[tuple[str, Any]]) -> dict:
    d: dict = {}
    for k, v in pairs:
        if k in d:
            raise JCSError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _no_float(s: str):
    raise JCSError("non-integer number")


def strict_loads(data: bytes | str) -> Any:
    """Разбор JSON для протокола (spec/04, «Строгий JSON»): дубли ключей, дробные числа, NaN, целые вне ±(2^53−1),
    одиночные суррогаты и вложенность глубже 32 отклоняются — как у сервера."""
    def _const(name: str):
        raise JCSError(f"constant {name} not allowed")
    v = json.loads(data, object_pairs_hook=_no_dups, parse_float=_no_float, parse_constant=_const)
    _check_tree(v, 1)
    return v


MAX_DEPTH = 32  # как у сервера (spec/04, «Строгий JSON»)


def _check_tree(v: Any, depth: int) -> None:
    """Глубина вложенности, одиночные суррогаты (\\ud800 без пары) и целые вне безопасного диапазона: сервер отвергает
    всё это, клиент — так же (иначе подпись по канонической форме считалась бы по-разному)."""
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise JCSError("lone surrogate")
        return
    if isinstance(v, int) and not isinstance(v, bool):
        if abs(v) > MAX_SAFE_INT:
            raise JCSError("integer out of safe range")
        return
    if isinstance(v, (dict, list)):
        if depth > MAX_DEPTH:
            raise JCSError("nesting too deep")
        for k, x in (v.items() if isinstance(v, dict) else enumerate(v)):
            if isinstance(k, str):
                _check_tree(k, depth)
            _check_tree(x, depth + 1)
