"""base64url без '=' (RFC 4648 §5). Декодирование строгое: только каноническая форма."""
from __future__ import annotations

import base64
import binascii


def enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def dec(s: str) -> bytes:
    if not isinstance(s, str) or "=" in s or len(s) % 4 == 1:
        raise ValueError("bad base64url")
    try:
        b = base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError("bad base64url") from e
    if enc(b) != s:
        raise ValueError("non-canonical base64url")
    return b
