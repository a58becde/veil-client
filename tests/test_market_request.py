"""Core.market_request и Core.server_sig_pk: интерфейс маркета ходит к серверу только через ядро."""
import asyncio

import pytest
from harness import KEYS_DOC, Env

from veil.core.protocol import b64


def test_market_request_rejects_foreign_op(tmp_path):
    e = Env(tmp_path)
    for op in ("post.publish", "keys.get", "nick.lookup", "device.get", ""):
        with pytest.raises(ValueError):
            asyncio.run(e.core.market_request(op, {}))


def test_market_request_uses_ephemeral_envelope(tmp_path):
    e = Env(tmp_path)
    seen = []

    async def request(op, mode, key, **kw):
        seen.append((op, mode, kw.get("body")))
        return {"ok": True}
    e.core.exchange.request = request
    for op in ("market.redeem", "market.key"):
        assert asyncio.run(e.core.market_request(op, {"x": 1})) == {"ok": True}
    assert seen == [("market.redeem", "ephemeral", {"x": 1}), ("market.key", "ephemeral", {"x": 1})]


def test_server_sig_pk_pinned_and_empty(tmp_path):
    e = Env(tmp_path)
    assert e.core.server_sig_pk() == b64.dec(KEYS_DOC["server_sig"])
    e.store.put("pinned_server_sig", None)
    assert e.core.server_sig_pk() == b""
