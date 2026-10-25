"""Наблюдатель вызовов Bot API и точка входа апдейта UI.handle_update."""
import asyncio
import json
import logging

import httpx
from harness import Env

from veil.core.transport.telegram import Bot

TOKEN = "123:SECRETTOKEN"


def bot_with(handler, observer):
    async def no_sleep(_seconds):
        return None
    return Bot(TOKEN, base_url="https://tg.test", transport=httpx.MockTransport(handler), sleep=no_sleep,
               observer=observer)


def ok(result):
    return httpx.Response(200, json={"ok": True, "result": result})


def test_observer_gets_method_params_result_without_token():
    seen = []
    b = bot_with(lambda req: ok({"message_id": 5}), lambda *a: seen.append(a))
    asyncio.run(b.send(7, "привет"))
    assert len(seen) == 1
    method, params, result = seen[0]
    assert method == "sendMessage" and params["chat_id"] == 7 and params["text"] == "привет"
    assert result == {"message_id": 5}
    assert "SECRETTOKEN" not in repr(seen) and "tg.test" not in repr(seen)


def test_observer_upload_shows_file_meta_not_bytes():
    seen = []
    b = bot_with(lambda req: ok({"message_id": 9}), lambda *a: seen.append(a))
    asyncio.run(b.upload("sendDocument", "document", "a.bin", b"\x01\x02\x03", "application/octet-stream", chat_id=1))
    method, params, _ = seen[0]
    assert method == "sendDocument" and params["chat_id"] == "1"
    assert params["_file"] == {"field": "document", "name": "a.bin", "mime": "application/octet-stream", "size": 3}
    assert "SECRETTOKEN" not in repr(seen) and b"\x01\x02\x03" not in json.dumps(params).encode()


def test_observer_upload_group_lists_files():
    seen = []
    b = bot_with(lambda req: ok([{"message_id": 1}, {"message_id": 2}]), lambda *a: seen.append(a))
    asyncio.run(b.upload_group(1, [("photo", "a.jpg", b"xx", "image/jpeg"), ("photo", "b.jpg", b"yyy", "image/jpeg")]))
    method, params, _ = seen[0]
    assert method == "sendMediaGroup" and [f["size"] for f in params["_file"]] == [2, 3]


def test_observer_exception_does_not_break_call(caplog):
    def bad(method, params, result):
        raise RuntimeError(f"boom {params}")
    b = bot_with(lambda req: ok({"message_id": 5}), bad)
    with caplog.at_level(logging.WARNING):
        r = asyncio.run(b.send(7, "секрет-текст"))
    assert r["message_id"] == 5
    assert "секрет-текст" not in caplog.text and "RuntimeError" in caplog.text


def test_observer_not_called_on_failure_and_service_calls():
    seen = []

    def h(req):
        if req.url.path.endswith("/sendMessage"):
            return httpx.Response(400, json={"ok": False, "error_code": 400, "description": "bad"})
        if req.url.path.endswith("/getUpdates"):
            return ok([])
        if req.url.path.endswith("/getFile"):
            return ok({"file_path": "x", "file_size": 1})
        return httpx.Response(200, content=b"z")
    b = bot_with(h, lambda *a: seen.append(a[0]))
    try:
        asyncio.run(b.send(7, "x"))
    except Exception:
        pass
    asyncio.run(b.get_updates(0, 0))
    assert asyncio.run(b.download("f", 10)) == b"z"
    assert seen == []


def test_no_observer_by_default():
    asyncio.run(bot_with(lambda req: ok({"message_id": 1}), None).send(1, "x"))


def test_handle_update_routes_like_before(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("/help"))  # стенд подаёт апдейты через UI.handle_update
    assert any("Как пользоваться" in str(p.get("text", "")) for _m, p in e.tg.calls)
    assert not hasattr(e.ui, "_route")
