"""Обёртка Bot API (veil/core/transport/telegram.py): успехи, ошибки сети и API, загрузка, скачивание."""
import asyncio
import json

import httpx
import pytest

from veil.core.transport.telegram import Bot, TelegramError, keyboard


def bot_with(handler):
    b = Bot("123:SECRET", base_url="https://tg.test")
    b._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return b


def ok(result):
    return httpx.Response(200, json={"ok": True, "result": result})


def run(coro):
    return asyncio.run(coro)


def test_empty_token_rejected():
    with pytest.raises(ValueError):
        Bot("")


def test_call_ok_drops_none_params():
    seen = {}

    def h(req):
        seen["path"], seen["body"] = req.url.path, json.loads(req.content)
        return ok({"message_id": 5})
    b = bot_with(h)
    r = run(b.send(1, "hi", reply_to=3, markup=keyboard([[("A", "a")]])))
    assert r["message_id"] == 5 and seen["path"] == "/bot123:SECRET/sendMessage"
    assert seen["body"]["reply_parameters"]["message_id"] == 3 and "entities" not in seen["body"]
    assert seen["body"]["reply_markup"] == {"inline_keyboard": [[{"text": "A", "callback_data": "a"}]]}


def test_api_error_and_retry_after_token_not_leaked():
    b = bot_with(lambda req: httpx.Response(429, json={"ok": False, "error_code": 429, "description": "Too Many",
                                                       "parameters": {"retry_after": 7}}))
    with pytest.raises(TelegramError) as e:
        run(b.call("getMe"))
    assert e.value.code == 429 and e.value.retry_after == 7 and "SECRET" not in str(e.value)


def test_network_error_and_bad_json():
    def boom(req):
        raise httpx.ConnectError("connect to https://tg.test/bot123:SECRET/x failed")
    with pytest.raises(TelegramError) as e:
        run(bot_with(boom).call("getMe"))
    assert e.value.code == 0 and "SECRET" not in str(e.value)
    with pytest.raises(TelegramError, match="bad JSON"):
        run(bot_with(lambda r: httpx.Response(502, text="<html>")).call("getMe"))


def test_upload_and_errors():
    seen = {}

    def h(req):
        seen["body"] = req.content
        return ok({"message_id": 9})
    assert run(bot_with(h).upload("sendDocument", "document", "a.bin", b"\x01\x02", "application/octet-stream",
                                  chat_id=1, caption="c", reply_parameters={"message_id": 2}))["message_id"] == 9
    assert b'name="reply_parameters"' in seen["body"] and b'{"message_id": 2}' in seen["body"]
    with pytest.raises(TelegramError):
        run(bot_with(lambda r: httpx.Response(400, json={"ok": False, "error_code": 400, "description": "x"}))
            .upload("sendDocument", "document", "a", b"", "x"))

    def boom(req):
        raise httpx.ReadTimeout("t")
    with pytest.raises(TelegramError):
        run(bot_with(boom).upload("sendDocument", "document", "a", b"", "x"))


def test_upload_group():
    seen = {}

    def h(req):
        seen["body"] = req.content.decode("utf-8", "replace")
        return ok([{"message_id": 1}, {"message_id": 2}])
    r = run(bot_with(h).upload_group(1, [("photo", "a.jpg", b"1", "image/jpeg"), ("photo", "b.jpg", b"2", "image/jpeg")],
                                     caption="подпись", caption_entities=[{"type": "bold", "offset": 0, "length": 2}]))
    media = json.loads(seen["body"].split('name="media"\r\n\r\n', 1)[1].split("\r\n--", 1)[0])
    assert len(r) == 2 and media[0]["media"] == "attach://f0" and media[0]["caption"] == "подпись"
    assert media[0]["caption_entities"][0]["type"] == "bold" and "caption" not in media[1]
    with pytest.raises(TelegramError):
        run(bot_with(lambda r: httpx.Response(200, json={"ok": False, "error_code": 400, "description": "x"}))
            .upload_group(1, [("photo", "a", b"1", "image/jpeg")]))

    def boom(req):
        raise httpx.ConnectError("x")
    with pytest.raises(TelegramError):
        run(bot_with(boom).upload_group(1, [("photo", "a", b"1", "image/jpeg")]))


def test_download_limits():
    def h(req):
        if req.url.path.endswith("/getFile"):
            fid = json.loads(req.content)["file_id"]
            return ok({"file_id": fid, "file_path": f"d/{fid}", "file_size": {"big": 999}.get(fid, 3)})
        if "/file/bot" in req.url.path:
            if req.url.path.endswith("/gone"):
                return httpx.Response(404)
            return httpx.Response(200, content=b"abc" if not req.url.path.endswith("/huge") else b"x" * 50)
        return ok(True)
    b = bot_with(h)
    assert run(b.download("ok", 10)) == b"abc"
    for fid in ("big", "gone", "huge"):
        with pytest.raises(TelegramError):
            run(b.download(fid, 10))


def test_edit_not_modified_answer_delete_swallow():
    def h(req):
        method = req.url.path.rsplit("/", 1)[1]
        desc = {"editMessageText": "Bad Request: message is not modified"}.get(method, "Bad Request: other")
        return httpx.Response(400, json={"ok": False, "error_code": 400, "description": desc})
    b = bot_with(h)
    run(b.edit(1, 2, "t"))          # «не изменилось» — не ошибка
    run(b.answer("q"))              # устаревший callback — не ошибка
    run(b.delete(1, 2))             # уже удалено — не ошибка

    def h2(req):
        return httpx.Response(400, json={"ok": False, "error_code": 400, "description": "Bad Request: other"})
    with pytest.raises(TelegramError):
        run(bot_with(h2).edit(1, 2, "t"))


def test_misc_methods():
    log = []

    def h(req):
        method = req.url.path.rsplit("/", 1)[1]
        log.append((method, json.loads(req.content or b"{}")))
        return ok({"copyMessage": {"message_id": 3}, "copyMessages": [{"message_id": 4}, {"message_id": 5}],
                   "getUpdates": [], "getMe": {"id": 1}, "sendMediaGroup": [{"message_id": 6}]}.get(method, True))
    b = bot_with(h)
    assert run(b.copy(1, 2, 3, caption="c")) == 3
    assert run(b.copy_many(1, 2, [9, 8], remove_caption=True)) == [4, 5]
    assert log[-1][1]["message_ids"] == [8, 9] and log[-1][1]["remove_caption"] is True
    assert run(b.get_updates(10)) == [] and log[-1][1]["allowed_updates"] == ["message", "callback_query"]
    assert run(b.get_me()) == {"id": 1}
    assert run(b.send_group(1, [{"type": "photo", "media": "x"}])) == [{"message_id": 6}]
    run(b.set_commands([("start", "старт")]))
    assert [m for m, _ in log[-2:]] == ["setMyCommands", "setChatMenuButton"]
    run(b.close())


def test_download_stops_at_limit_without_file_size():
    """getFile не сообщил размер: тело читается потоком и обрывается на пределе, а не целиком в память."""
    served = {"bytes": 0}

    def h(req):
        if req.url.path.endswith("/getFile"):
            return ok({"file_id": "f", "file_path": "d/f"})  # file_size нет
        if "/file/bot" in req.url.path:
            async def chunks():
                for _ in range(1000):
                    served["bytes"] += 1024
                    yield b"x" * 1024
            return httpx.Response(200, content=chunks())
        return ok(True)
    with pytest.raises(TelegramError, match="too big"):
        run(bot_with(h).download("f", 4096))
    assert served["bytes"] < 1000 * 1024  # дальше предела не читали


def test_upload_sanitizes_name_and_mime():
    seen = {}

    def h(req):
        seen["body"] = req.content
        return ok({"message_id": 1})
    run(bot_with(h).upload("sendDocument", "document", 'a"\r\nb.txt', b"x", "text/plain\r\nX-Evil: 1", chat_id=1))
    assert b"X-Evil" not in seen["body"] and b'filename="a_b.txt"' in seen["body"]
    assert b"Content-Type: application/octet-stream" in seen["body"]


def test_upload_bad_json_is_telegram_error():
    b = bot_with(lambda req: httpx.Response(502, content=b"<html>"))
    with pytest.raises(TelegramError, match="bad JSON"):
        run(b.upload("sendDocument", "document", "a", b"x", "text/plain", chat_id=1))
    with pytest.raises(TelegramError, match="bad JSON"):
        run(b.upload_group(1, [("photo", "a", b"x", "image/jpeg")]))
