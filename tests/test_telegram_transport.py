"""Транспорт Bot API: токен и адрес, пределы ответа, разбор, повтор при 429, answer/delete, copy, опрос."""
import asyncio
import gzip
import json
import logging
import traceback

import httpx
import pytest

from veil.core.transport import telegram as tg
from veil.core.transport.telegram import Bot, TelegramError

TOKEN = "123:SECRETtoken_x-y"


def run(coro):
    return asyncio.run(coro)


class Net:
    """Подставной транспорт: отвечает по очереди; sleeps — паузы, о которых попросил бот."""

    def __init__(self, *answers):
        self.answers, self.requests, self.sleeps = list(answers), [], []

    def __call__(self, req: httpx.Request):
        self.requests.append(req)
        a = self.answers.pop(0) if self.answers else asyncio.CancelledError()
        if isinstance(a, BaseException):
            raise a
        return a(req) if callable(a) else a

    def bot(self, **kw) -> Bot:
        async def sleep(seconds):
            self.sleeps.append(seconds)
        return Bot(TOKEN, base_url="https://tg.test", transport=httpx.MockTransport(self), sleep=sleep, **kw)

    def bodies(self) -> list[dict]:
        return [json.loads(r.content) for r in self.requests]


def ok(result):
    return httpx.Response(200, json={"ok": True, "result": result})


def fail(code=400, desc="x", status=200, **params):
    body = {"ok": False, "error_code": code, "description": desc}
    if params:
        body["parameters"] = params
    return httpx.Response(status, json=body)


class Chunks(httpx.AsyncByteStream):
    """Тело ответа кусками, без Content-Length."""

    def __init__(self, *chunks: bytes):
        self.chunks = chunks

    async def __aiter__(self):
        for c in self.chunks:
            yield c


def padded(total: int) -> bytes:
    """JSON-ответ ok ровно из total байт."""
    head, tail = b'{"ok":true,"result":"', b'"}'
    return head + b"a" * (total - len(head) - len(tail)) + tail


# --- токен и адрес ---

@pytest.mark.parametrize("token", ["", "abc", "123", "123:", ":abc", "12 3:abc", "123:abc\n", "123:ab/c", "1x:abc",
                                   "123:abc:def", "123:" + "a" * 129, "1" * 21 + ":abc", "123:абв"])
def test_bad_token_rejected_without_echo(token):
    with pytest.raises(ValueError) as e:
        Bot(token)
    assert token not in str(e.value) or token == ""


def test_token_limits_accepted():
    Bot("1" * 20 + ":" + "a" * 128)
    Bot("1:A_-")


@pytest.mark.parametrize("url", ["https://api.telegram.org", "https://api.telegram.org/", "https://h.test:8443",
                                 "http://127.0.0.1:8081", "http://localhost", "http://[::1]:8081/"])
def test_good_base_url(url):
    Bot(TOKEN, base_url=url)


@pytest.mark.parametrize("url", ["http://api.telegram.org", "http://127.0.0.2", "https://", "ftp://h.test",
                                 "https://u:p@h.test", "https://u@h.test", "https://h.test/x", "https://h.test?q=1",
                                 "https://h.test?", "https://h.test#f", "https://h.test:abc", "https://h .test",
                                 "https://h.test\\@evil", "", "api.telegram.org", "//h.test", "https://h.test:99999",
                                 "http://localhost.evil.test"])
def test_bad_base_url(url):
    with pytest.raises(ValueError):
        Bot(TOKEN, base_url=url)


def test_http_loopback_with_proxy_refused():
    """Через прокси токен ушёл бы открытым текстом."""
    with pytest.raises(ValueError):
        Bot(TOKEN, base_url="http://127.0.0.1:8081", proxy="socks5://127.0.0.1:1080")


def test_request_goes_to_normalized_url():
    net = Net(ok(True))
    run(net.bot().call("getMe"))
    assert str(net.requests[0].url) == f"https://tg.test/bot{TOKEN}/getMe"


# --- пределы ответа ---

def test_response_limit_exact_and_plus_one():
    exact = Net(httpx.Response(200, content=padded(tg.MAX_RESPONSE)))
    assert run(exact.bot().call("getMe")).startswith("a")
    over = Net(httpx.Response(200, content=padded(tg.MAX_RESPONSE + 1)))
    with pytest.raises(TelegramError, match="response too big") as e:
        run(over.bot().call("getMe"))
    assert e.value.code == 0


def test_upload_limit_exact_and_plus_one():
    def up(net):
        return net.bot().upload("sendDocument", "document", "a", b"x", "text/plain", chat_id=1)
    assert run(up(Net(httpx.Response(200, content=padded(tg.MAX_UPLOAD_RESPONSE))))).startswith("a")
    with pytest.raises(TelegramError, match="response too big"):
        run(up(Net(httpx.Response(200, content=padded(tg.MAX_UPLOAD_RESPONSE + 1)))))
    with pytest.raises(TelegramError, match="response too big"):
        run(Net(httpx.Response(200, content=padded(tg.MAX_UPLOAD_RESPONSE + 1)))
            .bot().upload_group(1, [("photo", "a", b"1", "image/jpeg")]))


def test_limit_without_content_length_counts_chunks():
    body = padded(tg.MAX_RESPONSE)
    chunks = [body[i:i + 65536] for i in range(0, len(body), 65536)]
    net = Net(httpx.Response(200, stream=Chunks(*chunks)))
    assert "content-length" not in net.answers[0].headers
    assert run(net.bot().call("getMe")).startswith("a")
    big = padded(tg.MAX_RESPONSE + 1)
    chunks = [big[i:i + 65536] for i in range(0, len(big), 65536)]
    with pytest.raises(TelegramError, match="response too big"):
        run(Net(httpx.Response(200, stream=Chunks(*chunks))).bot().call("getMe"))


def test_declared_length_over_limit_body_not_read():
    served = []

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            served.append(1)
            yield b"{}"
    r = httpx.Response(200, headers={"content-length": str(tg.MAX_RESPONSE + 1)}, stream=Body())
    with pytest.raises(TelegramError, match="response too big"):
        run(Net(r).bot().call("getMe"))
    assert served == []
    # ровно предел по заголовку — читаем
    r = httpx.Response(200, headers={"content-length": str(tg.MAX_RESPONSE)}, stream=Chunks(b'{"ok":true,"result":1}'))
    assert run(Net(r).bot().call("getMe")) == 1


def test_gzip_bomb_is_cut_after_decompression():
    raw = gzip.compress(padded(tg.MAX_RESPONSE + 4096), 9)
    assert len(raw) < 100_000  # сжатое тело маленькое, распакованное — больше предела
    r = httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Chunks(raw))
    with pytest.raises(TelegramError, match="response too big"):
        run(Net(r).bot().call("getMe"))


def test_gzip_normal_body_is_read():
    r = httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Chunks(gzip.compress(padded(100))))
    assert len(run(Net(r).bot().call("getMe"))) == 100 - len('{"ok":true,"result":"') - 2


def test_broken_gzip_is_telegram_error():
    r = httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Chunks(b"not gzip at all"))
    with pytest.raises(TelegramError) as e:
        run(Net(r).bot().call("getMe"))
    assert e.value.code == 0 and "SECRET" not in str(e.value)


def test_redirect_is_not_followed():
    net = Net(httpx.Response(302, headers={"location": "https://evil.test/steal"}, content=b"moved"), ok(True))
    with pytest.raises(TelegramError) as e:
        run(net.bot().call("getMe"))
    assert e.value.code == 302 and len(net.requests) == 1


# --- токен не виден в ошибках и журнале ---

def test_token_never_in_exception_or_log(caplog):
    caplog.set_level(logging.DEBUG)
    leak = httpx.ConnectError(f"connect to https://tg.test/bot{TOKEN}/getMe failed")
    for exc in (leak, httpx.ReadTimeout(f"{TOKEN}"), httpx.InvalidURL(TOKEN), httpx.StreamConsumed()):
        net = Net(exc)
        with pytest.raises(TelegramError) as e:
            run(net.bot().call("getMe"))
        err = e.value
        text = str(err) + repr(err) + "".join(traceback.format_exception(err))
        assert "SECRET" not in text and TOKEN not in text
        assert err.__cause__ is None and err.__context__ is None and err.code == 0
    with pytest.raises(TelegramError) as e:
        run(Net(leak).bot().upload("sendDocument", "document", "a", b"x", "text/plain", chat_id=1))
    assert e.value.__cause__ is None and "SECRET" not in str(e.value)
    assert "SECRET" not in caplog.text


def test_token_not_in_log_when_poll_and_answer_fail(caplog):
    caplog.set_level(logging.DEBUG)
    net = Net(fail(500, "boom", status=500), httpx.ConnectError(TOKEN))
    b = net.bot()
    with pytest.raises(asyncio.CancelledError):
        run(b.poll(lambda u: None, allowed=("message",)))
    run(Net(httpx.ConnectError(TOKEN)).bot().answer("q"))
    assert "SECRET" not in caplog.text


# --- разбор ответа ---

@pytest.mark.parametrize("resp", [
    httpx.Response(200, content=b"<html>"), httpx.Response(200, content=b"[1, 2]"), httpx.Response(200, content=b'"x"'),
    httpx.Response(200, content=b"null"), httpx.Response(200, content=b"\xff\xfe"),
    httpx.Response(200, content=b"[" * 100000), httpx.Response(200, json={"ok": True}),
    httpx.Response(200, json={"ok": "true", "result": 1}), httpx.Response(200, json={"ok": 1, "result": 1}),
    httpx.Response(200, json={"result": 1})])
def test_malformed_answers_are_telegram_errors(resp):
    with pytest.raises(TelegramError) as e:
        run(Net(resp).bot().call("getMe"))
    assert e.value.code in (200, 0) or e.value.description in ("bad JSON", "")


def test_ok_must_be_real_true():
    with pytest.raises(TelegramError):
        run(Net(httpx.Response(200, json={"ok": "true", "result": 5})).bot().call("getMe"))
    with pytest.raises(TelegramError, match="bad JSON"):
        run(Net(httpx.Response(200, json={"ok": True})).bot().call("getMe"))
    assert run(Net(httpx.Response(200, json={"ok": True, "result": None})).bot().call("getMe")) is None


def test_error_fields_are_checked():
    cases = [({"ok": False, "error_code": True, "description": "d"}, 502, 502, "d"),
             ({"ok": False, "error_code": "400", "description": "d"}, 502, 502, "d"),
             ({"ok": False, "error_code": 403, "description": 5}, 502, 403, ""),
             ({"ok": False, "description": "x" * 600}, 502, 502, "x" * 512),
             ({"ok": False, "error_code": 400, "parameters": [1]}, 502, 400, "")]
    for body, status, code, desc in cases:
        with pytest.raises(TelegramError) as e:
            run(Net(httpx.Response(status, json=body)).bot().call("getMe"))
        assert (e.value.code, e.value.description, e.value.retry_after) == (code, desc, 0)


@pytest.mark.parametrize("value,expect", [(7, 7), (0, 0), (-1, 0), (10 ** 9, 86400), (86400, 86400), ("5", 0),
                                          (True, 0), (5.0, 0), (None, 0), ([3], 0)])
def test_retry_after_parsing(value, expect):
    """Код 400 (не 429): повтора нет, retry_after разобран как есть."""
    with pytest.raises(TelegramError) as e:
        run(Net(fail(400, "x", retry_after=value)).bot().call("getMe"))
    assert e.value.retry_after == expect


# --- повтор при 429 ---

@pytest.mark.parametrize("value,sleeps", [(10, [10]), (1, [1]), (0, [1]), (-1, [1]), ("5", [1]), (True, [1]),
                                          (11, []), (10 ** 9, [])])
def test_429_retry_once_only_for_short_waits(value, sleeps):
    net = Net(fail(429, "Too Many", retry_after=value), ok({"id": 1}))
    b = net.bot()
    if sleeps:
        assert run(b.call("getMe")) == {"id": 1}
        assert net.sleeps == sleeps and len(net.requests) == 2
    else:
        with pytest.raises(TelegramError) as e:
            run(b.call("getMe"))
        assert e.value.code == 429 and net.sleeps == [] and len(net.requests) == 1


def test_second_429_raises():
    net = Net(fail(429, "x", retry_after=2), fail(429, "x", retry_after=2), ok(True))
    with pytest.raises(TelegramError) as e:
        run(net.bot().call("getMe"))
    assert e.value.code == 429 and net.sleeps == [2] and len(net.requests) == 2


@pytest.mark.parametrize("answer", [fail(500, "x", status=500), fail(403, "x"), httpx.ConnectError("x"),
                                    httpx.Response(502, content=b"<html>")])
def test_other_failures_are_not_retried(answer):
    net = Net(answer, ok(True))
    with pytest.raises(TelegramError):
        run(net.bot().call("getMe"))
    assert len(net.requests) == 1 and net.sleeps == []


def test_429_retry_for_upload_resends_file():
    net = Net(fail(429, "x", retry_after=1), ok({"message_id": 4}))
    r = run(net.bot().upload("sendDocument", "document", "a.bin", b"\x01\x02", "application/octet-stream", chat_id=1))
    assert r == {"message_id": 4} and len(net.requests) == 2
    assert all(b"\x01\x02" in q.content for q in net.requests) and net.sleeps == [1]


def test_429_http_status_without_json_is_retried_after_one_second():
    net = Net(httpx.Response(429, content=b"slow down"), ok(1))
    assert run(net.bot().call("getMe")) == 1 and net.sleeps == [1]


# --- answer и delete ---

def test_answer_never_raises(caplog):
    caplog.set_level(logging.INFO)
    run(Net(fail(400, "query is too old")).bot().answer("q"))
    run(Net(fail(400, "QUERY_ID_INVALID")).bot().answer("q", "t", True))
    assert not [r for r in caplog.records if r.name.startswith("veil")]
    for a in (fail(403, "blocked"), fail(401, "Unauthorized"), httpx.ConnectError("x"), fail(500, "x", status=500),
              fail(429, "x", retry_after=1000)):
        run(Net(a).bot().answer("q"))
    run(Net(fail(429, "x", retry_after=1), fail(429, "x", retry_after=1)).bot().answer("q"))
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 6
    assert "answerCallbackQuery" in caplog.text


@pytest.mark.parametrize("answer,result", [
    (ok(True), True),
    (fail(400, "Bad Request: message to delete not found"), True),
    (fail(400, "Bad Request: MESSAGE NOT FOUND"), True),
    (fail(400, "Bad Request: message can't be deleted"), False),
    (fail(400, "Bad Request: message can't be deleted for everyone"), False),
    (fail(400, ""), False)])
def test_delete_results(answer, result):
    assert run(Net(answer).bot().delete(1, 2)) is result


@pytest.mark.parametrize("answer", [fail(403, "x"), fail(401, "x"), fail(404, "not found"), fail(409, "x"),
                                    fail(429, "x", retry_after=99), fail(500, "x", status=500),
                                    fail(502, "x", status=502), httpx.ConnectError("x"),
                                    httpx.Response(200, content=b"junk")])
def test_delete_failures_propagate(answer):
    with pytest.raises(TelegramError):
        run(Net(answer).bot().delete(1, 2))


def test_delete_repeats_after_short_429():
    net = Net(fail(429, "x", retry_after=3), ok(True))
    assert run(net.bot().delete(1, 2)) is True and net.sleeps == [3]


# --- copy и copy_many ---

BAD_CHATS = [0, True, False, 2 ** 53, -2 ** 53, 1.5, None, "", "abc", "@ab", "@" + "a" * 33, "@1abc", "@abc def",
             "@abcd\n", " @abcd", "123", [1], b"@abcd"]
GOOD_CHATS = [1, -1, 2 ** 53 - 1, -(2 ** 53 - 1), -1004360023194, "@abcd", "@A" + "b" * 31]


@pytest.mark.parametrize("bad", BAD_CHATS)
def test_copy_rejects_bad_chat_refs_without_request(bad):
    net = Net(ok({"message_id": 1}))
    b = net.bot()
    for call in (lambda: b.copy(bad, 5, 7), lambda: b.copy(5, bad, 7), lambda: b.copy_many(bad, 5, [7]),
                 lambda: b.copy_many(5, bad, [7])):
        with pytest.raises(ValueError):
            run(call())
    assert net.requests == []


@pytest.mark.parametrize("good", GOOD_CHATS)
def test_copy_accepts_good_chat_refs(good):
    net = Net(ok({"message_id": 1}), ok([{"message_id": 1}]))
    b = net.bot()
    assert run(b.copy(good, 5, 7)) == 1 and run(b.copy_many(5, good, [7])) == [1]


@pytest.mark.parametrize("mid", [0, -1, True, 2 ** 53 + 1, 1.0, "1", None])
def test_copy_rejects_bad_message_id(mid):
    net = Net(ok({"message_id": 1}))
    with pytest.raises(ValueError):
        run(net.bot().copy(1, 2, mid))
    with pytest.raises(ValueError):
        run(net.bot().copy_many(1, 2, [3, mid]))
    assert net.requests == []


def test_copy_message_id_bounds():
    net = Net(ok({"message_id": 1}), ok({"message_id": 1}))
    run(net.bot().copy(1, 2, 1))
    run(net.bot().copy(1, 2, 2 ** 53))


@pytest.mark.parametrize("ids", [[], [1, 1], [5, 3, 5], list(range(1, 102)), [True], [1, False], "12", None, 5,
                                 [1, None]])
def test_copy_many_rejects_bad_id_lists(ids):
    net = Net(ok([]))
    with pytest.raises(ValueError):
        run(net.bot().copy_many(1, 2, ids))
    assert net.requests == []


def test_copy_many_boundaries_and_sorting():
    ids = list(range(100, 0, -1))
    net = Net(ok([{"message_id": i + 1000} for i in range(100)]), ok([{"message_id": 9}]))
    b = net.bot()
    assert len(run(b.copy_many(1, 2, ids))) == 100
    assert net.bodies()[0]["message_ids"] == list(range(1, 101))
    assert run(b.copy_many(1, 2, (7,), remove_caption=True)) == [9]
    assert net.bodies()[1]["remove_caption"] is True


@pytest.mark.parametrize("result", [{"message_id": 1}, "x", None, [{"message_id": 1}, {"id": 2}],
                                    [{"message_id": True}, {"message_id": 2}], [{"message_id": "1"}, {"message_id": 2}],
                                    [1, 2]])
def test_copy_many_bad_result(result):
    with pytest.raises(TelegramError, match="bad result"):
        run(Net(ok(result)).bot().copy_many(1, 2, [3, 4]))


@pytest.mark.parametrize("result", [[], [{"message_id": 1}], [{"message_id": 1}] * 3])
def test_copy_many_partial_copy(result):
    with pytest.raises(TelegramError, match="partial copy") as e:
        run(Net(ok(result)).bot().copy_many(1, 2, [3, 4]))
    assert e.value.method == "copyMessages" and e.value.code == 0


@pytest.mark.parametrize("result", [[], "x", None, {"id": 1}, {"message_id": True}, {"message_id": "1"}, 5])
def test_copy_bad_result(result):
    with pytest.raises(TelegramError, match="bad result"):
        run(Net(ok(result)).bot().copy(1, 2, 3))


# --- getUpdates ---

def test_get_updates_limit_and_bad_result():
    net = Net(ok([]), ok([]), ok({"update_id": 1}), ok(None))
    b = net.bot()
    run(b.get_updates(5))
    run(b.get_updates(5, 20, limit=1, allowed=("message", "managed_bot")))
    first, second = net.bodies()
    assert "limit" not in first and first["allowed_updates"] == ["message", "callback_query"]
    assert second["limit"] == 1 and second["timeout"] == 20 and second["allowed_updates"] == ["message", "managed_bot"]
    for _ in range(2):
        with pytest.raises(TelegramError, match="bad result"):
            run(b.get_updates(0))


# --- poll ---

def upd(i, **kw):
    return {"update_id": i, "message": {"text": str(i)}, **kw}


def test_poll_offsets_and_skips_bad_updates():
    seen = []
    batch = [upd(5), {"message": {}}, {"update_id": True}, {"update_id": "7"}, {"update_id": -1}, 42, None, [1],
             upd(3), upd(5), upd(6)]
    net = Net(ok(batch), ok([upd(7)]))

    async def handle(u):
        seen.append(u["update_id"])
    with pytest.raises(asyncio.CancelledError):
        run(net.bot().poll(handle, allowed=("message", "callback_query")))
    assert seen == [5, 6, 7]
    assert [b["offset"] for b in net.bodies()] == [0, 7, 8]


def test_poll_sync_handler_and_handler_errors_do_not_stop(caplog):
    seen = []

    def handle(u):
        seen.append(u["update_id"])
        if u["update_id"] == 1:
            raise RuntimeError("boom")
    net = Net(ok([upd(1), upd(2)]))
    with pytest.raises(asyncio.CancelledError):
        run(net.bot().poll(handle, allowed=("message",)))
    assert seen == [1, 2] and "boom" in caplog.text
    assert net.bodies()[0]["allowed_updates"] == ["message"] and net.bodies()[0]["timeout"] == 50


def test_poll_async_handler_error_is_logged_and_next_update_runs(caplog):
    seen = []

    async def handle(u):
        if u["update_id"] == 1:
            raise ValueError("async boom")
        seen.append(u["update_id"])
    with pytest.raises(asyncio.CancelledError):
        run(Net(ok([upd(1), upd(2)])).bot().poll(handle, allowed=("message",)))
    assert seen == [2] and "async boom" in caplog.text


def test_poll_cancel_in_handler_propagates():
    async def handle(u):
        raise asyncio.CancelledError
    net = Net(ok([upd(1)]), ok([upd(2)]))
    with pytest.raises(asyncio.CancelledError):
        run(net.bot().poll(handle, allowed=("message",)))
    assert len(net.requests) == 1


def test_poll_429_waits_but_no_longer_than_cap():
    net = Net(fail(429, "x", retry_after=100), fail(429, "x", retry_after=11), fail(429, "x", retry_after=3),
              fail(429, "x", retry_after=3), ok([upd(1)]))
    seen = []
    with pytest.raises(asyncio.CancelledError):
        run(net.bot().poll(lambda u: seen.append(1), allowed=("message",)))
    # 100 и 11 — вызов не повторяет, ждёт цикл; 3 + 3: вызов подождал 3 и получил второй 429, затем ждёт цикл
    assert net.sleeps == [tg.POLL_WAIT_MAX, 11, 3, 3] and seen == [1]


def test_poll_response_too_big_switches_to_limit_one():
    huge = httpx.Response(200, headers={"content-length": str(tg.MAX_RESPONSE + 1)}, stream=Chunks())
    net = Net(huge, ok([upd(1)]), ok([upd(2)]), ok([]), ok([upd(3)]))
    seen = []
    with pytest.raises(asyncio.CancelledError):
        run(net.bot().poll(lambda u: seen.append(u["update_id"]), allowed=("message",)))
    assert [b.get("limit") for b in net.bodies()] == [None, 1, 1, 1, None, None] and seen == [1, 2, 3]
    assert net.sleeps == []  # пауза не нужна


def test_poll_too_big_even_with_limit_one_backs_off():
    big = httpx.Response(200, headers={"content-length": str(tg.MAX_RESPONSE + 1)}, stream=Chunks())
    big2 = httpx.Response(200, headers={"content-length": str(tg.MAX_RESPONSE + 1)}, stream=Chunks())
    net = Net(big, big2)
    with pytest.raises(asyncio.CancelledError):
        run(net.bot().poll(lambda u: None, allowed=("message",)))
    assert net.sleeps == [3]


def test_poll_backoff_grows_and_resets_after_success(caplog):
    errors = [fail(502, "bad", status=502) for _ in range(8)]
    net = Net(*errors, ok([]), fail(500, "x", status=500), httpx.ConnectError("x"))
    with pytest.raises(asyncio.CancelledError):
        run(net.bot().poll(lambda u: None, allowed=("message",)))
    assert net.sleeps == [3, 6, 12, 24, 48, 60, 60, 60, 3, 6]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 10 and "getUpdates" in caplog.text


def test_poll_bad_result_and_bad_json_do_not_crash():
    net = Net(ok({"update_id": 1}), httpx.Response(200, content=b"[]"), ok([upd(1)]))
    seen = []
    with pytest.raises(asyncio.CancelledError):
        run(net.bot().poll(lambda u: seen.append(1), allowed=("message",)))
    assert seen == [1] and net.sleeps == [3, 6]
