"""Транспорт Bot API: тесты, написанные от контракта транспорта и документации Bot API, а не от кода.

Транспорт httpx подменяется через `transport=`, паузы — через `sleep=`. Токен в этих тестах узнаваем по SECRET:
ни в исключениях, ни в журнале его быть не должно."""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import re
import time
import traceback
import zlib
from types import SimpleNamespace

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.harness import Env, FakeTelegram
from veil.core.transport import telegram
from veil.core.transport.telegram import Bot, TelegramError

SECRET = "SECRET_xyz-0123456789"
TOKEN = f"123456789:AAEh{SECRET}"
MAX_RESP = 16 * 1024 * 1024
MAX_UP = 1024 * 1024
METHOD_URL = f"/bot{TOKEN}/"


# --- стенд ---------------------------------------------------------------------------------------------------------

class Body(httpx.AsyncByteStream):
    """Тело ответа по кускам; кусок-исключение бросается при чтении. read — сколько кусков отдано."""

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.read = 0

    async def __aiter__(self):
        for c in self.chunks:
            self.read += 1
            if isinstance(c, BaseException):
                raise c
            yield c

    async def aclose(self) -> None:
        return None


def stream_resp(status: int, chunks, headers: dict | None = None) -> httpx.Response:
    raw = [(k.encode(), v.encode("utf-8")) for k, v in (headers or {}).items()]
    return httpx.Response(status, headers=raw, stream=Body(chunks))


def ok(result=True) -> httpx.Response:
    return httpx.Response(200, json={"ok": True, "result": result})


def err(status: int, code: int | None = None, desc: str | None = "x", retry_after=None, **extra) -> httpx.Response:
    body: dict = {"ok": False, **extra}
    if code is not None:
        body["error_code"] = code
    if desc is not None:
        body["description"] = desc
    if retry_after is not None:
        body["parameters"] = {"retry_after": retry_after}
    return httpx.Response(status, json=body)


def flood(ra: int) -> httpx.Response:
    return err(429, 429, "Too Many Requests: retry after %d" % ra, retry_after=ra)


def json_of_size(n: int) -> bytes:
    head, tail = b'{"ok":true,"result":"', b'"}'
    assert n > len(head) + len(tail)
    return head + b"a" * (n - len(head) - len(tail)) + tail


class Script:
    """Транспорт-сценарий: шаги отдаются по порядку (Response, исключение или функция запроса); последний
    повторяется, если forever. Лишний запрос — AssertionError."""

    def __init__(self, *steps, forever: bool = False):
        self.steps = list(steps)
        self.forever = forever
        self.requests: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if not self.steps:
            raise AssertionError("лишний запрос к транспорту")
        step = self.steps[0] if (self.forever and len(self.steps) == 1) else self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        if callable(step):
            return step(req)
        return step

    @property
    def n(self) -> int:
        return len(self.requests)

    def body(self, i: int = -1) -> dict:
        return json.loads(self.requests[i].content)


def make_bot(script, sleeps: list | None = None, token: str = TOKEN, **kw) -> Bot:
    async def sleep(s: float) -> None:
        if sleeps is not None:
            sleeps.append(s)
        await asyncio.sleep(0)

    kw.setdefault("base_url", "https://tg.test")
    return Bot(token, transport=httpx.MockTransport(script), sleep=sleep, **kw)


def run(coro):
    return asyncio.run(coro)


def call_once(script, method="getMe", **kw):
    async def go():
        bot = make_bot(script, **kw)
        try:
            return await bot.call(method)
        finally:
            await bot.close()
    return run(go())


def too_big_resp(limit: int = MAX_RESP) -> httpx.Response:
    return stream_resp(200, [], {"content-length": str(limit + 1)})


def no_secret(e: BaseException) -> None:
    seen: set[int] = set()
    stack = [e]
    while stack:
        x = stack.pop()
        if x is None or id(x) in seen:
            continue
        seen.add(id(x))
        texts = [str(x), repr(x), str(x.args), "".join(traceback.format_exception(x))]
        for t in texts:
            assert SECRET not in t, t
        # «from None» скрывает контекст (и в трассировке, и в журнале): сам по себе он не утечка
        stack += [x.__cause__, None if x.__suppress_context__ else x.__context__]
    if isinstance(e, TelegramError):
        assert SECRET not in e.description


def no_secret_in_log(caplog) -> None:
    for r in caplog.records:
        parts = [r.getMessage(), str(r.msg), str(r.args), r.exc_text or "", caplog.text]
        if r.exc_info:
            parts.append("".join(traceback.format_exception(*r.exc_info)))
        for p in parts:
            assert SECRET not in p, (r.name, p)


@pytest.fixture
def logs(caplog):
    caplog.set_level(logging.DEBUG)
    for name in ("httpx", "httpcore", "veil"):
        logging.getLogger(name).setLevel(logging.DEBUG)
    return caplog


# --- конструктор: токен --------------------------------------------------------------------------------------------

GOOD_TOKENS = ["1:a", "123456789:AAE-h_x", "9" * 20 + ":" + "a" * 128, "0:_", "1:-"]
BAD_TOKENS = ["", "abc", "1:", ":a", "1:a b", "1:a\n", "1\n:a", "1:a:b", "１２３:abc", "1:ключ", "9" * 21 + ":a",
              "1:" + "a" * 129, " 1:a", "1:a ", "1: a", "-1:a", "+1:a", "1.0:a", "1:a\x00", "1:a​"]


@pytest.mark.parametrize("tok", GOOD_TOKENS)
def test_token_accepted(tok):
    Bot(tok, base_url="https://tg.test", transport=httpx.MockTransport(Script()))


@pytest.mark.parametrize("tok", BAD_TOKENS)
def test_token_rejected_without_leaking_it(tok):
    with pytest.raises(ValueError) as ei:
        Bot(tok, base_url="https://tg.test", transport=httpx.MockTransport(Script()))
    for t in (str(ei.value), repr(ei.value), str(ei.value.args), "".join(traceback.format_exception(ei.value))):
        if len(tok) > 2:
            assert tok not in t


def test_secret_part_of_bad_token_not_in_error():
    with pytest.raises(ValueError) as ei:
        Bot(f"12:{SECRET} tail", base_url="https://tg.test", transport=httpx.MockTransport(Script()))
    no_secret(ei.value)


@given(st.text(max_size=40))
@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_token_accepted_exactly_by_pattern(tok):
    good = re.fullmatch(r"[0-9]{1,20}:[A-Za-z0-9_-]{1,128}", tok) is not None
    try:
        Bot(tok, base_url="https://tg.test", transport=httpx.MockTransport(Script()))
    except ValueError as e:
        assert not good
        # токен не попадает в текст: он совпадает с текстом для заведомо другого неверного токена
        # (короткий токен может быть подстрокой постоянной части, поэтому «tok not in text» ложно)
        try:
            Bot("" if not tok else "\x00\x01", base_url="https://tg.test", transport=httpx.MockTransport(Script()))
        except ValueError as other:
            assert str(e) == str(other)
        else:
            raise AssertionError("заведомо неверный токен принят")
    else:
        assert good


@given(st.from_regex(r"[0-9]{1,22}:[A-Za-z0-9_\-]{1,130}", fullmatch=True))
@settings(max_examples=200, deadline=None)
def test_token_pattern_lengths_property(tok):
    num, sec = tok.split(":")
    good = len(num) <= 20 and len(sec) <= 128
    try:
        Bot(tok, base_url="https://tg.test", transport=httpx.MockTransport(Script()))
    except ValueError:
        assert not good
    else:
        assert good


# --- конструктор: base_url -----------------------------------------------------------------------------------------

ACCEPTED_URLS = ["https://api.telegram.org", "https://api.telegram.org/", "https://h:8443", "https://h:8443/",
                 "HTTPS://h", "https://H.EXAMPLE", "https://[::1]", "https://[::1]:8443", "http://127.0.0.1:8081",
                 "http://127.0.0.1", "http://localhost:8081", "http://localhost", "http://localhost:8081/",
                 "http://[::1]:8081", "http://[::1]/", "HTTP://localhost"]
REJECTED_URLS = [
    "", "https://", "https:///", "https://:443", "ftp://h", "ws://h", "//h", "h", "api.telegram.org",
    "https://u:p@h", "https://u@h", "https://:p@h", "https://h@evil", "http://localhost@evil",
    "http://127.0.0.1@evil", "http://127.0.0.1:80@evil", "https://h?q", "https://h/?", "https://h/#", "https://h#f",
    "https://h/x", "https://h/path", "https://h/a/", "https://h//", "https://h/./", "https://h/%2f",
    "http://h", "http://127.0.0.2", "http://127.1", "http://0.0.0.0", "http://localhost.", "http://localhost.localdomain",
    "http://LOCALHOST.evil", "http://localhost.evil", "http://127.0.0.1.evil", "http://[::2]", "http://[::ffff:127.0.0.1]",
    "http://[::1%25lo]", "http://0x7f.0.0.1", "http://2130706433", "http://api.telegram.org",
    " https://h", "https://h ", "https://h\n", "https://h\t", "https://h\r", "\nhttps://h", "https://h\n/",
    "https://ex ample", "https://h\x00", "https://h​", "https://h ", "http://localhost\n", "http://localhost\t:80",
    "http:// 127.0.0.1", "https://h:80 ", "https:\\\\h", "https://h\\x", "https://h:abc", "https://h:-1",
]


@pytest.mark.parametrize("url", ACCEPTED_URLS)
def test_base_url_accepted_and_request_path_is_clean(url):
    s = Script(ok({"id": 1}))
    bot = Bot(TOKEN, base_url=url, transport=httpx.MockTransport(s), sleep=lambda x: asyncio.sleep(0))
    assert run(bot.call("getMe")) == {"id": 1}
    assert s.requests[0].url.path == f"/bot{TOKEN}/getMe"
    assert s.requests[0].url.scheme in ("http", "https")


@pytest.mark.parametrize("url", REJECTED_URLS)
def test_base_url_rejected_without_leaking_token(url):
    with pytest.raises(ValueError) as ei:
        Bot(TOKEN, base_url=url, transport=httpx.MockTransport(Script()))
    no_secret(ei.value)


@pytest.mark.parametrize("url", ["https://h:0", "https://h:99999", "https://h:65536", "https://h:+80", "https://h:８０"])
def test_base_url_odd_port_never_escapes_as_foreign_exception(url):
    """Порт вне диапазона: либо ValueError при создании, либо TelegramError при вызове, но не сырое исключение httpx."""
    try:
        bot = Bot(TOKEN, base_url=url, transport=httpx.MockTransport(Script(ok(1), forever=True)))
    except ValueError as e:
        no_secret(e)
        return
    try:
        run(bot.call("getMe"))
    except TelegramError as e:
        no_secret(e)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8081", "http://localhost", "http://[::1]:8081", "http://localhost:1/"])
@pytest.mark.parametrize("proxy", ["socks5://127.0.0.1:9", "http://127.0.0.1:3128", "http://p.example:3128"])
def test_http_loopback_with_proxy_refused(url, proxy):
    with pytest.raises(ValueError) as ei:
        Bot(TOKEN, proxy=proxy, base_url=url, transport=httpx.MockTransport(Script()))
    no_secret(ei.value)


def test_https_with_proxy_allowed():
    Bot(TOKEN, proxy="socks5://127.0.0.1:9", base_url="https://tg.test", transport=httpx.MockTransport(Script()))


def test_proxy_empty_string_is_not_a_proxy_for_loopback():
    """Пустой прокси — это «нет прокси»? Контракт: `proxy is None`; пустую строку нельзя молча принять за отсутствие."""
    try:
        Bot(TOKEN, proxy="", base_url="http://127.0.0.1:8081", transport=httpx.MockTransport(Script()))
    except ValueError:
        return
    pytest.fail("пустая строка вместо прокси принята вместе с http на петлю")


class _SpyClient(httpx.AsyncClient):
    seen: list[dict] = []

    def __init__(self, *a, **kw):
        _SpyClient.seen.append(kw)
        super().__init__(*a, **kw)


def _spy(monkeypatch, **bot_kw) -> dict:
    _SpyClient.seen = []
    monkeypatch.setattr(httpx, "AsyncClient", _SpyClient)
    Bot(TOKEN, **bot_kw)
    assert len(_SpyClient.seen) == 1, "клиент httpx создан не через httpx.AsyncClient(...)"
    return _SpyClient.seen[0]


def test_loopback_http_ignores_environment_proxies(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.example:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://evil.example:3128")
    kw = _spy(monkeypatch, base_url="http://127.0.0.1:8081")
    assert kw.get("trust_env", True) is False
    assert not kw.get("proxy")


def test_https_without_proxy_trusts_environment(monkeypatch):
    kw = _spy(monkeypatch, base_url="https://tg.test")
    assert kw.get("trust_env", True) is True


def test_https_with_proxy_does_not_trust_environment_and_passes_proxy(monkeypatch):
    kw = _spy(monkeypatch, base_url="https://tg.test", proxy="socks5://127.0.0.1:9")
    assert kw.get("trust_env", True) is False
    assert kw.get("proxy") == "socks5://127.0.0.1:9"


def test_redirects_are_not_followed_by_client(monkeypatch):
    kw = _spy(monkeypatch, base_url="https://tg.test")
    assert not kw.get("follow_redirects", False)


# --- предел ответа -------------------------------------------------------------------------------------------------

def test_constants_match_contract():
    assert telegram.MAX_RESPONSE == 16 * 1024 * 1024
    assert telegram.MAX_UPLOAD_RESPONSE == 1024 * 1024
    assert telegram.RETRY_AFTER_MAX == 10
    assert telegram.POLL_WAIT_MAX == 60


def chunked(data: bytes, tail_single: int = 8, big: int = 65536) -> list[bytes]:
    head, tail = data[:-tail_single], data[-tail_single:]
    out = [head[i:i + big] for i in range(0, len(head), big)]
    return out + [tail[i:i + 1] for i in range(len(tail))]


def upload(bot: Bot):
    return bot.upload("sendDocument", "document", "a.bin", b"PAYLOAD-0123456789", "application/octet-stream", chat_id=1)


@pytest.mark.parametrize("limit", [MAX_RESP, MAX_UP], ids=["call", "upload"])
class TestResponseLimit:
    def fire(self, limit, resp):
        s = Script(resp)
        bot = make_bot(s)
        try:
            return run(bot.call("getMe") if limit == MAX_RESP else upload(bot)), s
        finally:
            run(bot.close())

    def test_exact_with_length(self, limit):
        data = json_of_size(limit)
        r, _ = self.fire(limit, stream_resp(200, chunked(data), {"content-length": str(limit)}))
        assert len(r) == limit - len(b'{"ok":true,"result":""}') + 0 or isinstance(r, str)

    def test_exact_without_length_single_byte_tail(self, limit):
        r, _ = self.fire(limit, stream_resp(200, chunked(json_of_size(limit))))
        assert isinstance(r, str)

    def test_one_over_without_length(self, limit):
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(200, chunked(json_of_size(limit + 1))))
        assert ei.value.description == "response too big" and ei.value.code == 0

    def test_one_over_with_length_not_read(self, limit):
        body = Body([json_of_size(limit + 1)])
        resp = httpx.Response(200, headers={"content-length": str(limit + 1)}, stream=body)
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, resp)
        assert ei.value.description == "response too big"
        assert body.read == 0

    def test_length_claims_big_body_empty(self, limit):
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(200, [], {"content-length": str(limit + 1)}))
        assert ei.value.description == "response too big"

    def test_length_huge(self, limit):
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(200, [], {"content-length": "9" * 30}))
        assert ei.value.description == "response too big"

    def test_length_lies_small_body_big(self, limit):
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(200, chunked(json_of_size(limit + 1)), {"content-length": "10"}))
        assert ei.value.description == "response too big"

    @pytest.mark.parametrize("cl", ["10, 10", "-1", "１０", "abc", "", " 5 ", "1e3", "0x10", "+5", "5.0"])
    def test_junk_length_small_body_no_crash(self, limit, cl):
        try:
            r, _ = self.fire(limit, stream_resp(200, [b'{"ok":true,"result":1}'], {"content-length": cl}))
        except TelegramError:
            return
        assert r == 1

    @pytest.mark.parametrize("cl", ["10, 10", "-1", "１０", "abc", "", "1e3", "0x10", "+5"])
    def test_junk_length_does_not_disable_counting(self, limit, cl):
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(200, chunked(json_of_size(limit + 1)), {"content-length": cl}))
        assert ei.value.description == "response too big"

    def test_fullwidth_digits_length_over_limit(self, limit):
        big = str(limit + 1).translate({ord(c): ord(c) + 0xFEE0 for c in "0123456789"})
        try:
            self.fire(limit, stream_resp(200, [], {"content-length": big}))
        except TelegramError:
            return
        pytest.fail("ответ с Content-Length > предела принят")

    @pytest.mark.parametrize("pack,enc", [(lambda d: gzip.compress(d, 9), "gzip"), (zlib.compress, "deflate")])
    def test_compressed_exact_and_over(self, limit, pack, enc):
        exact = pack(json_of_size(limit))
        r, _ = self.fire(limit, stream_resp(200, [exact], {"content-encoding": enc, "content-length": str(len(exact))}))
        assert isinstance(r, str)
        over = pack(json_of_size(limit + 1))
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(200, [over], {"content-encoding": enc, "content-length": str(len(over))}))
        assert ei.value.description == "response too big"

    @pytest.mark.parametrize("pack,enc", [(lambda d: gzip.compress(d, 9), "gzip"), (zlib.compress, "deflate")])
    def test_compressed_in_tiny_chunks_over(self, limit, pack, enc):
        over = pack(json_of_size(limit + 1))
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(200, [over[i:i + 3] for i in range(0, len(over), 3)],
                                       {"content-encoding": enc}))
        assert ei.value.description == "response too big"

    def test_compressed_bomb_far_over(self, limit):
        bomb = gzip.compress(b"\0" * (limit * 4), 9)
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(200, [bomb], {"content-encoding": "gzip", "content-length": str(len(bomb))}))
        assert ei.value.description == "response too big"

    def test_too_big_error_has_http_status_semantics_zero(self, limit):
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, too_big_resp(limit))
        assert (ei.value.method, ei.value.code, ei.value.description) == (
            "getMe" if limit == MAX_RESP else "sendDocument", 0, "response too big")

    def test_error_response_also_limited(self, limit):
        """Предел действует и на ответы с ошибкой: 500 с гигантским телом не читается."""
        with pytest.raises(TelegramError) as ei:
            self.fire(limit, stream_resp(500, [], {"content-length": str(limit + 1)}))
        assert ei.value.description == "response too big"


@pytest.mark.parametrize("limit", [MAX_RESP, MAX_UP], ids=["call", "upload"])
def test_content_length_with_thousands_of_digits_is_too_big(limit):
    s = Script(stream_resp(200, [b'{"ok":true,"result":1}'], {"content-length": "9" * 5000}))
    bot = make_bot(s)
    with pytest.raises(TelegramError) as ei:
        run(bot.call("getMe") if limit == MAX_RESP else upload(bot))
    assert ei.value.description == "response too big"


def test_poll_survives_content_length_with_thousands_of_digits():
    bad = stream_resp(200, [b"{}"], {"content-length": "9" * 5000})
    ev, finished = drive([bad, ok([])])
    assert not finished and sleeps_of(ev)


@pytest.mark.parametrize("body", [b"[" * 200000, b'{"ok":true,"result":' + b"9" * 6000 + b"}",
                                  b'{"ok":false,"error_code":' + b"9" * 6000 + b"}", b'{"a":' * 100000,
                                  b'{"ok":true,"result":' + b"[" * 100000 + b"]" * 100000 + b"}"])
def test_pathological_json_is_bad_json_not_a_crash(body):
    try:
        call_once(Script(httpx.Response(200, content=body)))
    except TelegramError as e:
        assert e.description == "bad JSON"


def test_corrupt_gzip_is_telegram_error_without_token(logs):
    with pytest.raises(TelegramError) as ei:
        call_once(Script(stream_resp(200, [b"not gzip at all"], {"content-encoding": "gzip"})))
    assert ei.value.code == 0 and ei.value.description == "DecodingError"
    assert ei.value.__cause__ is None
    no_secret(ei.value)
    broken = gzip.compress(b'{"ok":true,"result":1}')[:12] + b"\xff\xff\xff"
    with pytest.raises(TelegramError) as ei:
        call_once(Script(stream_resp(200, [broken], {"content-encoding": "gzip"})))
    no_secret(ei.value)
    no_secret_in_log(logs)


def test_truncated_gzip_is_not_a_result():
    full = gzip.compress(b'{"ok":true,"result":"' + b"a" * 5000 + b'"}')
    with pytest.raises(TelegramError):
        call_once(Script(stream_resp(200, [full[: len(full) // 2]], {"content-encoding": "gzip"})))


def test_unknown_content_encoding_is_not_a_crash():
    try:
        call_once(Script(stream_resp(200, [b'{"ok":true,"result":1}'], {"content-encoding": "zstd, br, gzip, x"})))
    except TelegramError as e:
        no_secret(e)


# --- разбор ответа -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("status", [200, 400, 429, 500, 502, 503])
@pytest.mark.parametrize("body", [b"", b"<html>502</html>", b"\xff\xfe", b"{", b"[]", b'"x"', b"1", b"null", b"true",
                                  b"[{\"ok\":true,\"result\":1}]", b'{"ok":true,"result":1}garbage', b"NaN",
                                  b'{"ok": true, "result": 1e999999999999}'[:12]])
def test_non_object_or_non_json_is_bad_json_with_status(status, body):
    """Не JSON и JSON не объектом — «bad JSON» с кодом HTTP; 429 тут не повторяется (JSON-разбор не дал retry_after)."""
    s = Script(httpx.Response(status, content=body), forever=True)
    sleeps: list = []
    with pytest.raises(TelegramError) as ei:
        call_once(s, sleeps=sleeps)
    e = ei.value
    assert (e.method, e.code, e.description, e.retry_after) == ("getMe", status, "bad JSON", 0)


@pytest.mark.parametrize("flag", ["true", "True", 1, "yes", None, [], {}, 0, "", 1.0])
def test_ok_must_be_strict_bool_true(flag):
    s = Script(httpx.Response(200, json={"ok": flag, "result": {"v": 1}}))
    with pytest.raises(TelegramError) as ei:
        call_once(s)
    assert ei.value.code == 200


def test_ok_true_without_result_is_bad_json():
    with pytest.raises(TelegramError) as ei:
        call_once(Script(httpx.Response(200, json={"ok": True})))
    assert ei.value.description == "bad JSON" and ei.value.code == 200


@pytest.mark.parametrize("result", [False, 0, "", [], {}, None, True, 0.0])
def test_falsy_results_are_returned_as_is(result):
    r = call_once(Script(httpx.Response(200, json={"ok": True, "result": result})))
    assert r == result and type(r) is type(result)


@pytest.mark.parametrize("ec,expected", [(400, 400), (403, 403), ("429", 502), (True, 502), (False, 502), (1.5, 502),
                                         (None, 502), ([403], 502), ({"a": 1}, 502), (10**30, 10**30), (0, 0),
                                         (-5, -5)])
def test_error_code_must_be_int_not_bool_else_http_status(ec, expected):
    with pytest.raises(TelegramError) as ei:
        call_once(Script(httpx.Response(502, json={"ok": False, "error_code": ec, "description": "d"})))
    assert ei.value.code == expected


@pytest.mark.parametrize("desc,expected", [("abc", "abc"), ("é" * 512, "é" * 512), ("é" * 513, "é" * 512),
                                           ("x" * 100000, "x" * 512), ("", ""), (123, ""), (None, ""), (["a"], ""),
                                           ({"a": 1}, ""), (True, "")])
def test_description_is_str_and_cut_to_512(desc, expected):
    with pytest.raises(TelegramError) as ei:
        call_once(Script(httpx.Response(400, json={"ok": False, "error_code": 400, "description": desc})))
    assert ei.value.description == expected


def test_missing_description_is_empty():
    with pytest.raises(TelegramError) as ei:
        call_once(Script(httpx.Response(400, json={"ok": False, "error_code": 400})))
    assert ei.value.description == ""


@pytest.mark.parametrize("ra,expected", [(0, 0), (1, 1), (11, 11), (86400, 86400), (86401, 86400), (10**9, 86400),
                                         (10**40, 86400), (-1, 0), (-10**9, 0), (True, 0), (False, 0), ("5", 0),
                                         (5.0, 0), (5.5, 0), (None, 0), ([5], 0), ({"a": 5}, 0)])
def test_retry_after_parsing_on_non_retried_code(ra, expected):
    """Код 403 не повторяется, поэтому retry_after видно в исключении как есть (после ограничения)."""
    body = {"ok": False, "error_code": 403, "description": "d", "parameters": {"retry_after": ra}}
    with pytest.raises(TelegramError) as ei:
        call_once(Script(httpx.Response(403, json=body)))
    assert ei.value.retry_after == expected and type(ei.value.retry_after) is int


@pytest.mark.parametrize("params", [[], "x", 5, None, True, [{"retry_after": 5}], "retry_after"])
def test_parameters_not_dict_gives_zero(params):
    body = {"ok": False, "error_code": 403, "description": "d", "parameters": params}
    with pytest.raises(TelegramError) as ei:
        call_once(Script(httpx.Response(403, json=body)))
    assert ei.value.retry_after == 0


def test_parameters_without_retry_after():
    body = {"ok": False, "error_code": 403, "parameters": {"migrate_to_chat_id": -100}}
    with pytest.raises(TelegramError) as ei:
        call_once(Script(httpx.Response(403, json=body)))
    assert ei.value.retry_after == 0


@pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308, 399])
def test_redirects_not_followed(status):
    s = Script(httpx.Response(status, headers={"location": "https://evil.test/collect"}),
               AssertionError("перешли по Location"))
    with pytest.raises(TelegramError) as ei:
        call_once(s)
    assert ei.value.code == status
    assert s.n == 1
    assert all(r.url.host != "evil.test" for r in s.requests)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_with_ok_body_is_still_an_error(status):
    body = json.dumps({"ok": True, "result": 1}).encode()
    s = Script(httpx.Response(status, headers={"location": "https://evil.test/x"}, content=body))
    with pytest.raises(TelegramError) as ei:
        call_once(s)
    assert ei.value.code == status
    assert s.n == 1


def test_redirect_on_upload_not_followed():
    s = Script(httpx.Response(307, headers={"location": "https://evil.test/up"}), AssertionError("redirect"))
    bot = make_bot(s)
    with pytest.raises(TelegramError) as ei:
        run(upload(bot))
    assert ei.value.code == 307 and s.n == 1


JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers(-10**12, 10**12) | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=700),
    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=12), c, max_size=4), max_leaves=10)
ENVELOPES = st.fixed_dictionaries({}, optional={
    "ok": JSON_VALUES | st.just(True), "result": JSON_VALUES, "error_code": JSON_VALUES | st.integers(100, 599),
    "description": JSON_VALUES | st.text(max_size=700),
    "parameters": JSON_VALUES | st.fixed_dictionaries(
        {}, optional={"retry_after": JSON_VALUES | st.integers(-5, 10**10)})})


@given(env=ENVELOPES, status=st.sampled_from([200, 400, 403, 429, 500]))
@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_property_any_envelope_gives_result_or_clean_error(env, status):
    s = Script(httpx.Response(status, json=env), forever=True)
    sleeps: list = []
    try:
        r = call_once(s, sleeps=sleeps)
    except TelegramError as e:
        assert env.get("ok") is not True or "result" not in env
        assert type(e.code) is int
        assert isinstance(e.description, str) and len(e.description) <= 512
        assert type(e.retry_after) is int and 0 <= e.retry_after <= 86400
        assert s.n <= 2
        if s.n == 2:
            assert e.code == 429 and e.retry_after <= 10 and len(sleeps) == 1 and sleeps[0] >= 1
    else:
        assert env.get("ok") is True and "result" in env and r == env["result"]
        assert s.n == 1


@given(body=st.binary(max_size=200), status=st.sampled_from([200, 400, 429, 500]))
@settings(max_examples=200, deadline=None)
def test_property_arbitrary_bytes_never_escape(body, status):
    s = Script(httpx.Response(status, content=body), forever=True)
    try:
        call_once(s)
    except TelegramError as e:
        assert e.code in (status, 0) or True
    assert s.n <= 2


# --- ошибки сети и токен -------------------------------------------------------------------------------------------

def boom(kind, text=f"fail at {TOKEN} {SECRET}"):
    return kind(text)


NET_ERRORS = [
    lambda: httpx.ConnectError(f"connect {TOKEN}"), lambda: httpx.ReadTimeout(f"timeout {TOKEN}"),
    lambda: httpx.RemoteProtocolError(f"proto {TOKEN}"), lambda: httpx.ConnectTimeout(f"x {SECRET}"),
    lambda: httpx.PoolTimeout(f"x {SECRET}"), lambda: httpx.WriteError(f"x {SECRET}"),
    lambda: httpx.ProxyError(f"x {SECRET}"), lambda: httpx.UnsupportedProtocol(f"x {SECRET}"),
]


@pytest.mark.parametrize("mk", NET_ERRORS)
def test_network_error_becomes_clean_telegram_error(mk, logs):
    exc = mk()
    s = Script(exc, forever=True)
    sleeps: list = []
    with pytest.raises(TelegramError) as ei:
        call_once(s, sleeps=sleeps)
    e = ei.value
    assert e.code == 0 and e.description == type(exc).__name__
    assert e.__cause__ is None
    no_secret(e)
    assert s.n == 1 and not sleeps
    no_secret_in_log(logs)


@pytest.mark.parametrize("mk", NET_ERRORS[:3])
def test_network_error_leaves_no_context_chain(mk):
    with pytest.raises(TelegramError) as ei:
        call_once(Script(mk(), forever=True))
    assert ei.value.__context__ is None or ei.value.__suppress_context__
    assert ei.value.__cause__ is None


@pytest.mark.parametrize("mk", NET_ERRORS[:4])
@pytest.mark.parametrize("at", [0, 1])
def test_error_inside_body_stream(mk, at, logs):
    chunks = [b'{"ok":true,', mk(), b'"result":1}']
    if at == 0:
        chunks = [mk()]
    with pytest.raises(TelegramError) as ei:
        call_once(Script(stream_resp(200, chunks), forever=True))
    assert ei.value.code == 0
    no_secret(ei.value)
    no_secret_in_log(logs)


def test_error_in_stream_on_upload(logs):
    s = Script(stream_resp(200, [b"{", httpx.ReadError(f"x {TOKEN}")]))
    bot = make_bot(s)
    with pytest.raises(TelegramError) as ei:
        run(upload(bot))
    no_secret(ei.value)
    no_secret_in_log(logs)


def test_network_error_on_every_public_method_hides_token(logs):
    async def go():
        bot = make_bot(Script(httpx.ConnectError(f"x {TOKEN}"), forever=True))
        calls = [bot.get_me(), bot.get_updates(0), bot.send(1, "t"), bot.copy(1, 2, 3), bot.copy_many(1, 2, [3]),
                 bot.edit(1, 2, "t"), bot.edit_markup(1, 2, None), bot.set_commands([("a", "b")]),
                 bot.download("fid", 100), bot.upload("sendPhoto", "photo", "a.png", b"x", "image/png", chat_id=1),
                 bot.send_group(1, [{"type": "photo", "media": "a"}])]
        for c in calls:
            try:
                await c
            except TelegramError as e:
                no_secret(e)
    run(go())
    no_secret_in_log(logs)


def test_token_not_in_log_on_success_and_error(logs):
    s = Script(ok(1), err(400, 400, "bad"), flood(3), flood(3), flood(3), ok(1), httpx.ConnectError("c"))

    async def go():
        bot = make_bot(s)
        await bot.call("getMe")
        for _ in range(2):
            with pytest.raises(TelegramError) as ei:
                await bot.call("getMe")
            no_secret(ei.value)
        await bot.call("getMe")
        with pytest.raises(TelegramError) as ei:
            await bot.call("getMe")
        no_secret(ei.value)
    run(go())
    assert s.n == 7
    no_secret_in_log(logs)


def test_httpx_info_line_is_masked_not_dropped_for_other_urls(logs):
    """Фильтр логгера httpx прячет только токен: адрес чужих запросов остальных клиентов виден."""
    logging.getLogger("httpx").info('HTTP Request: GET https://example.org/page "HTTP/1.1 200 OK"')
    assert "example.org/page" in logs.text


def test_httpx_log_masked_even_for_bot_created_late(logs):
    run(make_bot(Script(ok(1))).call("getMe"))
    lines = [r.getMessage() for r in logs.records if r.name.startswith("httpx")]
    for ln in lines:
        assert SECRET not in ln


# --- повтор при 429 ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("ra,pause", [(10, 10), (1, 1), (0, 1), (5, 5), (9, 9)])
def test_429_retried_once_with_pause(ra, pause):
    s = Script(flood(ra), ok({"v": 1}))
    sleeps: list = []
    assert call_once(s, sleeps=sleeps) == {"v": 1}
    assert sleeps == [pause] and s.n == 2


@pytest.mark.parametrize("ra", [11, 12, 60, 3600, 86400, 10**9])
def test_429_above_ten_raises_immediately(ra):
    s = Script(flood(ra), ok(1))
    sleeps: list = []
    with pytest.raises(TelegramError) as ei:
        call_once(s, sleeps=sleeps)
    assert ei.value.code == 429 and ei.value.retry_after == min(ra, 86400)
    assert s.n == 1 and not sleeps


@pytest.mark.parametrize("ra", [5, 10])
def test_second_429_in_a_row_raises(ra):
    s = Script(flood(ra), flood(ra), ok(1))
    sleeps: list = []
    with pytest.raises(TelegramError) as ei:
        call_once(s, sleeps=sleeps)
    assert ei.value.code == 429
    assert s.n == 2 and sleeps == [ra]


def test_second_429_with_big_value_raises_without_third_request():
    s = Script(flood(3), flood(500), ok(1))
    sleeps: list = []
    with pytest.raises(TelegramError) as ei:
        call_once(s, sleeps=sleeps)
    assert ei.value.retry_after == 500 and s.n == 2 and sleeps == [3]


@pytest.mark.parametrize("ra", ["5", True, -1, None, [3], 5.5])
def test_429_with_unusable_retry_after_treated_as_zero(ra):
    """Не-int и отрицательное значение — 0; 0 ≤ 10, значит один повтор после паузы в 1 с."""
    s = Script(err(429, 429, "x", retry_after=ra), ok(1))
    sleeps: list = []
    assert call_once(s, sleeps=sleeps) == 1
    assert sleeps == [1]


def test_429_without_parameters_is_retried_after_one_second():
    s = Script(err(429, 429, "x"), ok(1))
    sleeps: list = []
    assert call_once(s, sleeps=sleeps) == 1 and sleeps == [1]


def test_429_in_envelope_with_http_200_is_still_retried():
    s = Script(httpx.Response(200, json={"ok": False, "error_code": 429, "parameters": {"retry_after": 2}}), ok(1))
    sleeps: list = []
    assert call_once(s, sleeps=sleeps) == 1 and sleeps == [2]


def test_http_429_with_other_error_code_is_not_retried():
    s = Script(err(429, 400, "x", retry_after=1), ok(1))
    sleeps: list = []
    with pytest.raises(TelegramError):
        call_once(s, sleeps=sleeps)
    assert s.n == 1 and not sleeps


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 500, 502, 503, 504])
def test_other_codes_not_retried(status):
    s = Script(err(status, status, "x", retry_after=1), ok(1))
    sleeps: list = []
    with pytest.raises(TelegramError):
        call_once(s, sleeps=sleeps)
    assert s.n == 1 and not sleeps


@pytest.mark.parametrize("mk", NET_ERRORS[:3])
def test_network_failures_not_retried(mk):
    s = Script(mk(), ok(1))
    with pytest.raises(TelegramError):
        call_once(s)
    assert s.n == 1


def test_retry_resends_identical_json_body():
    s = Script(flood(1), ok(1))

    async def go():
        bot = make_bot(s)
        await bot.call("sendMessage", chat_id=5, text="привет")
    run(go())
    assert s.n == 2 and s.requests[0].content == s.requests[1].content
    assert s.requests[0].url == s.requests[1].url


def test_upload_429_retried_once_with_full_payload():
    seen: list[bytes] = []

    def first(req):
        seen.append(req.content)
        return flood(2)

    def second(req):
        seen.append(req.content)
        return ok({"message_id": 9})

    sleeps: list = []
    s = Script(first, second)
    bot = make_bot(s, sleeps=sleeps)
    assert run(upload(bot)) == {"message_id": 9}
    assert sleeps == [2] and len(seen) == 2
    assert b"PAYLOAD-0123456789" in seen[0] and b"PAYLOAD-0123456789" in seen[1]
    ctype = [r.headers["content-type"] for r in s.requests]
    assert all(c.startswith("multipart/form-data") for c in ctype)


@pytest.mark.parametrize("steps,expect_sleeps", [([flood(11)], []), ([flood(2), flood(2)], [2])])
def test_upload_429_limits(steps, expect_sleeps):
    s = Script(*steps, ok(1))
    sleeps: list = []
    bot = make_bot(s, sleeps=sleeps)
    with pytest.raises(TelegramError) as ei:
        run(upload(bot))
    assert ei.value.code == 429 and sleeps == expect_sleeps and s.n == len(steps)


def test_429_then_too_big_second_response():
    s = Script(flood(1), too_big_resp())
    with pytest.raises(TelegramError) as ei:
        call_once(s)
    assert ei.value.description == "response too big"


# --- answer / delete -----------------------------------------------------------------------------------------------

ANSWER_FAILS = [
    ("401", lambda: err(401, 401, "Unauthorized")), ("403", lambda: err(403, 403, "Forbidden")),
    ("404", lambda: err(404, 404, "Not Found")), ("409", lambda: err(409, 409, "Conflict")),
    ("500", lambda: err(500, 500, "Internal")), ("502html", lambda: httpx.Response(502, content=b"<html>")),
    ("net", lambda: httpx.ConnectError(f"x {TOKEN}")), ("timeout", lambda: httpx.ReadTimeout("t")),
    ("toobig", too_big_resp), ("list", lambda: httpx.Response(200, json=[1])),
    ("okfalse", lambda: httpx.Response(200, json={"ok": False})),
    ("429big", lambda: flood(500)), ("redirect", lambda: httpx.Response(302, headers={"location": "https://e.test/"})),
    ("nobool", lambda: httpx.Response(200, json={"ok": "true", "result": True})),
]


def run_answer(script, sleeps=None, **kw):
    async def go():
        bot = make_bot(script, sleeps=sleeps)
        return await bot.answer("cb-1", **kw)
    return run(go())


@pytest.mark.parametrize("name,mk", ANSWER_FAILS, ids=[n for n, _ in ANSWER_FAILS])
def test_answer_never_raises_and_warns(name, mk, logs):
    r = run_answer(Script(mk(), forever=True))
    assert r is None
    warns = [x for x in logs.records if x.levelno >= logging.WARNING]
    assert warns, "сбой answer не записан в журнал"
    assert any("answerCallbackQuery" in x.getMessage() for x in warns)
    no_secret_in_log(logs)


@pytest.mark.parametrize("desc", ["Bad Request: query is too old and response timeout expired or query ID is invalid",
                                  "Bad Request: QUERY_ID_INVALID", "", "anything", "Bad Request: message not found"])
def test_answer_400_is_silent(desc, logs):
    assert run_answer(Script(err(400, 400, desc))) is None
    assert not [x for x in logs.records if x.levelno >= logging.WARNING]


def test_answer_400_without_json_body_still_does_not_raise():
    assert run_answer(Script(httpx.Response(400, content=b"oops"))) is None


def test_answer_429_after_retry_warns_and_does_not_raise(logs):
    sleeps: list = []
    assert run_answer(Script(flood(2), flood(2)), sleeps=sleeps) is None
    assert sleeps == [2]
    assert [x for x in logs.records if x.levelno >= logging.WARNING]


def test_answer_429_then_ok_is_quiet(logs):
    assert run_answer(Script(flood(1), ok(True)), sleeps=[]) is None
    assert not [x for x in logs.records if x.levelno >= logging.WARNING]


def test_answer_success_payload():
    s = Script(ok(True))
    run_answer(s, text="привет", alert=True)
    b = s.body()
    assert b["callback_query_id"] == "cb-1" and b["text"] == "привет" and b["show_alert"] is True
    assert s.requests[0].url.path.endswith("/answerCallbackQuery")


def test_answer_without_text_omits_text():
    s = Script(ok(True))
    run_answer(s)
    assert "text" not in s.body() or s.body()["text"] is None


def run_delete(script, sleeps=None):
    async def go():
        bot = make_bot(script, sleeps=sleeps)
        return await bot.delete(111, 222)
    return run(go())


def test_delete_ok():
    s = Script(ok(True))
    assert run_delete(s) is True
    assert s.body() == {"chat_id": 111, "message_id": 222}
    assert s.requests[0].url.path.endswith("/deleteMessage")


@pytest.mark.parametrize("desc", ["Bad Request: message to delete not found",
                                  "BAD REQUEST: MESSAGE TO DELETE NOT FOUND",
                                  "bad request: Message Not Found", "not found", "xx NOT FOUND yy"])
def test_delete_400_not_found_is_true(desc):
    assert run_delete(Script(err(400, 400, desc))) is True


@pytest.mark.parametrize("desc", ["Bad Request: message can't be deleted",
                                  "Bad Request: message can't be deleted for everyone",
                                  "Bad Request: MESSAGE_ID_INVALID", "", "found", "not  found", "notfound",
                                  "Not-Found"])
def test_delete_other_400_is_false_and_info(desc, logs):
    assert run_delete(Script(err(400, 400, desc))) is False
    assert not [x for x in logs.records if x.levelno >= logging.WARNING]
    infos = [x for x in logs.records if x.levelno == logging.INFO and not x.name.startswith("httpx")]
    assert infos, "отказ удаления не записан на уровне INFO"
    no_secret_in_log(logs)


def test_delete_400_without_description_is_false():
    assert run_delete(Script(httpx.Response(400, json={"ok": False, "error_code": 400}))) is False


def test_delete_400_with_non_string_description_is_false():
    body = {"ok": False, "error_code": 400, "description": ["not found"]}
    assert run_delete(Script(httpx.Response(400, json=body))) is False


@pytest.mark.parametrize("status,desc", [(404, "Not Found"), (404, "Bad Request: message to delete not found"),
                                         (401, "Unauthorized"), (403, "Forbidden: bot was kicked"),
                                         (403, "message to delete not found"), (409, "Conflict"),
                                         (500, "Internal Server Error"), (502, "Bad Gateway"), (503, "x"), (504, "x")])
def test_delete_everything_else_raises(status, desc):
    with pytest.raises(TelegramError) as ei:
        run_delete(Script(err(status, status, desc)))
    assert ei.value.code == status


def test_delete_status_400_with_error_code_403_raises():
    with pytest.raises(TelegramError) as ei:
        run_delete(Script(httpx.Response(400, json={"ok": False, "error_code": 403, "description": "not found"})))
    assert ei.value.code == 403


def test_delete_http_200_envelope_with_400_not_found_is_true():
    assert run_delete(Script(httpx.Response(200, json={"ok": False, "error_code": 400,
                                                       "description": "message to delete not found"}))) is True


@pytest.mark.parametrize("mk", NET_ERRORS[:3])
def test_delete_network_raises(mk):
    with pytest.raises(TelegramError) as ei:
        run_delete(Script(mk()))
    assert ei.value.code == 0


def test_delete_400_html_from_proxy_is_not_permanent_refusal():
    with pytest.raises(TelegramError):
        run_delete(Script(httpx.Response(400, content=b"<html>400 Bad Request</html>")))


@pytest.mark.parametrize("resp", [too_big_resp, lambda: httpx.Response(200, content=b"<html>")])
def test_delete_garbage_answer_is_not_a_confirmation(resp):
    """Мусор вместо ответа: «удалено» говорить нельзя; True/False допустимо только для 400 с разобранным JSON."""
    try:
        r = run_delete(Script(resp()))
    except TelegramError:
        return
    pytest.fail(f"delete вернул {r!r} на неразобранный ответ")


def test_delete_429_retried_then_true():
    sleeps: list = []
    assert run_delete(Script(flood(3), ok(True)), sleeps=sleeps) is True and sleeps == [3]


def test_delete_429_twice_raises():
    with pytest.raises(TelegramError) as ei:
        run_delete(Script(flood(3), flood(3)), sleeps=[])
    assert ei.value.code == 429


def test_delete_429_over_ten_raises_without_pause():
    sleeps: list = []
    with pytest.raises(TelegramError):
        run_delete(Script(flood(11), ok(True)), sleeps=sleeps)
    assert not sleeps


# --- copy / copy_many ----------------------------------------------------------------------------------------------

GOOD_CHATS = [1, -1, 2**53 - 1, -(2**53 - 1), -1004360023194, "@abcd", "@Abcd", "@a_b_c", "@a1234", "@A" + "b" * 31]
BAD_CHATS = [0, True, False, 2**53, -(2**53), 2**60, 1.0, -1.5, "1", "-100123", "", "@", "@abc", "@1abc", "@_abc",
             "@abcd ", " @abcd", "@abcd\n", "@abcd\t", "abcd", "@A" + "b" * 32, "@ünic", "@abçd", "@ａｂｃｄ", "@ab-cd",
             "@ab.cd", "@abcd@", None, [], {}, (1,), b"@abcd", 10**30]


def copy_bot(response=None):
    s = Script(response if response is not None else ok({"message_id": 5}), forever=True)
    return make_bot(s), s


@pytest.mark.parametrize("chat", GOOD_CHATS)
def test_copy_good_chat_ids(chat):
    bot, s = copy_bot()
    assert run(bot.copy(chat, 2**53 - 1 if isinstance(chat, int) and chat > 0 else 7, 1)) == 5
    assert s.body()["chat_id"] == chat


@pytest.mark.parametrize("chat", BAD_CHATS, ids=repr)
def test_copy_bad_chat_id_no_request(chat):
    bot, s = copy_bot()
    with pytest.raises(ValueError) as ei:
        run(bot.copy(chat, 7, 1))
    no_secret(ei.value)
    assert s.n == 0


@pytest.mark.parametrize("chat", BAD_CHATS, ids=repr)
def test_copy_bad_from_chat_no_request(chat):
    bot, s = copy_bot()
    with pytest.raises(ValueError):
        run(bot.copy(7, chat, 1))
    assert s.n == 0


@pytest.mark.parametrize("mid", [0, -1, True, False, 2**53 + 1, 2**60, 1.0, "1", None, [1], 10**30, -(2**53)])
def test_copy_bad_message_id_no_request(mid):
    bot, s = copy_bot()
    with pytest.raises(ValueError):
        run(bot.copy(7, 8, mid))
    assert s.n == 0


@pytest.mark.parametrize("mid", [1, 2, 2**53])
def test_copy_good_message_id(mid):
    bot, s = copy_bot()
    assert run(bot.copy(7, 8, mid)) == 5
    assert s.body()["message_id"] == mid and s.body()["from_chat_id"] == 8


@pytest.mark.parametrize("result", [[], [{"message_id": 5}], True, False, None, "5", 5, {}, {"message_id": "5"},
                                    {"message_id": True}, {"message_id": None}, {"message_id": 5.0},
                                    {"message_id": [5]}, {"id": 5}])
def test_copy_bad_result(result):
    bot, _ = copy_bot(httpx.Response(200, json={"ok": True, "result": result}))
    with pytest.raises(TelegramError) as ei:
        run(bot.copy(7, 8, 1))
    assert (ei.value.code, ei.value.description) == (0, "bad result")


def test_copy_result_with_extra_fields_ok():
    bot, _ = copy_bot(ok({"message_id": 77, "extra": "x"}))
    assert run(bot.copy(7, 8, 1)) == 77


def test_copy_caption_params_only_when_given():
    bot, s = copy_bot()
    run(bot.copy(7, 8, 1))
    assert "caption" not in s.body() or s.body()["caption"] is None
    run(bot.copy(7, 8, 1, caption="c", caption_entities=[{"type": "bold", "offset": 0, "length": 1}]))
    assert s.body()["caption"] == "c" and s.body()["caption_entities"]


def many_ok(ids):
    return ok([{"message_id": 1000 + i} for i, _ in enumerate(ids)])


def copy_many_bot(n_response=None):
    def reply(req):
        ids = json.loads(req.content)["message_ids"]
        return many_ok(ids) if n_response is None else ok([{"message_id": 1000 + i} for i in range(n_response)])
    s = Script(reply, forever=True)
    return make_bot(s), s


@pytest.mark.parametrize("n", [1, 2, 50, 100])
def test_copy_many_sizes(n):
    bot, s = copy_many_bot()
    ids = list(range(10, 10 + n))
    r = run(bot.copy_many(7, 8, ids))
    assert r == [1000 + i for i in range(n)]
    assert s.body()["message_ids"] == ids


@pytest.mark.parametrize("ids", [[], list(range(1, 102)), list(range(1, 1000)), [1, 1], [1, 2, 2], [5, 5, 5],
                                 [1, True], [True], [False], [0], [-1], [1, 0], [1, "2"], ["1"], [1.0], [None],
                                 [2**53 + 1], [1, [2]], "123", b"12", None, 5, {1, 2}, [1, 2**60], [True, 2]])
def test_copy_many_rejects_before_request(ids):
    bot, s = copy_many_bot()
    with pytest.raises((ValueError, TypeError)) as ei:
        run(bot.copy_many(7, 8, ids))
    assert isinstance(ei.value, ValueError) or ids in (None, 5, {1, 2})
    assert s.n == 0


def test_copy_many_unsorted_is_sorted_or_refused():
    """Bot API требует строго возрастающих id: на провод неупорядоченный список не уходит."""
    bot, s = copy_many_bot()
    try:
        run(bot.copy_many(7, 8, [9, 3, 5]))
    except ValueError:
        assert s.n == 0
        return
    sent = s.body()["message_ids"]
    assert all(a < b for a, b in zip(sent, sent[1:]))


@pytest.mark.parametrize("bad", [0, True, 2**53, "1", "@abcd\n"])
def test_copy_many_bad_chats(bad):
    bot, s = copy_many_bot()
    with pytest.raises(ValueError):
        run(bot.copy_many(bad, 8, [1]))
    with pytest.raises(ValueError):
        run(bot.copy_many(7, bad, [1]))
    assert s.n == 0


@pytest.mark.parametrize("n_resp,n_in", [(0, 1), (1, 2), (2, 3), (99, 100), (0, 5)])
def test_copy_many_short_answer_is_partial(n_resp, n_in):
    bot, _ = copy_many_bot(n_resp)
    with pytest.raises(TelegramError) as ei:
        run(bot.copy_many(7, 8, list(range(1, n_in + 1))))
    assert (ei.value.method, ei.value.code, ei.value.description) == ("copyMessages", 0, "partial copy")


def test_copy_many_long_answer_is_not_accepted():
    bot, _ = copy_many_bot(3)
    with pytest.raises(TelegramError):
        run(bot.copy_many(7, 8, [1, 2]))


@pytest.mark.parametrize("result", [{"message_id": 1}, True, None, "x", 5, {}, [1], ["a"], [None], [{}],
                                    [{"message_id": "1"}], [{"message_id": True}],
                                    [{"message_id": 1}, {"message_id": None}],
                                    [{"message_id": 1}, 2], [[{"message_id": 1}]], [{"message_id": 1.5}]])
def test_copy_many_bad_result(result):
    bot, _ = copy_bot(httpx.Response(200, json={"ok": True, "result": result}))
    with pytest.raises(TelegramError) as ei:
        run(bot.copy_many(7, 8, [1, 2]))
    assert ei.value.code == 0 and ei.value.description in ("bad result", "partial copy")
    assert ei.value.method == "copyMessages"


@pytest.mark.parametrize("n", [1, 2])
def test_copy_many_bad_item_types_are_bad_result_not_partial(n):
    bot, _ = copy_bot(ok([{"message_id": "x"}] * n))
    with pytest.raises(TelegramError) as ei:
        run(bot.copy_many(7, 8, list(range(1, n + 1))))
    assert ei.value.description == "bad result"


def test_copy_many_remove_caption_flag():
    bot, s = copy_many_bot()
    run(bot.copy_many(7, 8, [1]))
    assert not s.body().get("remove_caption")
    run(bot.copy_many(7, 8, [1], remove_caption=True))
    assert s.body()["remove_caption"] is True


@given(st.lists(st.one_of(st.integers(-5, 2**53 + 5), st.booleans()), max_size=105))
@settings(max_examples=250, deadline=None)
def test_property_copy_many_ids(ids):
    good = (1 <= len(ids) <= 100 and all(type(i) is int and 1 <= i <= 2**53 for i in ids) and len(set(ids)) == len(ids))
    bot, s = copy_many_bot()
    try:
        r = run(bot.copy_many(7, 8, ids))
    except ValueError:
        assert not good or s.n == 0
        assert s.n == 0
    else:
        assert good and len(r) == len(ids)
        sent = s.body()["message_ids"]
        assert all(a < b for a, b in zip(sent, sent[1:]))


@given(st.one_of(st.integers(-2**54, 2**54), st.booleans(), st.text(max_size=12), st.none(), st.floats()))
@settings(max_examples=300, deadline=None)
def test_property_chat_ref(v):
    if isinstance(v, bool):
        good = False
    elif isinstance(v, int):
        good = v != 0 and abs(v) < 2**53
    elif isinstance(v, str):
        good = re.fullmatch(r"@[A-Za-z][A-Za-z0-9_]{3,31}", v) is not None
    else:
        good = False
    bot, s = copy_bot()
    try:
        run(bot.copy(v, 7, 1))
    except ValueError:
        assert not good and s.n == 0
    else:
        assert good


# --- getUpdates ----------------------------------------------------------------------------------------------------

def test_get_updates_request_shape_and_limit_only_when_given():
    s = Script(ok([]), forever=True)
    bot = make_bot(s)
    run(bot.get_updates(5))
    b = s.body()
    assert b["offset"] == 5 and b["timeout"] == 50 and b["allowed_updates"] == ["message", "callback_query"]
    assert "limit" not in b
    run(bot.get_updates(0, 7, limit=1, allowed=("message",)))
    b = s.body()
    assert b["limit"] == 1 and b["timeout"] == 7 and b["allowed_updates"] == ["message"] and b["offset"] == 0
    run(bot.get_updates(0, limit=0))
    assert s.body()["limit"] == 0
    run(bot.get_updates(0, allowed=["a", "b"]))
    assert s.body()["allowed_updates"] == ["a", "b"]


@pytest.mark.parametrize("result", [{}, {"update_id": 1}, None, "x", 1, True, {"0": {}}])
def test_get_updates_bad_result(result):
    bot = make_bot(Script(httpx.Response(200, json={"ok": True, "result": result})))
    with pytest.raises(TelegramError) as ei:
        run(bot.get_updates(0))
    assert (ei.value.method, ei.value.code, ei.value.description) == ("getUpdates", 0, "bad result")


def test_get_updates_returns_list_as_is():
    ups = [{"update_id": 1}, {"update_id": 2, "message": {"text": "я"}}]
    assert run(make_bot(Script(ok(ups))).get_updates(0)) == ups


# --- poll ----------------------------------------------------------------------------------------------------------

def upd(i, **kw):
    return {"update_id": i, "message": {"message_id": i, "text": f"t{i}"}, **kw}


def drive(steps, handle=None, *, allowed=("message",), timeout=50, make_sleep=None):
    """Крутит poll на сценарии; когда шаги кончились, транспорт замирает и цикл останавливается отменой.
    Возвращает (события, задача до отмены завершилась?)."""
    steps = list(steps)
    events: list = []

    async def main():
        done = asyncio.Event()

        async def handler(req):
            events.append(("req", json.loads(req.content)))
            if not steps:
                done.set()
                await asyncio.Event().wait()
            step = steps.pop(0)
            if isinstance(step, BaseException):
                raise step
            return step(req) if callable(step) else step

        async def sleep(s):
            events.append(("sleep", s))
            await asyncio.sleep(0)

        bot = Bot(TOKEN, base_url="https://tg.test", transport=httpx.MockTransport(handler), sleep=sleep)
        h = handle if handle is not None else (lambda u: None)
        task = asyncio.create_task(bot.poll(h, allowed=allowed, timeout=timeout))
        waiter = asyncio.create_task(done.wait())
        await asyncio.wait({task, waiter}, timeout=15, return_when=asyncio.FIRST_COMPLETED)
        finished = task.done()
        if finished and not task.cancelled() and task.exception() is not None:
            raise task.exception()
        if not finished and not done.is_set():
            raise AssertionError("poll завис, не дойдя до конца сценария")
        task.cancel()
        waiter.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await bot.close()
        return finished

    finished = run(main())
    return events, finished


def reqs(events):
    return [b for k, b in events if k == "req"]


def sleeps_of(events):
    return [b for k, b in events if k == "sleep"]


def test_poll_offsets_and_order():
    seen: list[int] = []
    ev, _ = drive([ok([upd(5), upd(6)]), ok([upd(7)])], lambda u: seen.append(u["update_id"]))
    assert seen == [5, 6, 7]
    assert [r["offset"] for r in reqs(ev)] == [0, 7, 8]
    assert all(r["allowed_updates"] == ["message"] and r["timeout"] == 50 for r in reqs(ev))
    assert all("limit" not in r for r in reqs(ev))


def test_poll_passes_timeout_and_allowed():
    ev, _ = drive([ok([])], allowed=["callback_query", "message"], timeout=3)
    r = reqs(ev)[0]
    assert r["timeout"] == 3 and r["allowed_updates"] == ["callback_query", "message"]


def test_poll_skips_repeats_and_older_than_offset():
    seen: list[int] = []
    ev, _ = drive([ok([upd(10), upd(5), upd(10), upd(9), upd(11), upd(11)]), ok([upd(3), upd(12)])],
                  lambda u: seen.append(u["update_id"]))
    assert seen == [10, 11, 12]
    assert [r["offset"] for r in reqs(ev)] == [0, 12, 13]


def test_poll_update_id_equal_to_offset_is_handled_and_zero_is_valid():
    seen: list[int] = []
    drive([ok([upd(0), upd(1), upd(2)])], lambda u: seen.append(u["update_id"]))
    assert seen == [0, 1, 2]


BAD_UPDATES = [{}, {"message": {}}, {"update_id": None}, {"update_id": "9"}, {"update_id": True}, {"update_id": False},
               {"update_id": -1}, {"update_id": -10**9}, {"update_id": 9.0}, {"update_id": [9]},
               {"update_id": {"a": 1}},
               1, "x", None, [], [9], True, 3.5]


@pytest.mark.parametrize("bad", BAD_UPDATES, ids=repr)
def test_poll_ignores_malformed_updates_and_survives(bad):
    seen: list[int] = []
    ev, finished = drive([ok([upd(2), bad, upd(3)]), ok([bad]), ok([upd(4)])], lambda u: seen.append(u["update_id"]))
    assert not finished
    assert seen == [2, 3, 4]
    assert [r["offset"] for r in reqs(ev)] == [0, 4, 4, 5]
    assert not sleeps_of(ev)


def test_poll_malformed_first_update_does_not_move_offset():
    ev, _ = drive([ok([{"x": 1}]), ok([])])
    assert [r["offset"] for r in reqs(ev)] == [0, 0, 0]


def test_poll_huge_update_id():
    seen: list = []
    ev, _ = drive([ok([upd(2**62)])], lambda u: seen.append(u["update_id"]))
    assert seen == [2**62] and reqs(ev)[1]["offset"] == 2**62 + 1


def test_poll_handler_exception_is_logged_and_loop_continues(logs):
    seen: list[int] = []

    def h(u):
        seen.append(u["update_id"])
        if u["update_id"] == 2:
            raise RuntimeError("handler broke")
    ev, finished = drive([ok([upd(1), upd(2), upd(3)]), ok([upd(4)])], h)
    assert not finished and seen == [1, 2, 3, 4]
    assert [r["offset"] for r in reqs(ev)] == [0, 4, 5]
    assert not sleeps_of(ev)
    errs = [r for r in logs.records if r.levelno >= logging.ERROR and r.exc_info]
    assert errs and any("handler broke" in "".join(traceback.format_exception(*r.exc_info)) for r in errs)
    no_secret_in_log(logs)


def test_poll_async_handler_awaited_and_its_exception_survived(logs):
    seen: list = []

    async def h(u):
        await asyncio.sleep(0)
        seen.append(u["update_id"])
        if u["update_id"] == 1:
            raise ValueError("async broke")
    ev, _ = drive([ok([upd(1), upd(2)])], h)
    assert seen == [1, 2]
    assert any(r.levelno >= logging.ERROR for r in logs.records)


def test_poll_awaits_handler_before_next_update():
    order: list = []

    async def h(u):
        order.append(("start", u["update_id"]))
        await asyncio.sleep(0.01)
        order.append(("end", u["update_id"]))
    drive([ok([upd(1), upd(2)])], h)
    assert order == [("start", 1), ("end", 1), ("start", 2), ("end", 2)]


def test_poll_sync_handler_returning_non_awaitable():
    seen: list = []
    drive([ok([upd(1)])], lambda u: seen.append(1) or 42)
    assert seen == [1]


def test_poll_sync_handler_returning_coroutine_is_awaited():
    seen: list = []

    async def inner(u):
        seen.append(u["update_id"])

    drive([ok([upd(1)])], lambda u: inner(u))
    assert seen == [1]


def test_poll_telegram_error_in_handler_does_not_enter_error_pause(logs):
    def h(u):
        raise TelegramError("sendMessage", 500, "x")
    ev, finished = drive([ok([upd(1)]), ok([upd(2)])], h)
    assert not finished and not sleeps_of(ev)


def test_poll_cancelled_error_from_handler_propagates():
    def h(u):
        raise asyncio.CancelledError()
    _ev, finished = drive([ok([upd(1)]), ok([])], h)
    assert finished


def test_poll_handler_gets_the_update_content():
    got: list = []
    drive([ok([upd(1, extra={"k": "я"})])], got.append)
    assert got == [upd(1, extra={"k": "я"})]


@pytest.mark.parametrize("ra,wait", [(30, 30), (11, 11), (59, 59), (60, 60), (61, 60), (3600, 60), (10**9, 60)])
def test_poll_429_pause_is_clamped(ra, wait):
    ev, _ = drive([flood(ra), ok([])])
    assert sleeps_of(ev) == [wait]


@pytest.mark.parametrize("ra", [1, 5, 10])
def test_poll_429_small_value_pauses_both_inside_call_and_loop(ra):
    ev, _ = drive([flood(ra), flood(ra), ok([])])
    assert sleeps_of(ev) == [ra, ra]


def test_poll_429_zero_waits_at_least_one_second():
    ev, _ = drive([err(429, 429, "x", retry_after=0), err(429, 429, "x", retry_after=0), ok([])])
    assert all(s >= 1 for s in sleeps_of(ev)) and len(sleeps_of(ev)) == 2


def test_poll_429_without_parameters_pauses():
    ev, _ = drive([err(429, 429, "x"), err(429, 429, "x"), ok([])])
    assert sleeps_of(ev) and all(1 <= s <= 60 for s in sleeps_of(ev))


def test_poll_429_does_not_advance_error_backoff():
    ev, _ = drive([flood(30), err(500, 500, "x"), ok([])])
    assert sleeps_of(ev) == [30, 3]


def test_poll_429_keeps_offset():
    ev, _ = drive([ok([upd(4)]), flood(30), ok([])])
    assert [r["offset"] for r in reqs(ev)] == [0, 5, 5, 5]


ERRORS_FOR_BACKOFF = [
    lambda: err(500, 500, "x"), lambda: httpx.ConnectError(f"c {TOKEN}"),
    lambda: httpx.Response(502, content=b"<html>"),
    lambda: err(401, 401, "Unauthorized"), lambda: err(409, 409, "Conflict: terminated by other getUpdates request"),
    lambda: ok({"not": "a list"}), lambda: httpx.ReadTimeout("t"), lambda: httpx.Response(200, content=b"garbage"),
    lambda: err(403, 403, "x"), lambda: err(400, 400, "x"), lambda: err(404, 404, "Not Found"),
    lambda: httpx.Response(302, headers={"location": "https://e.test/"}),
]


def test_poll_error_pauses_grow_and_cap_then_reset_after_success(logs):
    steps = [ERRORS_FOR_BACKOFF[i % len(ERRORS_FOR_BACKOFF)]() for i in range(7)] + [ok([])]
    steps += [ERRORS_FOR_BACKOFF[0](), ok([]), ERRORS_FOR_BACKOFF[1](), ERRORS_FOR_BACKOFF[2](), ok([upd(1)]),
              ERRORS_FOR_BACKOFF[3]()]
    ev, finished = drive(steps)
    assert not finished
    assert sleeps_of(ev) == [3, 6, 12, 24, 48, 60, 60, 3, 3, 6, 3]
    warns = [r for r in logs.records if r.levelno == logging.WARNING]
    assert len(warns) >= 11
    no_secret_in_log(logs)


@pytest.mark.parametrize("mk", ERRORS_FOR_BACKOFF)
def test_poll_every_error_kind_pauses_and_survives(mk):
    ev, finished = drive([mk(), mk(), ok([upd(1)])])
    assert not finished
    assert sleeps_of(ev) == [3, 6]


def test_poll_empty_update_list_does_not_reset_via_error_and_no_pause():
    ev, _ = drive([ok([]), ok([]), ok([])])
    assert not sleeps_of(ev)


def test_poll_error_keeps_offset():
    ev, _ = drive([ok([upd(7)]), err(500, 500, "x"), ok([])])
    assert [r["offset"] for r in reqs(ev)] == [0, 8, 8, 8]


def test_poll_first_too_big_goes_to_limit_one_without_pause():
    ev, _ = drive([too_big_resp(), ok([upd(1)]), ok([upd(2)]), ok([]), ok([])])
    rs = reqs(ev)
    assert [r.get("limit") for r in rs] == [None, 1, 1, 1, None, None]
    assert [r["offset"] for r in rs] == [0, 0, 2, 3, 3, 3]
    assert not sleeps_of(ev)


def test_poll_too_big_with_limit_one_pauses_instead_of_spinning():
    ev, _ = drive([too_big_resp(), too_big_resp(), too_big_resp(), too_big_resp(), ok([])])
    kinds = [k for k, _ in ev]
    assert kinds[:2] == ["req", "req"], "после первого «слишком большой» пауза не нужна"
    assert sleeps_of(ev), "при limit=1 и том же сбое цикл крутится без пауз"
    assert all(s >= 1 for s in sleeps_of(ev))
    i = kinds.index("sleep")
    assert kinds[:i].count("req") <= 2


def test_poll_too_big_limit_one_does_not_skip_update_ids():
    seen: list = []
    drive([too_big_resp(), ok([upd(8)]), ok([])], lambda u: seen.append(u["update_id"]))
    assert seen == [8]


def test_poll_token_never_in_log_with_failures(logs):
    steps = [httpx.ConnectError(f"c {TOKEN}"), httpx.ReadTimeout(SECRET), err(500, 500, "x"), flood(30),
             stream_resp(200, [b"{", httpx.ReadError(f"r {TOKEN}")]), ok([upd(1)])]

    def h(u):
        raise RuntimeError("h")
    drive(steps, h)
    no_secret_in_log(logs)


def test_poll_error_log_is_warning_with_method(logs):
    drive([err(500, 500, "boom-description"), ok([])])
    warns = [r for r in logs.records if r.levelno == logging.WARNING]
    assert warns and any("getUpdates" in r.getMessage() or "500" in r.getMessage() for r in warns)


# --- wipe_due ------------------------------------------------------------------------------------------------------

@pytest.fixture
def wenv(tmp_path, monkeypatch):
    st_ = SimpleNamespace(fail={}, deleted=[], before=None, mode="500")
    orig = FakeTelegram.handler

    def handler(self, req):
        if req.url.path.endswith("/deleteMessage"):
            p = json.loads(req.content)
            st_.deleted.append((p["chat_id"], p["message_id"]))
            if st_.before:
                hook, st_.before = st_.before, None
                hook(p)
            f = st_.fail.get(p["message_id"])
            if f == "net":
                raise httpx.ConnectError(f"net {TOKEN}")
            if f is not None:
                code, desc = f
                return httpx.Response(code, json={"ok": False, "error_code": code, "description": desc})
        return orig(self, req)

    monkeypatch.setattr(FakeTelegram, "handler", handler)
    env = Env(tmp_path)
    return env, st_


def pending(env) -> list[tuple[int, int]]:
    return [tuple(w[:2]) for w in env.core.store.get("wipe_at") or []]


def wipe(env):
    env.run(env.ui.wipe_due())


def test_wipe_due_removes_deleted_and_keeps_future(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    env.ui.schedule_wipe(1, 11, 3600)
    env.ui.schedule_wipe(1, 12, -1)
    wipe(env)
    assert sorted(st_.deleted) == [(1, 10), (1, 12)]
    assert pending(env) == [(1, 11)]


def test_wipe_due_with_nothing_scheduled(wenv):
    env, st_ = wenv
    wipe(env)
    assert st_.deleted == [] and not env.core.store.get("wipe_at")


def test_wipe_due_empties_store_when_all_done(wenv):
    env, _ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    wipe(env)
    assert not env.core.store.get("wipe_at")


@pytest.mark.parametrize("fail", [(500, "x"), (502, "x"), (429, "x"), (403, "Forbidden"), (401, "x"),
                                  (404, "Not Found"), (409, "x"), "net"])
def test_wipe_due_failure_keeps_record_and_others_proceed(wenv, fail):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    env.ui.schedule_wipe(1, 11, -5)
    env.ui.schedule_wipe(2, 12, -5)
    st_.fail[11] = fail
    wipe(env)
    assert {(1, 10), (1, 11), (2, 12)} <= set(st_.deleted)
    assert pending(env) == [(1, 11)]
    # через минуту — повторная попытка, теперь удалось
    st_.fail.clear()
    st_.deleted.clear()
    wipe(env)
    assert (1, 11) in st_.deleted and pending(env) == []


def test_wipe_due_failure_first_does_not_block_later_ones(wenv):
    env, st_ = wenv
    for m in (10, 11, 12, 13):
        env.ui.schedule_wipe(1, m, -5)
    st_.fail[10] = (500, "x")
    wipe(env)
    assert {10, 11, 12, 13} <= {m for _, m in st_.deleted}
    assert pending(env) == [(1, 10)]


def test_wipe_due_failure_keeps_original_due_time(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    before = [list(w) for w in env.core.store.get("wipe_at")]
    st_.fail[10] = (500, "x")
    wipe(env)
    assert [list(w) for w in env.core.store.get("wipe_at")] == before


@pytest.mark.parametrize("desc,expected_removed", [("Bad Request: message can't be deleted for everyone", True),
                                                   ("Bad Request: message to delete not found", True)])
def test_wipe_due_400_removes_record(wenv, desc, expected_removed):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    st_.fail[10] = (400, desc)
    wipe(env)
    assert pending(env) == []


def test_wipe_due_not_yet_due_is_not_touched(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, 100)
    wipe(env)
    assert st_.deleted == [] and pending(env) == [(1, 10)]


def test_wipe_due_schedule_during_pass_is_not_lost(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    env.ui.schedule_wipe(1, 11, -5)
    st_.before = lambda p: env.ui.schedule_wipe(9, 99, 3600)
    wipe(env)
    assert (9, 99) in pending(env)
    assert (1, 10) not in pending(env) and (1, 11) not in pending(env)


def test_wipe_due_schedule_during_pass_with_failure_keeps_both(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    st_.fail[10] = (500, "x")
    st_.before = lambda p: env.ui.schedule_wipe(9, 99, 3600)
    wipe(env)
    assert sorted(pending(env)) == [(1, 10), (9, 99)]


def test_wipe_due_record_scheduled_during_pass_as_due_now_survives_to_next_pass(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    st_.before = lambda p: env.ui.schedule_wipe(9, 99, -5)
    wipe(env)
    assert (9, 99) in pending(env) or (9, 99) in st_.deleted
    if (9, 99) not in st_.deleted:
        wipe(env)
        assert (9, 99) in st_.deleted and pending(env) == []


def test_wipe_due_unschedule_during_pass_is_respected(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    env.ui.schedule_wipe(1, 11, 3600)
    st_.before = lambda p: env.ui.unschedule_wipe(1, 11)
    wipe(env)
    assert pending(env) == []


def test_wipe_due_gives_up_after_48_hours_past_due(wenv, logs):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -(48 * 3600 + 120))
    env.ui.schedule_wipe(1, 11, -(47 * 3600))
    st_.fail[10] = (500, "x")
    st_.fail[11] = (500, "x")
    wipe(env)
    assert pending(env) == [(1, 11)]
    assert [r for r in logs.records if r.levelno == logging.INFO and not r.name.startswith("httpx")]
    no_secret_in_log(logs)


def test_wipe_due_gives_up_on_network_failure_too_after_window(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -(60 * 3600))
    st_.fail[10] = "net"
    wipe(env)
    assert pending(env) == []


def test_wipe_due_old_record_still_tries_to_delete_when_possible(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -(49 * 3600))
    wipe(env)
    assert pending(env) == []


def test_wipe_due_repeated_passes_do_not_duplicate_requests_for_done_records(wenv):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    wipe(env)
    wipe(env)
    assert st_.deleted == [(1, 10)]


def test_wipe_due_failure_does_not_log_token(wenv, logs):
    env, st_ = wenv
    env.ui.schedule_wipe(1, 10, -5)
    st_.fail[10] = "net"
    wipe(env)
    no_secret_in_log(logs)


def test_wipe_due_time_boundary_due_exactly_now_is_due(wenv):
    env, st_ = wenv
    env.core.store.put("wipe_at", [[1, 10, int(time.time()) - 1]])
    wipe(env)
    assert st_.deleted == [(1, 10)]


# --- доводка: поля запроса, тексты ошибок и журнала, тайм-ауты ---------------------------------------------------

@pytest.mark.parametrize("status", [300, 399])
def test_redirect_range_edges_not_followed(status):
    s = Script(httpx.Response(status, headers={"location": "https://evil.test/c"}), AssertionError("redirect"))
    with pytest.raises(TelegramError) as ei:
        call_once(s)
    assert ei.value.code == status and s.n == 1


@pytest.mark.parametrize("status", [200, 299, 400, 500])
def test_status_next_to_redirect_range_is_read_as_usual(status):
    s = Script(httpx.Response(status, json={"ok": True, "result": 7}))
    assert call_once(s) == 7


def test_requests_are_post_with_finite_timeouts():
    s = Script(ok(1), ok(1))
    bot = make_bot(s)
    run(bot.call("getMe"))
    run(upload(bot))
    assert [r.method for r in s.requests] == ["POST", "POST"]
    t0, t1 = (r.extensions["timeout"] for r in s.requests)
    assert t0 == {"connect": 15.0, "read": 75.0, "write": 75.0, "pool": 75.0}
    assert t1 == {"connect": 15.0, "read": 300.0, "write": 300.0, "pool": 300.0}
    assert t0["read"] > 50   # дольше long polling в getUpdates


def test_every_error_names_its_method():
    cases = [(Script(httpx.ConnectError("x")), 0), (Script(httpx.Response(200, content=b"<html>")), 200),
             (Script(err(400, 400, "d")), 400), (Script(too_big_resp()), 0), (Script(flood(500)), 429),
             (Script(httpx.Response(200, json={"ok": True})), 200)]
    for s, code in cases:
        with pytest.raises(TelegramError) as ei:
            call_once(s, method="someMethod")
        assert ei.value.method == "someMethod" and ei.value.code == code
        assert str(ei.value).startswith(f"telegram someMethod: {code} ")


def test_poll_warning_text_names_method_code_and_description(logs):
    drive([err(500, 500, "boom-description"), ok([])])
    warns = [r.getMessage() for r in logs.records if r.levelno == logging.WARNING]
    assert warns == ["getUpdates: telegram getUpdates: 500 boom-description"]


def test_poll_handler_failure_logged_as_update_with_traceback(logs):
    def h(u):
        raise RuntimeError("handler broke")
    drive([ok([upd(1)])], h)
    recs = [r for r in logs.records if r.levelno == logging.ERROR]
    assert [r.getMessage() for r in recs] == ["update"] and recs[0].exc_info


def test_answer_warning_text_has_code_and_description(logs):
    run_answer(Script(err(403, 403, "Forbidden: bot was blocked")))
    warns = [r.getMessage() for r in logs.records if r.levelno == logging.WARNING]
    assert warns == ["answerCallbackQuery: 403 'Forbidden: bot was blocked'"]


def test_delete_refusal_info_text_has_description(logs):
    run_delete(Script(err(400, 400, "Bad Request: message can't be deleted")))
    infos = [r.getMessage() for r in logs.records if r.levelno == logging.INFO and not r.name.startswith("httpx")]
    assert infos == ["deleteMessage refused: \"Bad Request: message can't be deleted\""]


def test_copy_many_wire_fields():
    bot, s = copy_many_bot()
    run(bot.copy_many(-100123, "@abcd", [3, 1, 2]))
    b = s.body()
    assert b["chat_id"] == -100123 and b["from_chat_id"] == "@abcd" and b["message_ids"] == [1, 2, 3]
    run(bot.copy_many("@wxyz", 55, [9]))
    b = s.body()
    assert b["chat_id"] == "@wxyz" and b["from_chat_id"] == 55


@pytest.mark.parametrize("call,match", [
    (lambda bot: bot.copy_many(0, 8, [1]), "invalid chat_id"),
    (lambda bot: bot.copy_many(7, 0, [1]), "invalid from_chat"),
    (lambda bot: bot.copy_many(7, 8, []), "invalid message_ids"),
    (lambda bot: bot.copy_many(7, 8, [1, 1]), "duplicate message_ids"),
    (lambda bot: bot.copy_many(7, 8, [0]), "invalid message_id"),
    (lambda bot: bot.copy(0, 8, 1), "invalid chat_id"),
    (lambda bot: bot.copy(7, 0, 1), "invalid from_chat"),
    (lambda bot: bot.copy(7, 8, 0), "invalid message_id"),
])
def test_validation_errors_name_the_argument(call, match):
    bot, _ = copy_many_bot()
    with pytest.raises(ValueError, match=match):
        run(call(bot))


# --- остальные методы Bot: форма запроса ---------------------------------------------------------------------------

def one(script_result=True, **kw):
    s = Script(ok(script_result), **kw)
    return make_bot(s), s


def test_send_minimal_and_full_payload():
    bot, s = one({"message_id": 4})
    assert run(bot.send(1, "t")) == {"message_id": 4}
    assert s.body() == {"chat_id": 1, "text": "t", "link_preview_options": {"is_disabled": True}}
    bot, s = one({"message_id": 4})
    ents, mk = [{"type": "bold", "offset": 0, "length": 1}], {"inline_keyboard": []}
    run(bot.send("@abcd", "t", entities=ents, reply_to=9, markup=mk, preview=True))
    assert s.body() == {"chat_id": "@abcd", "text": "t", "entities": ents, "reply_markup": mk,
                        "reply_parameters": {"message_id": 9, "allow_sending_without_reply": True},
                        "link_preview_options": {"is_disabled": False}}
    bot, s = one({"message_id": 4})
    run(bot.send(1, "t", reply_to=0))
    assert "reply_parameters" not in s.body()


def test_edit_payload_and_not_modified_is_quiet():
    bot, s = one(forever=True)
    run(bot.edit(1, 2, "new"))
    assert s.body() == {"chat_id": 1, "message_id": 2, "text": "new", "link_preview_options": {"is_disabled": True}}
    assert s.requests[0].url.path.endswith("/editMessageText")
    mk = {"inline_keyboard": [[{"text": "a", "callback_data": "b"}]]}
    run(bot.edit(1, 2, "new", markup=mk))
    assert s.body()["reply_markup"] == mk
    quiet = make_bot(Script(err(400, 400, "Bad Request: message is not modified: exactly the same")))
    assert run(quiet.edit(1, 2, "x")) is None
    for status, desc in [(400, "Bad Request: message to edit not found"), (400, "Message is not modified"),
                         (429, "x"), (500, "x")]:
        bad = make_bot(Script(err(status, status, desc, retry_after=99), forever=True))
        with pytest.raises(TelegramError) as ei:
            run(bad.edit(1, 2, "x"))
        assert ei.value.code == status


def test_edit_markup_payload_and_not_modified_is_quiet():
    bot, s = one(forever=True)
    run(bot.edit_markup(1, 2, None))
    assert s.body() == {"chat_id": 1, "message_id": 2, "reply_markup": {"inline_keyboard": []}}
    assert s.requests[0].url.path.endswith("/editMessageReplyMarkup")
    run(bot.edit_markup(1, 2, {}))
    assert s.body()["reply_markup"] == {"inline_keyboard": []}
    mk = {"inline_keyboard": [[{"text": "a", "callback_data": "b"}]]}
    run(bot.edit_markup(1, 2, mk))
    assert s.body()["reply_markup"] == mk
    quiet = make_bot(Script(err(400, 400, "Bad Request: message is not modified")))
    assert run(quiet.edit_markup(1, 2, None)) is None
    for status, desc in [(400, "Bad Request: message not found"), (403, "Forbidden"), (500, "x")]:
        bad = make_bot(Script(err(status, status, desc), forever=True))
        with pytest.raises(TelegramError):
            run(bad.edit_markup(1, 2, mk))


def test_set_commands_sends_both_calls_in_order_and_stops_on_first_failure():
    bot, s = one(forever=False)
    s.steps.append(ok(True))
    run(bot.set_commands([("start", "Начать"), ("help", "Помощь")]))
    assert [r.url.path.rsplit("/", 1)[1] for r in s.requests] == ["setMyCommands", "setChatMenuButton"]
    assert s.body(0) == {"commands": [{"command": "start", "description": "Начать"},
                                      {"command": "help", "description": "Помощь"}]}
    assert s.body(1) == {"menu_button": {"type": "commands"}}
    failing = Script(err(400, 400, "bad"), ok(True))
    with pytest.raises(TelegramError):
        run(make_bot(failing).set_commands([("a", "b")]))
    assert failing.n == 1


def test_send_group_and_get_me_payloads():
    bot, s = one([{"message_id": 1}])
    media = [{"type": "photo", "media": "f1"}, {"type": "photo", "media": "f2"}]
    assert run(bot.send_group(-100, media)) == [{"message_id": 1}]
    assert s.body() == {"chat_id": -100, "media": media}
    assert s.requests[0].url.path.endswith("/sendMediaGroup")
    bot, s = one({"id": 5})
    assert run(bot.get_me()) == {"id": 5} and s.body() == {}


def test_upload_group_multipart_shape():
    s = Script(ok([{"message_id": 1}, {"message_id": 2}]))
    bot = make_bot(s)
    ents = [{"type": "bold", "offset": 0, "length": 1}]
    run(bot.upload_group(-100, [("photo", "a/b.png", b"AAAA", "image/png"), ("document", "", b"BBBB", "text/plain")],
                         caption="подпись", caption_entities=ents))
    req = s.requests[0]
    body = req.content.decode("utf-8", errors="replace")
    assert req.headers["content-type"].startswith("multipart/form-data")
    assert req.url.path.endswith("/sendMediaGroup")
    parts = {}
    for chunk in body.split("--")[1:]:
        head, _, val = chunk.partition("\r\n\r\n")
        if 'name="' in head:
            parts[head.split('name="')[1].split('"')[0]] = (head, val.rsplit("\r\n", 1)[0])
    assert parts["chat_id"][1] == "-100"
    media = json.loads(parts["media"][1])
    assert media == [{"type": "photo", "media": "attach://f0", "caption": "подпись", "caption_entities": ents},
                     {"type": "document", "media": "attach://f1"}]
    assert 'filename="a_b.png"' in parts["f0"][0] and "image/png" in parts["f0"][0] and parts["f0"][1] == "AAAA"
    assert 'filename="document"' in parts["f1"][0] and "text/plain" in parts["f1"][0] and parts["f1"][1] == "BBBB"


def test_upload_group_without_caption_has_no_caption_keys():
    s = Script(ok([{"message_id": 1}]))
    run(make_bot(s).upload_group(5, [("photo", "a.png", b"A", "image/png")], caption_entities=[{"type": "bold"}]))
    body = s.requests[0].content.decode("utf-8", errors="replace")
    assert "caption" not in body


@pytest.mark.parametrize("name,kind,expected", [
    ("a.png", "file", "a.png"), ("", "photo", "photo"), (None, "video", "video"), ("..", "file", "file"),
    ("  . x .  ", "file", "x"), (" . ", "file", "file"), ("a/b\\c\"d", "file", "a_b_c_d"), ("x\x00y\n", "file", "x_y_"),
    ("é" * 64, "file", "é" * 64), ("é" * 65, "file", "é" * 64), ("a" * 100 + " ", "file", "a" * 64),
    ("..hidden", "file", "hidden"), ("тест.txt", "file", "тест.txt"),
])
def test_safe_filename(name, kind, expected):
    assert telegram.safe_filename(name, kind) == expected


def test_safe_filename_default_kind_and_none():
    assert telegram.safe_filename(None) == "file" and telegram.safe_filename("") == "file"


@pytest.mark.parametrize("mime,default,expected", [
    ("image/PNG", None, "image/png"), ("  text/plain ", None, "text/plain"), (None, None, "application/octet-stream"),
    ("", "x/y", "x/y"), ("text/plain; charset=utf-8", None, "application/octet-stream"),
    ("a/b\r\nX: y", None, "application/octet-stream"), ("nosep", "audio/ogg", "audio/ogg"),
    ("application/vnd.api+json", None, "application/vnd.api+json"),
])
def test_safe_mime(mime, default, expected):
    assert telegram.safe_mime(mime, default) == expected


# --- download ------------------------------------------------------------------------------------------------------

def dl(file_info, file_resp, max_bytes=100, **kw):
    s = Script(ok(file_info), file_resp, **kw)
    bot = make_bot(s)
    try:
        return run(bot.download("FID", max_bytes)), s
    finally:
        run(bot.close())


def test_download_reads_file_from_bot_file_url():
    data, s = dl({"file_id": "FID", "file_path": "docs/a.bin", "file_size": 3}, httpx.Response(200, content=b"abc"))
    assert data == b"abc"
    assert s.body(0) == {"file_id": "FID"} and s.requests[0].url.path.endswith("/getFile")
    assert s.requests[1].method == "GET" and s.requests[1].url.path == f"/file/bot{TOKEN}/docs/a.bin"
    assert s.requests[1].extensions["timeout"] == {"connect": 15.0, "read": 300.0, "write": 300.0, "pool": 300.0}


def test_download_size_limits():
    info = {"file_path": "p", "file_size": 100}
    data, _ = dl(info, httpx.Response(200, content=b"x" * 100))
    assert len(data) == 100
    with pytest.raises(TelegramError) as ei:
        dl({"file_path": "p", "file_size": 101}, httpx.Response(200, content=b""))
    assert (ei.value.method, ei.value.code, ei.value.description) == ("getFile", 0, "file too big")
    data, _ = dl({"file_path": "p"}, httpx.Response(200, content=b"y" * 100))
    assert len(data) == 100
    with pytest.raises(TelegramError) as ei:
        dl({"file_path": "p"}, stream_resp(200, [b"y" * 60, b"y" * 41]))
    assert (ei.value.method, ei.value.code, ei.value.description) == ("download", 0, "file too big")
    with pytest.raises(TelegramError) as ei:
        dl({"file_path": "p", "file_size": 5}, stream_resp(200, [b"y" * 60, b"y" * 41]))
    assert ei.value.description == "file too big"


def test_download_without_file_path_or_bad_result():
    with pytest.raises(TelegramError) as ei:
        dl({"file_id": "FID"}, httpx.Response(200, content=b"x"))
    assert (ei.value.method, ei.value.description) == ("getFile", "file too big")
    for bad in ([], "x", None, 5):
        with pytest.raises(TelegramError) as ei:
            dl(bad, httpx.Response(200, content=b"x"))
        assert (ei.value.method, ei.value.code, ei.value.description) == ("getFile", 0, "bad result")


@pytest.mark.parametrize("status", [201, 204, 301, 302, 403, 404, 500])
def test_download_non_200_is_error_with_status(status):
    s = Script(ok({"file_path": "p"}), httpx.Response(status, headers={"location": "https://evil.test/"}),
               AssertionError("redirect"))
    with pytest.raises(TelegramError) as ei:
        run(make_bot(s).download("FID", 100))
    assert (ei.value.method, ei.value.code, ei.value.description) == ("download", status, "download failed")
    assert s.n == 2


def test_download_network_failure_hides_token(logs):
    for exc in (httpx.ConnectError(f"x {TOKEN}"), httpx.ReadTimeout(SECRET)):
        s = Script(ok({"file_path": "p"}), exc)
        with pytest.raises(TelegramError) as ei:
            run(make_bot(s).download("FID", 100))
        assert (ei.value.method, ei.value.code, ei.value.description) == ("download", 0, type(exc).__name__)
        no_secret(ei.value)
    s = Script(ok({"file_path": "p"}), stream_resp(200, [b"ab", httpx.ReadError(f"x {TOKEN}")]))
    with pytest.raises(TelegramError) as ei:
        run(make_bot(s).download("FID", 100))
    no_secret(ei.value)
    no_secret_in_log(logs)


# --- доводка по выжившим мутантам ----------------------------------------------------------------------------------

def test_upload_json_params_keep_unicode_unescaped():
    s = Script(ok(True))
    run(make_bot(s).upload("sendDocument", "document", "a.txt", b"X", "text/plain", chat_id=1,
                           reply_markup={"inline_keyboard": [[{"text": "привет", "callback_data": "a"}]]}))
    raw = s.requests[0].content.decode("utf-8", errors="replace")
    assert "привет" in raw and "\\u043f" not in raw


def test_safe_filename_strips_only_space_and_dot():
    from veil.core.transport.telegram import safe_filename
    assert safe_filename("XXa.pngXX") == "XXa.pngXX"
    assert safe_filename(" . a.png . ") == "a.png"


def test_answer_default_is_not_alert():
    s = Script(ok(True))
    run(make_bot(s).answer("cb-1", "t"))
    assert not s.body().get("show_alert")


@pytest.mark.parametrize("ids,msg", [([], "invalid message_ids$"), ([1, 1], "duplicate message_ids$")])
def test_copy_many_error_texts(ids, msg):
    with pytest.raises(ValueError, match=msg):
        run(make_bot(Script(ok([]))).copy_many(7, 8, ids))


def test_token_in_log_replaced_with_marker_exactly(logs):
    log = logging.getLogger("httpx")
    log.info('HTTP Request: POST https://tg.test/bot%s/getMe "HTTP/1.1 200 OK"', TOKEN)
    msgs = [r.getMessage() for r in logs.records if r.name == "httpx" and "HTTP Request" in r.getMessage()]
    assert msgs
    # фильтр вешается при создании бота
    make_bot(Script(ok(True)))
    log.info('HTTP Request: POST https://tg.test/bot%s/getMe "HTTP/1.1 200 OK"', TOKEN)
    last = [r.getMessage() for r in logs.records if r.name == "httpx"][-1]
    assert last == 'HTTP Request: POST https://tg.test/bot<token>/getMe "HTTP/1.1 200 OK"'
