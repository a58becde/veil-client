"""Первое касание приёмного бота (spec/04, «Первое касание»; spec/02, `inbox_names`): тесты от правил spec.

Telegram здесь — модель bot-to-bot: числовой ID чужого бота «неизвестен», пока по нему не писали; `sendMessage` по
@username разрешает имя, делает чат известным и возвращает сообщение с `chat.id` адресата. Главный инвариант —
по @username уходит только `/start` без других полей, на любых путях и при любых ответах."""
import asyncio
import copy
import json
import logging
import re
import time

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core import api
from veil.core.protocol import b64, envelope, jcs, keysdoc
from veil.core.store.db import Store
from veil.core.transport import exchange as exmod
from veil.core.transport.exchange import Exchange, NoReplyError, ServerError
from veil.core.transport.telegram import Bot, TelegramError

REAL_SLEEP = asyncio.sleep
VECTORS = json.loads((__import__("pathlib").Path(__file__).resolve().parents[2] / "veil-protocol" / "test-vectors"
                      / "veil-v1.json").read_text())
A, B = 111_222_333, 222_333_444
NAME_A, NAME_B = "veil_inbox_bot", "veil_second_bot"
IDS = [A, B]
ALLOWED = (TelegramError, ServerError, NoReplyError)
NAME_RE = re.compile(r"@[A-Za-z][A-Za-z0-9_]{1,28}[Bb][Oo][Tt]")
PROP = settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.too_slow])
NOT_FOUND = (400, "Bad Request: chat not found")


def err(code: int, desc: str, **params):
    return ("err", code, desc, params)


def ok(result):
    return ("ok", result)


class Net:
    """Bot API бота клиента. known — чаты, куда можно писать по ID; owners — кто стоит за @username (имя → ID);
    rules — правила поверх модели: rule(method, params) → None | err(...) | ok(...)."""

    def __init__(self, known=(), owners=None):
        self.known = set(known)
        self.owners = {k.lower(): v for k, v in (owners or {}).items()}
        self.rules: list = []
        self.calls: list[tuple[str, dict]] = []
        self.envs: list[tuple[int, int, str]] = []
        self.mid = 1000

    def at_calls(self) -> list[dict]:
        return [p for _, p in self.calls if isinstance(p.get("chat_id"), str)]

    def to(self, chat: int, method: str | None = None) -> list[tuple[str, dict]]:
        return [(m, p) for m, p in self.calls if p.get("chat_id") == chat and (method is None or m == method)]

    def _msg(self, chat) -> dict:
        self.mid += 1
        return {"message_id": self.mid, "chat": {"id": chat, "type": "private"}, "date": 0}

    def _parse(self, req: httpx.Request) -> tuple[dict, str | None]:
        ctype = req.headers.get("content-type", "")
        if ctype.startswith("application/json"):
            return json.loads(req.content or b"{}"), None
        p, filedata = {}, None
        boundary = ctype.split("boundary=")[1].encode()
        for part in req.content.split(b"--" + boundary)[1:-1]:
            head, _, data = part.partition(b"\r\n\r\n")
            data = data.rsplit(b"\r\n", 1)[0]
            name = head.split(b'name="', 1)[1].split(b'"', 1)[0].decode()
            if b"filename=" in head:
                filedata = data.decode("utf-8", "replace")
            else:
                v = data.decode()
                p[name] = int(v) if re.fullmatch(r"-?\d+", v) else v
        return p, filedata

    def handler(self, req: httpx.Request) -> httpx.Response:
        method = req.url.path.rsplit("/", 1)[1]
        p, filedata = self._parse(req)
        self.calls.append((method, p))
        out = None
        for rule in self.rules:
            out = rule(method, p)
            if out is not None:
                break
        if out is None:
            out = self._model(method, p)
        if out[0] == "err":
            _, code, desc, params = out
            return httpx.Response(200, json={"ok": False, "error_code": code, "description": desc,
                                             "parameters": params})
        result = out[1]
        chat = p.get("chat_id")
        if isinstance(chat, int) and method in ("sendMessage", "sendDocument") and isinstance(result, dict):
            text = p.get("text") if method == "sendMessage" else filedata
            if isinstance(text, str) and text.startswith("VEIL1"):
                self.envs.append((chat, result["message_id"], text))
        return httpx.Response(200, json={"ok": True, "result": result})

    def _model(self, method: str, p: dict):
        chat = p.get("chat_id")
        if isinstance(chat, str):
            owner = self.owners.get(chat.lstrip("@").lower())
            if owner is None:
                return err(*NOT_FOUND)
            self.known.add(owner)
            return ok(self._msg(owner))
        if chat not in self.known:
            return err(*NOT_FOUND)
        if method == "getChat":
            return ok({"id": chat, "type": "private"})
        if method in ("sendMessage", "sendDocument"):
            return ok(self._msg(chat))
        if method == "copyMessage":
            self.mid += 1
            return ok({"message_id": self.mid})
        if method == "copyMessages":
            self.mid += 1
            return ok([{"message_id": self.mid}])
        if method == "sendMediaGroup":
            return ok([self._msg(chat)])
        return ok(True)


class Rig:
    def __init__(self, net: Net, ids=IDS, names="default", username=NAME_A, flag=None):
        self.net, self.ids = net, list(ids)
        self.names = {A: NAME_A, B: NAME_B} if names == "default" else names
        self.sleeps: list[float] = []
        self.flags: list = [] if flag is None else flag

        async def sleep(s):
            self.sleeps.append(s)
        self.bot = Bot("1:x", base_url="https://tg.test", transport=httpx.MockTransport(net.handler), sleep=sleep)
        self.inbox, self.server = PrivateKey.generate(), SigningKey.generate()
        self.ex = Exchange(self.bot, "@" + username, bytes(self.server.verify_key),
                           lambda: ("i1", bytes(self.inbox.public_key)), lambda: self.ids, lambda: self.names,
                           self.flags.append)
        self.split = False
        self.reply = {}

    async def serve(self):
        done = 0
        while True:
            while done < len(self.net.envs):
                chat, mid, text = self.net.envs[done]
                done += 1
                env = envelope.open_envelope(text, self.inbox, max_plain=envelope.MAX_DOC_PLAINTEXT)
                resp = envelope.build_response(env["id"], self.server, result=self.reply)
                sealed = envelope.seal_response(resp, b64.dec(env["resp_pk"]))
                for part in (envelope.split_response(sealed) if self.split else [sealed]):
                    self.ex.on_inbox_message({"from": {"is_bot": True, "id": chat}, "chat": {"id": chat}, "text": part,
                                              "reply_to_message": {"message_id": mid}})
            await REAL_SLEEP(0.002)

    def drive(self, factory):
        async def go():
            t = asyncio.create_task(self.serve())
            try:
                try:
                    return ("ok", await asyncio.wait_for(factory(), 10))
                except Exception as e:  # noqa: BLE001
                    return ("err", e)
            finally:
                t.cancel()
        return asyncio.run(go())

    def req(self, op="keys.get", **kw):
        return self.ex.request(op, "ephemeral", SigningKey.generate(), body=kw.pop("body", {}), **kw)


class Clock:
    def __init__(self):
        self.t = 10_000.0

    def monotonic(self):
        return self.t

    def __getattr__(self, name):
        return getattr(time, name)


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(exmod, "time", c)
    return c


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    async def quick(s):
        await REAL_SLEEP(0)
    monkeypatch.setattr(exmod.asyncio, "sleep", quick)
    monkeypatch.setattr(exmod, "WAIT", 0.3)


def assert_only_start_by_name(net: Net) -> None:
    for method, p in net.calls:
        for field in ("chat_id", "from_chat_id"):
            v = p.get(field)
            if isinstance(v, str):
                assert field == "chat_id" and method == "sendMessage", (method, p)
                assert v.startswith("@") and NAME_RE.fullmatch(v), (method, p)
                assert p == {"chat_id": v, "text": "/start"}, (method, p)
        assert not (isinstance(p.get("chat_id"), str) and "VEIL1" in json.dumps(p)), (method, p)


def at_start_count(net: Net) -> int:
    return len([p for p in net.at_calls()])


# --- сценарии сети и пути отправки -------------------------------------------------------------------------
def scenario(name: str) -> Net:
    if name == "known":
        return Net(known=IDS)
    if name == "touch_ok":
        return Net(owners={NAME_A: A, NAME_B: B})
    if name == "touch_other":
        return Net(known=[], owners={NAME_A: B, NAME_B: B})
    if name == "stranger":
        return Net(owners={NAME_A: 777, NAME_B: 888})
    if name == "no_such_name":
        return Net()
    if name == "dead_403":
        n = Net(known=[B])
        n.rules.append(lambda m, p: err(403, "Forbidden: bot was blocked by the user")
                       if p.get("chat_id") == A else None)
        return n
    if name == "garbage":
        n = Net(owners={NAME_A: A, NAME_B: B})
        n.rules.append(lambda m, p: ok("garbage") if isinstance(p.get("chat_id"), str) else None)
        return n
    if name == "touch_429":
        n = Net(owners={NAME_A: A, NAME_B: B})
        n.rules.append(lambda m, p: err(429, "Too Many Requests", retry_after=1)
                       if isinstance(p.get("chat_id"), str) else None)
        return n
    raise KeyError(name)


SCENARIOS = ["known", "touch_ok", "touch_other", "stranger", "no_such_name", "dead_403", "garbage", "touch_429"]
BIG = "".join(chr(33 + (i * 7919) % 90) for i in range(30000))


def _copy(r: Rig, method: str):
    async def deliver():
        got = await r.bot.call(method, chat_id=r.ex.inbox, from_chat_id=5, message_id=7, message_ids=[7, 8])
        return got["message_id"] if isinstance(got, dict) else got[0]["message_id"]
    return deliver


def _state() -> tuple[dict, SigningKey, PrivateKey]:
    r, auth, rsk, states = Rig(scenario("known")), SigningKey.generate(), PrivateKey.generate(), []
    out = r.drive(lambda: r.ex.request("post.create", "ephemeral", auth, body={"x": 1}, journal=states.append,
                                       resp_sk=rsk))
    assert out[0] == "ok"
    return states[0], auth, rsk


PATHS = {
    "plain": lambda r: r.req(),
    "media": lambda r: r.req("post.create", deliver=_copy(r, "copyMessage")),
    "album": lambda r: r.req("post.create", deliver=_copy(r, "copyMessages")),
    "big_document": lambda r: r.req("post.create", body={"x": BIG}),
    "hidden_to": lambda r: r.req("hidden.file", to=B),
}


def _resume_factory(r: Rig):
    state, auth, rsk = _state()
    return lambda: r.ex.resume(state, auth_key=auth, resp_sk=rsk)


def run_path(path: str, r: Rig):
    if path == "resume":
        return r.drive(_resume_factory(r))
    if path == "parts":
        r.split, r.reply = True, {"posts": ["я" * 100] * 50}
    return r.drive(lambda: PATHS.get(path, PATHS["plain"])(r))


ALL_PATHS = ["plain", "media", "album", "big_document", "hidden_to", "resume", "parts"]


@pytest.mark.parametrize("scn", SCENARIOS)
@pytest.mark.parametrize("path", ALL_PATHS)
def test_by_name_only_start_on_every_path(path, scn):
    net = scenario(scn)
    r = Rig(net)
    kind, value = run_path(path, r)
    assert_only_start_by_name(net)
    if kind == "err":
        assert isinstance(value, ALLOWED), repr(value)
    # не больше одного касания на приёмный бот
    names = [p["chat_id"].lower() for p in net.at_calls()]
    per_touch = 2 if scn == "touch_429" else 1  # 429: транспорт сам повторяет вызов один раз
    assert len(set(names)) <= len(IDS) and all(names.count(n) <= per_touch for n in set(names))


@pytest.mark.parametrize("path", ["plain", "media", "album", "big_document", "resume", "parts"])
def test_touch_then_single_retry_same_id_and_success(path):
    net = scenario("touch_ok")
    r = Rig(net)
    kind, value = run_path(path, r)
    assert kind == "ok", repr(value)
    assert [p for p in net.at_calls()] == [{"chat_id": "@" + NAME_A, "text": "/start"}]
    first = {"media": "copyMessage", "album": "copyMessages", "big_document": "sendDocument"}.get(path, "sendMessage")
    tries = [m for m, p in net.calls if p.get("chat_id") == A and m == first]
    assert len(tries) == 2  # неудача + ровно один повтор (у медиа и альбома конверт идёт отдельным sendMessage)
    assert net.envs and all(c == A for c, _, _ in net.envs)
    assert not net.to(B)


def test_hidden_file_to_second_bot_touches_second_name():
    net = scenario("touch_ok")
    r = Rig(net)
    kind, value = r.drive(lambda: r.req("hidden.file", to=B))
    assert kind == "ok", repr(value)
    assert [p["chat_id"] for p in net.at_calls()] == ["@" + NAME_B]
    assert all(c == B for c, _, _ in net.envs) and not net.to(A)


def test_big_envelope_goes_as_document_by_id_never_by_name():
    net = scenario("touch_ok")
    r = Rig(net)
    kind, value = r.drive(lambda: r.req("post.create", body={"x": BIG}))
    assert kind == "ok", repr(value)
    assert "sendDocument" in [m for m, _ in net.calls]
    assert all(isinstance(p["chat_id"], int) for m, p in net.calls if m == "sendDocument")
    assert_only_start_by_name(net)


def test_touch_other_inbox_bot_known_then_switch_without_second_touch():
    net = scenario("touch_other")
    r = Rig(net)
    kind, value = r.drive(lambda: r.req())
    assert kind == "ok", repr(value)
    assert [p["chat_id"] for p in net.at_calls()] == ["@" + NAME_A]  # B уже известен: второго касания нет
    assert len(net.to(A, "sendMessage")) == 1  # исходный вызов по A не повторяется
    assert [c for c, _, _ in net.envs] == [B]


def test_no_touch_when_known_and_nothing_by_name():
    net = scenario("known")
    r = Rig(net)
    assert r.drive(lambda: r.req())[0] == "ok"
    assert net.at_calls() == [] and [m for m, _ in net.calls] == ["sendMessage"]


# --- когда касаться ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("desc", ["Bad Request: chat not found", "BAD REQUEST: CHAT NOT FOUND", "chat not found",
                                  "Bad Request: Chat Not Found"])
def test_touch_on_chat_not_found_any_case(desc):
    net = Net(owners={NAME_A: A})
    net.rules.append(lambda m, p: err(400, desc) if p.get("chat_id") == A and not net.at_calls() else None)
    r = Rig(net, ids=[A])
    kind, value = r.drive(lambda: r.req())
    assert kind == "ok", repr(value)
    assert len(net.at_calls()) == 1


@pytest.mark.parametrize("code,desc", [
    (403, "Forbidden: bot was blocked by the user"), (403, "Forbidden: chat not found"),
    (400, "Bad Request: message to copy not found"), (400, "Bad Request: can't parse entities"),
    (400, "Bad Request: chat_id is empty"), (404, "Not Found"), (404, "chat not found"),
    (429, "Too Many Requests: retry later"), (500, "Internal Server Error"), (502, "Bad Gateway"),
    (0, "network"), (401, "Unauthorized")])
def test_no_touch_on_other_errors(code, desc):
    net = Net(known=[A], owners={NAME_A: A})
    net.rules.append(lambda m, p: err(code, desc, retry_after=60) if p.get("chat_id") == A else None)
    r = Rig(net, ids=[A])
    kind, value = r.drive(lambda: r.req())
    assert kind == "err" and isinstance(value, ALLOWED)
    assert net.at_calls() == []


def test_no_touch_on_network_failure():
    def boom(req):
        raise httpx.ConnectError("down")
    net = Net(owners={NAME_A: A})
    r = Rig(net, ids=[A])
    r.bot = Bot("1:x", base_url="https://tg.test", transport=httpx.MockTransport(boom),
                sleep=lambda s: asyncio.sleep(0))
    r.ex.bot = r.bot
    kind, value = r.drive(lambda: r.req())
    assert kind == "err"
    assert net.at_calls() == []


def test_no_ids_published_means_old_behaviour_no_touch():
    net = Net(owners={NAME_A: A})
    net.rules.append(lambda m, p: err(*NOT_FOUND) if isinstance(p.get("chat_id"), str) else None)
    r = Rig(net, ids=[])
    kind, value = r.drive(lambda: r.req())
    assert kind == "err" and isinstance(value, ALLOWED)
    assert len(net.at_calls()) == 1  # одна отправка по @username, как раньше: это сам запрос, а не касание
    asyncio.run(r.ex.ensure_known())
    assert len(net.at_calls()) == 1 and "getChat" not in [m for m, _ in net.calls]


def test_touch_unlisted_id_does_nothing():
    net = Net(owners={NAME_A: 999})
    r = Rig(net, ids=[A], names={999: NAME_A})
    assert asyncio.run(r.ex.touch(999)) is False
    assert net.at_calls() == []


def test_touch_returns_true_only_for_requested_id():
    net = scenario("touch_other")
    r = Rig(net)
    assert asyncio.run(r.ex.touch(A)) is False
    net2 = scenario("touch_ok")
    r2 = Rig(net2)
    assert asyncio.run(r2.ex.touch(A)) is True


def test_name_from_inbox_names_beats_config_and_case_is_ignored():
    net = Net(owners={"veil_inbox_bot": A, "config_name_bot": 999})
    r = Rig(net, ids=[A], names={A: "Veil_Inbox_BOT"}, username="config_name_bot")
    assert asyncio.run(r.ex.touch(A)) is True
    assert [p["chat_id"].lower() for p in net.at_calls()] == ["@veil_inbox_bot"]


def test_config_name_is_fallback_when_no_published_name():
    net = Net(owners={"config_name_bot": A})
    r = Rig(net, ids=[A], names={}, username="config_name_bot")
    assert asyncio.run(r.ex.touch(A)) is True
    assert [p["chat_id"].lower() for p in net.at_calls()] == ["@config_name_bot"]


def test_names_callable_raising_falls_back():
    net = Net(owners={"config_name_bot": A})
    r = Rig(net, ids=[A], username="config_name_bot")

    def boom():
        raise RuntimeError("x")
    r.ex.inbox_names = boom
    assert asyncio.run(r.ex.touch(A)) is True
    assert_only_start_by_name(net)


@pytest.mark.parametrize("bad", ["evil\nbot", "bad name bot", "@veil_inbox_bot", "xbot", "a" * 40 + "bot", "ботbot",
                                 "name.bot", "9name_bot", "veil_inbox_bot\n", "veil_inbox_bot ", "", None, 5,
                                 ["veil_inbox_bot"]])
def test_malformed_published_name_is_never_sent(bad):
    net = Net(owners={"config_name_bot": A})
    r = Rig(net, ids=[A], names={A: bad}, username="config_name_bot")
    asyncio.run(r.ex.touch(A))
    assert_only_start_by_name(net)
    assert all(p["chat_id"].lower() == "@config_name_bot" for p in net.at_calls())


def test_malformed_config_name_and_no_published_never_sent():
    net = Net(owners={})
    r = Rig(net, ids=[A], names={}, username="bad-name")
    assert asyncio.run(r.ex.touch(A)) is False
    assert net.at_calls() == []


# --- разбор ответа касания как внешнего ввода ------------------------------------------------------------
def _garbage_net(result, x=A):
    net = Net(owners={NAME_A: x})
    net.rules.append(lambda m, p: ok(result) if isinstance(p.get("chat_id"), str) else None)
    return net


GARBAGE = [None, True, False, 0, 5, 1.5, "chat", "", [], [1], {}, {"chat": None}, {"chat": []}, {"chat": "x"},
           {"chat": 5}, {"chat": {}}, {"chat": {"id": None}}, {"chat": {"id": True}}, {"chat": {"id": False}},
           {"chat": {"id": str(A)}}, {"chat": {"id": float(A)}}, {"chat": {"id": [A]}}, {"chat": {"id": {"v": A}}},
           {"chat": {"id": 10 ** 40}}, {"chat": {"id": -A}}, {"chat": {"id": 0}}, {"chat": {"id": A + 1}},
           {"chat": {"id": 777}}, {"message_id": 1}, {"chat_id": A}]


@pytest.mark.parametrize("result", GARBAGE, ids=[json.dumps(g)[:40] for g in GARBAGE])
def test_garbage_touch_result_no_retry_and_original_error(result, caplog):
    net = _garbage_net(result)
    r = Rig(net, ids=[A])
    caplog.set_level(logging.DEBUG)
    kind, value = r.drive(lambda: r.req())
    assert kind == "err" and isinstance(value, TelegramError), repr(value)
    assert value.code == 400 and "chat not found" in value.description.lower()
    assert len(net.to(A)) == 1 and not net.envs  # исходный вызов не повторён
    assert len(net.at_calls()) == 1
    assert_only_start_by_name(net)
    assert [x for x in r.flags if x]  # владелец узнаёт о неверном имени
    warn = [x for x in caplog.records if x.name.startswith("veil") and "resolves to" in x.getMessage()]
    assert len(warn) <= 1


@pytest.mark.parametrize("bad_id", [True, 1.0])
def test_bool_and_float_chat_id_not_confused_with_listed_int(bad_id):
    net = _garbage_net({"chat": {"id": bad_id}}, x=1)
    r = Rig(net, ids=[1, 2], names={1: NAME_A, 2: NAME_B})
    assert asyncio.run(r.ex.touch(1)) is False  # True == 1 и 1.0 == 1 в Python, но это не целое число chat.id
    assert any(r.flags)
    net2 = _garbage_net({"chat": {"id": bad_id}}, x=1)
    r2 = Rig(net2, ids=[1], names={1: NAME_A})
    kind, value = r2.drive(lambda: r2.req())
    assert kind == "err" and isinstance(value, TelegramError)
    assert len(net2.to(1)) == 1 and not net2.envs  # исходный вызов не повторён


@given(st.data())
@PROP
def test_touch_result_any_json_property(data):
    x = A
    leaf = st.one_of(st.none(), st.booleans(), st.integers(-10 ** 30, 10 ** 30),
                     st.floats(allow_nan=False, allow_infinity=False), st.text(max_size=5),
                     st.sampled_from([x, -x, x + 1, float(x), str(x), 0, 1]))
    chat = st.one_of(leaf, st.lists(leaf, max_size=2),
                     st.fixed_dictionaries({}, optional={"id": leaf, "type": leaf}))
    result = st.one_of(leaf, st.lists(leaf, max_size=2),
                       st.fixed_dictionaries({}, optional={"chat": chat, "message_id": leaf}))
    v = data.draw(result)
    good = (isinstance(v, dict) and isinstance(v.get("chat"), dict) and type(v["chat"].get("id")) is int
            and v["chat"]["id"] == x)
    net = Net(owners={NAME_A: x})

    def rule(m, p):
        if isinstance(p.get("chat_id"), str):
            if good:
                net.known.add(x)
            return ok(v)
    net.rules.append(rule)
    r = Rig(net, ids=[x], names={x: NAME_A})
    kind, value = r.drive(lambda: r.req())
    assert_only_start_by_name(net)
    assert len(net.at_calls()) == 1
    if good:
        assert kind == "ok", repr(value)
        assert len(net.to(x, "sendMessage")) == 2
    else:
        assert kind == "err" and isinstance(value, TelegramError), repr(value)
        assert len(net.to(x)) == 1


def test_stranger_name_blacklisted_warns_once_and_flags(caplog, clock):
    net = scenario("stranger")
    r = Rig(net, ids=[A], names={A: NAME_A})
    caplog.set_level(logging.DEBUG)
    r.drive(lambda: r.req())
    clock.t += 5000
    r.drive(lambda: r.req())
    clock.t += 5000
    asyncio.run(r.ex.touch(A))
    assert len(net.at_calls()) == 1  # имя, давшее чужой ID, не используется повторно даже спустя время
    warn = [x for x in caplog.records if "not an inbox bot" in x.getMessage()]
    assert len(warn) == 1 and "777" in warn[0].getMessage() and NAME_A in warn[0].getMessage()
    flags = [f for f in r.flags if f]
    assert flags and NAME_A in json.dumps(flags[0]) and "777" in json.dumps(flags[0])


def test_flag_cleared_after_successful_touch(clock):
    net = Net(owners={NAME_A: 777, NAME_B: B})
    r = Rig(net, ids=[A, B], names={A: NAME_A, B: NAME_B})
    asyncio.run(r.ex.touch(A))
    assert any(r.flags)
    clock.t += 700
    net.owners[NAME_A.lower()] = A
    r.ex._bad_names.clear() if hasattr(r.ex, "_bad_names") else None
    # имя, давшее чужой ID, не используется; успешное касание другим ботом сбрасывает флаг
    assert asyncio.run(r.ex.touch(B)) is True
    assert r.flags[-1] is None


# --- петли -------------------------------------------------------------------------------------------------
def never_known() -> Net:
    net = Net(owners={NAME_A: A, NAME_B: B})
    net.rules.append(lambda m, p: err(*NOT_FOUND) if isinstance(p.get("chat_id"), int) else None)
    return net


def test_endless_chat_not_found_touch_rate_limit_and_single_retry(clock):
    net = never_known()
    r = Rig(net)
    per_req = []
    for _ in range(15):
        before = len(net.calls)
        kind, value = r.drive(lambda: r.req())
        assert kind == "err" and isinstance(value, ALLOWED), repr(value)
        per_req.append(net.calls[before:])
    ats = [p["chat_id"].lower() for p in net.at_calls()]
    assert len(ats) <= len(IDS) and len(set(ats)) == len(ats)
    for calls in per_req:
        for ident in IDS:
            assert len([1 for m, p in calls if p.get("chat_id") == ident]) <= 2
    for calls in per_req[1:]:  # без касания нет повтора исходного вызова
        for ident in IDS:
            assert len([1 for m, p in calls if p.get("chat_id") == ident]) <= 1
    n0 = len(net.at_calls())
    clock.t += 599
    r.drive(lambda: r.req())
    assert len(net.at_calls()) == n0
    assert_only_start_by_name(net)


def test_endless_chat_not_found_retouch_after_interval(clock):
    net = never_known()
    r = Rig(net)
    r.drive(lambda: r.req())
    n0 = len(net.at_calls())
    clock.t += 601
    before = len(net.calls)
    kind, _ = r.drive(lambda: r.req())
    assert kind == "err"
    assert n0 < len(net.at_calls()) <= n0 + len(IDS)
    for ident in IDS:
        assert len([1 for m, p in net.calls[before:] if p.get("chat_id") == ident]) <= 2
    assert_only_start_by_name(net)


def test_endless_loop_via_ensure_known(clock):
    net = never_known()
    net.rules.insert(0, lambda m, p: err(*NOT_FOUND) if m == "getChat" else None)
    r = Rig(net)
    for _ in range(10):
        asyncio.run(r.ex.ensure_known())
    assert len(net.at_calls()) <= len(IDS)
    clock.t += 601
    asyncio.run(r.ex.ensure_known())
    assert len(net.at_calls()) <= 2 * len(IDS)


def test_touch_every_boundary_per_id(clock):
    net = Net(owners={})
    r = Rig(net, ids=[A], names={A: NAME_A})
    assert asyncio.run(r.ex.touch(A)) is False
    clock.t += 599
    assert asyncio.run(r.ex.touch(A)) is False
    assert len(net.at_calls()) == 1
    clock.t += 2
    asyncio.run(r.ex.touch(A))
    assert len(net.at_calls()) == 2


def test_touch_rate_is_per_id_not_global(clock):
    net = Net(owners={})
    r = Rig(net)
    asyncio.run(r.ex.touch(A))
    asyncio.run(r.ex.touch(B))
    assert len(net.at_calls()) == 2


def test_failed_touch_still_counts_as_attempt(clock):
    net = Net(owners={NAME_A: A})
    net.rules.append(lambda m, p: err(500, "boom") if isinstance(p.get("chat_id"), str) else None)
    r = Rig(net, ids=[A], names={A: NAME_A})
    assert asyncio.run(r.ex.touch(A)) is False
    assert asyncio.run(r.ex.touch(A)) is False
    assert len(net.at_calls()) == 1


def test_retry_fails_again_no_second_touch_no_third_call(clock):
    net = Net(owners={NAME_A: A})
    net.rules.append(lambda m, p: err(*NOT_FOUND) if isinstance(p.get("chat_id"), int) else None)
    r = Rig(net, ids=[A], names={A: NAME_A})
    kind, value = r.drive(lambda: r.req())
    assert kind == "err" and isinstance(value, TelegramError) and "chat not found" in value.description.lower()
    assert len(net.at_calls()) == 1 and len(net.to(A)) == 2


def test_deliver_called_at_most_twice(clock):
    net = Net(owners={NAME_A: A})
    net.rules.append(lambda m, p: err(*NOT_FOUND) if isinstance(p.get("chat_id"), int) else None)
    r = Rig(net, ids=[A], names={A: NAME_A})
    count = []

    async def deliver():
        count.append(1)
        return (await r.bot.call("copyMessage", chat_id=r.ex.inbox, from_chat_id=5, message_id=7))["message_id"]
    kind, value = r.drive(lambda: r.req("post.create", deliver=deliver))
    assert kind == "err" and len(count) == 2


def test_concurrent_requests_touch_once_per_id():
    net = scenario("touch_ok")
    r = Rig(net)

    async def many():
        return await asyncio.gather(*[r.req() for _ in range(8)], return_exceptions=True)
    kind, results = r.drive(many)
    assert len(net.at_calls()) <= len(IDS)
    assert_only_start_by_name(net)
    assert results == [{}] * 8  # параллельные запросы дожидаются одного касания и все доходят


# --- 429 на касании ------------------------------------------------------------------------------------------
def test_touch_429_waits_retry_after_and_retries_once_then_original_error(clock):
    net = scenario("touch_429")
    r = Rig(net, ids=[A], names={A: NAME_A})
    kind, value = r.drive(lambda: r.req())
    assert kind == "err" and isinstance(value, TelegramError) and value.code == 400
    ats = net.at_calls()
    assert len(ats) == 2 and all(p == {"chat_id": "@" + NAME_A, "text": "/start"} for p in ats)
    assert r.sleeps == [1]
    kind, value = r.drive(lambda: r.req())  # касание не повторяется
    assert len(net.at_calls()) == 2 and kind == "err"


@pytest.mark.parametrize("retry_after,retried", [(10, True), (11, False), (3600, False)])
def test_touch_429_retry_after_boundary(retry_after, retried):
    net = Net(owners={NAME_A: A})
    net.rules.append(lambda m, p: err(429, "Too Many Requests", retry_after=retry_after)
                     if isinstance(p.get("chat_id"), str) else None)
    r = Rig(net, ids=[A], names={A: NAME_A})
    kind, value = r.drive(lambda: r.req())
    assert kind == "err" and isinstance(value, TelegramError) and value.code == 400
    assert len(net.at_calls()) == (2 if retried else 1)
    assert (r.sleeps == [retry_after]) == retried


def test_touch_429_then_success_retries_original_once():
    net = Net(owners={NAME_A: A})
    state = {"n": 0}

    def rule(m, p):
        if isinstance(p.get("chat_id"), str):
            state["n"] += 1
            if state["n"] == 1:
                return err(429, "Too Many Requests", retry_after=2)
    net.rules.append(rule)
    r = Rig(net, ids=[A], names={A: NAME_A})
    kind, value = r.drive(lambda: r.req())
    assert kind == "ok", repr(value)
    assert len(net.at_calls()) == 2 and len(net.to(A, "sendMessage")) == 2


# --- ensure_known ----------------------------------------------------------------------------------------------
def test_ensure_known_success_means_no_touch_and_no_send():
    net = Net(known=IDS, owners={NAME_A: A, NAME_B: B})
    r = Rig(net)
    asyncio.run(r.ex.ensure_known())
    assert sorted(p["chat_id"] for m, p in net.calls if m == "getChat") == sorted(IDS)
    assert [m for m, _ in net.calls] == ["getChat", "getChat"]


def test_ensure_known_chat_not_found_touches_each_unknown():
    net = Net(owners={NAME_A: A, NAME_B: B})
    r = Rig(net)
    asyncio.run(r.ex.ensure_known())
    assert sorted(p["chat_id"].lower() for p in net.at_calls()) == sorted(["@" + NAME_A, "@" + NAME_B])
    assert net.known == {A, B}
    assert_only_start_by_name(net)
    net.calls.clear()
    asyncio.run(r.ex.ensure_known())  # известные процессу не перепроверяются
    assert net.calls == []


@pytest.mark.parametrize("code,desc", [(403, "Forbidden"), (400, "Bad Request: wrong chat id"), (500, "oops"),
                                       (429, "Too Many Requests"), (404, "Not Found"), (0, "x")])
def test_ensure_known_other_errors_do_not_touch_or_raise(code, desc):
    net = Net(owners={NAME_A: A, NAME_B: B})
    net.rules.append(lambda m, p: err(code, desc, retry_after=1) if m == "getChat" else None)
    r = Rig(net)
    asyncio.run(r.ex.ensure_known())
    assert net.at_calls() == [] and not any(m == "sendMessage" for m, _ in net.calls)


@pytest.mark.parametrize("exc", [RuntimeError("x"), ValueError("y"), KeyError("z"), TypeError("t")])
def test_ensure_known_never_raises(exc):
    net = Net(owners={NAME_A: A})
    r = Rig(net)

    async def boom(_):
        raise exc
    r.bot.get_chat = boom
    asyncio.run(r.ex.ensure_known())


def test_ensure_known_garbage_touch_result_does_not_raise():
    net = _garbage_net({"chat": {"id": "x"}})
    r = Rig(net, ids=[A])
    asyncio.run(r.ex.ensure_known())
    assert_only_start_by_name(net)


def test_ensure_known_new_ids_after_rotation_are_touched():
    net = Net(known=[A], owners={NAME_A: A, NAME_B: B})
    r = Rig(net, ids=[A])
    asyncio.run(r.ex.ensure_known())
    assert net.at_calls() == []
    r.ids.append(B)
    net.calls.clear()
    asyncio.run(r.ex.ensure_known())
    assert [p["chat_id"] for m, p in net.calls if m == "getChat"] == [B]
    assert [p["chat_id"].lower() for p in net.at_calls()] == ["@" + NAME_B]


def test_ensure_known_without_ids_does_nothing():
    net = Net(owners={NAME_A: A})
    r = Rig(net, ids=[])
    asyncio.run(r.ex.ensure_known())
    assert net.calls == []


@pytest.mark.parametrize("bad", [None, "x", [True], [1.5], [None], {"a": 1}, 5])
def test_ensure_known_with_corrupt_id_list_is_quiet(bad):
    net = Net(owners={NAME_A: A})
    r = Rig(net)
    r.ids = bad
    asyncio.run(r.ex.ensure_known())
    assert net.at_calls() == []


def test_refresh_keys_calls_ensure_known_after_each_refresh(tmp_path):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[5, 6])
    seen = []

    class Ex:
        server_sig_pk = bytes(sk.verify_key)

        async def request(self, *a, **kw):
            return _signed_doc(sk, inbox_bots=[5, 6])

        async def ensure_known(self):
            seen.append(1)
    core = api.Core(bot=None, store=Store(tmp_path), exchange=Ex(), keys_doc=old, owner_id=1)
    asyncio.run(core.refresh_keys())
    asyncio.run(core.refresh_keys())
    assert len(seen) == 2


def test_refresh_keys_does_not_touch_for_rejected_document(tmp_path):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[5])
    seen = []

    class Ex:
        server_sig_pk = bytes(sk.verify_key)

        async def request(self, *a, **kw):
            return _signed_doc(sk, inbox_bots=[5, 6], inbox_names=[{"id": 5, "username": "@bad"}])

        async def ensure_known(self):
            seen.append(1)
    core = api.Core(bot=None, store=Store(tmp_path), exchange=Ex(), keys_doc=old, owner_id=1)
    with pytest.raises(keysdoc.KeysError):
        asyncio.run(core.refresh_keys())
    assert core.keys_doc is old and core.store.get("keys_doc") is None


# --- состояние и журнал -------------------------------------------------------------------------------------
def test_touch_state_not_in_store_or_export(tmp_path):
    from veil.core import export
    store = Store(tmp_path)
    store.put("pinned_server_sig", b64.enc(bytes(32)))
    before = {k for (k,) in store.db.execute("SELECT key FROM meta").fetchall()}
    net = scenario("stranger")
    flags = []
    r = Rig(net)
    r.ex = Exchange(r.bot, "@" + NAME_A, bytes(r.server.verify_key), lambda: ("i1", bytes(r.inbox.public_key)),
                    lambda: IDS, lambda: r.names, lambda f: (flags.append(f), store.put("inbox_name_bad", f)))
    asyncio.run(r.ex.ensure_known())
    asyncio.run(r.ex.touch(A))
    after = {k for (k,) in store.db.execute("SELECT key FROM meta").fetchall()}
    assert after - before <= {"inbox_name_bad"}
    for (k,) in store.db.execute("SELECT key FROM meta").fetchall():
        v = json.dumps(store.get(k))
        assert "touch" not in k.lower() and "/start" not in v
    bundle = export.collect(store, 1, {})
    dump = json.dumps(bundle, default=str)
    assert "inbox_name_bad" not in dump and NAME_A not in dump and "/start" not in dump and "touch" not in dump.lower()


def test_journal_has_no_tokens_or_envelope_content(caplog):
    net = Net(owners={NAME_A: 777, NAME_B: 888})
    r = Rig(net)
    caplog.set_level(logging.DEBUG)
    r.drive(lambda: r.req("post.create", body={"secret_marker": "SECRETBODY12345"}))
    for rec in caplog.records:
        if rec.name.startswith("veil"):
            text = rec.getMessage() + str(rec.args)
            assert "1:x" not in text and "SECRETBODY12345" not in text and "VEIL1 " not in text
    assert "1:x" not in json.dumps([f for f in r.flags])


# --- keysdoc.inbox_names -------------------------------------------------------------------------------------
def _expect(case: dict) -> dict:
    return {int(k): v for k, v in case["inbox_names"].items()}


@pytest.mark.parametrize("case", VECTORS["keys_doc_reject"], ids=[c["why"] for c in VECTORS["keys_doc_reject"]])
def test_reject_vectors(case):
    with pytest.raises(keysdoc.KeysError):
        keysdoc.inbox_names(case["document"])


@pytest.mark.parametrize("case", VECTORS["keys_doc_accept"], ids=[c["why"] for c in VECTORS["keys_doc_accept"]])
def test_accept_vectors(case):
    assert keysdoc.verify(case["document"]) is case["document"]
    assert keysdoc.inbox_names(case["document"]) == _expect(case)


def test_reject_vectors_have_valid_signatures_so_inbox_names_is_the_reason():
    for case in VECTORS["keys_doc_reject"]:
        try:
            keysdoc.verify(case["document"])
        except keysdoc.KeysError:
            pytest.fail(f"вектор «{case['why']}» не подписан верно")


def test_keys_doc_vector_signature_and_names():
    v = VECTORS["keys_doc"]
    assert keysdoc.verify(v["document"]) is v["document"]
    assert keysdoc.inbox_names(v["document"]) == {int(k): n for k, n in v["inbox_names"].items()}
    assert envelope.signing_input(v["document"], keysdoc.CTX_KEYS).decode() == v["signing_input"]
    assert v["document_without_sig"] == {k: x for k, x in v["document"].items() if k != "sig"}


def _mutations(doc: dict):
    d = copy.deepcopy(doc)
    d["inbox_names"][0]["username"] = d["inbox_names"][0]["username"][:-4] + "Xbot"
    yield "renamed", d
    d = copy.deepcopy(doc)
    d["inbox_names"][0]["username"] = d["inbox_names"][0]["username"].upper()
    yield "upper", d
    d = copy.deepcopy(doc)
    d["inbox_names"].reverse()
    yield "reordered", d
    d = copy.deepcopy(doc)
    d["inbox_names"].pop()
    yield "removed", d
    d = copy.deepcopy(doc)
    del d["inbox_names"]
    yield "deleted field", d
    d = copy.deepcopy(doc)
    d["inbox_names"][0]["id"], d["inbox_names"][1]["id"] = d["inbox_names"][1]["id"], d["inbox_names"][0]["id"]
    yield "ids swapped", d
    d = copy.deepcopy(doc)
    d["inbox_names"][0]["extra"] = 1
    yield "extra key", d
    d = copy.deepcopy(doc)
    d["inbox_names"] = []
    yield "emptied", d


@pytest.mark.parametrize("why", ["renamed", "upper", "reordered", "removed", "deleted field", "ids swapped",
                                 "extra key", "emptied"])
def test_signature_covers_inbox_names(why):
    doc = VECTORS["keys_doc"]["document"]
    mutated = dict(_mutations(doc))[why]
    with pytest.raises(keysdoc.KeysError):
        keysdoc.verify(mutated)


OMIT = object()


def _signed(inbox_names, inbox_bots=(A, B), **extra) -> dict:
    sk = SigningKey.generate()
    doc = {"v": 1, "inbox_enc": [{"kid": "i1", "pk": b64.enc(bytes(32))}],
           "issuer_poprf": [{"kid": "t1", "pk": b64.enc(bytes(range(32)))}],
           "server_sig": b64.enc(bytes(sk.verify_key)), **extra}
    if inbox_bots is not None:
        doc["inbox_bots"] = list(inbox_bots)
    if inbox_names is not OMIT:
        doc["inbox_names"] = inbox_names
    try:
        doc["sig"] = b64.enc(sk.sign(envelope.signing_input(doc, keysdoc.CTX_KEYS)).signature)
    except jcs.JCSError:  # значение, которое нельзя подписать (дробное число): документ без подписи
        pass
    return doc


def item(i=A, u=NAME_A, **kw):
    return {"id": i, "username": u, **kw}


BAD_NAMES = [
    None, "x", 5, {}, {"id": A, "username": NAME_A}, True, [None], [[]], [5], ["str"],
    [{"id": A}], [{"username": NAME_A}], [{}], [item(extra=1)], [item(i="111222333")], [item(i=True)],
    [item(i=float(A))], [item(i=A + 1)], [item(i=None)], [item(i=-A)], [item(i=0)], [item(i=[A])],
    [item(), item()], [item(), item(A, NAME_B)], [item(u=None)], [item(u=5)], [item(u=[NAME_A])],
    [item(u={"a": 1})], [item(u="")], [item(u="bot")], [item(u="abot")], [item(u="a1bt")], [item(u="a" * 33)],
    [item(u="a" * 29 + "boT" + "x")], [item(u="@" + NAME_A)], [item(u=NAME_A + "\n")], [item(u=" " + NAME_A)],
    [item(u=NAME_A + " ")], [item(u="1" + NAME_A)], [item(u="_" + NAME_A)], [item(u="veil-inbox_bot")],
    [item(u="veil.inbox_bot")], [item(u="Веил_bot")], [item(u="veil_inbox_bot​")],
    [item(u="veil_inbox_bоt")], [item(u="veil_inbox_bot́")], [item(u="ｖeil_inbox_bot")],
    [item(u="veil_inbox_bots")], [item(u="veil_inbox_robot_x")], [item(u="a٣٣_bot")], [item(u="a\x00_bot")],
]


@pytest.mark.parametrize("names", BAD_NAMES, ids=[json.dumps(n, ensure_ascii=True)[:50] for n in BAD_NAMES])
def test_inbox_names_rejects(names):
    doc = _signed(names)
    if "sig" in doc:
        keysdoc.verify(doc)  # подпись верна: отказ — только из-за правил поля
    with pytest.raises(keysdoc.KeysError):
        keysdoc.inbox_names(doc)


@pytest.mark.parametrize("bots", [None, []])
def test_inbox_names_without_published_bots_rejected(bots):
    with pytest.raises(keysdoc.KeysError):
        keysdoc.inbox_names(_signed([item()], inbox_bots=bots))


GOOD = [
    ([], {}), ([item()], {A: NAME_A}), ([item(u="Veil_Inbox_BOT")], {A: "veil_inbox_bot"}),
    ([item(u="abbot")], {A: "abbot"}), ([item(u="a" + "b" * 28 + "bot")], {A: "a" + "b" * 28 + "bot"}),
    ([item(u="aaabOt")], {A: "aaabot"}), ([item(u="a_1_bot")], {A: "a_1_bot"}),
    ([item(), item(B, NAME_B)], {A: NAME_A, B: NAME_B}), ([item(B, NAME_B)], {B: NAME_B}),
    ([item(u="Z9_9_BOT")], {A: "z9_9_bot"}),
]


@pytest.mark.parametrize("names,expect", GOOD, ids=[json.dumps(g[1]) for g in GOOD])
def test_inbox_names_accepts(names, expect):
    doc = _signed(names)
    keysdoc.verify(doc)
    assert keysdoc.inbox_names(doc) == expect
    assert all(type(k) is int and isinstance(v, str) and v == v.lower() for k, v in keysdoc.inbox_names(doc).items())


def test_inbox_names_absent_is_empty_even_without_bots():
    assert keysdoc.inbox_names(_signed(OMIT, inbox_bots=None)) == {}
    assert keysdoc.inbox_names(_signed(OMIT)) == {}


def test_inbox_names_length_boundaries_exact():
    for n, good in [(4, False), (5, True), (32, True), (33, False)]:
        name = "a" * (n - 3) + "bot"
        if good:
            assert keysdoc.inbox_names(_signed([item(u=name)])) == {A: name}
        else:
            with pytest.raises(keysdoc.KeysError):
                keysdoc.inbox_names(_signed([item(u=name)]))


@given(st.text(max_size=40))
@PROP
def test_inbox_names_accepts_exactly_the_pattern(name):
    doc = {"inbox_bots": [A], "inbox_names": [{"id": A, "username": name}]}
    pattern = re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,28}[Bb][Oo][Tt]", name, flags=re.ASCII) is not None
    try:
        got = keysdoc.inbox_names(doc)
    except keysdoc.KeysError:
        assert not pattern
        return
    assert pattern and got == {A: name.lower()}


@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=4),
                    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=3), c, max_size=3),
                    max_leaves=8))
@PROP
def test_inbox_names_never_raises_anything_but_keyserror(value):
    try:
        keysdoc.inbox_names({"inbox_bots": [A, B], "inbox_names": value})
    except keysdoc.KeysError:
        pass


def test_inbox_names_does_not_mutate_document():
    doc = _signed([item(u="Veil_Inbox_BOT")])
    snapshot = copy.deepcopy(doc)
    keysdoc.inbox_names(doc)
    assert doc == snapshot


def test_inbox_names_with_corrupt_bots_list_or_foreign_id():
    with pytest.raises(keysdoc.KeysError):
        keysdoc.inbox_names({"inbox_bots": "x", "inbox_names": [item()]})
    with pytest.raises(keysdoc.KeysError):
        keysdoc.inbox_names({"inbox_bots": [A], "inbox_names": [item(i=B)]})


# --- refresh_keys и поле inbox_names ----------------------------------------------------------------------------
def _signed_doc(sk: SigningKey, **extra) -> dict:
    doc = {"inbox_enc": [{"kid": "i1", "pk": b64.enc(bytes(32))}],
           "issuer_poprf": [{"kid": "t1", "pk": b64.enc(bytes(range(32)))}],
           "server_sig": b64.enc(bytes(sk.verify_key)), **extra}
    doc["sig"] = b64.enc(sk.sign(envelope.signing_input(doc, keysdoc.CTX_KEYS)).signature)
    return doc


def _core(tmp_path, old, new, sk):
    class Ex:
        server_sig_pk = bytes(sk.verify_key)

        async def request(self, *a, **kw):
            return new

        async def ensure_known(self):
            pass
    return api.Core(bot=None, store=Store(tmp_path), exchange=Ex(), keys_doc=old, owner_id=1)


def test_refresh_keys_updates_inbox_names_with_bots(tmp_path):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[A])
    new = _signed_doc(sk, inbox_bots=[A, B], inbox_names=[item(), item(B, NAME_B)])
    core = _core(tmp_path, old, new, sk)
    asyncio.run(core.refresh_keys())
    assert keysdoc.inbox_names(core.keys_doc) == {A: NAME_A, B: NAME_B}
    assert keysdoc.inbox_names(core.store.get("keys_doc")) == {A: NAME_A, B: NAME_B}


@pytest.mark.parametrize("bad", [[item(u="@x")], "x", [item(i=999)], [item(), item()], {"a": 1}])
def test_refresh_keys_bad_inbox_names_never_saved(tmp_path, bad):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[A], inbox_names=[item()])
    core = _core(tmp_path, old, _signed_doc(sk, inbox_bots=[A], inbox_names=bad), sk)
    with pytest.raises(keysdoc.KeysError):
        asyncio.run(core.refresh_keys())
    assert core.keys_doc is old and core.store.get("keys_doc") is None


def test_refresh_keys_names_without_bots_rejected(tmp_path):
    sk = SigningKey.generate()
    core = _core(tmp_path, _signed_doc(sk), _signed_doc(sk, inbox_names=[item()]), sk)
    with pytest.raises(keysdoc.KeysError):
        asyncio.run(core.refresh_keys())
    assert core.store.get("keys_doc") is None


def test_refresh_keys_missing_names_in_new_doc_is_not_a_rejection(tmp_path):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[A], inbox_names=[item()])
    new = _signed_doc(sk, inbox_bots=[A])
    core = _core(tmp_path, old, new, sk)
    assert asyncio.run(core.refresh_keys()) == new  # документ без поля принимается (spec/02)
    assert core.store.get("keys_doc") is not None
    assert keysdoc.inbox_names(core.keys_doc) in ({}, {A: NAME_A})


def test_refresh_keys_names_for_removed_bot_do_not_survive(tmp_path):
    sk = SigningKey.generate()
    old = _signed_doc(sk, inbox_bots=[A, B], inbox_names=[item(), item(B, NAME_B)])
    core = _core(tmp_path, old, _signed_doc(sk, inbox_bots=[B], inbox_names=[item(B, NAME_B)]), sk)
    asyncio.run(core.refresh_keys())
    assert keysdoc.inbox_names(core.keys_doc) == {B: NAME_B}
    saved = core.store.get("keys_doc")
    assert keysdoc.inbox_names(saved) == {B: NAME_B}


# --- соседние функции keysdoc, затронутые разбором документа ----------------------------------------------------
@pytest.mark.parametrize("kid,expect", [("i1", ("i", 1, "1", "i1")), ("i007", ("i", 1, "7", "i007")),
                                        ("t10", ("t", 2, "10", "t10")), ("t0", ("t", 0, "", "t0")),
                                        ("abc", ("abc", 0, "", "abc")), ("", ("", 0, "", "")),
                                        ("a1b22", ("a1b", 2, "22", "a1b22"))])
def test_kid_order_exact_shape(kid, expect):
    assert keysdoc.kid_order(kid) == expect


def test_inbox_key_picks_numerically_newest():
    doc = {"inbox_enc": [{"kid": f"i{n}", "pk": b64.enc(bytes([n]) * 32)} for n in (9, 10, 2)]}
    assert keysdoc.inbox_key(doc) == ("i10", bytes([10]) * 32)


@pytest.mark.parametrize("doc", [{}, {"issuer_poprf": []}, {"issuer_poprf": None},
                                 {"issuer_poprf": [{"kid": "t1", "pk": b64.enc(bytes(31))}]},
                                 {"issuer_poprf": [{"kid": "t1", "pk": b64.enc(bytes(33))}]},
                                 {"issuer_poprf": [{"kid": 5, "pk": b64.enc(bytes(32))}]},
                                 {"issuer_poprf": [{"pk": b64.enc(bytes(32))}]}])
def test_issuer_key_rejects_missing_or_corrupt(doc):
    with pytest.raises(keysdoc.KeysError):
        keysdoc.issuer_key(doc)


def test_issuer_key_returns_first_entry():
    doc = {"issuer_poprf": [{"kid": f"t{n}", "pk": b64.enc(bytes([n]) * 32)} for n in (1, 2)]}
    assert keysdoc.issuer_key(doc) == ("t1", bytes([1]) * 32)


# --- добавлено по выжившим мутациям -----------------------------------------------------------------------------
def _journal(caplog, needle: str) -> list[str]:
    return [x.getMessage() for x in caplog.records if x.name.startswith("veil") and needle in x.getMessage()]


@pytest.mark.parametrize("ids", [["@veil_inbox_bot"], ("@veil_inbox_bot",), {A}, frozenset({A}), "@veil_inbox_bot"])
def test_ensure_known_ignores_id_lists_of_wrong_shape(ids):
    net = Net(owners={NAME_A: A})
    r = Rig(net)
    r.ids = ids
    asyncio.run(r.ex.ensure_known())
    assert net.calls == []


@pytest.mark.parametrize("names", [None, [], "x", 5, [(A, NAME_A)], {A}])
def test_non_dict_published_names_fall_back_to_config_name(names):
    net = Net(owners={"config_name_bot": A})
    r = Rig(net, ids=[A], username="config_name_bot")
    r.ex.inbox_names = lambda: names
    assert asyncio.run(r.ex.touch(A)) is True
    assert [p["chat_id"].lower() for p in net.at_calls()] == ["@config_name_bot"]


def test_touch_allowed_again_exactly_after_interval(clock):
    net = Net(owners={})
    r = Rig(net, ids=[A], names={A: NAME_A})
    asyncio.run(r.ex.touch(A))
    clock.t += 600
    asyncio.run(r.ex.touch(A))
    assert len(net.at_calls()) == 2


@pytest.mark.parametrize("code,desc", [(500, "boom"), (403, "Forbidden"), (400, "Bad Request: chat not found")])
def test_failed_touch_is_journaled_with_id_and_code(code, desc, caplog):
    net = Net(owners={NAME_A: A})
    net.rules.append(lambda m, p: err(code, desc) if isinstance(p.get("chat_id"), str) else None)
    r = Rig(net, ids=[A], names={A: NAME_A})
    caplog.set_level(logging.DEBUG)
    assert asyncio.run(r.ex.touch(A)) is False
    [line] = _journal(caplog, "touch")
    assert str(A) in line and str(code) in line and "1:x" not in line and desc not in line


def test_stranger_journal_line_and_flag_shape(caplog):
    net = scenario("stranger")
    r = Rig(net, ids=[A], names={A: NAME_A})
    caplog.set_level(logging.DEBUG)
    asyncio.run(r.ex.touch(A))
    assert _journal(caplog, "resolves to") == [f"inbox username @{NAME_A} resolves to 777, not an inbox bot"]
    assert r.flags == [{"name": NAME_A, "id": 777}]


def test_non_integer_answer_is_not_echoed_to_journal_or_flag(caplog):
    evil = "EVIL\nINJECT 000 fake line"
    net = _garbage_net({"chat": {"id": evil}})
    r = Rig(net, ids=[A], names={A: NAME_A})
    caplog.set_level(logging.DEBUG)
    asyncio.run(r.ex.touch(A))
    assert _journal(caplog, "resolves to") == [f"inbox username @{NAME_A} resolves to a non-integer id, "
                                               "not an inbox bot"]
    assert r.flags == [{"name": NAME_A, "id": None}]
    assert all("INJECT" not in x.getMessage() for x in caplog.records)


def test_ensure_known_failure_is_journaled_by_type_only(caplog):
    net = Net(owners={NAME_A: A})
    r = Rig(net, ids=[A], names={A: NAME_A})

    async def boom(_):
        raise RuntimeError("SECRETDETAIL")
    r.bot.get_chat = boom
    caplog.set_level(logging.DEBUG)
    asyncio.run(r.ex.ensure_known())
    assert _journal(caplog, "check failed") == ["inbox bots check failed (RuntimeError)"]
    assert all("SECRETDETAIL" not in x.getMessage() for x in caplog.records)


# spec/04: «chat not found» по известному боту снова делает его неизвестным; касание — по общему пределу
# TOUCH_EVERY на ID. Чат, известный без касания, коснуться можно сразу.
def test_successful_delivery_then_not_found_touches_once_and_retries(clock):
    net = Net(known=[A, B], owners={NAME_A: A, NAME_B: B})
    r = Rig(net)
    assert r.drive(lambda: r.req())[0] == "ok"
    net.known.discard(A)  # Telegram «забыл» чат
    kind, value = r.drive(lambda: r.req())
    assert kind == "ok" and [p["chat_id"].lower() for p in net.at_calls()] == ["@" + NAME_A.lower()]
    assert [c for c, _, _ in net.envs][-1] == A
    net.known.discard(A)  # снова раньше 600 с: без касания, переключение на следующий бот
    clock.t += 599
    kind, value = r.drive(lambda: r.req())
    assert kind == "ok" and len(net.at_calls()) == 1 and [c for c, _, _ in net.envs][-1] == B
    assert_only_start_by_name(net)


def test_ensure_known_then_not_found_touches_once_and_retries(clock):
    net = Net(known=IDS, owners={NAME_A: A, NAME_B: B})
    r = Rig(net)
    asyncio.run(r.ex.ensure_known())
    assert net.at_calls() == []
    net.known.discard(A)
    kind, value = r.drive(lambda: r.req())
    assert kind == "ok" and len(net.at_calls()) == 1 and [c for c, _, _ in net.envs] == [A]
    assert_only_start_by_name(net)


@pytest.mark.parametrize("ids", [[5, "x"], [5, True], [5, 5.0], [5, None], [5, [6]], "5", {5}])
def test_is_inbox_rejects_everyone_when_any_listed_id_is_not_an_int(ids, caplog):
    ex = Exchange(None, "@inbox_bot", bytes(32), lambda: ("i1", bytes(32)), lambda: ids)
    caplog.set_level(logging.DEBUG)
    assert ex.is_inbox({"is_bot": True, "id": 5}) is False
    if isinstance(ids, list):
        assert _journal(caplog, "malformed") == ["inbox bot ids malformed, sender rejected"]
