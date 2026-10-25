"""Первое касание приёмного бота (spec/04) и имена приёмных ботов в keys.json (spec/02)."""
import asyncio
import json
import logging
import types
from pathlib import Path

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core import api
from veil.core.protocol import b64, envelope, keysdoc
from veil.core.store.db import Store
from veil.core.transport import exchange as exmod
from veil.core.transport.exchange import Exchange
from veil.core.transport.telegram import TelegramError

REAL_SLEEP = asyncio.sleep
NOT_FOUND = "Bad Request: chat not found"
VECTORS = json.loads((Path(__file__).resolve().parents[2] / "veil-protocol/test-vectors/veil-v1.json").read_text())


class FakeBot:
    """Telegram с правилом «числовой ID известен только после обращения»: names — @username → ID адресата,
    known — чаты, которые бот уже знает; fail — (метод, ошибка) для разовых отказов."""

    def __init__(self, names=None, known=(), fail=None):
        self.names, self.known, self.fail = dict(names or {}), set(known), fail
        self.calls: list[tuple[str, dict]] = []
        self.not_found = NOT_FOUND

    def _check(self, method, params):
        self.calls.append((method, params))
        chat = params.get("chat_id")
        if self.fail and self.fail[0] == method and (self.fail[2] is None or self.fail[2] == chat):
            raise self.fail[1]
        if isinstance(chat, str):
            if not chat.startswith("@"):
                raise AssertionError(chat)
            target = self.names.get(chat[1:].lower())
            if target is None:
                raise TelegramError(method, 400, "Bad Request: chat not found")
            self.known.add(target)
            return {"message_id": 900 + len(self.calls), "chat": {"id": target, "type": "private"}}
        if chat not in self.known:
            raise TelegramError(method, 400, self.not_found)
        return {"message_id": 100 + len(self.calls), "chat": {"id": chat, "type": "private"}}

    async def call(self, method, **params):
        params = {k: v for k, v in params.items() if v is not None}
        return self._check(method, params)

    async def send(self, chat, text, **kw):
        return self._check("sendMessage", {"chat_id": chat, "text": text, **kw})

    async def upload(self, method, field, filename, data, mime, **params):
        return self._check(method, params)

    async def get_chat(self, chat_id):
        return self._check("getChat", {"chat_id": chat_id})

    def at_calls(self):
        """Вызовы с адресом по @username."""
        return [(m, p) for m, p in self.calls if isinstance(p.get("chat_id"), str)]


class Rig:
    def __init__(self, bot, ids=(10,), names=None, username="@fallback_bot"):
        self.inbox, self.server = PrivateKey.generate(), SigningKey.generate()
        self.bot, self.ids, self.names = bot, list(ids), dict(names or {})
        self.flags: list = []
        self.ex = Exchange(bot, username, bytes(self.server.verify_key), lambda: ("i1", bytes(self.inbox.public_key)),
                           lambda: self.ids, lambda: self.names, self.flags.append)

    def env(self, n=-1):
        texts = [p["text"] for m, p in self.bot.calls if m == "sendMessage" and p["text"].startswith("VEIL1 ")]
        return envelope.open_envelope(texts[n], self.inbox, max_plain=envelope.MAX_DOC_PLAINTEXT)

    async def run(self, *, deliver=None, to=None):
        """Одна операция до ответа сервера. Возвращает result; бросает то, что бросил обмен."""
        task = asyncio.create_task(self.ex.request("post.create", "ephemeral", SigningKey.generate(), body={"x": 1},
                                                   deliver=deliver, to=to))
        for _ in range(500):
            if task.done() or any(p.get("text", "").startswith("VEIL1 ") for m, p in self.bot.calls):
                break
            await REAL_SLEEP(0.002)
        if not task.done():
            env = self.env()
            resp = envelope.build_response(env["id"], self.server, result={"ok": 1})
            chat = next(p["chat_id"] for m, p in self.bot.calls if p.get("text", "").startswith("VEIL1 "))
            self.ex.on_inbox_message({"from": {"is_bot": True, "id": chat}, "chat": {"id": chat},
                                      "text": envelope.seal_response(resp, b64.dec(env["resp_pk"])),
                                      "reply_to_message": {"message_id": self._last_envelope_id()}})
        return await task

    def _last_envelope_id(self):
        n = 0
        for i, (m, p) in enumerate(self.bot.calls):
            if m == "sendMessage" and p.get("text", "").startswith("VEIL1 "):
                n = 100 + i + 1
        return n


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(exmod.time, "monotonic", lambda: now[0])
    return now


def run(coro):
    return asyncio.run(coro)


def assert_invariant(bot):
    """Единственный вызов по @username — sendMessage с текстом ровно /start и без других полей."""
    for method, params in bot.at_calls():
        assert method == "sendMessage" and params["text"] == "/start", (method, params)
        assert set(params) == {"chat_id", "text"}, params


# ── ленивое касание ──────────────────────────────────────────────────────────────────────────────────────────────

def test_lazy_touch_then_one_retry_by_id():
    bot = FakeBot(names={"example_inbox_bot": 10})
    r = Rig(bot, names={10: "example_inbox_bot"})
    assert run(r.run()) == {"ok": 1}
    kinds = [(m, p["chat_id"]) for m, p in bot.calls]
    # конверт по ID (отказ) → касание по имени → тот же конверт по ID
    assert kinds == [("sendMessage", 10), ("sendMessage", "@example_inbox_bot"), ("sendMessage", 10)]
    assert bot.calls[1][1] == {"chat_id": "@example_inbox_bot", "text": "/start"}
    assert_invariant(bot)


def test_lazy_touch_retries_content_delivery_once():
    bot = FakeBot(names={"example_inbox_bot": 10})
    r = Rig(bot, names={10: "example_inbox_bot"})
    delivered = []

    async def deliver():
        delivered.append(1)
        return (bot._check("copyMessage", {"chat_id": 10})["message_id"], {"kind": "text"})
    assert run(r.run(deliver=deliver)) == {"ok": 1}
    assert len(delivered) == 2  # отказ до касания и повтор после него
    assert_invariant(bot)


def test_retry_only_once_when_second_attempt_fails():
    bot = FakeBot(names={"example_inbox_bot": 10})
    r = Rig(bot, names={10: "example_inbox_bot"})
    attempts = []

    async def deliver():
        attempts.append(1)
        raise TelegramError("copyMessage", 400, NOT_FOUND)
    with pytest.raises(TelegramError):
        run(r.ex.request("post.create", "ephemeral", SigningKey.generate(), body={}, deliver=deliver))
    assert len(attempts) == 2 and len(bot.at_calls()) == 1


@pytest.mark.parametrize("err", [
    TelegramError("sendMessage", 403, "Forbidden: bot was blocked by the user"),
    TelegramError("sendMessage", 400, "Bad Request: message is too long"),
    TelegramError("sendMessage", 404, "Not Found"),
    TelegramError("sendMessage", 429, "Too Many Requests", 5),
    TelegramError("sendMessage", 500, "boom"),
    TelegramError("sendMessage", 0, "network"),
])
def test_no_touch_on_other_errors(err):
    bot = FakeBot(names={"example_inbox_bot": 10}, known={10}, fail=("sendMessage", err, 10))
    r = Rig(bot, names={10: "example_inbox_bot"})
    with pytest.raises(TelegramError):
        run(r.run())
    assert bot.at_calls() == []


def test_chat_not_found_any_case_touches():
    bot = FakeBot(names={"example_inbox_bot": 10})
    bot.not_found = "Bad Request: CHAT NOT FOUND"
    r = Rig(bot, names={10: "example_inbox_bot"})
    assert run(r.run()) == {"ok": 1}
    assert len(bot.at_calls()) == 1


def test_no_touch_for_unknown_id_or_without_inbox_ids():
    bot = FakeBot(names={"example_inbox_bot": 10})
    r = Rig(bot, ids=[10], names={10: "example_inbox_bot"})
    assert run(r.ex.touch(99)) is False and bot.calls == []
    r.ids = []
    assert run(r.ex.touch(10)) is False and bot.calls == []
    # без inbox_bots всё по @username, как раньше: касания и повторов нет
    bot2 = FakeBot()
    r2 = Rig(bot2, ids=[], username="@fallback_bot")
    with pytest.raises(TelegramError):
        run(r2.run())
    assert len(bot2.calls) == 1 and bot2.calls[0][1]["chat_id"] == "@fallback_bot"


def test_touch_sends_nothing_but_start_on_every_path():
    """Конверт, документ, контент, resume и переключение бота — по ID; по имени уходит только /start."""
    bot = FakeBot(names={"first_bot": 10, "second_bot": 20})
    r = Rig(bot, ids=[10, 20], names={10: "first_bot", 20: "second_bot"})
    big = {"x": 1, "pad": "a" * 3500}  # конверт больше 3000 байт — документом
    task = asyncio.run
    assert task(r.run()) == {"ok": 1}
    env_state = {"op": "post.create", "auth_mode": "ephemeral", "body": big, "token": None, "content": None,
                 "reply_to": None, "id": envelope.new_ulid(), "inbox": 20}

    async def resume():
        t = asyncio.create_task(r.ex.resume(env_state, SigningKey.generate(), PrivateKey.generate()))
        await REAL_SLEEP(0.05)
        t.cancel()
    asyncio.run(resume())
    assert_invariant(bot)
    assert any(m == "sendDocument" for m, _ in bot.calls)


# ── chat.id результата ─────────────────────────────────────────────────────────────────────────────────────────────

def test_touch_result_other_inbox_bot_marks_it_known_not_the_asked_one(clock):
    bot = FakeBot(names={"first_bot": 20})  # имя первого бота ведёт ко второму приёмному боту
    r = Rig(bot, ids=[10, 20], names={10: "first_bot"})
    assert run(r.ex.touch(10)) is False
    assert 20 in r.ex._known and 10 not in r.ex._known
    assert r.flags == []  # это приёмный бот: имя не «чужое»


@pytest.mark.parametrize("res", [
    {"chat": {"id": 777}}, {"chat": {"id": "10"}}, {"chat": {"id": True}}, {"chat": {"id": 1.0}}, {"chat": {}},
    {"chat": "x"}, {}, [], None, "ok", {"chat": {"id": 10 ** 30}},
])
def test_touch_result_not_inbox_blacklists_name_and_flags(res, caplog, clock):
    class Bot(FakeBot):
        async def call(self, method, **params):
            self.calls.append((method, params))
            return res
    bot = Bot()
    r = Rig(bot, names={10: "example_inbox_bot"})
    with caplog.at_level(logging.WARNING, logger="veil.exchange"):
        assert run(r.ex.touch(10)) is False
    assert "example_inbox_bot" in r.ex._bad_names and 10 not in r.ex._known
    assert r.flags and r.flags[-1]["name"] == "example_inbox_bot"
    assert sum("not an inbox bot" in m for m in caplog.messages) == 1
    clock[0] += exmod.TOUCH_EVERY + 1
    # имя больше не используется: ни повторного касания, ни второго предупреждения (запасное имя — отдельное)
    r.names = {10: "example_inbox_bot"}
    r.ex.username = "example_inbox_bot"
    calls = len(bot.calls)
    assert run(r.ex.touch(10)) is False and len(bot.calls) == calls
    assert sum("not an inbox bot" in m for m in caplog.messages) == 1


def test_bad_name_falls_back_to_configured_name(clock):
    bot = FakeBot(names={"hijacked_bot": 777, "fallback_bot": 10})
    r = Rig(bot, names={10: "hijacked_bot"})
    assert run(r.ex.touch(10)) is False  # имя из keys.json ведёт к чужому
    clock[0] += exmod.TOUCH_EVERY + 1
    assert run(r.ex.touch(10)) is True  # запасное имя из настроек
    assert r.flags[-1] is None  # отметка снята
    assert [p["chat_id"] for _, p in bot.at_calls()] == ["@hijacked_bot", "@fallback_bot"]


def test_touch_telegram_error_returns_false_and_keeps_original_error():
    bot = FakeBot()  # имя никому не принадлежит: «chat not found»
    r = Rig(bot, names={10: "example_inbox_bot"})
    with pytest.raises(TelegramError) as ei:
        run(r.run())
    assert ei.value.code == 400 and r.flags == []  # отметка «имя чужое» — только если имя привело к другому боту


# ── частота ──────────────────────────────────────────────────────────────────────────────────────────────────────

def test_touch_not_more_than_once_per_interval(clock):
    bot = FakeBot()
    r = Rig(bot, names={10: "example_inbox_bot"})
    assert run(r.ex.touch(10)) is False
    assert run(r.ex.touch(10)) is False
    clock[0] += exmod.TOUCH_EVERY - 1
    assert run(r.ex.touch(10)) is False
    assert len(bot.at_calls()) == 1
    clock[0] += 2
    assert run(r.ex.touch(10)) is False
    assert len(bot.at_calls()) == 2


def test_failed_touch_also_counts(clock):
    bot = FakeBot(fail=("sendMessage", TelegramError("sendMessage", 429, "Too Many Requests", 3), "@example_inbox_bot"))
    r = Rig(bot, names={10: "example_inbox_bot"})
    assert run(r.ex.touch(10)) is False
    assert run(r.ex.touch(10)) is False
    assert len(bot.at_calls()) == 1


def test_known_bot_forgotten_by_telegram_retouches_only_after_interval(monkeypatch):
    # часы подменяются только в модуле обмена: общий time.monotonic остановил бы и цикл событий
    now = [1000.0]
    clock = now
    monkeypatch.setattr(exmod, "time", types.SimpleNamespace(monotonic=lambda: now[0]))
    bot = FakeBot(names={"example_inbox_bot": 10})
    r = Rig(bot, names={10: "example_inbox_bot"})
    run(r.run())  # касание, чат известен
    assert len(bot.at_calls()) == 1
    # Telegram «забыл» чат раньше интервала: касания нет, исходная ошибка наружу
    bot.known.discard(10)
    clock[0] += exmod.TOUCH_EVERY - 1
    bot.calls.clear()  # Rig.run ждёт конверт в журнале вызовов: старые мешают
    with pytest.raises(TelegramError):
        run(r.run())
    assert bot.at_calls() == []
    # после интервала — одно касание и один повтор
    clock[0] += 2
    bot.calls.clear()
    assert run(r.run()) == {"ok": 1}
    assert [(m, p["chat_id"]) for m, p in bot.calls] == [
        ("sendMessage", 10), ("sendMessage", "@example_inbox_bot"), ("sendMessage", 10)]
    assert_invariant(bot)


def test_known_bot_is_not_touched_again():
    bot = FakeBot(names={"example_inbox_bot": 10})
    r = Rig(bot, names={10: "example_inbox_bot"})
    run(r.run())
    bot.calls.clear()
    run(r.run())
    assert bot.at_calls() == [] and len(bot.calls) == 1


# ── ensure_known ───────────────────────────────────────────────────────────────────────────────────────────────────

def test_ensure_known_getchat_success_does_not_touch():
    bot = FakeBot(names={"example_inbox_bot": 10}, known={10})
    r = Rig(bot, names={10: "example_inbox_bot"})
    run(r.ex.ensure_known())
    assert [m for m, _ in bot.calls] == ["getChat"] and 10 in r.ex._known
    run(r.ex.ensure_known())  # известный не проверяется повторно
    assert len(bot.calls) == 1


def test_ensure_known_chat_not_found_touches():
    bot = FakeBot(names={"example_inbox_bot": 10})
    r = Rig(bot, names={10: "example_inbox_bot"})
    run(r.ex.ensure_known())
    assert [(m, p["chat_id"]) for m, p in bot.calls] == [("getChat", 10), ("sendMessage", "@example_inbox_bot")]
    assert 10 in r.ex._known
    assert_invariant(bot)


@pytest.mark.parametrize("err", [TelegramError("getChat", 403, "Forbidden"), TelegramError("getChat", 500, "boom"),
                                 TelegramError("getChat", 429, "Too Many Requests", 3),
                                 TelegramError("getChat", 400, "Bad Request: wrong chat")])
def test_ensure_known_other_errors_do_not_touch_or_raise(err):
    bot = FakeBot(names={"example_inbox_bot": 10}, fail=("getChat", err, None))
    r = Rig(bot, names={10: "example_inbox_bot"})
    run(r.ex.ensure_known())
    assert bot.at_calls() == [] and 10 not in r.ex._known


def test_ensure_known_never_raises_on_broken_state():
    class Boom(FakeBot):
        async def get_chat(self, chat_id):
            raise RuntimeError("x")
    r = Rig(Boom(), names={10: "example_inbox_bot"})
    run(r.ex.ensure_known())

    def bad():
        raise ValueError("x")
    r.ex.inbox_ids = bad
    run(r.ex.ensure_known())


def test_ensure_known_covers_new_ids_after_refresh(tmp_path):
    bot = FakeBot(names={"first_bot": 10, "second_bot": 20}, known={10})
    r = Rig(bot, ids=[10], names={10: "first_bot"})
    run(r.ex.ensure_known())
    r.ids, r.names = [10, 20], {10: "first_bot", 20: "second_bot"}
    run(r.ex.ensure_known())
    assert ("sendMessage", "@second_bot") in [(m, p["chat_id"]) for m, p in bot.calls]
    assert_invariant(bot)


def test_refresh_keys_calls_ensure_known(tmp_path):
    sk = SigningKey.generate()
    body = {"v": 1, "issued_at": "2026-10-16T00:00:00Z", "inbox_enc": [{"kid": "i1", "pk": b64.enc(bytes(32))}],
            "issuer_poprf": [{"kid": "t1", "pk": b64.enc(bytes(32))}], "inbox_bots": [10],
            "server_sig": b64.enc(bytes(sk.verify_key))}
    doc = {**body, "sig": b64.enc(sk.sign(keysdoc.CTX_KEYS + envelope.jcs.canonicalize(body)).signature)}
    seen = []

    class Ex:
        server_sig_pk = bytes(sk.verify_key)

        async def request(self, *a, **kw):
            return doc

        async def ensure_known(self):
            seen.append(1)
    core = api.Core(bot=None, store=Store(tmp_path), exchange=Ex(), keys_doc=doc, owner_id=1)
    run(core.refresh_keys())
    assert seen == [1]
    # испорченные имена в подписанном документе: документ не сохраняется, касаться нечем
    bad_body = {**body, "inbox_names": [{"id": 10, "username": "@x_bot"}]}
    bad = {**bad_body, "sig": b64.enc(sk.sign(keysdoc.CTX_KEYS + envelope.jcs.canonicalize(bad_body)).signature)}
    Ex.request = lambda self, *a, **kw: _ret(bad)
    with pytest.raises(keysdoc.KeysError):
        run(core.refresh_keys())
    assert seen == [1] and core.keys_doc is doc


async def _ret(x):
    return x


# ── состояние не сохраняется ─────────────────────────────────────────────────────────────────────────────────────

def test_touch_state_is_in_memory_only(tmp_path, clock):
    store = Store(tmp_path)
    bot = FakeBot(names={"example_inbox_bot": 10})
    r = Rig(bot, names={10: "example_inbox_bot"})
    run(r.ex.touch(10))
    assert store.get("touched") is None and not any("touch" in str(k) for k in vars(store))
    assert "_known" in vars(r.ex) and "_touched" in vars(r.ex)


# ── keysdoc.inbox_names по векторам ──────────────────────────────────────────────────────────────────────────────

def test_keys_doc_vector_is_signed_and_parsed():
    v = VECTORS["keys_doc"]
    doc = keysdoc.verify(v["document"])
    assert keysdoc.inbox_names(doc) == {int(k): x for k, x in v["inbox_names"].items()}
    assert v["signing_input"].encode() == envelope.signing_input(doc, keysdoc.CTX_KEYS)
    assert {k: x for k, x in doc.items() if k != "sig"} == v["document_without_sig"]


@pytest.mark.parametrize("case", VECTORS["keys_doc_reject"], ids=lambda c: c["why"])
def test_keys_doc_reject_vectors(case):
    keysdoc.verify(case["document"])  # подпись верна: отказ — по правилу поля
    with pytest.raises(keysdoc.KeysError):
        keysdoc.inbox_names(case["document"])


@pytest.mark.parametrize("case", VECTORS["keys_doc_accept"], ids=lambda c: c["why"])
def test_keys_doc_accept_vectors(case):
    assert keysdoc.inbox_names(keysdoc.verify(case["document"])) == {int(k): x for k, x in case["inbox_names"].items()}


def test_signature_covers_inbox_names():
    doc = json.loads(json.dumps(VECTORS["keys_doc"]["document"]))
    doc["inbox_names"][0]["username"] = "intruder_bot"
    with pytest.raises(keysdoc.KeysError):
        keysdoc.verify(doc)


# ── /status ────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_status_text_mentions_wrong_inbox_name(tmp_path):
    from harness import Env
    env = Env(tmp_path)
    ui = env.ui
    ui.core.store.put("b2b_error", True)
    assert ui.T("text.status_b2b_off") in ui.status_text()
    ui.core.store.put("inbox_name_bad", {"name": "x_bot", "id": 5})
    text = ui.status_text()
    assert ui.T("text.status_inbox_name_bad") in text and ui.T("text.status_b2b_off") not in text
    ui.core.store.put("b2b_error", None)
    assert ui.T("text.status_b2b_ok") in ui.status_text()
