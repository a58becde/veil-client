"""Протокол на стороне клиента: строгий JSON как у сервера, проверки точек и порядка kid, хеш форматирования целиком,
схема чужого «лично для», форма запроса токенов, повтор того же конверта на E_PENDING."""
import asyncio

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core import api
from veil.core.crypto import ristretto as r255
from veil.core.protocol import content, envelope, jcs, keysdoc
from veil.core.store.db import Store
from veil.core.transport import exchange as exmod
from veil.core.transport.exchange import Exchange
from veil.core.wallet.issue import Token as IssuedToken


def test_strict_json_matches_server():
    """одиночный суррогат и вложенность глубже 32 отвергаются, как на сервере."""
    with pytest.raises(jcs.JCSError):
        jcs.strict_loads('{"text":"\\ud800"}')
    with pytest.raises(jcs.JCSError):
        jcs.strict_loads('{"\\udc00":1}')
    with pytest.raises(jcs.JCSError):
        jcs.strict_loads("[" * 33 + "]" * 33)
    assert jcs.strict_loads("[" * 32 + "]" * 32)
    assert jcs.strict_loads('{"t":"\\ud83d\\ude00"}') == {"t": "😀"}  # пара суррогатов — нормальный символ


def test_ristretto_check_rejects_identity():
    with pytest.raises(r255.InvalidElementError):
        r255.check(r255.IDENTITY)


def test_kid_order_is_numeric():
    """i10 новее i9."""
    doc = {"inbox_enc": [{"kid": "i9", "pk": "AA"}, {"kid": "i10", "pk": "AQ"}, {"kid": "i2", "pk": "Ag"}]}
    assert keysdoc.inbox_key(doc)[0] == "i10"
    assert sorted(["t10", "t9", "t1"], key=keysdoc.kid_order) == ["t1", "t9", "t10"]


def test_entities_hash_covers_all_fields():
    """поле вне прежней проекции (unix_time у date_time) меняет хеш."""
    a = [{"type": "date_time", "offset": 0, "length": 5, "unix_time": 1792000000, "date_time_format": "r"}]
    b = [{"type": "date_time", "offset": 0, "length": 5, "unix_time": 1, "date_time_format": "wDT"}]
    assert content.entities_sha256(a) != content.entities_sha256(b)
    with pytest.raises(ValueError):
        content.entities_sha256([{"type": "bold", "offset": "0", "length": 3}])


@pytest.mark.parametrize("pl", [
    {"text": "abc", "entities": [{"type": "bold", "offset": "0", "length": 3}]},  # строка вместо числа
    {"text": "abc", "entities": [{"type": "bold", "offset": 0, "length": 9}]},    # за пределами текста
    {"text": 5},
    {"text": "a" * 4097},
    {"text": "a", "pad": "x"},                                                     # pad — только пробелы
    {"text": "x", "files": [{"size": "1"}], "file_key": "k"},
    {"text": "x", "files": [{"size": 1}]},                                         # файлы без ключа
    {"text": "x", "entities": [{"type": "bold", "offset": True, "length": 1}]},  # bool — не число
    [],
])
def test_private_payload_schema_rejects(pl):
    """чужое «лично для» с битой схемой отбрасывается, а не роняет цикл ленты."""
    assert not api.valid_private(pl)


def test_private_payload_schema_accepts():
    assert api.valid_private({"text": "привет", "entities": [{"type": "bold", "offset": 0, "length": 6}]})
    assert api.valid_private({"text": "", "files": [{"size": 10, "kind": "photo", "name": "a.jpg", "mime": ""}],
                              "file_key": "AAAA"})


def test_token_request_shape_does_not_reveal_spending(tmp_path):
    """запрос на день = 50 − полученное за всё время, а не 50 − оставшееся."""
    s = Store(tmp_path)
    day = "2026-10-16"
    s.add_tokens([IssuedToken("t1", day, bytes([i]) * 32, bytes(64)) for i in range(50)])
    for _ in range(3):
        s.finish_token(s.take_token(day), "spent")
    assert s.token_counts() == {day: 47}
    assert s.token_received() == {day: 50}  # просить на этот день больше нечего, сколько бы ни потратили


INBOX_FROM = {"is_bot": True, "username": "inbox"}  # отправитель сообщений приёмного бота ("@inbox")


class _Bot:
    def __init__(self):
        self.sent = []

    async def send(self, chat, text, **kw):
        self.sent.append(text)
        return {"message_id": 100 + len(self.sent)}


def test_exchange_repeats_same_envelope_on_pending(monkeypatch):
    """на E_PENDING клиент повторяет тот же конверт (тот же id и resp_pk), а не теряет результат."""
    server, inbox, bot = SigningKey.generate(), PrivateKey.generate(), _Bot()
    ex = Exchange(bot, "@inbox", bytes(server.verify_key), lambda: ("i1", bytes(inbox.public_key)))
    real_sleep = asyncio.sleep
    monkeypatch.setattr(exmod.asyncio, "sleep", lambda s: real_sleep(0))

    def answer(env, error=None, result=None):
        resp = envelope.build_response(env["id"], server, error=error, result=result)
        return envelope.seal_response(resp, envelope.b64.dec(env["resp_pk"]))

    async def scenario():
        task = asyncio.create_task(ex.request("post.create", "ephemeral", SigningKey.generate(), body={"x": 1}))
        await real_sleep(0.01)
        first = envelope.open_envelope(bot.sent[-1], inbox)
        ex.on_inbox_message({"from": INBOX_FROM, "text": answer(first, error={"code": "E_PENDING", "retry_after": 5}),
                             "reply_to_message": {"message_id": 101}})
        for _ in range(50):
            await real_sleep(0.01)
            if len(bot.sent) == 2:
                break
        second = envelope.open_envelope(bot.sent[-1], inbox)
        assert second["id"] == first["id"] and second["resp_pk"] == first["resp_pk"]
        ex.on_inbox_message({"from": INBOX_FROM, "text": answer(second, result={"n": 7}),
                             "reply_to_message": {"message_id": 102}})
        return await task

    assert asyncio.run(scenario()) == {"n": 7}


def _exchange_in_flight(monkeypatch):
    """Обмен с ключами сервера и приёма; sleep не ждёт."""
    server, inbox, bot = SigningKey.generate(), PrivateKey.generate(), _Bot()
    ex = Exchange(bot, "@inbox", bytes(server.verify_key), lambda: ("i1", bytes(inbox.public_key)))
    real_sleep = asyncio.sleep
    monkeypatch.setattr(exmod.asyncio, "sleep", lambda s: real_sleep(0))
    return ex, bot, server, inbox, real_sleep


def test_signed_malformed_response_ends_request(monkeypatch):
    """подписано сервером, но испорчено (чужой re): операция завершается сразу, ProtocolError.signed."""
    ex, bot, server, inbox, real_sleep = _exchange_in_flight(monkeypatch)

    async def scenario():
        task = asyncio.create_task(ex.request("post.create", "ephemeral", SigningKey.generate(), body={"x": 1}))
        await real_sleep(0.01)
        env = envelope.open_envelope(bot.sent[-1], inbox)
        bad = envelope.build_response("other-id", server, result={"n": 1})
        ex.on_inbox_message({"from": INBOX_FROM, "text": envelope.seal_response(bad, envelope.b64.dec(env["resp_pk"])),
                             "reply_to_message": {"message_id": 101}})
        return await asyncio.wait_for(task, 1)

    with pytest.raises(exmod.ProtocolError) as ei:
        asyncio.run(scenario())
    assert ei.value.code == "E_MALFORMED" and ei.value.signed


def test_unsigned_malformed_response_is_ignored(monkeypatch):
    """E_MALFORMED до проверки подписи (не объект) — не завершает операцию: ждём настоящий ответ."""
    ex, bot, server, inbox, real_sleep = _exchange_in_flight(monkeypatch)

    async def scenario():
        task = asyncio.create_task(ex.request("post.create", "ephemeral", SigningKey.generate(), body={"x": 1}))
        await real_sleep(0.01)
        env = envelope.open_envelope(bot.sent[-1], inbox)
        resp_pk = envelope.b64.dec(env["resp_pk"])
        junk = envelope.seal_response([], resp_pk)  # type: ignore[arg-type]  # намеренно не объект
        resp_sk = next(iter(ex._pending.values())).resp_sk
        with pytest.raises(exmod.ProtocolError) as ei:
            envelope.open_response(junk, resp_sk, bytes(server.verify_key), env["id"])
        assert ei.value.code == "E_MALFORMED" and not ei.value.signed
        ex.on_inbox_message({"from": INBOX_FROM, "text": junk, "reply_to_message": {"message_id": 101}})
        await real_sleep(0.01)
        assert not task.done()
        good = envelope.build_response(env["id"], server, result={"n": 7})
        ex.on_inbox_message({"from": INBOX_FROM, "text": envelope.seal_response(good, resp_pk),
                             "reply_to_message": {"message_id": 101}})
        return await asyncio.wait_for(task, 1)

    assert asyncio.run(scenario()) == {"n": 7}
