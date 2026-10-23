"""Ядро бота без сети: скрытие ссылок, номер поста, кошелёк, сбор ответа сервера."""
import asyncio
import re

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core import api
from veil.core.crypto import keys
from veil.core.protocol import b64, envelope
from veil.core.store.db import Store
from veil.core.transport.exchange import Exchange, ServerError
from veil.core.transport.telegram import TelegramError
from veil.core.wallet.issue import Token as IssuedToken


def test_hide_links_shifts_entities():
    text = "Смотри 😀 https://a.example и жирное"
    ents = [{"type": "url", "offset": 10, "length": 17}, {"type": "bold", "offset": 30, "length": 6},
            {"type": "italic", "offset": 0, "length": 6}]
    vis, kept = api.hide_links(text, ents)
    assert vis == "Смотри 😀 [ссылка скрыта 🔐] и жирное"
    units = vis.encode("utf-16-le")
    got = {e["type"]: units[e["offset"] * 2:(e["offset"] + e["length"]) * 2].decode("utf-16-le") for e in kept}
    assert got == {"bold": "жирное", "italic": "Смотри"}


def bold_head(nick_line: str) -> list[dict]:
    """Ник·метка в шапке поста — жирным во всю первую строку (render.Render на сервере)."""
    return [{"type": "bold", "offset": 0, "length": len(nick_line.encode("utf-16-le")) // 2}]


def test_post_number_only_in_header_lines():
    assert api.post_number({"text": "Вася·7f3a9c\n№246  >>> №245\n\nтекст", "entities": bold_head("Вася·7f3a9c")}) == 246
    assert api.post_number({"caption": "Аня 😀·k2m9xq\n№8\n\nфото", "caption_entities": bold_head("Аня 😀·k2m9xq")}) == 8
    assert api.post_number({"caption": "№7\n\nфото"}) == 7
    assert api.post_number({"text": "№12  >>> №11"}) == 12
    assert api.post_number({"text": "a\nb\nв тексте №5"}) is None
    # Номер — только целая строка шапки: «№» в нике (старый ник, до запрета на сервере) и в тексте не подменяют его.
    assert api.post_number({"text": "№1·abc123\n№55  >>> №54\n\nтекст", "entities": bold_head("№1·abc123")}) == 55
    assert api.post_number({"text": "Вася·7f3a9c\n№55\n\nтекст"}) is None  # без жирного ника вторая строка — не шапка
    assert api.post_number({"text": "Смотри №3 и №4\n№5"}) is None
    assert api.post_number({"text": "№5 — пост удалён автором"}) is None  # заглушка удалённого поста


def test_wallet(tmp_path):
    s = Store(tmp_path)
    toks = [IssuedToken("2026-W42", "2026-10-15", bytes([i]) * 32, bytes(64)) for i in range(3)]
    assert s.add_tokens(toks) == 3 and s.add_tokens(toks) == 0
    t = s.take_token("2026-10-15")
    assert s.token_counts() == {"2026-10-15": 2}
    s.finish_token(t, "ready")
    assert s.token_counts() == {"2026-10-15": 3}
    t = s.take_token("2026-10-15")
    s.release_reserved()  # перезапуск
    assert s.token_counts() == {"2026-10-15": 3}
    assert s.take_token("2026-10-16") is None
    d = keys.issue_device(SigningKey.generate(), now=1_800_000_000, tag_fn=lambda pk: "abcdef")
    s.save_device(d)
    assert (tmp_path / "device.json").stat().st_mode & 0o077 == 0
    assert s.load_device().to_json() == d.to_json()
    assert "mnemonic" not in (tmp_path / "device.json").read_text()  # 12 слов на диске нет (spec/02)


def test_device_rotation_and_prune():
    """Ключ шифрования меняется раз в 7 дней; прежние хранятся до exp + 30 дней, затем удаляются."""
    t0 = 1_800_000_000
    d = keys.issue_device(SigningKey.generate(), now=t0, tag_fn=lambda pk: "abcdef")
    first = d.current
    assert not d.needs_rotation(t0 + 6 * 86400) and d.needs_rotation(t0 + 7 * 86400)
    d.new_enc(t0 + 7 * 86400)
    assert d.enc_secret(first.pk) == first.sk and d.current is not first
    d.prune(first.exp + keys.ENC_KEEP - 1)
    assert d.enc_secret(first.pk) is not None
    d.prune(first.exp + keys.ENC_KEEP + 1)
    assert d.enc_secret(first.pk) is None and len(d.enc) == 1


def test_lookup_chain_rejects_forgeries():
    """Цепочка «корень → устройство → ключ шифрования» (spec/02): подмена любого звена или просрочка — отказ."""
    root = SigningKey.generate()
    now = 1_800_000_000
    d = keys.issue_device(root, now=now, tag_fn=lambda pk: "abcdef")
    m = {"id_pk": b64.enc(d.id_pk), "nick": "Петя", "dev_pk": b64.enc(d.dev_pk), "seq": d.seq,
         "dev_sig": b64.enc(d.dev_sig), **d.enc_body()}
    v = keys.verify_lookup_match(m, "abcdef", now=now, tag_fn=lambda pk: "abcdef")
    assert v.enc_pk == d.current.pk and v.seq == d.seq
    evil = SigningKey.generate()
    forged = [
        dict(m, enc_pk=b64.enc(bytes(PrivateKey.generate().public_key))),  # сервер подставил свой ключ
        dict(m, dev_pk=b64.enc(bytes(evil.verify_key))),                    # своё устройство без подписи корня
        dict(m, seq=d.seq + 1),
    ]
    for f in forged:
        with pytest.raises(keys.KeyMismatch):
            keys.verify_lookup_match(f, "abcdef", now=now, tag_fn=lambda pk: "abcdef")
    with pytest.raises(keys.KeyMismatch):  # просрочен
        keys.verify_lookup_match(m, "abcdef", now=d.current.exp, tag_fn=lambda pk: "abcdef")
    with pytest.raises(keys.KeyMismatch):  # чужая метка
        keys.verify_lookup_match(m, "zzzz", now=now, tag_fn=lambda pk: "abcdef")


class FakeBot:
    def __init__(self):
        self.sent = []

    async def send(self, chat, text, **kw):
        self.sent.append(text)
        return {"message_id": 100 + len(self.sent)}


def test_exchange_multipart_and_forgery():
    server = SigningKey.generate()
    inbox = PrivateKey.generate()
    bot = FakeBot()
    ex = Exchange(bot, "@inbox", bytes(server.verify_key), lambda: ("i1", bytes(inbox.public_key)))

    async def scenario():
        task = asyncio.create_task(ex.request("feed.get", "ephemeral", SigningKey.generate(), body={}))
        await asyncio.sleep(0.01)
        env = envelope.open_envelope(bot.sent[0], inbox)
        resp_pk = envelope.b64.dec(env["resp_pk"])
        # Подделка (чужая подпись) игнорируется, настоящий ответ из нескольких частей принимается.
        fake = envelope.seal_response(envelope.build_response(env["id"], SigningKey.generate(), result={}), resp_pk)
        ex.on_inbox_message({"text": fake, "reply_to_message": {"message_id": 101}})
        big = envelope.build_response(env["id"], server, result={"posts": ["я" * 100] * 50})
        parts = envelope.split_response(envelope.seal_response(big, resp_pk))
        assert len(parts) > 1
        for p in reversed(parts):
            ex.on_inbox_message({"text": p, "reply_to_message": {"message_id": 101}})
        return await task

    assert len(asyncio.run(scenario())["posts"]) == 50


def test_exchange_error_and_hint():
    inbox = PrivateKey.generate()
    server = SigningKey.generate()
    bot = FakeBot()
    ex = Exchange(bot, "@inbox", bytes(server.verify_key), lambda: ("i1", bytes(inbox.public_key)))

    async def scenario(reply):
        task = asyncio.create_task(ex.request("ping", "ephemeral", SigningKey.generate()))
        await asyncio.sleep(0.01)
        env = envelope.open_envelope(bot.sent[-1], inbox)
        mid = 100 + len(bot.sent)
        ex.on_inbox_message({"text": reply(env), "reply_to_message": {"message_id": mid}})
        return await task

    err = lambda env: envelope.seal_response(envelope.build_response(  # noqa: E731
        env["id"], server, error={"code": "E_TOO_LONG", "overflow": 12}), envelope.b64.dec(env["resp_pk"]))
    with pytest.raises(ServerError) as e:
        asyncio.run(scenario(err))
    assert e.value.code == "E_TOO_LONG" and e.value.overflow == 12
    with pytest.raises(ServerError) as e:
        asyncio.run(scenario(lambda env: "VEIL1E E_DECRYPT"))
    assert e.value.hint and e.value.code == "E_DECRYPT"


def test_envelope_id_and_ts_reveal_no_clock():
    """id конверта — 128 случайных бит в записи ULID (без миллисекунд часов клиента), ts округлён до TS_STEP: по ним
    сервер не различает устройства по сдвигу часов."""
    ids = {envelope.new_ulid() for _ in range(2000)}
    assert len(ids) == 2000 and all(re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", i) for i in ids)
    assert len({i[:10] for i in ids}) > 1900  # в ULID первые 10 символов — время; здесь они случайны
    env, _ = envelope.build("ping", "ephemeral", SigningKey.generate(), "i1")
    assert env["ts"] % envelope.TS_STEP == 0


def test_exchange_routes_to_holder_bot():
    """Запрос без контента (hidden.file) уходит тому приёмному боту, который держит файл, если он из keys.json."""
    ex = Exchange(None, "@inbox", bytes(32), lambda: ("i1", bytes(32)), lambda: [111, 222])
    assert ex.inbox_for(222) == 222 and ex.inbox_for(333) == 111 and ex.inbox_for(None) == 111


class SwitchBot:
    """Bot API: приёмные боты из down не принимают сообщения (403), остальные отвечают как Telegram."""

    def __init__(self, down=()):
        self.down, self.sent = set(down), []

    async def send(self, chat, text, **kw):
        if chat in self.down:
            raise TelegramError("sendMessage", 403, "Forbidden: bot was blocked by the user")
        self.sent.append((chat, text))
        return {"message_id": 100 + len(self.sent), "chat": {"id": chat}}


def switch_exchange(bot, ids=(111, 222)):
    server, inbox = SigningKey.generate(), PrivateKey.generate()
    ex = Exchange(bot, "@inbox", bytes(server.verify_key), lambda: ("i1", bytes(inbox.public_key)), lambda: list(ids))

    def answer(chat, mid, text, result):
        env = envelope.open_envelope(text, inbox)
        resp = envelope.seal_response(envelope.build_response(env["id"], server, result=result),
                                      envelope.b64.dec(env["resp_pk"]))
        ex.on_inbox_message({"chat": {"id": chat}, "text": resp, "reply_to_message": {"message_id": mid}})
    return ex, answer


def test_exchange_switches_from_unreachable_inbox():
    """Приёмный бот удалён или заблокирован: запрос без контента уходит следующему из keys.json, и дальше клиент пишет
    ему. Ответ с тем же номером сообщения, но из чата другого бота, чужой ответ не подменяет."""
    bot = SwitchBot(down={111})
    ex, answer = switch_exchange(bot)

    async def scenario():
        task = asyncio.create_task(ex.request("feed.get", "ephemeral", SigningKey.generate(), body={}))
        await asyncio.sleep(0.01)
        assert [c for c, _ in bot.sent] == [222]
        answer(111, 101, bot.sent[0][1], {"posts": ["подмена"]})  # другой чат — не наш ответ
        await asyncio.sleep(0.01)
        assert not task.done()
        answer(222, 101, bot.sent[0][1], {"posts": []})
        return await task

    assert asyncio.run(scenario()) == {"posts": []} and ex.inbox == 222


def test_exchange_no_switch_for_holder_or_content():
    """Файл «лично для» держит конкретный бот — другой его не отдаст: ошибка, а не переключение. Контент, который не
    дошёл, тоже не переотправляется сам (токен не тронут), но следующая попытка пойдёт другому боту."""
    bot = SwitchBot(down={111})
    ex, _ = switch_exchange(bot)
    with pytest.raises(TelegramError):
        asyncio.run(ex.request("hidden.file", "ephemeral", SigningKey.generate(), body={"n": 1}, to=111))
    assert ex.inbox == 111 and not bot.sent

    async def deliver():
        raise TelegramError("copyMessage", 403, "Forbidden: bot was blocked by the user")
    with pytest.raises(TelegramError):
        asyncio.run(ex.request("post.create", "ephemeral", SigningKey.generate(), body={}, deliver=deliver))
    assert ex.inbox == 222 and not bot.sent


def test_exchange_all_inbox_bots_down():
    """Все приёмные боты недоступны — ошибка после одного круга, без бесконечного перебора."""
    bot = SwitchBot(down={111, 222})
    ex, _ = switch_exchange(bot)
    with pytest.raises(TelegramError):
        asyncio.run(ex.request("feed.get", "ephemeral", SigningKey.generate(), body={}))


def test_resume_goes_to_the_same_inbox_bot():
    """Журнал помнит приёмного бота: повтор конверта после переключения уходит туда же, где лежит контент."""
    bot = SwitchBot()
    ex, answer = switch_exchange(bot)
    states = []

    async def deliver():
        return 50

    async def first():
        task = asyncio.create_task(ex.request("post.create", "ephemeral", SigningKey.generate(), body={},
                                              deliver=deliver, journal=states.append))
        await asyncio.sleep(0.01)
        task.cancel()
    asyncio.run(first())
    assert states[0]["inbox"] == 111 and bot.sent[0][0] == 111
    ex.switch_from(111)
    assert ex.inbox == 222

    async def again():
        task = asyncio.create_task(ex.resume(states[0]))
        await asyncio.sleep(0.01)
        answer(111, 102, bot.sent[-1][1], {"n": 5})
        return await task
    assert asyncio.run(again()) == {"n": 5} and bot.sent[-1][0] == 111
