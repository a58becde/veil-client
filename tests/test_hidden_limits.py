"""Длинное скрытое (конверт документом), выравнивание длины «лично для», ID приёмного бота, пределы ника, видимая
случайная задержка."""
import asyncio
from pathlib import Path

import pytest
from nacl.public import PrivateKey

from veil.core.identity import nick
from veil.core.protocol import envelope, hidden, jcs, keysdoc
from veil.core.transport.exchange import Exchange
from veil.ui import bot as uibot

ROOT = Path(__file__).resolve().parent.parent


def test_padded_private_payload_hides_length():
    """«лично для» выравнивается до 256 байт; короткие тексты разной длины неразличимы."""
    sizes = {len(hidden.padded(hidden.payload(t))) for t in ("а", "привет", "x" * 200)}
    assert sizes == {256}
    long = hidden.padded(hidden.payload("я" * 300))
    assert len(long) % 256 == 0 and jcs.strict_loads(long.decode())["text"] == "я" * 300


def test_container_padding_roundtrip():
    """Контейнер файлов выравнивается по Padmé; нули в хвосте не принимаются за файл, подмена хвоста — ошибка."""
    files = [b"a" * 1000, b"b" * 37]
    container, key = hidden.seal_files(files)
    assert len(container) - 40 == hidden.padme(1037) > 1037
    assert hidden.open_files(container, key, [1000, 37]) == files
    with pytest.raises(ValueError):
        hidden.open_files(container, key, [1000, 36])  # байт файла оказался бы «хвостом» — не нулевой
    assert hidden.padme(19 * 10 ** 6) <= hidden.MAX_CONTAINER


def test_long_hidden_text_fits():
    """Скрытый текст до 4096 символов (лимит сообщения Telegram); конверт с ним уходит документом."""
    pl = hidden.payload("я" * 4096)
    assert len(pl) <= hidden.MAX_PAYLOAD
    with pytest.raises(ValueError):
        hidden.payload("я" * 4097)
    env = {"v": 1, "body": {"blob": "A" * 6000}}
    assert envelope.needs_document(env) and not envelope.needs_document({"v": 1})


def test_nick_limits():
    """не больше 128 кодовых точек и 3 комбинирующих знаков на графему."""
    assert nick.normalize("q́̂̃a")
    with pytest.raises(nick.NickError):
        nick.normalize("q́̂̃̄a")
    family = "👨\u200d👩\u200d👧\u200d👦"
    assert nick.normalize(family * 18)
    with pytest.raises(nick.NickError):
        nick.normalize(family * 19)


def test_inbox_bot_ids():
    """при ID в keys.json клиент шлёт по ID и принимает только от этих ID, а не от любого с @username."""
    assert keysdoc.inbox_bots({"inbox_bots": [5, 7]}) == [5, 7]
    assert keysdoc.inbox_bots({}) == []
    for bad in (["5"], [0], [True], "5"):
        with pytest.raises(keysdoc.KeysError):
            keysdoc.inbox_bots({"inbox_bots": bad})
    ids: list[int] = []
    ex = Exchange(None, "@Inbox_Bot", b"", lambda: ("i1", b""), lambda: ids)
    assert ex.inbox == "@inbox_bot" and ex.is_inbox({"is_bot": True, "username": "inbox_bot", "id": 99})
    ids.append(5)
    assert ex.inbox == 5
    assert not ex.is_inbox({"is_bot": True, "username": "inbox_bot", "id": 99})  # имя сменило владельца
    assert ex.is_inbox({"is_bot": True, "username": "renamed", "id": 5})
    assert not ex.is_inbox({"is_bot": False, "id": 5})


class _Bot:
    def __init__(self):
        self.sent, self.uploads = [], []

    async def send(self, chat, text, **kw):
        self.sent.append((chat, text))
        return {"message_id": 100 + len(self.sent)}

    async def upload(self, method, field, name, data, mime, **params):
        self.uploads.append((method, params["caption"], data.decode(), params["chat_id"]))
        return {"message_id": 200}

    async def edit(self, chat, mid, text, markup=None):
        self.sent.append(("edit", text))


def test_big_envelope_goes_as_document():
    """Конверт больше 3000 байт — документом VEIL1D на числовой ID приёмного бота."""
    inbox = PrivateKey.generate()
    b = _Bot()
    ex = Exchange(b, "@inbox", b"\0" * 32, lambda: ("i1", bytes(inbox.public_key)), lambda: [77])
    env = {"v": 1, "body": {"x": "я" * 2000}}
    asyncio.run(ex._send(env, envelope.PREFIX + "AAAA", reply_to=5))
    assert b.uploads == [("sendDocument", envelope.DOC_CAPTION, envelope.PREFIX + "AAAA", 77)] and not b.sent


def test_random_delay_is_shown(monkeypatch):
    """перед новым постом бот пишет, через сколько отправит, затем «Отправляю…» и итог."""
    slept = []

    async def fake_sleep(s):
        slept.append(s)
    monkeypatch.setattr(uibot.asyncio, "sleep", fake_sleep)
    b = _Bot()
    texts = uibot.Texts(ROOT / "locales" / "ru.toml", {})
    ui = uibot.UI.__new__(uibot.UI)
    ui.bot, ui.T, ui.cfg, ui.config_name = b, texts, {"privacy": {"random_delay_seconds": [30, 30]}}, "config.toml"
    ui.plugins = uibot.plug.Registry()  # UI собран без __init__: плагинов нет

    async def op():
        return {"n": 7}
    status = {"chat": {"id": 1}, "message_id": 2}
    asyncio.run(ui._run(op, lambda r: f"готово {r['n']}", status=status, delay=True))
    shown = [t for k, t in b.sent if k == "edit"]
    assert slept == [30] and shown[0].startswith("Отправлю через 30 с") and shown[1] == texts("text.sending")
    assert shown[-1] == "готово 7"
    b.sent.clear()
    slept.clear()
    asyncio.run(ui._run(op, lambda r: "ok", status=status))  # правки и удаление — без задержки
    assert slept == []
