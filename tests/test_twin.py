"""Сценарий «двойник»: у злоумышленника личность с той же меткой, что у настоящей
«Ромашка у дороги·k7m2qa». Подбор не выполняется — метка обеим личностям подставляется (tag_fn), то есть проверяется
худший случай, когда перебор уже удался. Пара к серверному TestTwinWithSameTag."""
import asyncio
from pathlib import Path

import pytest
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey

from veil.core import api
from veil.core.crypto import keys
from veil.core.protocol import b64, hidden
from veil.core.store.db import Store
from veil.ui import bot as uibot

ROOT = Path(__file__).resolve().parent.parent
DAISY, TAG = "Ромашка у дороги", "k7m2qa"
SAME_TAG = lambda pk: TAG  # noqa: E731 — «подбор удался»: у обеих личностей одна метка


def match(d: keys.Device) -> dict:
    """Запись nick.lookup так, как её отдаёт сервер (подписи настоящие)."""
    return {"id_pk": b64.enc(d.id_pk), "nick": DAISY, "dev_pk": b64.enc(d.dev_pk), "seq": d.seq,
            "dev_sig": b64.enc(d.dev_sig), **d.enc_body()}


class _Exchange:
    def __init__(self, matches):
        self.matches = matches

    async def request(self, op, *a, **kw):
        assert op == "nick.lookup"
        return {"matches": self.matches}


def core_with(tmp, matches) -> api.Core:
    c = api.Core.__new__(api.Core)
    c.store, c.exchange, c.tag_of = Store(tmp), _Exchange(matches), SAME_TAG
    return c


@pytest.fixture
def daisy_and_twin():
    return (keys.issue_device(SigningKey.generate(), tag_fn=SAME_TAG),
            keys.issue_device(SigningKey.generate(), tag_fn=SAME_TAG))


def test_twin_cannot_read_private_for_daisy(daisy_and_twin):
    """Текст «лично для» шифруется ключом Ромашки, а не меткой: ключ двойника его не открывает."""
    daisy, twin = daisy_and_twin
    blob = hidden.seal_to(hidden.padded(hidden.payload("только Ромашке")), daisy.current.pk)
    assert hidden.open_to(blob, daisy.current.sk)["text"] == "только Ромашке"
    with pytest.raises(CryptoError):
        hidden.open_to(blob, twin.current.sk)


def test_server_returning_both_is_refused(tmp_path, daisy_and_twin):
    """Сервер (взломанный) отдаёт обе личности под одной парой ник·метка: клиент не выбирает наугад — отказ."""
    daisy, twin = daisy_and_twin
    core = core_with(tmp_path, [match(daisy), match(twin)])
    with pytest.raises(api.Ambiguous):
        asyncio.run(core.find_recipient(DAISY, TAG))


def test_twin_signature_must_be_real(tmp_path, daisy_and_twin):
    """Двойник не может выдать себя за ключ Ромашки: запись с ключом Ромашки, но чужим сертификатом устройства — отказ."""
    daisy, twin = daisy_and_twin
    forged = dict(match(daisy), dev_pk=b64.enc(twin.dev_pk), dev_sig=b64.enc(twin.dev_sig))
    core = core_with(tmp_path, [forged])
    with pytest.raises(keys.KeyMismatch):
        asyncio.run(core.find_recipient(DAISY, TAG))


class _Bot:
    def __init__(self):
        self.said = []

    async def send(self, chat, text, **kw):
        self.said.append(text)
        return {"message_id": 1}


def test_substitution_after_first_contact_warns(tmp_path, daisy_and_twin):
    """Сервер (взломанный) подменил Ромашку двойником после того, как вы ей уже писали: бот не шлёт молча, а
    предупреждает «под … теперь другая личность» и ждёт решения владельца."""
    daisy, twin = daisy_and_twin
    core = core_with(tmp_path, [match(twin)])
    core.remember_recipient(f"{DAISY}·{TAG}", b64.enc(daisy.id_pk), daisy.seq)  # уже писали настоящей Ромашке
    ui = uibot.UI.__new__(uibot.UI)
    ui.core, ui.bot, ui.owner = core, _Bot(), 1
    ui.T = uibot.Texts(ROOT / "locales" / "ru.toml", {})
    asyncio.run(ui._set_recipient({"draft": 0, "chat": 1, "mid": 1}, f"{DAISY}·{TAG}"))
    assert ui.bot.said and ui.bot.said[0].startswith("Внимание: под Ромашка у дороги·k7m2qa теперь другая личность")
    assert core.store.get("pending_recipient")["id"] == b64.enc(twin.id_pk)  # отправка ждёт «доверять» / «отмена»
