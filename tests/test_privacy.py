"""Единая таблица скрытия (privacy.py) — зеркало таблицы сервера (spec/07)."""
import asyncio

from nacl.public import PrivateKey

from veil.core import api, privacy
from veil.core.protocol import b64, hidden
from veil.core.protocol import content as contentmod

TEXT = {"message_id": 1, "text": "привет https://e.x", "entities": [{"type": "url", "offset": 7, "length": 11}]}
PHOTO = {"message_id": 2, "photo": [{"file_id": "p1", "file_unique_id": "u1", "file_size": 1000}], "caption": "фото"}
NOTE = {"message_id": 3, "video_note": {"file_id": "v1", "file_unique_id": "vu", "file_size": 500}}
POLL = {"message_id": 4, "poll": {"question": "?", "type": "regular"}}
QUIZ = {"message_id": 5, "poll": {"question": "?", "type": "quiz"}}
ALBUM = [{"message_id": 6, "media_group_id": "g",
          "photo": [{"file_id": "a1", "file_unique_id": "au1", "file_size": 10}],
          "caption": "смотри https://e.x", "caption_entities": [{"type": "url", "offset": 7, "length": 11}]},
         {"message_id": 7, "media_group_id": "g", "video": {"file_id": "a2", "file_unique_id": "au2", "file_size": 20}}]


def test_modes_table():
    """Каждый вид контента: какие режимы доступны. Совпадает с таблицей сервера (TestDecideTable)."""
    assert privacy.modes([TEXT]) == ["", "links", "message", "to"]
    assert privacy.modes([PHOTO]) == ["", "message", "to"]          # ссылок в подписи нет
    assert privacy.modes([NOTE]) == ["", "message", "to"]           # кружок: подписи нет
    assert privacy.modes(ALBUM) == ["", "links", "message", "to"]
    assert privacy.modes([POLL]) == [""]
    assert privacy.kind([QUIZ]) == "unsupported" and privacy.modes([QUIZ]) == [""]


def test_preview_problems():
    d = api.Draft(chat_id=1, messages=[{"message_id": 1, "text": "я" * 4000}, {"message_id": 2, "text": "хвост"}])
    p = privacy.preview(d, None)
    assert p.kind == "split" and p.problems[0][0] == "text.split" and p.check["body_units"] == 4005
    big = [{"file_id": "p", "file_unique_id": "u", "file_size": 25 << 20}]
    d = api.Draft(chat_id=1, messages=[dict(PHOTO, photo=big)],
                  hide="to", to_label="Имя·nky1", to_pk="A" * 43)
    assert ("text.file_too_big", {}) in privacy.preview(d, None).problems
    # Скрытый текст до 4096 символов помещается: конверт больше 3000 байт уходит документом.
    link = [{"type": "url", "offset": 0, "length": 13}]
    for hide, ents in (("message", []), ("links", link)):
        d = api.Draft(chat_id=1, messages=[{"message_id": 1, "text": "https://a.com " + "я" * 4000, "entities": ents}],
                      hide=hide)
        assert privacy.preview(d, None).problems == [], hide
    d = api.Draft(chat_id=1, messages=[{"message_id": 1, "text": "я" * 4000}], hide="to", to_label="Имя·nky1",
                  to_pk="A" * 43)
    assert privacy.preview(d, None).problems == []
    d = api.Draft(chat_id=1, messages=[PHOTO], hide="to", to_label="Имя·nky1", to_pk="A" * 43)
    assert privacy.preview(d, "Имя·nky1").check == {
        "kind": "document", "body_units": privacy.utf16(privacy.HIDDEN_MESSAGE),
        "nick": "Имя·nky1", "hidden": {"mode": "to", "to_label": "Имя·nky1", "file": True}}


class FakeBot:
    def __init__(self, files):
        self.files, self.uploaded, self.sent = files, [], []

    async def download(self, file_id, max_bytes):
        return self.files[file_id]

    async def upload(self, method, field, name, data, mime, **params):
        self.uploaded.append((method, name, data, params))
        return {"message_id": 77, "caption": params.get("caption"),
                "document": {"file_id": "doc", "file_unique_id": "docu", "file_name": name}}

    async def send(self, chat, text, **kw):
        self.sent.append(text)
        return {"message_id": 50}

    async def copy(self, *a, **kw):
        return 51

    async def copy_many(self, *a, **kw):
        return [52, 53]

    async def send_group(self, chat, media):
        self.group = media
        return [{"message_id": 54}]


def _core(bot):
    core = api.Core.__new__(api.Core)
    core.bot = bot
    core.exchange = type("E", (), {"inbox": "@inbox"})()
    return core


def test_private_media_end_to_end():
    """Альбом «лично для»: файлы скачаны, зашифрованы в контейнер; сервер видит только документ-плашку;
    получатель своим ключом открывает payload и контейнер и получает те же байты."""
    rk = PrivateKey.generate()
    bot = FakeBot({"a1": b"\xff\xd8 photo bytes", "a2": b"video bytes" * 100})
    d = api.Draft(chat_id=1, messages=ALBUM, hide="to", to_label="Друг·w49p", to_pk=b64.enc(bytes(rk.public_key)))
    plan = asyncio.run(privacy.build(_core(bot), d))
    assert plan.shown == [] and plan.hidden["file"] is True and plan.hidden["mode"] == "to"
    mid, content = asyncio.run(plan.deliver())
    method, _, container, params = bot.uploaded[0]
    assert method == "sendDocument" and params["caption"] == privacy.HIDDEN_MESSAGE
    assert content == contentmod.describe([{"message_id": 77, "caption": privacy.HIDDEN_MESSAGE,
                                           "document": {"file_id": "doc", "file_unique_id": "docu"}}])
    assert b"photo bytes" not in container and "смотри" not in str(plan.hidden)
    pl = hidden.open_to(b64.dec(plan.hidden["blob"]), bytes(rk))
    files = hidden.open_files(container, b64.dec(pl["file_key"]), [f["size"] for f in pl["files"]])
    assert files == [b"\xff\xd8 photo bytes", b"video bytes" * 100]
    assert [f["kind"] for f in pl["files"]] == ["photo", "video"] and pl["text"].startswith("смотри")


def test_links_in_album_resend_with_new_captions():
    bot = FakeBot({})
    d = api.Draft(chat_id=1, messages=ALBUM, hide="links")
    plan = asyncio.run(privacy.build(_core(bot), d))
    asyncio.run(plan.deliver())
    assert bot.group[0]["caption"] == "смотри " + privacy.HIDDEN_LINK
    assert bot.group[1] == {"type": "video", "media": "a2"}
    assert plan.shown[0]["caption"] == "смотри " + privacy.HIDDEN_LINK
