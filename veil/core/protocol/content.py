"""Привязка контента к конверту (spec/04, «Привязка контента»).

Вход — сообщение в формате Bot API (dict). Сервер вычисляет то же самое по копии сообщения.
"""
from __future__ import annotations

import hashlib

from veil.core.protocol import jcs

# kind → поле сообщения Bot API
MEDIA_KINDS = ("photo", "video", "animation", "document", "audio", "voice", "video_note", "sticker")


def text_sha256(text: str) -> str:
    return hashlib.sha256(b"veil/v1/text\n" + text.encode("utf-8")).hexdigest()




def entities_sha256(entities: list | None) -> str:
    """Хеш форматирования (spec/04): каждая entity целиком (все поля, их сервер и опубликует), user → user_id.
    Иначе поле вне хеша (например, unix_time у date_time) можно было бы подменить.
    Telegram нормализует entities при отправке, а копия сохраняет их байт в байт (проверено вживую), поэтому
    хешируется вид, который видит сервер: у сообщений владельца — как пришли боту, у своих — из ответа Telegram."""
    proj = []
    for e in entities or []:
        if not isinstance(e.get("type"), str) or type(e.get("offset")) is not int or type(e.get("length")) is not int:
            raise ValueError("entity")
        x = {k: v for k, v in e.items() if k != "user"}
        if isinstance(e.get("user"), dict):
            x["user_id"] = int(e["user"]["id"])
        proj.append(x)
    return hashlib.sha256(b"veil/v1/entities\n" + jcs.canonicalize(proj)).hexdigest()


def message_entities(msg: dict) -> list:
    if "text" in msg:
        return msg.get("entities") or []
    if "poll" in msg:
        return []
    return msg.get("caption_entities") or []


def message_kind(msg: dict) -> str:
    if "text" in msg:
        return "text"
    if "poll" in msg:
        return "poll"
    for k in MEDIA_KINDS:
        if k in msg:
            return k
    return "unsupported"


def message_file_unique_id(msg: dict) -> str | None:
    kind = message_kind(msg)
    if kind == "photo":
        return msg["photo"][-1]["file_unique_id"]  # самый большой размер
    if kind in MEDIA_KINDS:
        return msg[kind]["file_unique_id"]
    return None


def message_text(msg: dict) -> str:
    if "text" in msg:
        return msg["text"]
    if "poll" in msg:
        return msg["poll"]["question"]
    return msg.get("caption", "")


def describe(messages: list[dict]) -> dict:
    """Описание контента для поля `content`. Для альбома — все элементы в порядке отправки."""
    if not messages:
        raise ValueError("no content")
    if len(messages) == 1:
        m = messages[0]
        kind = message_kind(m)
        fid = message_file_unique_id(m)
        return {"kind": kind, "text_sha256": text_sha256(message_text(m)),
                "entities_sha256": entities_sha256(message_entities(m)), "files": [fid] if fid else []}
    first = next((m for m in messages if message_text(m)), None)
    return {"kind": "album", "text_sha256": text_sha256(message_text(first) if first else ""),
            "entities_sha256": entities_sha256(message_entities(first) if first else []),
            "files": [message_file_unique_id(m) for m in messages]}
