"""Скрытие и доставка контента: ЕДИНСТВЕННАЯ таблица на стороне клиента (зеркало таблицы сервера, spec/07).

Режимы черновика (Draft.hide):
    ""        — ничего не скрывать;
    "links"   — скрыть ссылки (для всех, по кнопке «Показать»);
    "message" — скрыть всё: текст, подпись и само медиа (для всех, по кнопке);
    "to"      — лично для одного человека: шифруется его ключом, не прочитают ни сервер, ни группа.

    контент \\ режим     ""    links            message                to
    текст                да    если есть ссылки да                     да (текст)
    медиа с подписью     да    если есть ссылки да (медиа + подпись)  да (файл-контейнер)
    кружок, стикер       да    —                да (медиа)             да (файл-контейнер)
    альбом               да    если есть ссылки да (медиа + подпись)  да (файл-контейнер)
    опрос                да    —                —                      —

Интерфейс берёт доступные режимы из modes(), проверка черновика — preview(), отправка — build().
Новый вид контента или режим добавляется здесь и в таблице сервера, больше нигде.
"""
from __future__ import annotations

import copy
import secrets
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from nacl.signing import SigningKey

from veil.core.protocol import b64, envelope, hidden, jcs
from veil.core.protocol import content as contentmod

HIDDEN_LINK = "[ссылка скрыта 🔐]"
HIDDEN_MESSAGE = "[сообщение скрыто 🔐]"
CAPTION_KINDS = ("photo", "video", "animation", "document", "audio", "voice")
FILE_KINDS = CAPTION_KINDS + ("video_note", "sticker")
MAX_FILES = hidden.MAX_CONTAINER
ENVELOPE_LIMIT = envelope.MAX_DOC_PLAINTEXT  # больше 3000 байт конверт уходит документом (spec/04)


def utf16(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def text_of(msg: dict) -> tuple[str, list]:
    if "text" in msg:
        return msg["text"], msg.get("entities", [])
    return msg.get("caption", ""), msg.get("caption_entities", [])


def kind(msgs: list[dict]) -> str:
    """Вид контента черновика: вид сообщения, "album", "split" (Telegram разбил длинный текст) или "unsupported"."""
    if len(msgs) == 1:
        k = contentmod.message_kind(msgs[0])
        if k == "poll" and msgs[0]["poll"].get("type") == "quiz":
            return "unsupported"
        return k
    if all("text" in m for m in msgs):
        return "split"
    return "album" if album_ok([contentmod.message_kind(m) for m in msgs]) else "unsupported"


def album_ok(kinds: list[str]) -> bool:
    """Альбом, который примет сервер (вектор album_kinds) и sendMediaGroup: 2–10 элементов, фото и видео вместе,
    документы и аудио — только со своим видом. Общий вектор album_kinds."""
    group = {"photo": "visual", "video": "visual", "document": "document", "audio": "audio"}
    return 2 <= len(kinds) <= 10 and all(k in group for k in kinds) and len({group[k] for k in kinds}) == 1


def has_links(msgs: list[dict]) -> bool:
    return any(e["type"] in ("url", "text_link") for m in msgs for e in text_of(m)[1])


def modes(msgs: list[dict]) -> list[str]:
    """Доступные режимы скрытия по таблице модуля (порядок — для кнопок)."""
    k = kind(msgs)
    if k in ("poll", "unsupported", "split"):
        return [""]
    out = [""]
    if k != "text" and k not in CAPTION_KINDS and k != "album":
        return out + ["message", "to"]  # кружок, стикер: подписи нет
    if has_links(msgs):
        out.append("links")
    return out + ["message", "to"]


def hide_links(text: str, entities: list) -> tuple[str, list]:
    """Заменяет ссылки (url, text_link) плашкой; возвращает видимый текст и сдвинутые entities."""
    units = text.encode("utf-16-le")
    links = sorted((e for e in entities if e["type"] in ("url", "text_link")), key=lambda e: e["offset"])
    if not links:
        return text, entities
    out, kept, pos, spans = b"", [], 0, []
    plate = HIDDEN_LINK.encode("utf-16-le")
    for e in links:
        a, z = e["offset"] * 2, (e["offset"] + e["length"]) * 2
        if a < pos:
            continue
        out += units[pos:a] + plate
        spans.append((e["offset"], e["offset"] + e["length"], utf16(HIDDEN_LINK) - e["length"]))
        pos = z
    out += units[pos:]
    for e in entities:
        if e["type"] in ("url", "text_link"):
            continue
        a, z = e["offset"], e["offset"] + e["length"]
        if any(s < z and a < t for s, t, _ in spans):
            continue  # пересекается со скрытой ссылкой — форматирование теряем
        delta = sum(d for s, t, d in spans if t <= a)
        kept.append({**e, "offset": a + delta})
    return out.decode("utf-16-le"), kept


@dataclass
class FileInfo:
    """Файл сообщения: что нужно, чтобы скачать его, зашифровать и у получателя отправить тем же видом."""
    kind: str
    file_id: str
    size: int
    name: str
    mime: str


def file_info(msg: dict) -> FileInfo | None:
    k = contentmod.message_kind(msg)
    if k == "photo":
        p = msg["photo"][-1]
        return FileInfo(k, p["file_id"], p.get("file_size", 0), "photo.jpg", "image/jpeg")
    if k not in FILE_KINDS:
        return None
    f = msg[k]
    defaults = {"video": ("video.mp4", "video/mp4"), "animation": ("animation.mp4", "video/mp4"),
                "document": ("file", "application/octet-stream"), "audio": ("audio.mp3", "audio/mpeg"),
                "voice": ("voice.ogg", "audio/ogg"), "video_note": ("video_note.mp4", "video/mp4")}
    if k == "sticker":
        name, mime = (("sticker.tgs", "application/x-tgsticker") if f.get("is_animated") else
                      ("sticker.webm", "video/webm") if f.get("is_video") else ("sticker.webp", "image/webp"))
    else:
        name, mime = defaults[k]
    return FileInfo(k, f["file_id"], f.get("file_size", 0), f.get("file_name") or name, f.get("mime_type") or mime)


@dataclass
class Preview:
    """Проверка черновика без сети (кроме post.check, который делает api по полю check)."""
    kind: str
    check: dict | None              # тело post.check; None — проверять нечего (например, неподдерживаемое)
    problems: list[tuple[str, dict]] = field(default_factory=list)  # (ключ локали, параметры)


@dataclass
class Plan:
    shown: list[dict]               # что увидит сервер (для content); для файла — документ после загрузки
    deliver: Callable[[], Awaitable[int | tuple[int, dict]]]
    hidden: dict | None


def _shape(d, k: str, has_media: bool) -> dict | None:
    if d.hide == "links":
        return {"mode": "all"}
    if d.hide == "message":
        return {"mode": "all", "media": True} if has_media else {"mode": "all"}
    if d.hide == "to":
        h = {"mode": "to", "to_label": d.to_label}
        if has_media:
            h["file"] = True
        return h
    return None


def _visible(d, msgs: list[dict], k: str) -> tuple[str, list]:
    """Видимый текст поста (то, что сервер поставит телом) после скрытия — по той же таблице, что build()."""
    if d.hide == "to":
        return HIDDEN_MESSAGE, []  # текст-плашка или подпись-плашка у контейнера
    if d.hide == "message":
        return (HIDDEN_MESSAGE, []) if k == "text" or k in CAPTION_KINDS else ("", [])  # альбом, кружок: без подписи
    if k in ("video_note", "sticker", "poll"):
        return "", []
    first = next((m for m in msgs if text_of(m)[0]), msgs[0])
    text, ents = text_of(first)
    if k == "split":
        return "".join(text_of(m)[0] for m in msgs), []
    if d.hide == "links":
        return hide_links(text, ents)
    return text, ents


def preview(d, nick_label: str | None) -> Preview:
    msgs = sorted(d.messages, key=lambda m: m["message_id"])
    k = kind(msgs)
    if k == "unsupported":
        return Preview(k, None, [("text.cannot_publish", {})])
    if d.hide not in modes(msgs):
        return Preview(k, None, [("text.mode_unavailable", {})])
    has_media = k != "text" and k != "split"
    p = Preview(k, None)
    if k == "split":
        p.problems.append(("text.split", {"parts": len(msgs)}))
    vis, _ = _visible(d, msgs, k)
    p.check = {"kind": "document" if (d.hide == "to" and has_media) else ("text" if k == "split" else k),
               "body_units": utf16(vis)}
    if nick_label and not d.anonymous:
        p.check["nick"] = nick_label
    if d.reply_to:
        p.check["reply_to"] = d.reply_to
    shape = _shape(d, k, has_media)
    if shape:
        p.check["hidden"] = shape
    if d.hide == "to" and has_media:
        infos = [file_info(m) for m in msgs]
        if sum(i.size for i in infos if i) > MAX_FILES:
            p.problems.append(("text.file_too_big", {}))
    if _envelope_overflow(d, msgs, k, has_media) > 0:
        p.problems.append(("text.hidden_too_big", {"n": _chars_to_cut(d, msgs, k, has_media)}))
    return p


def _chars_to_cut(d, msgs, k, has_media) -> int:
    """На сколько символов сократить скрытый текст, чтобы конверт поместился (точно, подбором)."""
    idx = next((i for i, m in enumerate(msgs) if text_of(m)[0]), 0)
    text, _ = text_of(msgs[idx])
    field_ = "text" if "text" in msgs[idx] else "caption"

    def fits(n: int) -> bool:
        trial = [dict(m) for m in msgs]
        trial[idx] = dict(trial[idx], **{field_: text[:n]})
        trial[idx].pop("entities" if field_ == "text" else "caption_entities", None)
        dd = copy.copy(d)
        dd.messages = trial
        return _envelope_overflow(dd, trial, k, has_media) <= 0
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fits(mid):
            lo = mid
        else:
            hi = mid - 1
    return max(1, len(text) - lo)


def _hidden_payload_size(d, msgs: list[dict], k: str, has_media: bool) -> int:
    if not d.hide:
        return 0
    first = next((m for m in msgs if text_of(m)[0]), msgs[0])
    text, ents = text_of(first)
    files = None
    if d.hide == "to" and has_media:
        files = [{"kind": i.kind, "name": i.name, "mime": i.mime, "size": max(i.size, 1)}
                 for i in (file_info(m) for m in msgs) if i]
    try:
        if d.hide == "to":  # «лично для» несёт post_pk поста (43 символа base64url) и выравнивается
            pl = hidden.payload(text, ents or None, allow_empty=True, files=files,
                                file_key=bytes(32) if files else None,
                                post_pk=b64.enc(bytes(32)))
            return len(hidden.padded(pl))
        return len(hidden.payload(text, ents or None, allow_empty=True))
    except ValueError:
        return 10 ** 6


def _envelope_overflow(d, msgs, k, has_media) -> int:
    """Сколько байт лишних в конверте (лимит 3000 байт JSON, spec/04). 0 — помещается.

    Считается точно: собирается настоящий конверт тех же размеров с подставными данными."""
    size = _hidden_payload_size(d, msgs, k, has_media)
    body: dict = {"post_pk": b64.enc(bytes(32))}
    if d.reply_to:
        body["reply_to"] = d.reply_to
    if size:
        blob = b64.enc(bytes(size + (48 if d.hide == "to" else 40)))  # sealed box / nonce+тег
        if d.hide == "to":
            body["hidden"] = {"mode": "to", "to_pk": b64.enc(bytes(32)), "blob": blob}
            if has_media:
                body["hidden"]["file"] = True
        else:
            body["hidden"] = {"mode": "all", "blob": blob, "key": b64.enc(bytes(32))}
            if d.hide == "message" and has_media:
                body["hidden"]["media"] = True
    n_files = 1 if (d.hide == "to" and has_media) else sum(1 for m in msgs if file_info(m))
    content = {"kind": k, "text_sha256": "0" * 64, "files": ["A" * 20] * n_files}
    token = {"scheme": "poprf-r255-v1", "kid": "2026-W42", "day": "2026-10-16",
             "input": b64.enc(bytes(32)), "output": b64.enc(bytes(64))}
    env, _ = envelope.build("post.create", "identity", SigningKey(bytes(32)), "i1", body=body, token=token,
                            content=content)
    return envelope_size(env) - ENVELOPE_LIMIT


SEND_METHODS = {"photo": ("sendPhoto", "photo"), "video": ("sendVideo", "video"),
                "animation": ("sendAnimation", "animation"), "document": ("sendDocument", "document"),
                "audio": ("sendAudio", "audio"), "voice": ("sendVoice", "voice")}


async def build(core, d, post_pk: str | None = None) -> Plan:
    """План отправки: что увидит сервер, как доставить, что зашифровать. Для «лично для» с медиа
    здесь же скачиваются и шифруются файлы (до 20 МБ вместе). post_pk — ключ будущего поста: «лично для» к нему
    привязывается (spec/07)."""
    msgs = sorted(d.messages, key=lambda m: m["message_id"])
    k = kind(msgs)
    if k in ("unsupported", "split") or d.hide not in modes(msgs):
        raise ValueError("draft cannot be published")
    bot, inbox, chat = core.bot, core.exchange.inbox, d.chat_id
    first = msgs[0]
    text, ents = text_of(next((m for m in msgs if text_of(m)[0]), first))

    def sent(res) -> tuple[int, dict]:
        """Своё сообщение: описание контента — по ответу Telegram (он нормализует entities, spec/04)."""
        ms = res if isinstance(res, list) else [res]
        return ms[0]["message_id"], contentmod.describe(ms)

    async def resend(m: dict, caption: str, caption_entities):
        """Медиа с новой подписью — заново по file_id (copyMessage не возвращает итоговое сообщение)."""
        info = file_info(m)
        method, field = SEND_METHODS[info.kind]
        return await bot.call(method, chat_id=inbox, **{field: info.file_id}, caption=caption,
                              caption_entities=caption_entities or None)

    async def copy_all() -> int:
        if len(msgs) == 1:
            return await bot.copy(inbox, chat, first["message_id"])
        return (await bot.copy_many(inbox, chat, [m["message_id"] for m in msgs]))[0]

    if not d.hide:
        return Plan(msgs, copy_all, None)

    if d.hide == "links":
        vis, vis_ents = hide_links(text, ents)
        body = hidden.body_all(text, ents or None)
        if k == "text":
            async def deliver_text() -> tuple[int, dict]:
                return sent(await bot.send(inbox, vis, entities=vis_ents or None))
            return Plan([dict(first, text=vis, entities=vis_ents)], deliver_text, body)
        if k == "album":  # подписи альбома через copyMessages не поменять: отправляем заново по file_id
            media, shown = [], []
            for m in msgs:
                info = file_info(m)
                cap, cents = text_of(m)
                if cap and cap == text:
                    cap, cents = vis, vis_ents
                item = {"type": info.kind, "media": info.file_id}
                if cap:
                    item["caption"] = cap
                    if cents:
                        item["caption_entities"] = cents
                media.append(item)
                shown.append(dict(m, caption=cap, caption_entities=cents) if cap else
                             {kk: vv for kk, vv in m.items() if kk not in ("caption", "caption_entities")})

            async def deliver_album() -> tuple[int, dict]:
                return sent(await bot.send_group(inbox, media))
            return Plan(shown, deliver_album, body)

        async def deliver_caption() -> tuple[int, dict]:
            return sent(await resend(first, vis, vis_ents))
        return Plan([dict(first, caption=vis, caption_entities=vis_ents)], deliver_caption, body)

    if d.hide == "message":
        if k == "text":
            async def deliver_placeholder() -> tuple[int, dict]:
                return sent(await bot.send(inbox, HIDDEN_MESSAGE))
            return Plan([dict(first, text=HIDDEN_MESSAGE, entities=[])], deliver_placeholder,
                        hidden.body_all(text, ents or None))
        body = hidden.body_all(text, ents or None, media=True)
        strip = lambda m: {kk: vv for kk, vv in m.items() if kk not in ("caption", "caption_entities")}  # noqa: E731
        if k == "album":
            async def deliver_album_hidden() -> int:
                return (await bot.copy_many(inbox, chat, [m["message_id"] for m in msgs], remove_caption=True))[0]
            return Plan([strip(m) for m in msgs], deliver_album_hidden, body)
        if k in CAPTION_KINDS:
            async def deliver_media_hidden() -> tuple[int, dict]:
                return sent(await resend(first, HIDDEN_MESSAGE, None))
            return Plan([dict(strip(first), caption=HIDDEN_MESSAGE)], deliver_media_hidden, body)
        return Plan([strip(first)], copy_all, body)  # кружок, стикер

    # d.hide == "to": лично для одного
    to_pk = b64.dec(d.to_pk)
    if k == "text":
        async def deliver_to_text() -> tuple[int, dict]:
            return sent(await bot.send(inbox, HIDDEN_MESSAGE))
        return Plan([dict(first, text=HIDDEN_MESSAGE, entities=[])], deliver_to_text,
                    hidden.body_to(text, to_pk, ents or None, post_pk=post_pk))
    infos = [file_info(m) for m in msgs]
    blobs = [await bot.download(i.file_id, MAX_FILES) for i in infos]
    container, key = hidden.seal_files(blobs)
    files = [{"kind": i.kind, "name": i.name, "mime": i.mime, "size": len(b)} for i, b in zip(infos, blobs)]
    pl = hidden.payload(text, ents or None, allow_empty=True, files=files, file_key=key, post_pk=post_pk)
    body = {"mode": "to", "to_pk": d.to_pk, "blob": b64.enc(hidden.seal_to(hidden.padded(pl), to_pk)), "file": True}
    name = f"veil-{secrets.token_hex(4)}.bin"

    async def deliver_container() -> tuple[int, dict]:
        msg = await bot.upload("sendDocument", "document", name, container, "application/octet-stream",
                               chat_id=inbox, caption=HIDDEN_MESSAGE)
        return msg["message_id"], contentmod.describe([msg])
    return Plan([], deliver_container, body)


def envelope_size(env: dict) -> int:
    return len(jcs.canonicalize(env))
