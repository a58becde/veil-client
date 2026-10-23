"""Тонкий асинхронный клиент Bot API: только нужные методы (Bot API 10.3).

Своя обёртка вместо aiogram: нужен bot-to-bot по @username и copyMessages, а обёртки отстают
от Bot API. Прокси берётся из окружения (HTTPS_PROXY) или из конфига.
Токен не попадает в тексты ошибок.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

# MIME вида «тип/подтип» (RFC 6838, без параметров): файлы «лично для» присылает другой человек, и в Content-Type части
# multipart иначе прошли бы переводы строк (подмена заголовков части).
_MIME = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}")
_UNSAFE_NAME = re.compile(r"[\x00-\x1f\x7f/\\\"]+")


def safe_mime(mime: str, default: str | None = None) -> str:
    m = (mime or "").strip().lower()
    return m if _MIME.fullmatch(m) else (default or "application/octet-stream")


def safe_filename(name: str, kind: str = "file") -> str:
    """Имя файла без управляющих символов, разделителей пути и кавычек, не длиннее 64 символов."""
    clean = _UNSAFE_NAME.sub("_", name or "").strip(" .")[:64]
    return clean or kind


class TelegramError(Exception):
    def __init__(self, method: str, code: int, description: str, retry_after: int = 0):
        super().__init__(f"telegram {method}: {code} {description}")
        self.method, self.code, self.description, self.retry_after = method, code, description, retry_after


class Bot:
    def __init__(self, token: str, *, proxy: str | None = None, base_url: str = "https://api.telegram.org"):
        if not token:
            raise ValueError("empty bot token")
        self._url = f"{base_url.rstrip('/')}/bot{token}/"
        self._file_url = f"{base_url.rstrip('/')}/file/bot{token}/"
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(75.0, connect=15.0), proxy=proxy, trust_env=proxy is None)

    async def close(self) -> None:
        await self._http.aclose()

    @staticmethod
    def _result(method: str, r: httpx.Response) -> Any:
        try:
            data = r.json()
        except ValueError:
            raise TelegramError(method, r.status_code, "bad JSON") from None
        if not data.get("ok"):
            raise TelegramError(method, data.get("error_code", r.status_code), data.get("description", ""),
                                (data.get("parameters") or {}).get("retry_after", 0))
        return data["result"]

    async def call(self, method: str, **params: Any) -> Any:
        params = {k: v for k, v in params.items() if v is not None}
        try:
            r = await self._http.post(self._url + method, json=params)
        except httpx.HTTPError as e:  # в тексте исключения httpx есть URL с токеном
            raise TelegramError(method, 0, type(e).__name__) from None
        return self._result(method, r)

    async def _post_files(self, method: str, form: dict, files: dict) -> Any:
        try:
            r = await self._http.post(self._url + method, data=form, files=files, timeout=httpx.Timeout(300.0, connect=15.0))
        except httpx.HTTPError as e:
            raise TelegramError(method, 0, type(e).__name__) from None
        return self._result(method, r)

    async def upload(self, method: str, field: str, filename: str, data: bytes, mime: str, **params: Any) -> Any:
        """Метод с загрузкой файла (multipart/form-data). Сложные параметры — JSON-строкой."""
        form = {k: (v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))
                for k, v in params.items() if v is not None}
        return await self._post_files(method, form, {field: (safe_filename(filename), data, safe_mime(mime))})

    async def upload_group(self, chat_id: int | str, items: list[tuple[str, str, bytes, str]],
                           caption: str = "", caption_entities: list | None = None) -> list[dict]:
        """Альбом из загружаемых файлов: items = [(type, имя, байты, mime)], подпись — у первого."""
        media, files = [], {}
        for i, (kind, name, data, mime) in enumerate(items):
            m = {"type": kind, "media": f"attach://f{i}"}
            if i == 0 and caption:
                m["caption"] = caption
                if caption_entities:
                    m["caption_entities"] = caption_entities
            media.append(m)
            files[f"f{i}"] = (safe_filename(name, kind), data, safe_mime(mime))
        return await self._post_files("sendMediaGroup", {"chat_id": str(chat_id), "media": json.dumps(media)}, files)

    async def download(self, file_id: str, max_bytes: int) -> bytes:
        """Скачать файл этого бота (Bot API отдаёт ботам не больше 20 МБ). Тело читается потоком и обрывается на
        max_bytes: getFile может не сообщить размер, а чужой файл не должен занимать память целиком."""
        f = await self.call("getFile", file_id=file_id)
        if f.get("file_size", 0) > max_bytes or "file_path" not in f:
            raise TelegramError("getFile", 0, "file too big")
        buf = bytearray()
        try:
            async with self._http.stream("GET", self._file_url + f["file_path"],
                                         timeout=httpx.Timeout(300.0, connect=15.0)) as r:
                if r.status_code != 200:
                    raise TelegramError("download", r.status_code, "download failed")
                async for chunk in r.aiter_bytes():
                    buf += chunk
                    if len(buf) > max_bytes:
                        raise TelegramError("download", 0, "file too big")
        except httpx.HTTPError as e:
            raise TelegramError("download", 0, type(e).__name__) from None
        return bytes(buf)

    async def send_group(self, chat_id: int | str, media: list[dict]) -> list[dict]:
        """Альбом по file_id этого бота (InputMedia: type, media, caption…)."""
        return await self.call("sendMediaGroup", chat_id=chat_id, media=media)

    async def get_me(self) -> dict:
        return await self.call("getMe")

    async def get_updates(self, offset: int, timeout: int = 50) -> list[dict]:
        return await self.call("getUpdates", offset=offset, timeout=timeout,
                               allowed_updates=["message", "callback_query"])

    async def send(self, chat_id: int | str, text: str, *, entities: list | None = None, reply_to: int | None = None,
                   markup: dict | None = None, preview: bool = False) -> dict:
        return await self.call("sendMessage", chat_id=chat_id, text=text, entities=entities,
                               reply_parameters={"message_id": reply_to, "allow_sending_without_reply": True}
                               if reply_to else None,
                               reply_markup=markup, link_preview_options={"is_disabled": not preview})

    async def copy(self, chat_id: int | str, from_chat: int, message_id: int, *, caption: str | None = None,
                   caption_entities: list | None = None) -> int:
        r = await self.call("copyMessage", chat_id=chat_id, from_chat_id=from_chat, message_id=message_id,
                            caption=caption, caption_entities=caption_entities)
        return r["message_id"]

    async def copy_many(self, chat_id: int | str, from_chat: int, message_ids: list[int], *,
                        remove_caption: bool = False) -> list[int]:
        r = await self.call("copyMessages", chat_id=chat_id, from_chat_id=from_chat, message_ids=sorted(message_ids),
                            remove_caption=remove_caption or None)
        return [x["message_id"] for x in r]

    async def edit_markup(self, chat_id: int, message_id: int, markup: dict | None) -> None:
        """Сменить или снять кнопки сообщения (None — снять)."""
        try:
            await self.call("editMessageReplyMarkup", chat_id=chat_id, message_id=message_id,
                            reply_markup=markup or {"inline_keyboard": []})
        except TelegramError as e:
            if "message is not modified" not in e.description:
                raise

    async def edit(self, chat_id: int, message_id: int, text: str, *, markup: dict | None = None) -> None:
        try:
            await self.call("editMessageText", chat_id=chat_id, message_id=message_id, text=text,
                            reply_markup=markup, link_preview_options={"is_disabled": True})
        except TelegramError as e:
            if "message is not modified" not in e.description:
                raise

    async def set_commands(self, commands: list[tuple[str, str]]) -> None:
        await self.call("setMyCommands", commands=[{"command": c, "description": d} for c, d in commands])
        await self.call("setChatMenuButton", menu_button={"type": "commands"})

    async def answer(self, callback_id: str, text: str | None = None, alert: bool = False) -> None:
        try:
            await self.call("answerCallbackQuery", callback_query_id=callback_id, text=text, show_alert=alert)
        except TelegramError:
            pass  # устаревший callback — не ошибка

    async def delete(self, chat_id: int, message_id: int) -> None:
        try:
            await self.call("deleteMessage", chat_id=chat_id, message_id=message_id)
        except TelegramError:
            pass


def keyboard(rows: list[list[tuple[str, str]]]) -> dict:
    """[[(надпись, callback_data), ...], ...] → inline_keyboard."""
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows]}
