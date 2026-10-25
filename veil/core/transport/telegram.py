"""Тонкий асинхронный клиент Bot API: только нужные методы (Bot API 10.3).

Своя обёртка вместо aiogram: нужен bot-to-bot по @username и copyMessages, а обёртки отстают
от Bot API. Прокси берётся из окружения (HTTPS_PROXY) или из конфига.
Токен не попадает в тексты ошибок.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)


class _HideToken(logging.Filter):
    """httpx пишет в журнал адрес запроса (INFO), а в нём токен бота: заменяем токен, какой бы уровень ни выбрал
    запускающий."""

    _IN_URL = re.compile(r"/bot[0-9]{1,20}:[A-Za-z0-9_-]{1,128}")

    def filter(self, record: logging.LogRecord) -> bool:
        text = record.getMessage()
        if self._IN_URL.search(text):
            record.msg, record.args = self._IN_URL.sub("/bot<token>", text), None
        return True


logging.getLogger("httpx").addFilter(_HideToken())

# Предел тела ответа после распаковки. В пачке getUpdates до 100 апдейтов, у каждого может быть вложенный
# reply_to_message; посторонний способен завалить бота длинными сообщениями, и тогда poll переходит на limit=1.
MAX_RESPONSE = 16 * 1024 * 1024
# Ответ на загрузку файла — одно сообщение или альбом до 10 сообщений.
MAX_UPLOAD_RESPONSE = 1024 * 1024
# До скольких секунд «retry_after» вызов сам ждёт и повторяет запрос (один раз).
RETRY_AFTER_MAX = 10
# Потолок паузы в цикле опроса.
POLL_WAIT_MAX = 60
_RETRY_AFTER_CAP = 86400
_DESCRIPTION_CAP = 512
_BACKOFF = (3, 6, 12, 24, 48, 60)
# служебные вызовы, о которых наблюдатель не сообщается (опрос и получение пути файла)
_UNOBSERVED = frozenset({"getUpdates", "getFile"})
_MAX_ID = 2 ** 53

_TOKEN = re.compile(r"[0-9]{1,20}:[A-Za-z0-9_-]{1,128}")
_USERNAME = re.compile(r"@[A-Za-z][A-Za-z0-9_]{3,31}")
_NETLOC = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?")
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
# Сбои httpx, не наследующие HTTPError: в их тексте тоже может оказаться адрес с токеном.
_HTTPX_FAILURES = (httpx.HTTPError, httpx.InvalidURL, httpx.StreamError)

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
    def __init__(self, method: str, code: int, description: str, retry_after: int = 0, *, api: bool = False):
        super().__init__(f"telegram {method}: {code} {description}")
        self.method, self.code, self.description, self.retry_after = method, code, description, retry_after
        # True — ошибка пришла в разобранном ответе Bot API (JSON с ok=false), а не от сети, прокси или мусора
        self.api = api


class _BogusLengthError(TelegramError):
    """Заявленная длина тела не помещается даже в 64-битное число: это не крупная пачка, а мусор в заголовке —
    уменьшение пачки не поможет, нужна обычная пауза."""


# цифр в наибольшем 64-битном числе: более длинная заявленная длина — мусор
_MAX_LENGTH_DIGITS = 20


def _checked_base_url(base_url: str, proxy: str | None) -> str:
    """Адрес Bot API: токен уходит в путь, поэтому — только https (или локальный сервер Bot API по http без прокси:
    через прокси токен ушёл бы открытым текстом). Возвращает «схема://хост[:порт]»."""
    bad = ValueError("invalid base_url")
    if not isinstance(base_url, str) or any(c in "?#\\\x7f" or c <= " " for c in base_url):
        raise bad
    try:
        u = urlsplit(base_url)
        host, _port = u.hostname, u.port  # разбор порта бросает ValueError на мусоре
    except ValueError:
        raise bad from None
    if not host or u.path not in ("", "/") or "@" in u.netloc or not _NETLOC.fullmatch(u.netloc):
        raise bad
    if u.scheme == "https":
        return f"https://{u.netloc}"
    if u.scheme == "http" and host in _LOOPBACK and proxy is None:
        return f"http://{u.netloc}"
    raise bad


def _positive_id(v: object, name: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= _MAX_ID:
        raise ValueError(f"invalid {name}")
    return v


def _chat_ref(v: object, name: str) -> int | str:
    if isinstance(v, int) and not isinstance(v, bool):
        if v == 0 or abs(v) >= _MAX_ID:
            raise ValueError(f"invalid {name}")
        return v
    if isinstance(v, str) and _USERNAME.fullmatch(v):
        return v
    raise ValueError(f"invalid {name}")


def _message_id(x: object, method: str) -> int:
    mid = x.get("message_id") if isinstance(x, dict) else None
    if isinstance(mid, bool) or not isinstance(mid, int):
        raise TelegramError(method, 0, "bad result")
    return mid


class Bot:
    def __init__(self, token: str, *, proxy: str | None = None, base_url: str = "https://api.telegram.org",
                 transport: httpx.AsyncBaseTransport | None = None,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
                 observer: Callable[[str, dict, Any], None] | None = None):
        if not token:
            raise ValueError("empty bot token")
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise ValueError("invalid bot token format")  # текст токена в сообщение не попадает
        root = _checked_base_url(base_url, proxy)
        self._url = f"{root}/bot{token}/"
        self._file_url = f"{root}/file/bot{token}/"
        self._sleep = sleep
        self._observer = observer
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(75.0, connect=15.0), proxy=proxy, transport=transport,
                                       trust_env=root.startswith("https") and proxy is None)

    async def close(self) -> None:
        await self._http.aclose()

    async def _fetch(self, method: str, limit: int, timeout: httpx.Timeout, **req: Any) -> tuple[int, bytes]:
        """Один POST: тело читается потоком и считается после распаковки; переадресации не выполняются.
        Ошибки — TelegramError без токена и без цепочки причин (в текстах httpx есть адрес с токеном)."""
        failure, too_big, bogus, status, body = "", False, False, 0, b""
        try:
            async with self._http.stream("POST", self._url + method, timeout=timeout, follow_redirects=False,
                                         **req) as r:
                status = r.status_code
                declared = r.headers.get("content-length", "")
                if 300 <= status < 400:
                    pass  # Location не читаем и не открываем
                elif declared.isascii() and declared.isdigit() and len(declared) > _MAX_LENGTH_DIGITS:
                    # длину строки сравниваем до int(): у CPython предел на число цифр при разборе
                    too_big = bogus = True
                elif declared.isascii() and declared.isdigit() and int(declared) > limit:
                    too_big = True
                else:
                    buf = bytearray()
                    async for chunk in r.aiter_bytes():
                        buf += chunk
                        if len(buf) > limit:
                            too_big = True
                            break
                    body = bytes(buf)
        except _HTTPX_FAILURES as e:
            failure = type(e).__name__
        if failure:
            raise TelegramError(method, 0, failure)
        if too_big:
            raise (_BogusLengthError if bogus else TelegramError)(method, 0, "response too big")
        return status, body

    @staticmethod
    def _parse(method: str, status: int, body: bytes) -> Any:
        try:
            data = json.loads(body)
        except (ValueError, RecursionError):
            data = None
        if not isinstance(data, dict):
            raise TelegramError(method, status, "bad JSON")
        if data.get("ok") is True:
            if "result" not in data:
                raise TelegramError(method, status, "bad JSON")
            return data["result"]
        code = data.get("error_code")
        if isinstance(code, bool) or not isinstance(code, int):
            code = status
        desc = data.get("description")
        desc = desc[:_DESCRIPTION_CAP] if isinstance(desc, str) else ""
        params = data.get("parameters")
        wait = params.get("retry_after") if isinstance(params, dict) else None
        wait = 0 if isinstance(wait, bool) or not isinstance(wait, int) else max(0, min(wait, _RETRY_AFTER_CAP))
        raise TelegramError(method, code, desc, wait, api=data.get("ok") is False)

    async def _request(self, method: str, limit: int, timeout: httpx.Timeout, **req: Any) -> Any:
        """Запрос с разбором ответа. 429 с короткой паузой повторяется один раз: Telegram отклонил запрос, не
        выполнив его. Остальные ошибки (5xx, сеть) не повторяются — запрос мог выполниться."""
        for attempt in (0, 1):
            status, body = await self._fetch(method, limit, timeout, **req)
            try:
                return self._parse(method, status, body)
            except TelegramError as e:
                err = e
            if attempt == 0 and err.code == 429 and err.retry_after <= RETRY_AFTER_MAX:
                await self._sleep(max(err.retry_after, 1))
                continue
            raise err
        raise AssertionError("unreachable")  # pragma: no cover

    def _observe(self, method: str, params: dict, result: Any) -> None:
        """Сообщить наблюдателю об успешном вызове. Токена и адреса в аргументах нет (они только в self._url);
        сбой наблюдателя пишется в журнал без параметров и вызов не ломает. Аргументы — те же объекты, что видит
        бот: наблюдатель их не изменяет."""
        if self._observer is None or method in _UNOBSERVED:
            return
        try:
            self._observer(method, params, result)
        except Exception as e:
            log.warning("observer %s failed: %s", method, type(e).__name__)

    async def call(self, method: str, **params: Any) -> Any:
        params = {k: v for k, v in params.items() if v is not None}
        result = await self._request(method, MAX_RESPONSE, self._http.timeout, json=params)
        self._observe(method, params, result)
        return result

    async def _post_files(self, method: str, form: dict, files: dict) -> Any:
        result = await self._request(method, MAX_UPLOAD_RESPONSE, httpx.Timeout(300.0, connect=15.0),
                                     data=form, files=files)
        # байты файлов наблюдателю не отдаются: имя, тип и размер
        shown = {"_file": [{"field": f, "name": v[0], "mime": v[2], "size": len(v[1])} for f, v in files.items()]}
        if len(files) == 1:
            shown = {"_file": shown["_file"][0]}
        self._observe(method, {**form, **shown}, result)
        return result

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
        if not isinstance(f, dict):
            raise TelegramError("getFile", 0, "bad result")
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

    async def get_updates(self, offset: int, timeout: int = 50, *, limit: int | None = None,
                          allowed: tuple[str, ...] | list[str] = ("message", "callback_query")) -> list[dict]:
        r = await self.call("getUpdates", offset=offset, timeout=timeout, limit=limit, allowed_updates=list(allowed))
        if not isinstance(r, list):
            raise TelegramError("getUpdates", 0, "bad result")
        return r

    async def poll(self, handle: Callable[[dict], Any], *, allowed: tuple[str, ...] | list[str],
                   timeout: int = 50) -> None:
        """Бесконечный цикл опроса: каждый апдейт — в handle (функция или корутина). Сбой обработчика пишется в
        журнал, цикл идёт дальше. Повторно пришедший апдейт и апдейт без внятного update_id пропускаются: они не
        должны ни ронять цикл, ни сдвигать смещение. Ошибки Telegram — пауза и новая попытка."""
        offset, limit, failures = 0, None, 0
        while True:
            try:
                ups = await self.get_updates(offset, timeout, limit=limit, allowed=allowed)
            except TelegramError as e:
                log.warning("getUpdates: %s", e)
                if e.code == 0 and e.description == "response too big" and limit is None \
                        and not isinstance(e, _BogusLengthError):
                    limit = 1  # пачка не помещается в предел: берём по одному апдейту, пока не придёт пустой ответ
                elif e.code == 429:
                    await self._sleep(min(max(e.retry_after, 1), POLL_WAIT_MAX))
                else:
                    await self._sleep(_BACKOFF[min(failures, len(_BACKOFF) - 1)])
                    failures += 1
                continue
            failures = 0
            if limit is not None and not ups:
                limit = None
            for u in ups:
                uid = u.get("update_id") if isinstance(u, dict) else None
                if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0 or uid < offset:
                    continue
                offset = uid + 1
                try:
                    res = handle(u)
                    if inspect.isawaitable(res):
                        await res
                except Exception:
                    log.exception("update")

    async def send(self, chat_id: int | str, text: str, *, entities: list | None = None, reply_to: int | None = None,
                   markup: dict | None = None, preview: bool = False) -> dict:
        return await self.call("sendMessage", chat_id=chat_id, text=text, entities=entities,
                               reply_parameters={"message_id": reply_to, "allow_sending_without_reply": True}
                               if reply_to else None,
                               reply_markup=markup, link_preview_options={"is_disabled": not preview})

    async def copy(self, chat_id: int | str, from_chat: int, message_id: int, *, caption: str | None = None,
                   caption_entities: list | None = None) -> int:
        chat_id, from_chat = _chat_ref(chat_id, "chat_id"), _chat_ref(from_chat, "from_chat")
        message_id = _positive_id(message_id, "message_id")
        r = await self.call("copyMessage", chat_id=chat_id, from_chat_id=from_chat, message_id=message_id,
                            caption=caption, caption_entities=caption_entities)
        return _message_id(r, "copyMessage")

    async def copy_many(self, chat_id: int | str, from_chat: int, message_ids: list[int], *,
                        remove_caption: bool = False) -> list[int]:
        """Скопировать сообщения по порядку id. Bot API пропускает то, что скопировать нельзя, поэтому ответ короче
        запроса — ошибка: иначе номера в ответе не соответствовали бы входным."""
        chat_id, from_chat = _chat_ref(chat_id, "chat_id"), _chat_ref(from_chat, "from_chat")
        if not isinstance(message_ids, (list, tuple)) or not 1 <= len(message_ids) <= 100:
            raise ValueError("invalid message_ids")
        ids = [_positive_id(m, "message_id") for m in message_ids]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate message_ids")
        r = await self.call("copyMessages", chat_id=chat_id, from_chat_id=from_chat, message_ids=sorted(ids),
                            remove_caption=remove_caption or None)
        if not isinstance(r, list):
            raise TelegramError("copyMessages", 0, "bad result")
        got = [_message_id(x, "copyMessages") for x in r]
        if len(got) != len(ids):
            raise TelegramError("copyMessages", 0, "partial copy")
        return got

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
        """Ответ на нажатие кнопки. Не бросает: устаревший или неверный query id (400) — не ошибка, остальное —
        в журнал."""
        try:
            await self.call("answerCallbackQuery", callback_query_id=callback_id, text=text, show_alert=alert)
        except TelegramError as e:
            if e.code != 400 or not e.api:
                log.warning("answerCallbackQuery: %d %r", e.code, e.description)

    async def delete(self, chat_id: int, message_id: int) -> bool:
        """True — сообщения больше нет (удалено сейчас или раньше). False — Telegram отказал насовсем (например,
        сообщению больше 48 ч). Сбой сети, лимит, 5xx и прочее — исключение: удаление надо повторить."""
        try:
            await self.call("deleteMessage", chat_id=chat_id, message_id=message_id)
        except TelegramError as e:
            if e.code != 400 or not e.api:
                raise  # 400 не из ответа Bot API (страница прокси и т. п.) — не отказ Telegram, удаление повторить
            if "not found" in e.description.lower():
                return True
            log.info("deleteMessage refused: %r", e.description)
            return False
        return True


def keyboard(rows: list[list[tuple[str, str]]]) -> dict:
    """[[(надпись, callback_data), ...], ...] → inline_keyboard."""
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows]}
