"""Обмен с приёмным ботом сервера по bot-to-bot (spec/04): контент, конверт ответом на него, ответ VEIL1R.

Ответы приходят обычными апдейтами бота; цикл апдейтов передаёт сообщения приёмного бота в
`Exchange.on_inbox_message`, а ожидающая операция получает расшифрованный и проверенный ответ.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core.protocol import envelope
from veil.core.protocol.errors import ProtocolError

from .telegram import Bot, TelegramError

log = logging.getLogger("veil.exchange")
_warned_username = False  # предупреждение о режиме по @username — один раз за процесс

WAIT = 125.0  # сервер отвечает после публикации, до 100 с (ARCHITECTURE сервера)
PENDING_RETRIES = 6  # E_PENDING: сколько раз повторить тот же конверт
DEADLINE = 600.0  # общий срок одной операции (10 мин), включая ожидания и паузы между повторами
MAX_ATTACHMENTS = 4  # документов-вложений на одно ожидание
HINT_PREFIX = "VEIL1E "
HINT_CODE = re.compile(r"E_[A-Z_]{1,32}")  # допустимый код в подсказке VEIL1E (spec/04)


class ServerError(Exception):
    """Ошибка операции от сервера (поле error ответа) или незашифрованная подсказка VEIL1E.

    accepted — раньше на этот же конверт сервер ответил E_PENDING: действие принято, токен за ним закреплён. Любая
    поздняя ошибка повтора (например, E_TOKEN_DAY после полуночи у старого сервера) не значит, что действия нет."""

    def __init__(self, code: str, overflow: int = 0, retry_after: int = 0, hint: bool = False, accepted: bool = False):
        super().__init__(code)
        self.code, self.overflow, self.retry_after, self.hint = code, overflow, retry_after, hint
        self.accepted = accepted


class NoReplyError(Exception):
    pass


def unreachable(e: TelegramError) -> bool:
    """Приёмный бот не принимает сообщения (удалён, заблокирован): тому же боту повтор не поможет."""
    return e.code == 403 or (e.code == 400 and "chat not found" in e.description.lower())


class PartBuffer:
    """Части многочастного ответа (spec/04): группы по n, кусок под парой (n, i), повтор пары заменяет прежний.
    Хранится не больше 136 кусков (сумма n при n = 1..16)."""

    def __init__(self) -> None:
        self._parts: dict[tuple[int, int], str] = {}

    def __len__(self) -> int:
        return len(self._parts)

    def add(self, text: str) -> str | None:
        """Кладёт часть; возвращает склеенный `VEIL1R …`, когда группа её n полна (при каждом приходе части
        полной группы, в том числе замене), иначе None. Не часть — None, буфер не меняется."""
        num = envelope.is_response_part(text)
        if num is None:
            return None
        i, n = num
        self._parts[(n, i)] = text
        if not all((n, k) in self._parts for k in range(1, n + 1)):
            return None
        try:
            return envelope.join_response([self._parts[(n, k)] for k in range(1, n + 1)])
        except ProtocolError:  # части уже проверены шаблоном; на всякий случай — как неполная группа
            return None


@dataclass
class _Pending:
    env_id: str
    resp_sk: PrivateKey
    future: asyncio.Future
    parts: PartBuffer = field(default_factory=PartBuffer)
    attachments: list[dict] = field(default_factory=list)  # документы ответом на конверт (hidden.file)
    collect: bool = False  # вложения нужны только запросу, который их ждёт (attachments is not None)
    keys: list[tuple[int | None, int]] = field(default_factory=list)  # (чат, message_id) всех конвертов операции


class Exchange:
    def __init__(self, bot: Bot, inbox: str, server_sig_pk: bytes, inbox_key: Callable[[], tuple[str, bytes]],
                 inbox_ids: Callable[[], list[int]] = lambda: []):
        self.bot, self.server_sig_pk, self.inbox_key = bot, server_sig_pk, inbox_key
        self.username = inbox.lstrip("@").lower()
        self.inbox_ids = inbox_ids  # ID приёмных ботов из подписанного keys.json
        self._current: int | None = None  # приёмный бот после переключения (switch_from)
        # (чат, message_id конверта) → ожидание: номера сообщений у каждого приёмного бота свои
        self._pending: dict[tuple[int | None, int], _Pending] = {}

    @property
    def inbox(self) -> int | str:
        """Куда слать: числовой ID из keys.json (первый или тот, на который переключились). По @username — только если
        сервер ID ещё не публикует: имя может сменить владельца, и тогда контент открытым текстом ушёл бы чужому боту
        (spec/04, «Адрес приёмного бота»)."""
        ids = self.inbox_ids()
        if not ids:
            return "@" + self.username
        return self._current if self._current in ids else ids[0]

    def switch_from(self, failed: int | str) -> bool:
        """Приёмный бот failed перестал принимать сообщения: дальше — следующий из keys.json (тот же сервер и те же
        ключи, другой адрес). False — переключиться не на кого."""
        ids = self.inbox_ids()
        if len(ids) < 2 or failed not in ids:
            return False
        self._current = ids[(ids.index(failed) + 1) % len(ids)]
        log.warning("inbox bot %s does not accept messages, switching to %s", failed, self._current)
        return True

    def inbox_for(self, bot_id: int | None) -> int | str:
        """Приёмный бот для запроса: указанный (например, тот, что держит файл «лично для»), если он из keys.json, —
        иначе обычный."""
        return bot_id if bot_id is not None and bot_id in self.inbox_ids() else self.inbox

    def is_inbox(self, sender: dict) -> bool:
        """Сообщение от приёмного бота сервера (ответы, подсказки VEIL1E, вложения)."""
        global _warned_username
        try:
            if not isinstance(sender, dict) or sender.get("is_bot") is not True:
                return False
            try:
                ids = self.inbox_ids()
            except Exception as e:  # испорченный список ID: отказ без доверия, а не падение на каждом апдейте
                log.warning("inbox bot ids unreadable (%s), sender rejected", type(e).__name__)
                return False
            if not isinstance(ids, (list, tuple)) or any(type(i) is not int for i in ids):
                log.warning("inbox bot ids malformed, sender rejected")
                return False
            if ids:
                sid = sender.get("id")
                return type(sid) is int and sid in ids
            if not _warned_username:
                _warned_username = True
                log.warning("inbox bots not published, using @username")
            name = sender.get("username")
            return isinstance(name, str) and name.isascii() and name.lower() == self.username
        except Exception as e:  # чужой объект с неожиданным поведением: не доверяем, не падаем
            log.warning("inbox sender check failed (%s), sender rejected", type(e).__name__)
            return False

    async def request(self, op: str, auth_mode: str, auth_key: SigningKey, *, body=None, token: dict | None = None,
                      content: dict | None = None,
                      deliver: Callable[[], Awaitable[int | tuple[int, dict]]] | None = None,
                      attachments: list[dict] | None = None,
                      journal: Callable[[dict], None] | None = None, to: int | None = None,
                      resp_sk: PrivateKey | None = None) -> dict:
        """Выполняет операцию: доставить контент (deliver → id первого сообщения у приёмного бота и,
        если контент формируется при доставке, его описание), отправить конверт ответом на него,
        дождаться ответа. attachments — сюда складываются документы, пришедшие ответом на конверт.
        journal — получает состояние конверта до первой отправки: по нему resume повторит тот же конверт после
        перезапуска или когда повторы кончились; ключей в нём нет — их выводят из post_secret (spec/05).
        to — ID приёмного бота, которому адресован запрос (без контента). resp_sk — секрет resp_pk (по умолчанию
        случайный). Возвращает result или бросает ServerError."""
        chat = self.inbox_for(to)
        reply_to = None
        if deliver:
            try:
                got = await deliver()
            except TelegramError as e:
                # Контент не дошёл: конверта ещё нет, токен не тронут. Следующая попытка пойдёт другому приёмному боту.
                if unreachable(e):
                    self.switch_from(chat)
                raise
            reply_to, content = (got if isinstance(got, tuple) else (got, content))
        resp_sk = resp_sk or PrivateKey.generate()
        env_id = envelope.new_ulid()
        if journal:
            journal({"op": op, "auth_mode": auth_mode, "body": body, "token": token, "content": content,
                     "reply_to": reply_to, "id": env_id, "inbox": chat if isinstance(chat, int) else None})
        # Без контента и без явного адресата конверт можно отправить и другому приёмному боту того же сервера.
        return await self._exchange(op, auth_mode, auth_key, body, token, content, reply_to, env_id, resp_sk,
                                    attachments, chat, may_switch=deliver is None and to is None)

    async def resume(self, state: dict, auth_key: SigningKey | None = None,
                     resp_sk: PrivateKey | None = None) -> dict:
        """Тот же конверт, что записал journal: тот же id, токен и resp_pk (spec/09) — сервер вернёт итог операции,
        а второй раз её не выполнит. Ключи в журнале не хранятся: auth_key и resp_sk выводит вызывающий (spec/05).
        Строка старого вида с resp_sk / auth_seed читается, пока жива."""
        if state.get("resp_sk"):
            resp_sk = PrivateKey(envelope.b64.dec(state["resp_sk"]))
        if resp_sk is None:
            raise ValueError("resp key required")
        if state.get("auth_seed"):
            auth_key = SigningKey(envelope.b64.dec(state["auth_seed"]))
        if auth_key is None:
            raise ValueError("auth key required")
        # Тому же приёмному боту, что и в первый раз: контент поста лежит у него.
        return await self._exchange(state["op"], state["auth_mode"], auth_key, state.get("body"), state.get("token"),
                                    state.get("content"), state.get("reply_to"), state["id"], resp_sk, None,
                                    self.inbox_for(state.get("inbox")))

    async def _exchange(self, op, auth_mode, auth_key, body, token, content, reply_to, env_id, resp_sk,
                        attachments, chat: int | str, may_switch: bool = False) -> dict:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + DEADLINE  # общий срок операции; deliver в него не входит
        kid, inbox_pk = self.inbox_key()
        env, resp_sk = envelope.build(op, auth_mode, auth_key, kid, body=body, token=token, content=content,
                                      id_=env_id, resp_sk=resp_sk)
        text = envelope.seal(env, inbox_pk)
        attempt, pending_left, accepted = 0, PENDING_RETRIES, False
        switches = len(self.inbox_ids()) - 1
        # Одно ожидание на всю операцию: ответ на любой отправленный конверт (первый, повтор, после смены бота)
        # засчитывается ей — сервер отвечает на первую копию, повтор остаётся без ответа (spec/09).
        pending = _Pending(env["id"], resp_sk, loop.create_future(), collect=attachments is not None)
        try:
            return await self._attempts(pending, op, auth_mode, auth_key, body, token, content, reply_to, chat,
                                        attachments, may_switch, deadline, kid, inbox_pk, env, text, attempt,
                                        pending_left, accepted, switches)
        finally:
            for key in pending.keys:
                if self._pending.get(key) is pending:
                    del self._pending[key]

    async def _attempts(self, pending: _Pending, op, auth_mode, auth_key, body, token, content, reply_to, chat,
                        attachments, may_switch, deadline, kid, inbox_pk, env, text, attempt, pending_left, accepted,
                        switches) -> dict:
        loop = asyncio.get_running_loop()
        resp_sk = pending.resp_sk
        while attempt < 2:  # повтор с тем же id: сервер вернёт сохранённый ответ (spec/04)
            left = deadline - loop.time()
            if left <= 0:
                break
            attempt += 1
            try:
                sent = await self._send(env, text, reply_to, chat)
            except TelegramError as e:
                if accepted:  # принято раньше (E_PENDING): сбой повтора не значит, что действия нет
                    raise ServerError("E_PENDING", accepted=True) from e
                if not (may_switch and switches > 0 and unreachable(e) and self.switch_from(chat)):
                    raise
                switches, chat, attempt = switches - 1, self.inbox, attempt - 1
                continue
            key = ((sent.get("chat") or {}).get("id"), sent["message_id"])
            fut = loop.create_future()
            pending.future = fut  # прежнее ожидание закончилось (таймаут или итог); части и вложения остаются
            pending.keys.append(key)
            self._pending[key] = pending
            try:
                resp = await asyncio.wait_for(fut, min(WAIT, max(left, 0.0)))
                if attachments is not None and resp.get("ok") and not pending.attachments:
                    for _ in range(25):  # документ отправлен раньше ответа, но может прийти чуть позже
                        await asyncio.sleep(0.2)
                        if pending.attachments:
                            break
            except asyncio.TimeoutError:
                continue
            except (ServerError, ProtocolError) as e:
                if not accepted:
                    raise
                # Подсказка или испорченный подписанный ответ после E_PENDING: действие принято.
                raise ServerError(e.code, accepted=True) from e
            if attachments is not None:
                attachments.extend(pending.attachments)
            if resp.get("ok"):
                return resp.get("result")
            err = resp.get("error") or {}
            if err.get("code") == "E_PENDING":
                accepted = True
            if err.get("code") == "E_PENDING" and pending_left > 0:
                # Операция принята и ещё выполняется (пост в очереди публикации): тот же конверт — тот же id, токен
                # и resp_pk, новый ts (spec/09). Действие второй раз не выполнится, а ответ с итогом придёт.
                pending_left -= 1
                attempt = 0
                pause = max(1, min(int(err.get("retry_after") or 5), 60))
                await asyncio.sleep(min(pause, max(deadline - loop.time(), 0.0)))
                env, resp_sk = envelope.build(op, auth_mode, auth_key, kid, body=body, token=token, content=content,
                                              id_=env["id"], resp_sk=resp_sk)
                text = envelope.seal(env, inbox_pk)
                pending.parts = PartBuffer()  # ответ E_PENDING закрыт; части следующего итога собираются заново
                pending.attachments.clear()
                continue
            raise ServerError(err.get("code", "E_INTERNAL"), err.get("overflow", 0), err.get("retry_after", 0),
                              accepted=accepted)
        if accepted:  # срок, повторы или ожидания кончились после E_PENDING: итог узнает resume
            raise ServerError("E_PENDING", accepted=True)
        raise NoReplyError(op)

    async def _send(self, env: dict, text: str, reply_to: int | None, to: int | None = None) -> dict:
        """Конверт текстом, а не помещающийся в 3000 байт — документом ответом на контент (spec/04)."""
        chat = self.inbox_for(to)
        if not envelope.needs_document(env):
            return await self.bot.send(chat, text, reply_to=reply_to)
        return await self.bot.upload("sendDocument", "document", "veil.txt", text.encode(), "text/plain",
                                     chat_id=chat, caption=envelope.DOC_CAPTION,
                                     reply_parameters={"message_id": reply_to, "allow_sending_without_reply": True}
                                     if reply_to else None)

    def on_inbox_message(self, msg: dict) -> None:
        """Сообщение от приёмного бота: часть ответа, ответ целиком или подсказка VEIL1E. Не бросает исключений:
        апдейт чужого или испорченного вида не должен ронять цикл апдейтов."""
        try:
            self._on_inbox_message(msg)
        except Exception as e:  # граница ввода от Telegram: любой сбой разбора = сообщение игнорируется
            log.warning("inbox message ignored: %s", type(e).__name__)

    def _on_inbox_message(self, msg: dict) -> None:
        if not isinstance(msg, dict) or not self.is_inbox(msg.get("from") or {}):
            return
        ref = ((msg.get("chat") or {}).get("id"), (msg.get("reply_to_message") or {}).get("message_id"))
        p = self._pending.get(ref)
        if p is None:
            return
        if "document" in msg:  # вложение к ответу (hidden.file); текстом ответа не является
            if p.collect and len(p.attachments) < MAX_ATTACHMENTS:
                p.attachments.append(msg)
            return
        text = msg.get("text")
        if p.future.done() or not isinstance(text, str):
            return  # первый годный итог побеждает
        if text.startswith(HINT_PREFIX):  # не подписано: только намёк (spec/04)
            code = text[len(HINT_PREFIX):].strip()
            if HINT_CODE.fullmatch(code):
                p.future.set_exception(ServerError(code, hint=True))
            return
        if not text.startswith(envelope.RESP_PREFIX):
            return
        if envelope.is_response_part(text) is not None:
            text = p.parts.add(text)
            if text is None:
                return
        try:
            p.future.set_result(envelope.open_response(text, p.resp_sk, self.server_sig_pk, p.env_id))
        except ProtocolError as e:
            # Подделка или чужой ответ (E_DECRYPT, E_SIG, E_NOT_ENVELOPE, E_MALFORMED до проверки подписи): ждём
            # дальше настоящего. Ответ, подписанный сервером, но испорченный, настоящего не заменит: завершаем сразу
            # (одно правило для одиночного и собранного ответа, spec/04).
            if e.signed:
                p.future.set_exception(e)
