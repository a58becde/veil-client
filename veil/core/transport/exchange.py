"""Обмен с приёмным ботом сервера по bot-to-bot (spec/04): контент, конверт ответом на него, ответ VEIL1R.

Ответы приходят обычными апдейтами бота; цикл апдейтов передаёт сообщения приёмного бота в
`Exchange.on_inbox_message`, а ожидающая операция получает расшифрованный и проверенный ответ.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from veil.core.protocol import envelope
from veil.core.protocol.errors import ProtocolError

from .telegram import Bot, TelegramError

log = logging.getLogger("veil.exchange")

WAIT = 125.0  # сервер отвечает после публикации, до 100 с (ARCHITECTURE сервера)
PENDING_RETRIES = 6  # E_PENDING: сколько раз повторить тот же конверт (~ до 10 мин вместе с ожиданием сервера)
HINT_PREFIX = "VEIL1E "


class ServerError(Exception):
    """Ошибка операции от сервера (поле error ответа) или незашифрованная подсказка VEIL1E.

    accepted — раньше на этот же конверт сервер ответил E_PENDING: действие принято, токен за ним закреплён. Любая
    поздняя ошибка повтора (например, E_TOKEN_DAY после полуночи у старого сервера) не значит, что действия нет."""

    def __init__(self, code: str, overflow: int = 0, retry_after: int = 0, hint: bool = False, accepted: bool = False):
        super().__init__(code)
        self.code, self.overflow, self.retry_after, self.hint = code, overflow, retry_after, hint
        self.accepted = accepted


class NoReply(Exception):
    pass


def unreachable(e: TelegramError) -> bool:
    """Приёмный бот не принимает сообщения (удалён, заблокирован): тому же боту повтор не поможет."""
    return e.code == 403 or (e.code == 400 and "chat not found" in e.description.lower())


@dataclass
class _Pending:
    env_id: str
    resp_sk: PrivateKey
    future: asyncio.Future
    parts: list[str] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)  # документы ответом на конверт (hidden.file)


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
        if not sender.get("is_bot"):
            return False
        ids = self.inbox_ids()
        if ids:
            return sender.get("id") in ids
        return (sender.get("username") or "").lower() == self.username

    async def request(self, op: str, auth_mode: str, auth_key: SigningKey, *, body=None, token: dict | None = None,
                      content: dict | None = None,
                      deliver: Callable[[], Awaitable[int | tuple[int, dict]]] | None = None,
                      attachments: list[dict] | None = None,
                      journal: Callable[[dict], None] | None = None, to: int | None = None) -> dict:
        """Выполняет операцию: доставить контент (deliver → id первого сообщения у приёмного бота и,
        если контент формируется при доставке, его описание), отправить конверт ответом на него,
        дождаться ответа. attachments — сюда складываются документы, пришедшие ответом на конверт.
        journal — получает состояние конверта до первой отправки: по нему resume повторит тот же конверт после
        перезапуска или когда повторы кончились. to — ID приёмного бота, которому адресован запрос (без контента).
        Возвращает result или бросает ServerError."""
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
        resp_sk = PrivateKey.generate()
        env_id = envelope.new_ulid()
        if journal:
            journal({"op": op, "auth_mode": auth_mode, "body": body, "token": token, "content": content,
                     "reply_to": reply_to, "id": env_id, "resp_sk": envelope.b64.enc(bytes(resp_sk)),
                     "auth_seed": envelope.b64.enc(bytes(auth_key)) if auth_mode == "ephemeral" else None,
                     "inbox": chat if isinstance(chat, int) else None})
        # Без контента и без явного адресата конверт можно отправить и другому приёмному боту того же сервера.
        return await self._exchange(op, auth_mode, auth_key, body, token, content, reply_to, env_id, resp_sk,
                                    attachments, chat, may_switch=deliver is None and to is None)

    async def resume(self, state: dict, auth_key: SigningKey | None = None) -> dict:
        """Тот же конверт, что записал journal: тот же id, токен и resp_pk (spec/09) — сервер вернёт итог операции,
        а второй раз её не выполнит. auth_key — для режимов без сохранённого ключа (identity)."""
        if state.get("auth_seed"):
            auth_key = SigningKey(envelope.b64.dec(state["auth_seed"]))
        if auth_key is None:
            raise ValueError("auth key required")
        # Тому же приёмному боту, что и в первый раз: контент поста лежит у него.
        return await self._exchange(state["op"], state["auth_mode"], auth_key, state.get("body"), state.get("token"),
                                    state.get("content"), state.get("reply_to"), state["id"],
                                    PrivateKey(envelope.b64.dec(state["resp_sk"])), None,
                                    self.inbox_for(state.get("inbox")))

    async def _exchange(self, op, auth_mode, auth_key, body, token, content, reply_to, env_id, resp_sk,
                        attachments, chat: int | str, may_switch: bool = False) -> dict:
        kid, inbox_pk = self.inbox_key()
        env, resp_sk = envelope.build(op, auth_mode, auth_key, kid, body=body, token=token, content=content,
                                      id_=env_id, resp_sk=resp_sk)
        text = envelope.seal(env, inbox_pk)
        attempt, pending_left, accepted = 0, PENDING_RETRIES, False
        switches = len(self.inbox_ids()) - 1
        while attempt < 2:  # повтор с тем же id: сервер вернёт сохранённый ответ (spec/04)
            attempt += 1
            try:
                sent = await self._send(env, text, reply_to, chat)
            except TelegramError as e:
                if not (may_switch and switches > 0 and unreachable(e) and self.switch_from(chat)):
                    raise
                switches, chat, attempt = switches - 1, self.inbox, attempt - 1
                continue
            key = ((sent.get("chat") or {}).get("id"), sent["message_id"])
            fut = asyncio.get_running_loop().create_future()
            pending = _Pending(env["id"], resp_sk, fut)
            self._pending[key] = pending
            try:
                resp = await asyncio.wait_for(fut, WAIT)
                if attachments is not None and resp.get("ok") and not pending.attachments:
                    for _ in range(25):  # документ отправлен раньше ответа, но может прийти чуть позже
                        await asyncio.sleep(0.2)
                        if pending.attachments:
                            break
            except asyncio.TimeoutError:
                continue
            finally:
                self._pending.pop(key, None)
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
                await asyncio.sleep(max(1, min(int(err.get("retry_after") or 5), 60)))
                env, resp_sk = envelope.build(op, auth_mode, auth_key, kid, body=body, token=token, content=content,
                                              id_=env["id"], resp_sk=resp_sk)
                text = envelope.seal(env, inbox_pk)
                continue
            raise ServerError(err.get("code", "E_INTERNAL"), err.get("overflow", 0), err.get("retry_after", 0),
                              accepted=accepted)
        raise NoReply(op)

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
        """Сообщение от приёмного бота: часть ответа, ответ целиком или подсказка VEIL1E."""
        ref = ((msg.get("chat") or {}).get("id"), (msg.get("reply_to_message") or {}).get("message_id"))
        p = self._pending.get(ref)
        text = msg.get("text", "")
        if p is None:
            return
        if "document" in msg:  # вложение к ответу (hidden.file); текстом ответа не является
            p.attachments.append(msg)
            return
        if p.future.done():
            return
        if text.startswith(HINT_PREFIX):  # не подписано: только намёк (spec/04)
            p.future.set_exception(ServerError(text[len(HINT_PREFIX):].strip(), hint=True))
            return
        if not text.startswith(envelope.RESP_PREFIX):
            return
        part = envelope.is_response_part(text)
        if part:
            p.parts.append(text)
            if len({envelope.is_response_part(x)[0] for x in p.parts}) < part[1]:
                return
            try:
                text = envelope.join_response(p.parts)
            except ProtocolError as e:
                p.future.set_exception(e)
                return
        try:
            p.future.set_result(envelope.open_response(text, p.resp_sk, self.server_sig_pk, p.env_id))
        except ProtocolError as e:  # подделка или чужой ответ: ждём дальше настоящего
            if part is None:
                return
            p.future.set_exception(e)
