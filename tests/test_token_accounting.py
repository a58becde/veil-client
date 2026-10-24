"""Учёт токенов: принятое сервером действие не повторяется с новым токеном, свои токены тратятся раньше перенесённых."""
import asyncio
import hashlib

import pytest
from harness import Env

from veil.core import api
from veil.core.store.db import Store
from veil.core.transport.exchange import NoReplyError, ServerError
from veil.core.wallet.issue import Token


def tokens(store: Store, n: int, origin: str = "", seed: str = "own") -> None:
    store.add_tokens([Token("t1", api.today(), hashlib.sha256(f"{seed}{i}".encode()).digest(), bytes(64))
                      for i in range(n)], origin=origin)


def statuses(store: Store) -> dict[str, int]:
    return dict(store.db.execute("SELECT status, count(*) FROM tokens GROUP BY status").fetchall())


def test_token_error_after_pending_keeps_post(tmp_path):
    """Сервер ответил E_PENDING (пост в очереди, токен потрачен вместе с ним), а повтор того же конверта после полуночи
    получил E_TOKEN_DAY (старый сервер). Клиент не берёт новый токен и не собирает второй конверт — иначе вышел бы
    второй пост, а секрет первого был бы стёрт из журнала. Итог — «пост в очереди», журнал сохранён."""
    e = Env(tmp_path, tokens=3)
    calls = []

    async def request(op, *a, journal=None, **kw):
        calls.append(op)
        if journal:
            journal({"op": op, "id": "01JA000000000000000000PEND", "auth_mode": "ephemeral"})
        raise ServerError("E_TOKEN_DAY", accepted=True)
    e.core.exchange.request = request
    d = api.Draft(e.ui.owner, [{"message_id": 1, "text": "пост", "chat": {"id": 1}}])
    with pytest.raises(api.PostQueuedError):
        asyncio.run(e.core.create_post(d))
    assert calls == ["post.create"] and statuses(e.store) == {"spent": 1, "ready": 2}
    assert [p[0] for p in e.store.pending_posts()] == ["01JA000000000000000000PEND"]


def test_pending_edit_spends_token(tmp_path):
    """E_PENDING на правку после всех повторов: правка принята и выполнится, токен потрачен вместе с ней — клиент не
    возвращает его в готовые (иначе следующая операция получила бы E_TOKEN_SPENT)."""
    e = Env(tmp_path, tokens=2)
    e.store.add_post(5, bytes([5]) * 32, "", "text")

    async def request(op, *a, **kw):
        raise ServerError("E_PENDING")
    e.core.exchange.request = request
    d = api.Draft(e.ui.owner, [{"message_id": 1, "text": "UPD", "chat": {"id": 1}}], mode="append", target=5)
    with pytest.raises(ServerError):
        asyncio.run(e.core.edit_post(d))
    assert statuses(e.store) == {"spent": 1, "ready": 1}


def test_no_reply_without_journal_returns_token(tmp_path):
    """Нет ответа на удаление (конверт не записан в журнал): токен не закреплён ни за чем — снова готов."""
    e = Env(tmp_path, tokens=1)
    e.store.add_post(5, bytes(32), "", "text")

    async def request(op, *a, **kw):
        raise NoReplyError(op)
    e.core.exchange.request = request
    with pytest.raises(NoReplyError):
        asyncio.run(e.core.delete_post(5))
    assert statuses(e.store) == {"ready": 1}


def test_own_tokens_before_transferred(tmp_path):
    """Сначала тратятся свои токены (от эмитента), потом перенесённые: их значения знает отдавший бот."""
    s = Store(tmp_path)
    tokens(s, 2, origin="abcd0123", seed="other")
    tokens(s, 2)
    got = [s.take_token(api.today()) for _ in range(4)]
    assert [t.origin for t in got] == ["", "", "abcd0123", "abcd0123"]


def test_rejected_transfer_not_retried_token_by_token(tmp_path):
    """Сервер отверг перенесённый токен — остальные из того же переноса на этот день больше не пробуются: мусорный
    перенос стоит одного обмена с сервером, а не по обмену на каждый токен."""
    e = Env(tmp_path, tokens=0)
    tokens(e.store, 5, origin="abcd0123", seed="junk")
    tokens(e.store, 1, origin="ffff0000", seed="good")
    used = []

    async def request(op, auth_mode, auth_key, *, token=None, **kw):
        used.append(token["input"])
        if len(used) == 1:
            raise ServerError("E_TOKEN_SPENT")
        return {"n": 5, "deleted": True}
    e.core.exchange.request = request
    e.store.add_post(5, bytes(32), "", "text")
    asyncio.run(e.core.delete_post(5))
    assert len(used) == 2 and statuses(e.store) == {"bad": 5, "spent": 1}
