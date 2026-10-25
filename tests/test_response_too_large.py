"""E_RESPONSE_TOO_LARGE (spec/09): итог не поместился в ответ. Токен потрачен, конверт не повторяется, пост не
дублируется, владельцу — «проверьте группу»; лента не сдвигает курсор."""
import asyncio
import json
from pathlib import Path

import pytest
from harness import Env

from veil.core import api
from veil.core.protocol import errors
from veil.core.store.db import Store
from veil.core.transport.exchange import ServerError

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "veil-protocol" / "test-vectors" / "veil-v1.json")
                     .read_text(encoding="utf-8"))
TOO_LARGE = "E_RESPONSE_TOO_LARGE"


def statuses(store: Store) -> dict[str, int]:
    return dict(store.db.execute("SELECT status, count(*) FROM tokens GROUP BY status").fetchall())


def draft(env: Env, **kw) -> api.Draft:
    return api.Draft(env.ui.owner, [{"message_id": 1, "text": "пост", "chat": {"id": 1}}], **kw)


def test_codes_and_semantics_match_vectors():
    """C1: список кодов и «токен потрачен» — как в общем векторе; новый код последний."""
    assert list(errors.CODES) == VECTORS["error_codes"] and errors.CODES[-1] == TOO_LARGE
    assert list(errors.TOKEN_SPENT) == VECTORS["error_semantics"]["token_spent"]
    assert set(VECTORS["error_semantics"]["not_saved"]) < set(errors.CODES)


def test_paid_op_too_large_spends_token_once(tmp_path):
    """C2: ответ «слишком большой» на платную операцию — токен spent, конверт один, второй токен не взят."""
    e = Env(tmp_path, tokens=3)
    e.store.add_post(5, bytes([5]) * 32, "", "text")
    calls = []

    async def request(op, *a, **kw):
        calls.append(op)
        raise ServerError(TOO_LARGE)
    e.core.exchange.request = request
    with pytest.raises(ServerError) as ei:
        asyncio.run(e.core.edit_post(draft(e, mode="append", target=5)))
    assert ei.value.code == TOO_LARGE
    assert calls == ["post.edit"] and statuses(e.store) == {"spent": 1, "ready": 2}


def test_set_nick_too_large_spends_token(tmp_path):
    """C2 для nick.set: то же правило, не только для постов."""
    e = Env(tmp_path, tokens=3, identity=True)
    asyncio.run(e.core.sync_device())
    before = statuses(e.store).get("spent", 0)  # device.set мог взять токен
    calls = []

    async def request(op, *a, **kw):
        calls.append(op)
        if op == "nick.set":
            raise ServerError(TOO_LARGE)
        return {}
    e.core.exchange.request = request
    with pytest.raises(ServerError):
        asyncio.run(e.core.set_nick("Роза"))
    assert calls.count("nick.set") == 1 and statuses(e.store).get("spent", 0) == before + 1


def test_other_error_still_returns_token(tmp_path):
    """Контроль границы правила: обычная ошибка токен не тратит."""
    e = Env(tmp_path, tokens=2)
    e.store.add_post(5, bytes([5]) * 32, "", "text")

    async def request(op, *a, **kw):
        raise ServerError("E_NOT_OWNER")
    e.core.exchange.request = request
    with pytest.raises(ServerError):
        asyncio.run(e.core.edit_post(draft(e, mode="append", target=5)))
    assert statuses(e.store) == {"ready": 2}


def test_create_post_too_large_is_plain_error(tmp_path):
    """C3: ServerError, не PostQueuedError; журнал пуст; пост в «мои» не добавлен."""
    e = Env(tmp_path, tokens=2)
    calls = []
    added = []
    e.store.add_post = lambda *a, **kw: added.append(a)

    async def request(op, *a, journal=None, **kw):
        calls.append(op)
        if journal:
            journal({"op": op, "id": "01JA000000000000000000BIG1", "auth_mode": "ephemeral"})
        raise ServerError(TOO_LARGE)
    e.core.exchange.request = request
    with pytest.raises(ServerError) as ei:
        asyncio.run(e.core.create_post(draft(e)))
    assert not isinstance(ei.value, api.PostQueuedError) and ei.value.code == TOO_LARGE
    assert calls == ["post.create"] and e.store.pending_posts() == [] and added == []
    assert statuses(e.store) == {"spent": 1, "ready": 1}


@pytest.mark.parametrize("code,event", [(TOO_LARGE, "unconfirmed"), ("E_UNCONFIRMED", "unconfirmed"),
                                        ("E_NOT_OWNER", "failed")])
def test_resume_pending_events(tmp_path, code, event):
    """C4: итог неизвестен — «unconfirmed», не «failed» (совет «отправьте снова» ведёт к дублю); запись удалена."""
    e = Env(tmp_path)
    e.store.save_pending_post("a", bytes(32), "text", {"id": "a", "auth_mode": "ephemeral"})

    async def resume(state, auth_key=None, resp_sk=None):
        raise ServerError(code)
    e.server.resume = resume
    assert asyncio.run(e.core.resume_pending()) == [(event, None)]
    assert e.store.pending_posts() == []


def test_explain_has_text_without_code(tmp_path):
    """C5: объяснение из локали, не общее, кода в тексте нет."""
    e = Env(tmp_path)
    text = e.ui.explain(ServerError(TOO_LARGE))
    assert text != e.ui.T("error.default") and TOO_LARGE not in text and "E_" not in text
    assert "группу" in text
    assert "E_" not in e.ui.T("text.post_unconfirmed") and "группу" in e.ui.T("text.post_unconfirmed")


def test_feed_too_large_keeps_cursor_and_does_not_resend(tmp_path):
    """C6: лента ответила «слишком большой» — исключение, курсор на месте, конверт не повторяется."""
    e = Env(tmp_path)
    e.store.put("feed_cursor", 7)
    calls = []

    async def request(op, *a, **kw):
        calls.append(op)
        raise ServerError(TOO_LARGE)
    e.core.exchange.request = request
    with pytest.raises(ServerError):
        asyncio.run(e.core.sync_feed())
    assert calls == ["feed.get"] and e.store.get("feed_cursor") == 7
