"""Ответ сервера «слишком большой» (spec/04, 09): токен потрачен, пост не дублируется, ошибка объяснена словами,
старые клиенты (неизвестный код) не ломаются. Проверки от spec и общих векторов, без опоры на устройство кода."""
import asyncio
import json
import re
from pathlib import Path

import pytest
from harness import Env
from nacl.signing import SigningKey
from test_exchange_adversary import REAL_SLEEP, Rig, req

from veil.core import api
from veil.core.protocol import b64, envelope, errors, jcs
from veil.core.transport import exchange as exmod
from veil.core.transport.exchange import NoReplyError, ServerError

V = json.loads((Path(__file__).parents[2] / "veil-protocol/test-vectors/veil-v1.json").read_text("utf-8"))
BIG = "E_RESPONSE_TOO_LARGE"
N_TOKENS = 4


def statuses(env) -> dict[str, int]:
    return dict(env.store.db.execute("SELECT status, count(*) FROM tokens GROUP BY status").fetchall())


def msgs(text="пост"):
    return [{"message_id": 1, "text": text, "chat": {"id": 1}}]


def ops(env, name):
    return [o for o, _ in env.server.ops if o == name]


# --- векторы ---
def test_error_semantics_match_vectors():
    sem = V["error_semantics"]
    assert list(errors.TOKEN_SPENT) == sem["token_spent"]
    assert set(sem["token_spent"]) <= set(errors.CODES) and set(sem["not_saved"]) <= set(errors.CODES)
    assert list(errors.CODES) == V["error_codes"] and errors.CODES[-1] == BIG
    assert len(set(errors.CODES)) == len(errors.CODES)
    assert errors.E_RESPONSE_TOO_LARGE == BIG
    assert BIG not in sem["not_saved"] and "E_UNCONFIRMED" not in sem["not_saved"]  # эти ответы сохраняются


def test_every_code_has_text_or_default(tmp_path):
    """Каждый код из общего списка объясним: либо свой текст, либо error.default; кода в тексте нет."""
    e = Env(tmp_path)
    for code in errors.CODES:
        text = e.ui.explain(ServerError(code))
        assert text and not re.search(r"\bE_[A-Z_]+\b", text), code


# --- токен после E_RESPONSE_TOO_LARGE ---
def _edit_env(tmp_path):
    e = Env(tmp_path, tokens=N_TOKENS)
    e.store.add_post(5, bytes([5]) * 32, "", "text")
    return e, lambda: e.core.edit_post(api.Draft(e.ui.owner, msgs("UPD"), mode="append", target=5)), "post.edit"


def _delete_env(tmp_path):
    e = Env(tmp_path, tokens=N_TOKENS)
    e.store.add_post(5, bytes([5]) * 32, "", "text")
    return e, lambda: e.core.delete_post(5), "post.delete"


def _create_env(tmp_path):
    e = Env(tmp_path, tokens=N_TOKENS)
    return e, lambda: e.core.create_post(api.Draft(e.ui.owner, msgs())), "post.create"


def _anon_create_env(tmp_path):
    e = Env(tmp_path, tokens=N_TOKENS)
    return e, lambda: e.core.create_post(api.Draft(e.ui.owner, msgs(), anonymous=True)), "post.create"


def _nick_env(tmp_path):
    e = Env(tmp_path, tokens=N_TOKENS, identity=True)
    asyncio.run(e.core.sync_device())
    return e, lambda: e.core.set_nick("Роза"), "nick.set"


PAID = [_edit_env, _delete_env, _create_env, _anon_create_env, _nick_env]


@pytest.mark.parametrize("make", PAID, ids=lambda f: f.__name__)
def test_token_spent_once_no_second_envelope(tmp_path, make):
    e, run, op = make(tmp_path)
    before, st0 = len(ops(e, op)), statuses(e)
    e.server.fail(op, BIG)
    with pytest.raises(ServerError) as ei:
        asyncio.run(run())
    assert ei.value.code == BIG
    assert len(ops(e, op)) - before == 1, "новый конверт после E_RESPONSE_TOO_LARGE"
    st = statuses(e)
    assert st.get("spent", 0) == st0.get("spent", 0) + 1 and st.get("ready") == st0["ready"] - 1, (st0, st)


@pytest.mark.parametrize("make", PAID, ids=lambda f: f.__name__)
def test_token_spent_even_if_pending_came_first(tmp_path, make):
    """E_PENDING, затем на повтор того же конверта — E_RESPONSE_TOO_LARGE: действие принято, токен потрачен."""
    e, run, op = make(tmp_path)
    st0 = statuses(e)
    e.server.fail(op, BIG, accepted=True)
    with pytest.raises((ServerError, api.PostQueuedError)):
        asyncio.run(run())
    st = statuses(e)
    assert st.get("spent", 0) == st0.get("spent", 0) + 1 and st.get("ready") == st0["ready"] - 1, (st0, st)


@pytest.mark.parametrize("make", [_edit_env, _delete_env], ids=lambda f: f.__name__)
@pytest.mark.parametrize("code", ["E_NOT_OWNER", "E_EDIT_LIMIT", "E_WHATEVER_NEW"])
def test_other_errors_return_token(tmp_path, make, code):
    """Контроль: обычная ошибка, как и неизвестный будущий код (старый клиент), токен не тратит."""
    e, run, op = make(tmp_path)
    e.server.fail(op, code)
    with pytest.raises(ServerError):
        asyncio.run(run())
    assert statuses(e) == {"ready": N_TOKENS}


def test_unknown_code_old_client_explained_by_default(tmp_path):
    """Клиент, не знающий кода, показывает общий текст, кода владельцу не показывает."""
    e = Env(tmp_path)
    t = e.ui.explain(ServerError("E_SOMETHING_FROM_THE_FUTURE"))
    assert t == e.ui.T("error.default") and "E_" not in t


# --- create_post ---
@pytest.mark.parametrize("anonymous", [False, True])
@pytest.mark.parametrize("accepted", [False, True])
def test_create_post_no_queue_no_my_post(tmp_path, monkeypatch, anonymous, accepted):
    e = Env(tmp_path, tokens=N_TOKENS, identity=not anonymous)
    if not anonymous:
        asyncio.run(e.core.sync_device())
        e.server.registered[e.store.load_device().dev_pk]["nick"] = "Роза"
    added, st0 = [], statuses(e)
    real = e.store.add_post
    monkeypatch.setattr(e.store, "add_post", lambda *a, **kw: (added.append(a), real(*a, **kw))[1])
    e.server.fail("post.create", BIG, accepted=accepted)
    d = api.Draft(e.ui.owner, msgs(), anonymous=anonymous)
    try:
        asyncio.run(e.core.create_post(d))
    except api.PostQueuedError:
        # допустимо только при accepted: запись журнала остаётся, итог дозапросится и станет «неизвестно»
        assert accepted
        e.server.resume = _raise(ServerError(BIG, accepted=True))
        got = asyncio.run(e.core.resume_pending())
        if not got:  # «принято раньше»: следующий дозапрос получает уже окончательный ответ
            e.server.resume = _raise(ServerError(BIG))
            got = asyncio.run(e.core.resume_pending())
        assert got == [("unconfirmed", None)]
    except ServerError as ex:
        assert ex.code == BIG
    else:
        pytest.fail("исключения нет")
    assert e.store.pending_posts() == [] and added == [] and not e.store.my_numbers()
    assert len(ops(e, "post.create")) == 1
    assert statuses(e).get("spent", 0) == st0.get("spent", 0) + 1


def _raise(exc):
    async def f(*a, **kw):
        raise exc
    return f


# --- resume_pending ---
def _pending(e, *ids):
    for i in ids:
        e.store.save_pending_post(i, bytes(32), "text", {"id": i, "auth_mode": "ephemeral"})


@pytest.mark.parametrize("accepted", [False, True])
@pytest.mark.parametrize("code,event", [(BIG, "unconfirmed"), ("E_UNCONFIRMED", "unconfirmed"),
                                        ("E_NOT_OWNER", "failed"), ("E_TOO_LONG", "failed")])
def test_resume_events_and_journal(tmp_path, code, event, accepted):
    e = Env(tmp_path, tokens=N_TOKENS)
    _pending(e, "01JA00000000000000000000A1")
    e.server.resume = _raise(ServerError(code, accepted=accepted))
    got = asyncio.run(e.core.resume_pending())
    if accepted and not got:
        # «принято раньше»: итог дозапрашивается ещё раз, и уже без признака «принято» он окончателен
        assert len(e.store.pending_posts()) == 1
        e.server.resume = _raise(ServerError(code))
        got = asyncio.run(e.core.resume_pending())
    assert got == [(event, None)]
    assert e.store.pending_posts() == []
    assert statuses(e) == {"ready": N_TOKENS}, "дозапрос итога не трогает токены"
    assert asyncio.run(e.core.resume_pending()) == []  # запись не вернулась


def test_resume_mixed_entries_each_gets_its_own_event(tmp_path):
    e = Env(tmp_path)
    ids = ["01JA00000000000000000000B1", "01JA00000000000000000000B2", "01JA00000000000000000000B3",
           "01JA00000000000000000000B4"]
    _pending(e, *ids)
    plan = {ids[0]: BIG, ids[1]: "E_NOT_OWNER", ids[2]: "E_UNCONFIRMED", ids[3]: "E_PENDING"}

    async def resume(state, auth_key=None, resp_sk=None):
        raise ServerError(plan[state["id"]])
    e.server.resume = resume
    got = asyncio.run(e.core.resume_pending())
    assert sorted(x for x, _ in got) == ["failed", "unconfirmed", "unconfirmed"]
    assert [p[0] for p in e.store.pending_posts()] == [ids[3]]  # E_PENDING — ждёт следующего дозапроса


def test_resume_one_stuck_entry_does_not_block_the_others(tmp_path):
    """Запись, ответ на которую ещё ждёт исходный запрос / не пришёл / ждёт очереди, не мешает остальным: все
    дозапрашиваются в одном проходе, итог каждой публикуется и записывается (url и вид сохраняются)."""
    e = Env(tmp_path)
    stuck = ["01JA00000000000000000000D1", "01JA00000000000000000000D2", "01JA00000000000000000000D3"]
    good = "01JA00000000000000000000D9"
    for i, env_id in enumerate(stuck + [good]):
        e.store.save_pending_post(env_id, bytes([i + 1]) * 32, "photo" if env_id == good else "text",
                                  {"id": env_id, "auth_mode": "ephemeral"})
    e.store.db.execute("UPDATE pending_posts SET created = created - 100 WHERE id != ?", (good,))
    e.core._inflight.add(stuck[0])

    async def resume(state, auth_key=None, resp_sk=None):
        if state["id"] == stuck[1]:
            raise NoReplyError("x")
        if state["id"] == stuck[2]:
            raise ServerError("E_PENDING")
        return {"n": 77, "url": "https://t.me/c/1/77"}
    e.server.resume = resume
    assert asyncio.run(e.core.resume_pending()) == [("published", {"n": 77, "url": "https://t.me/c/1/77"})]
    assert [p[0] for p in e.store.pending_posts()] == stuck
    row = e.store.db.execute("SELECT url, kind, post_secret FROM my_posts WHERE n = 77").fetchone()
    assert row == ("https://t.me/c/1/77", "photo", bytes([4]) * 32)


def test_resume_ttl_boundary_and_drop(tmp_path, monkeypatch):
    """Дольше часа не дозапрашиваем: запись удаляется, владелец узнаёт «не удалось»; ровно час — ещё дозапрашиваем;
    просроченная запись не мешает свежим."""
    from types import SimpleNamespace
    e = Env(tmp_path)
    now = 2_000_000_000.0
    monkeypatch.setattr(api, "time", SimpleNamespace(time=lambda: now))
    ids = {"old": "01JA00000000000000000000E1", "edge": "01JA00000000000000000000E2",
           "new": "01JA00000000000000000000E3"}
    for i, env_id in enumerate(ids.values()):
        e.store.save_pending_post(env_id, bytes([i + 1]) * 32, "text", {"id": env_id, "auth_mode": "ephemeral"})
    ttl = api.Core.PENDING_TTL
    for key, age in (("old", ttl + 1), ("edge", ttl), ("new", 5)):
        e.store.db.execute("UPDATE pending_posts SET created = ? WHERE id = ?", (now - age, ids[key]))
    seen = []

    async def resume(state, auth_key=None, resp_sk=None):
        seen.append(state["id"])
        return {"n": 10 + len(seen), "url": "u"}
    e.server.resume = resume
    got = asyncio.run(e.core.resume_pending())
    assert [x for x, _ in got] == ["lost", "published", "published"]
    assert seen == [ids["edge"], ids["new"]] and e.store.pending_posts() == []


def test_resume_without_reply_keeps_entry(tmp_path):
    e = Env(tmp_path)
    _pending(e, "01JA00000000000000000000C1")
    e.server.resume = _raise(NoReplyError("x"))
    assert asyncio.run(e.core.resume_pending()) == []
    assert len(e.store.pending_posts()) == 1


# --- что видит владелец ---
def test_explain_text(tmp_path):
    e = Env(tmp_path)
    t = e.ui.explain(ServerError(BIG))
    assert t != e.ui.T("error.default") and t.strip()
    assert not re.search(r"\bE_[A-Z_]+\b", t) and "RESPONSE" not in t
    assert "групп" in t.lower(), "владелец должен узнать, что пост мог выйти и надо проверить группу"
    # принято раньше (E_PENDING) — текст не говорит «не выполнено» и не пропадает
    t2 = e.ui.explain(ServerError(BIG, accepted=True))
    assert t2.strip() and t2 != e.ui.T("error.default") and "E_" not in t2


def test_explain_too_large_after_pending_is_not_queue_text(tmp_path):
    e = Env(tmp_path)
    t = e.ui.explain(ServerError(BIG, accepted=True))
    assert t != e.ui.T("error.E_PENDING")
    assert "групп" in t.lower()


def test_explain_unconfirmed_after_pending_says_check_group_and_token_spent(tmp_path):
    e = Env(tmp_path)
    t = e.ui.explain(ServerError("E_UNCONFIRMED", accepted=True))
    low = t.lower()
    assert t != e.ui.T("error.E_PENDING") and t != e.ui.T("error.default")
    assert "групп" in low and "не потрачен" not in low and "потрачен" in low
    assert not re.search(r"\bE_[A-Z_]+\b", t)


def test_unconfirmed_and_too_large_texts_never_offer_blind_resend(tmp_path):
    """Если предлагается отправить снова — только после «проверьте группу»."""
    e = Env(tmp_path)
    for code in (BIG, "E_UNCONFIRMED"):
        t = e.ui.explain(ServerError(code)).lower()
        assert "групп" in t
        if "отправ" in t:
            assert t.index("групп") < t.rindex("отправ"), t
    for key in ("text.post_unconfirmed",):
        t = e.ui.T(key).lower()
        assert "групп" in t and ("отправ" not in t or t.index("групп") < t.rindex("отправ"))


@pytest.mark.parametrize("code", [BIG, "E_UNCONFIRMED"])
def test_ui_send_flow_never_resends(tmp_path, code):
    """Отправка поста из бота: ответ слишком большой / без подтверждения → слова, один конверт, черновика нет,
    повторное нажатие «Отправить» (устаревшая кнопка) новый конверт не создаёт."""
    e = Env(tmp_path)
    e.route(e.msg("Привет"))
    i = e.draft_id()
    e.server.fail("post.create", code)
    e.route(e.press(f"d:{i}:send", msg_id=55))
    assert e.store.draft(i) is None and e.store.pending_posts() == []
    assert any("групп" in t.lower() for t in e.tg.texts())
    assert not any(re.search(r"\bE_[A-Z_]+\b", t) for t in e.tg.texts())
    e.route(e.press(f"d:{i}:send", msg_id=55))
    e.route(e.press(f"d:{i}:send", msg_id=55))
    assert len(ops(e, "post.create")) == 1
    if code == BIG:
        assert statuses(e)["spent"] == 1 and statuses(e)["ready"] == 9
    else:
        assert statuses(e) == {"ready": 10}


def test_ui_resume_notifications(tmp_path, monkeypatch):
    """События очереди → сообщения владельцу: unconfirmed — «проверьте группу», не «сервер отказал, отправьте снова»."""
    e = Env(tmp_path)
    events = [("unconfirmed", None), ("failed", None), ("lost", None)]

    async def fake_resume():
        out, events[:] = list(events), []
        return out
    monkeypatch.setattr(e.core, "resume_pending", fake_resume)

    async def go():
        task = asyncio.create_task(e.ui._resume_scheduled())
        for _ in range(100):
            await asyncio.sleep(0.01)
            if len(e.tg.texts()) >= 3:
                break
        task.cancel()
    asyncio.run(go())
    texts = e.tg.texts()
    assert texts[0] == e.ui.T("text.post_unconfirmed") and "групп" in texts[0].lower()
    assert texts[1] == e.ui.T("text.post_failed") and texts[2] == e.ui.T("text.post_lost")
    assert len(set(texts[:3])) == 3


# --- лента ---
def test_feed_too_large_keeps_cursor_and_retries_with_new_envelope(tmp_path):
    e = Env(tmp_path)
    e.store.put("feed_cursor", 7)
    e.server.fail("feed.get", BIG)
    with pytest.raises(ServerError) as ei:
        asyncio.run(e.core.fetch_feed(e.store.get("feed_cursor", 0)))
    assert ei.value.code == BIG
    assert e.store.get("feed_cursor") == 7
    assert len(ops(e, "feed.get")) == 1, "тот же запрос не повторяется внутри вызова"
    assert statuses(e) == {"ready": 10}, "лента бесплатна: токены не нужны и не тратятся"
    # следующий опрос — новый запрос, и он проходит
    e.server.feed = [{"n": 8, "kind": "text", "url": "u", "excerpt": "x"}]
    posts, cursor = asyncio.run(e.core.fetch_feed(7))
    assert [p["n"] for p in posts] == [8] and cursor == 8 and len(ops(e, "feed.get")) == 2


def test_feed_error_midway_does_not_move_cursor(tmp_path):
    """Первая страница прошла, вторая — E_RESPONSE_TOO_LARGE: курсор в хранилище не сдвинут (его двигает обработка)."""
    e = Env(tmp_path)
    e.store.put("feed_cursor", 3)
    calls = []
    real = e.server.request

    async def request(op, *a, **kw):
        calls.append(op)
        if len(calls) == 2:
            raise ServerError(BIG)
        await real(op, *a, **kw)
        return {"posts": [{"n": 4, "kind": "text", "url": "u", "excerpt": "x"}], "next": 4}
    e.core.exchange.request = request
    with pytest.raises(ServerError):
        asyncio.run(e.core.fetch_feed(3))
    assert e.store.get("feed_cursor") == 3 and calls == ["feed.get", "feed.get"]


def test_fetch_feed_default_page_limit(tmp_path):
    """Сервер всё время говорит «есть ещё»: за один вызов читается не больше пяти страниц."""
    e = Env(tmp_path)
    seen = []

    async def request(op, auth_mode, auth_key, *, body=None, **kw):
        seen.append(body["since"])
        return {"posts": [], "next": body["since"] + 1}
    e.core.exchange.request = request
    _, cursor = asyncio.run(e.core.fetch_feed(0))
    assert seen == [0, 1, 2, 3, 4] and cursor == 5


def test_result_without_url_is_stored_as_empty_string(tmp_path):
    """Сервер не обязан присылать url: пост всё равно запоминается (с пустой ссылкой), а не с None или заглушкой."""
    e = Env(tmp_path)

    async def request(op, auth_mode, auth_key, *, journal=None, **kw):
        if journal:
            journal({"op": op, "id": "01JA00000000000000000000F1", "auth_mode": auth_mode})
        return {"n": 31}
    e.core.exchange.request = request
    asyncio.run(e.core.create_post(api.Draft(e.ui.owner, msgs(), anonymous=True)))
    assert e.store.db.execute("SELECT url FROM my_posts WHERE n = 31").fetchone() == ("",)
    e.store.save_pending_post("01JA00000000000000000000F2", bytes([2]) * 32, "text",
                              {"id": "x", "auth_mode": "ephemeral"})
    e.server.resume = lambda *a, **kw: _result({"n": 32})
    assert asyncio.run(e.core.resume_pending()) == [("published", {"n": 32})]
    assert e.store.db.execute("SELECT url FROM my_posts WHERE n = 32").fetchone() == ("",)


async def _result(value):
    return value


def test_fetch_feed_requests_and_paging(tmp_path):
    """Лента — бесплатный запрос без личности; страницы читаются по next, пока он не пуст."""
    e = Env(tmp_path)
    seen = []

    async def request(op, auth_mode, auth_key, *, body=None, **kw):
        seen.append((op, auth_mode, body, kw))
        n = len(seen)
        return {"posts": [{"n": 10 * n}], "next": 10 * n + 5 if n < 3 else None}
    e.core.exchange.request = request
    posts, cursor = asyncio.run(e.core.fetch_feed(2))
    assert [(o, m, b) for o, m, b, _ in seen] == [("feed.get", "ephemeral", {"since": s}) for s in (2, 15, 25)]
    assert all("token" not in kw for *_, kw in seen)
    assert [p["n"] for p in posts] == [10, 20, 30] and cursor == 30
    seen.clear()
    asyncio.run(e.core.fetch_feed(2, pages=2))
    assert len(seen) == 2


# --- что именно уходит серверу ---
def _spy(e):
    sent = []
    real = e.server.request

    async def request(op, auth_mode, auth_key, **kw):
        sent.append((op, auth_mode, bytes(auth_key.verify_key), kw))
        return await real(op, auth_mode, auth_key, **kw)
    e.core.exchange.request = request
    return sent


def test_create_post_request_and_records(tmp_path):
    from veil.core.crypto import keys as ckeys
    e = Env(tmp_path)
    sent = _spy(e)
    inflight = []
    asyncio.run(e.core.create_post(api.Draft(e.ui.owner, msgs("привет"), anonymous=True),
                                   on_journal=lambda: inflight.append(set(e.core._inflight))))
    [(op, mode, auth_pk, kw)] = sent
    [(n, secret, url, kind)] = e.store.db.execute("SELECT n, post_secret, url, kind FROM my_posts").fetchall()
    post_pk = b64.enc(bytes(ckeys.post_signing_key(secret).verify_key))
    assert (op, mode) == ("post.create", "ephemeral") and kw["body"]["post_pk"] == post_pk
    assert auth_pk == bytes(ckeys.journal_keys(secret)[0].verify_key)
    assert kw["content"] and callable(kw["deliver"]) and callable(kw["journal"]) and kw["resp_sk"] is not None
    assert url == f"https://t.me/c/1/{n}" and kind == "text"
    assert len(inflight) == 1 and len(inflight[0]) == 1 and e.core._inflight == set()
    assert e.store.pending_posts() == []


def test_create_post_signed_uses_device_key(tmp_path):
    e = Env(tmp_path, identity=True)
    asyncio.run(e.core.sync_device())
    e.server.registered[e.store.load_device().dev_pk]["nick"] = "Роза"
    asyncio.run(e.core.sync_device(force=True))
    sent = _spy(e)
    asyncio.run(e.core.create_post(api.Draft(e.ui.owner, msgs(), reply_to=7)))
    [(op, mode, auth_pk, kw)] = [s for s in sent if s[0] == "post.create"]
    assert mode == "identity" and auth_pk == e.store.load_device().dev_pk and kw["body"]["reply_to"] == 7


def test_pending_without_accepted_flag_is_queued_with_kind(tmp_path):
    """E_PENDING как итог (без признака «принято»): пост в очереди, запись журнала остаётся с видом поста."""
    e = Env(tmp_path)
    e.server.fail("post.create", "E_PENDING")
    with pytest.raises(api.PostQueuedError):
        asyncio.run(e.core.create_post(api.Draft(e.ui.owner, msgs(), anonymous=True)))
    [(_, _, kind, _, _)] = e.store.pending_posts()
    assert kind == "text" and statuses(e) == {"spent": 1, "ready": 9}


def test_device_reset_resyncs_forced(tmp_path):
    e = Env(tmp_path, identity=True)
    asyncio.run(e.core.sync_device())
    e.server.registered[e.store.load_device().dev_pk]["nick"] = "Роза"
    asyncio.run(e.core.sync_device(force=True))
    calls = []
    real = e.core.sync_device

    async def sync(**kw):
        calls.append(kw)
        return await real(**kw)
    e.core.sync_device = sync
    e.server.fail("post.create", "E_DEVICE")
    asyncio.run(e.core.create_post(api.Draft(e.ui.owner, msgs())))
    assert calls and calls[-1].get("force") is True
    assert len(ops(e, "post.create")) == 2


def test_edit_delete_nick_requests(tmp_path):
    from veil.core.crypto import keys as ckeys
    e = Env(tmp_path, identity=True)
    secret = bytes([5]) * 32
    e.store.add_post(5, secret, "", "text")
    post_pk = bytes(ckeys.post_signing_key(secret).verify_key)
    sent = _spy(e)
    asyncio.run(e.core.edit_post(api.Draft(e.ui.owner, msgs("UPD"), mode="append", target=5)))
    [(op, mode, auth_pk, kw)] = sent
    assert (op, mode, auth_pk) == ("post.edit", "post_secret", post_pk)
    assert kw["body"] == {"n": 5, "mode": "append"} and kw["content"] and callable(kw["deliver"])
    sent.clear()
    asyncio.run(e.core.delete_post(5))
    [(op, mode, auth_pk, kw)] = sent
    assert (op, mode, auth_pk, kw["body"]) == ("post.delete", "post_secret", post_pk, {"n": 5})
    sent.clear()
    asyncio.run(e.core.set_nick("Роза"))
    [(op, mode, auth_pk, kw)] = [s for s in sent if s[0] == "nick.set"]
    assert (op, mode, auth_pk, kw["body"]) == ("nick.set", "identity", e.store.load_device().dev_pk, {"nick": "Роза"})


# --- обмен на уровне настоящего Exchange: подписанная ошибка и ответ ровно на пределе ---
@pytest.fixture
def fast(monkeypatch):
    async def quick(s):
        await REAL_SLEEP(0)
    monkeypatch.setattr(exmod.asyncio, "sleep", quick)
    monkeypatch.setattr(exmod, "WAIT", 0.02)


def test_exchange_too_large_is_final_one_envelope(fast):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), error={"code": BIG}), 101)
        with pytest.raises(ServerError) as ei:
            await asyncio.wait_for(t, 2)
        await REAL_SLEEP(0.05)
        return ei.value
    err = asyncio.run(go())
    assert err.code == BIG and not err.accepted and not err.hint
    assert len(r.wire.sent) == 1, "конверт не повторяется"


def test_exchange_too_large_after_pending_is_accepted_same_id(fast):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        r.feed(r.sealed(r.env(), error={"code": "E_PENDING", "retry_after": 0}), 101)
        await r.sent(2)
        first_id = r.env(0)["id"]
        assert r.env(1)["id"] == first_id
        r.feed(r.sealed(r.env(), error={"code": BIG}), 102)
        with pytest.raises(ServerError) as ei:
            await asyncio.wait_for(t, 2)
        await REAL_SLEEP(0.05)
        return ei.value
    err = asyncio.run(go())
    assert err.code == BIG and err.accepted
    assert len(r.wire.sent) == 2


def _resp_with_pad(r: Rig, env: dict, delta: int):
    base = envelope.build_response(env["id"], r.server, result={"pad": ""})
    n = envelope.MAX_RESPONSE - len(jcs.canonicalize(base)) + delta
    # подпись ответа не зависит от длины, но входит в размер: пересчитываем после подбора
    return envelope.build_response(env["id"], r.server, result={"pad": "a" * n})


def test_exchange_response_exactly_at_limit_arrives_in_16_parts(fast):
    r = Rig()

    async def go():
        t = req(r)
        await r.sent(1)
        env = r.env()
        resp = _resp_with_pad(r, env, 0)
        assert len(jcs.canonicalize(resp)) == envelope.MAX_RESPONSE == 47951
        parts = envelope.split_response(envelope.seal_response(resp, b64.dec(env["resp_pk"])))
        assert len(parts) == 16 and all(len(p) <= 4096 for p in parts)
        for p in reversed(parts):
            r.feed(p, 101)
        return await asyncio.wait_for(t, 2), resp
    got, resp = asyncio.run(go())
    assert got == resp["result"]


def test_response_one_byte_over_limit_is_not_sealable():
    r = Rig()
    env = {"id": envelope.new_ulid()}
    resp = _resp_with_pad(r, env, 1)
    assert len(jcs.canonicalize(resp)) == envelope.MAX_RESPONSE + 1
    with pytest.raises(ValueError):
        envelope.seal_response(resp, bytes(SigningKey.generate().verify_key))
    # и у настоящей границы: на байт меньше — запечатывается
    envelope.seal_response(_resp_with_pad(r, env, 0), bytes(SigningKey.generate().verify_key)[:32])
