"""Сквозные сценарии бота: апдейт Telegram → интерфейс → ядро → Bot API (tests/harness.py)."""
import asyncio

import pytest
from harness import OWNER, Env, person

from veil import pool
from veil.core import api
from veil.core.protocol import b64, hidden
from veil.core.transport.exchange import NoReplyError, ServerError
from veil.core.transport.telegram import TelegramError
from veil.ui import bot as uibot


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    async def no_sleep(s):
        pass
    monkeypatch.setattr(uibot, "ALBUM_WAIT", 0)
    monkeypatch.setattr(uibot, "SPLIT_WAIT", 0)
    monkeypatch.setattr(uibot.asyncio, "sleep", no_sleep)


def has(env, fragment):
    return any(fragment in t for t in env.tg.texts())


# --- владелец ---
def test_claim_flow(tmp_path):
    e = Env(tmp_path, owner=0)
    code = e.ui.claim_code()
    assert code and len(code) >= 22 and e.ui.claim_code() == code
    stranger = {"id": 777, "is_bot": False}
    upd = lambda text: {"update_id": 1, "message": {"message_id": 1, "chat": {"id": 777, "type": "private"},  # noqa: E731
                                                  "from": stranger, "text": text}}
    e.route(upd("/start"))
    assert has(e, "владельца")
    e.store.put("b2b_error", True)
    e.route(upd("привет"))
    assert has(e, "Bot-to-Bot")
    for _ in range(5):
        e.route(upd("/start wrongcodewrongcode123"))
    assert has(e, "Код не подошёл")
    e.route(upd(f"/start {code}"))
    assert has(e, "Слишком много") and e.ui.owner == 0  # 5 ошибок — блок даже для верного кода
    e.ui.claim_fails.clear()
    e.route({"update_id": 2, "message": {"message_id": 2, "chat": {"id": 777, "type": "private"},
                                         "from": {"id": 5, "is_bot": True}, "text": f"/start {code}"}})
    assert e.ui.owner == 0  # бот владельцем не становится
    e.route(upd(f"/start {code}"))
    assert e.ui.owner == 777 and e.store.get("owner_id") == 777 and e.store.get("claim_code") is None
    assert has(e, "вы — владелец") and e.ui.claim_code() is None


def test_strangers_and_groups_ignored(tmp_path):
    e = Env(tmp_path)
    e.route({"update_id": 1, "message": {"message_id": 1, "chat": {"id": 5, "type": "private"},
                                         "from": {"id": 5, "is_bot": False}, "text": "/start"}},
            {"update_id": 2, "message": {"message_id": 2, "chat": {"id": -100, "type": "supergroup"},
                                         "from": {"id": OWNER}, "text": "/start"}},
            {"update_id": 3, "callback_query": {"id": "q", "from": {"id": 5}, "data": "tok:req"}},
            {"update_id": 4})
    assert e.tg.calls == []


def test_inbox_messages_go_to_exchange(tmp_path):
    e = Env(tmp_path)
    m = {"message_id": 9, "chat": {"id": 1, "type": "private"}, "from": {"id": 1, "is_bot": True,
                                                                      "username": "inbox_bot"}, "text": "VEIL1R x"}
    e.route({"update_id": 1, "message": m})
    assert e.server.ops == [("inbox_message", m)]


# --- команды ---
def test_simple_commands(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("/help"), e.msg("/cancel"), e.msg("/whatever"), e.msg("/start@test_veil_bot"))
    texts = e.tg.texts()
    assert "Как пользоваться" in texts[0] and texts[1] == "Отменено."
    assert "Не понял. /help" in texts
    assert "публикует ваши сообщения" in texts[-1]


def test_command_with_b2b_off_rechecks_link(tmp_path):
    e = Env(tmp_path)
    e.store.put("b2b_error", True)
    e.server.fail("keys.get", "E_INTERNAL")  # setup не смог — связь всё ещё не проверена, но флаг снимется
    e.route(e.msg("/help"))
    assert "setMyCommands" in e.tg.methods()
    e2 = Env(tmp_path / "b")
    e2.store.put("b2b_error", True)

    async def broken(*a, **kw):
        raise TelegramError("sendMessage", 400, "USER_BOT_TO_BOT_DISABLED")
    e2.server.request = broken
    e2.route(e2.msg("/help"))
    assert has(e2, "не может писать серверу")


def test_tokens_command(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("/tokens"))
    assert has(e, f"{api.today()}: 10") and "tok:give" in e.last_markup_data()
    e0 = Env(tmp_path / "z", tokens=0)
    e0.route(e0.msg("/tokens"))
    assert has(e0, "Токенов нет") and "tok:give" not in e0.last_markup_data()


def test_nick_set_and_remove(tmp_path):
    e = Env(tmp_path, identity=True)
    e.route(e.msg("/nick Роза"))
    assert has(e, "Роза") and e.store.get("nick") == "Роза"
    assert ("device.set", ) == tuple(op for op, _ in e.server.ops if op == "device.set")[:1]  # устройство — сначала
    e.route(e.msg("/nick -"))
    assert any(op == "nick.set" and b == {"nick": None} for op, b in e.server.ops)
    e.route(e.msg("/nick a"))  # слишком короткий: отказ до траты токена
    assert has(e, "Ник не подходит")
    e_no = Env(tmp_path / "noid")
    e_no.route(e_no.msg("/nick Роза"))
    assert has(e_no, "Личности ещё нет")


def test_nick_from_menu_never_removes(tmp_path):
    """/nick из меню Telegram уходит без аргумента: раньше это убирало ник (токен и сутки до смены). Теперь — кнопки:
    задать (вопрос, ответ следующим сообщением), сменить, убрать — только с подтверждением."""
    e = Env(tmp_path, identity=True)
    e.route(e.msg("/nick"))
    assert not any(op == "nick.set" for op, _ in e.server.ops) and has(e, "Ника нет")
    assert e.last_markup_data() == ["nk:set"]
    e.route(e.press("nk:set"))
    assert has(e, "Пришлите ник")
    e.route(e.msg("Роза"))
    assert e.store.get("nick") == "Роза" and not has(e, "Черновик")  # ответ — ник, а не пост
    e.route(e.msg("/nick"))
    assert has(e, "Ваш ник: Роза") and e.last_markup_data() == ["nk:set", "nk:rm"]
    sets = sum(op == "nick.set" for op, _ in e.server.ops)
    e.route(e.press("nk:rm"))
    assert has(e, "Убрать ник?") and sum(op == "nick.set" for op, _ in e.server.ops) == sets  # ещё не убран
    e.route(e.press("aw:x"))
    assert e.store.get("nick") == "Роза"
    e.route(e.press("nk:rm"), e.press("nk:rm!"))
    assert any(op == "nick.set" and b == {"nick": None} for op, b in e.server.ops)


def test_export_key_without_command(tmp_path):
    """Ключ VEILIMP присылают обычным сообщением: набирать /export с аргументом не нужно."""
    e = Env(tmp_path, identity=True)
    e2 = Env(tmp_path / "dst")
    e2.route(e2.msg("/import"))
    key = e2.tg.texts()[-1]
    e.route(e.msg("/export"))
    assert has(e, "обычным сообщением")
    e.route(e.msg(key))
    assert "ex:ok" in e.last_markup_data() and not has(e, "Черновик")


# --- черновик и публикация ---
def test_draft_send_publishes(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("Привет, мир"))
    i = e.draft_id()
    assert e.server.ops[-1][0] == "post.check"
    e.route(e.press(f"d:{i}:send", msg_id=55))
    assert has(e, "Опубликовано: №101") and e.store.draft(i) is None
    assert e.store.token_counts()[api.today()] == 9 and e.store.post_secret(101)
    assert "sendMessage" in e.tg.methods()  # контент доставлен приёмному боту


def test_draft_send_blocked_without_tokens(tmp_path):
    e = Env(tmp_path, tokens=0)
    e.route(e.msg("пост"))
    i = e.draft_id()
    e.route(e.press(f"d:{i}:send"))
    assert has(e, "токенов на сегодня нет") and e.store.draft(i) is not None
    assert not any(op == "post.create" for op, _ in e.server.ops)


def test_draft_cancel_and_stale_button(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("пост"))
    i = e.draft_id()
    e.route(e.press(f"d:{i}:x"))
    assert e.store.draft(i) is None and has(e, "Отмен")
    n = len(e.tg.calls)
    e.route(e.press(f"d:{i}:send"))  # кнопка удалённого черновика — ничего
    assert [m for m, _ in e.tg.calls[n:]] == ["answerCallbackQuery"]


def test_hide_modes_and_anon(tmp_path):
    e = Env(tmp_path, identity=True)
    e.store.put("nick", "Роза")
    e.route(e.msg("смотри https://example.com",
                  entities=[{"type": "url", "offset": 7, "length": 19}]))
    i = e.draft_id()
    assert f"d:{i}:hl" in e.last_markup_data() and f"d:{i}:anon" in e.last_markup_data()
    e.route(e.press(f"d:{i}:hl"))
    assert api.Draft.from_json(e.store.draft(i)).hide == "links"
    e.route(e.press(f"d:{i}:hm"))
    assert api.Draft.from_json(e.store.draft(i)).hide == "message"
    e.route(e.press(f"d:{i}:h0"))
    assert api.Draft.from_json(e.store.draft(i)).hide == ""
    e.route(e.press(f"d:{i}:anon"))
    assert api.Draft.from_json(e.store.draft(i)).anonymous is True
    assert has(e, "анонимно")


def test_draft_problem_too_long(tmp_path):
    e = Env(tmp_path)
    e.server.overflow = 12
    e.route(e.msg("длинный"))
    assert has(e, "12") and not any(d.endswith(":send") for d in e.last_markup_data())


def test_check_draft_server_problems(tmp_path):
    e = Env(tmp_path)
    e.server.fail("post.check", "E_UNSUPPORTED")
    e.route(e.msg("x"))
    assert has(e, "Так скрыть это сообщение нельзя")
    e.server.fail("post.check", "E_RATE")
    e.route(e.msg("y"))  # сервер занят — проверит при отправке, кнопка есть
    assert any(d.endswith(":send") for d in e.last_markup_data())

    async def silent(*a, **kw):
        raise NoReplyError("post.check")
    e.server.request = silent
    e.route(e.msg("z"))
    assert any(d.endswith(":send") for d in e.last_markup_data())


# --- «лично для» ---
def test_private_recipient_flow(tmp_path):
    e = Env(tmp_path)
    rose, rec = person("Роза")
    e.server.people = [rec]
    e.route(e.msg("секрет"))
    i = e.draft_id()
    e.route(e.press(f"d:{i}:hto", msg_id=70))
    assert e.store.get("await")["what"] == "to_nick"
    e.route(e.msg(f"Роза·{rose.tag}"))
    d = api.Draft.from_json(e.store.draft(i))
    assert d.hide == "to" and d.to_label == f"Роза·{rose.tag}" and d.to_pk == b64.enc(rose.current.pk)
    assert e.core.known_recipient(f"Роза·{rose.tag}") == b64.enc(rose.id_pk)
    assert "deleteMessage" in e.tg.methods()  # старый черновик и вопрос «Кому?» убраны


def test_private_recipient_errors(tmp_path):
    e = Env(tmp_path)
    rose, rec = person("Роза")
    e.route(e.msg("секрет"))
    i = e.draft_id()

    def ask(text):
        e.route(e.press(f"d:{i}:hto"), e.msg(text))
    ask("без метки")
    assert has(e, "Не понял ник")
    ask(f"Роза·{rose.tag}")  # не найден
    assert has(e, "Такого ника с этой меткой нет")
    forged = dict(rec, dev_sig=b64.enc(bytes(64)))
    e.server.people = [forged]
    ask(f"Роза·{rose.tag}")
    assert has(e, "не подписаны этим человеком")
    _, rec2 = person("Роза")
    e.server.people = [rec, dict(rec2, nick="Роза")]
    e.server.people[1] = rec  # одна и та же — один ответ; две разные проверенные — неоднозначность
    e.server.people = [rec, dict(rec2, nick="Роза", id_pk=rec2["id_pk"])]
    real_tag = e.core.tag_of
    e.core.tag_of = lambda pk: rose.tag  # «двойник» с той же меткой: две проверенные записи — отказ выбирать
    ask(f"Роза·{rose.tag}")
    assert has(e, "несколько человек")
    e.core.tag_of = real_tag
    e.server.fail("nick.lookup", "E_RATE")
    ask(f"Роза·{rose.tag}")
    assert has(e, "Подождите")


def test_recipient_changed_asks_trust(tmp_path):
    e = Env(tmp_path)
    rose, rec = person("Роза")
    twin, _ = person("Роза")
    e.core.remember_recipient(f"Роза·{rose.tag}", b64.enc(twin.id_pk))  # раньше под этим ником был другой ключ
    e.server.people = [rec]
    e.route(e.msg("секрет"))
    i = e.draft_id()
    e.route(e.press(f"d:{i}:hto"), e.msg(f"Роза·{rose.tag}"))
    assert e.store.get("pending_recipient") and has(e, "другая личность")
    e.route(e.press("tn:no"))
    assert e.store.get("pending_recipient") is None and api.Draft.from_json(e.store.draft(i)).hide == ""
    e.route(e.press(f"d:{i}:hto"), e.msg(f"Роза·{rose.tag}"), e.press("tn:yes"))
    assert api.Draft.from_json(e.store.draft(i)).hide == "to"


# --- меню поста ---
def test_post_menu_and_actions(tmp_path):
    e = Env(tmp_path)
    e.store.add_post(5, bytes([5]) * 32, "", "text")
    fwd = e.forwarded_post
    e.route(fwd(5))
    assert {"p:5:append", "p:5:replace", "p:5:del", "p:5:reply", "p:5:none"} <= set(e.last_markup_data())
    e.route(fwd(6))
    assert e.last_markup_data() == ["p:6:reply", "p:6:none"]
    # ответ
    e.route(e.press("p:6:reply"), e.msg("мой ответ"))
    d = api.Draft.from_json(e.store.draft(e.draft_id()))
    assert d.reply_to == 6
    # UPD
    e.route(e.press("p:5:append"), e.msg("дополнение"))
    assert has(e, "№5") and any(op == "post.edit" and b == {"n": 5, "mode": "append"} for op, b in e.server.ops)
    # исправить не текстом
    e.route(e.press("p:5:replace"), e.msg(None, photo=[{"file_id": "p", "file_unique_id": "u"}]))
    assert has(e, "пришлите текст")
    # удалить
    e.route(e.press("p:5:del"))
    assert "p:5:delok" in e.last_markup_data()
    e.route(e.press("p:5:none"), e.press("p:5:delok"))
    assert has(e, "удалён") and e.store.post_secret(5) is None


def test_delete_partly_and_not_mine(tmp_path):
    e = Env(tmp_path)
    e.store.add_post(7, bytes([7]) * 32, "", "voice")
    real = e.server.request

    async def left(op, *a, **kw):
        r = await real(op, *a, **kw)
        return dict(r, left=1) if op == "post.delete" else r
    e.server.request = left
    e.route(e.press("p:7:delok"))
    assert has(e, "не полностью")
    e.route(e.press("p:99:delok"))  # чужой пост: секрета нет
    assert has(e, "Это не ваш пост")


# --- ошибки сервера в _run ---
@pytest.mark.parametrize("code,expect", [("E_TOO_LONG", "7"), ("E_RATE", "Подождите"),
                                         ("E_WHATEVER", "Действие не выполнено"),
                                         ("E_NOT_OWNER", "не ваш пост")])
def test_server_errors_explained(tmp_path, code, expect):
    e = Env(tmp_path)
    e.store.add_post(5, bytes([5]) * 32, "", "text")
    e.server.fail("post.delete", code, overflow=7, retry_after=30)
    e.route(e.press("p:5:delok"))
    assert has(e, expect)
    assert e.store.token_counts()[api.today()] == 10  # токен вернулся


def test_run_other_failures(tmp_path):
    e = Env(tmp_path)

    async def boom(exc):
        raise exc
    cases = [(NoReplyError("x"), "не ответил"), (api.PostQueuedError(), "в очереди"),
             (api.NotMineError(3), "не ваш пост"),
             (api.NoIdentityError(), "Личности ещё нет"), (api.DeviceRevokedError(), "восстановлена"),
             (api.OtherBotError(), "привязана к другому боту"),
             (ValueError("envelope too large: 1"), "слишком большое"),
             (ValueError("other"), "Внутренняя ошибка"), (RuntimeError("bug"), "Внутренняя ошибка")]
    for exc, frag in cases:
        e.run(e.ui._run(lambda exc=exc: boom(exc), lambda r: "ok"))
        assert any(frag.lower() in t.lower() for t in e.tg.texts()[-1:]), (exc, e.tg.texts()[-1])
    refreshed = []

    async def refresh():
        refreshed.append(True)
    e.core.refresh_keys = refresh
    e.run(e.ui._run(lambda: boom(ServerError("E_DECRYPT", hint=True)), lambda r: "ok"))
    assert refreshed == [True] and has(e, "Ключи сервера обновились")


def test_send_with_delay_and_status_edit(tmp_path):
    e = Env(tmp_path, delay=(5, 5))
    e.route(e.msg("пост"))
    i = e.draft_id()
    e.route(e.press(f"d:{i}:send", msg_id=55))
    texts = e.tg.texts()
    assert any(t.startswith("Отправлю через 5 с") for t in texts) and has(e, "Опубликовано")


# --- альбом и длинный текст ---
def test_album_becomes_one_draft(tmp_path):
    e = Env(tmp_path)
    a = e.msg(None, media_group_id="g1", photo=[{"file_id": "a", "file_unique_id": "ua"}], caption="подпись")
    b = e.msg(None, media_group_id="g1", photo=[{"file_id": "b", "file_unique_id": "ub"}])

    async def go():
        e.ui._route(a)
        e.ui._route(b)
        await e.drain()
    asyncio.run(go())
    d = api.Draft.from_json(e.store.draft(e.draft_id()))
    assert len(d.messages) == 2


def test_long_text_split_by_telegram_joined(tmp_path):
    e = Env(tmp_path)
    first = e.msg("я" * 4000)
    second = e.msg("хвост")

    async def go():
        e.ui._route(first)
        e.ui._route(second)
        await e.drain()
    asyncio.run(go())
    d = api.Draft.from_json(e.store.draft(e.draft_id()))
    assert [m["text"][:2] for m in d.messages] == ["яя", "хв"]
    single = Env(tmp_path / "s")
    single.route(single.msg("я" * 4000))
    assert len(api.Draft.from_json(single.store.draft(single.draft_id())).messages) == 1


# --- токены ---
def test_top_up_and_full(tmp_path):
    e = Env(tmp_path, tokens=0)
    e.route(e.press("tok:req"))
    reqs = [t for t in e.tg.texts() if t.startswith("VEILREQ ")]
    assert reqs and has(e, "@issuer_bot")
    e.store.put("issuer_mismatch", True)
    e.route(e.press("tok:req"))
    assert has(e, "другой ключ эмитента")
    full = Env(tmp_path / "f", tokens=0)
    from datetime import datetime, timedelta, timezone

    from veil.core.wallet.issue import Token
    start = datetime.now(timezone.utc).date()
    kid = full.store.get("pinned_issuer")["kid"]
    full.store.add_tokens([Token(kid, (start + timedelta(days=d)).isoformat(), bytes([d, i]) + bytes(30), bytes(64))
                           for d in range(api.DAYS_AHEAD) for i in range(api.TOKENS_PER_DAY)])
    full.route(full.press("tok:req"))
    assert has(full, "уже есть")


def test_token_parts_from_owner(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("VEILRES 0123456789abcdef 1/2 AAAA"))
    assert has(e, "другого бота")
    e.route(e.msg("VEILRES garbage"))
    assert has(e, "Не удалось принять")
    e.route(e.msg("VEILTOK zz"))
    assert has(e, "переданные токены")
    e.route(e.press("tok:give"))
    assert "tok:give:10" in e.last_markup_data()
    e0 = Env(tmp_path / "z", tokens=0)
    e0.route(e0.press("tok:give"), e0.press("tok:give:5"))
    assert has(e0, "передавать нечего")


# --- пул ---
def test_pool_commands_and_buttons(tmp_path):
    left = []

    async def leave():
        left.append(True)
    feed = []

    async def feed_now():
        feed.append(True)
    e = Env(tmp_path, pool={"identity": "words_once", "leave": leave, "feed_now": feed_now,
                            "create_identity": pool.create_identity})
    e.route(e.msg("/start"))
    assert "id:new" in e.last_markup_data() and has(e, "оператор") and feed
    e.route(e.msg("/leave"))
    assert e.last_markup_data() == ["pool:leave", "pool:stay"]
    e.route(e.press("pool:stay"))
    assert not left
    e.route(e.press("pool:leave"))
    assert left == [True]
    e.route(e.press("id:new", msg_id=3))
    assert e.store.load_device() is not None and e.store.get("words_msg")
    e.route(e.press("id:ok"))
    assert e.store.get("words_msg") is None
    e.route(e.press("id:new", msg_id=3))  # личность уже есть — ничего нового
    assert has(e, "Бот Veil готов")


def test_pool_table_without_pool_action_creates_no_identity(tmp_path):
    """Таблица [pool] в конфиге бота вне пула (нет create_identity) личность и слова в Telegram не открывает."""
    e = Env(tmp_path, pool={"identity": "words_once"})
    e.route(e.press("id:new", msg_id=3))
    assert e.store.load_device() is None and e.store.get("words_msg") is None
    assert has(e, e.ui.T("text.need_identity", config="config.toml"))
    assert not any("protect_content" in kw for _, kw in e.tg.calls)  # сообщения со словами не отправлялись


def test_leave_only_in_pool(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("/leave"))
    assert has(e, "Не понял. /help")


# --- служебное: setup, личность, лента, циклы ---
def test_setup_registers_device(tmp_path):
    e = Env(tmp_path, identity=True)
    e.run(e.ui.setup())
    assert "setMyCommands" in e.tg.methods() and e.store.get("b2b_error") is None
    assert any(op == "device.set" for op, _ in e.server.ops)
    e.run(e.ui.setup())  # второй раз — устройство уже известно серверу
    assert sum(op == "device.set" for op, _ in e.server.ops) == 1


@pytest.mark.parametrize("code,frag", [("E_STALE", "восстановлена"), ("E_BOT_NOT_BOUND", "другому боту")])
def test_identity_problems_reported_once(tmp_path, code, frag):
    e = Env(tmp_path, identity=True)
    e.server.fail("device.set", code, times=3)
    e.run(e.ui._sync_identity(quiet=True))
    e.run(e.ui._sync_identity(quiet=True))
    assert sum(frag in t for t in e.tg.texts()) == 1


def test_identity_needs_token(tmp_path):
    e = Env(tmp_path, identity=True, tokens=0)
    e.run(e.ui._sync_identity())
    assert has(e, "зарегистрировать")


def test_setup_survives_telegram_errors(tmp_path):
    e = Env(tmp_path)
    e.tg.fail["setMyCommands"] = (400, "bad")

    async def tg_fail(*a, **kw):
        raise TelegramError("sendMessage", 400, "USER_BOT_TO_BOT_DISABLED")
    e.server.request = tg_fail
    e.run(e.ui.setup())
    assert e.store.get("b2b_error") is True


def test_feed_events_delivered(tmp_path):
    e = Env(tmp_path, identity=True)
    e.store.add_post(5, bytes([5]) * 32, "", "text")
    me = e.store.load_device()
    pk7 = b64.enc(bytes([7]) * 32)
    blob = hidden.seal_to(hidden.padded(hidden.payload("лично тебе", [{"type": "bold", "offset": 0, "length": 5}],
                                                       post_pk=pk7)), me.current.pk)
    e.server.feed = [{"n": 6, "reply_to": 5, "url": "u6", "excerpt": "ответ"},
                     {"n": 7, "hidden_for": b64.enc(me.current.pk), "hidden_blob": b64.enc(blob), "url": "u7",
                      "post_pk": pk7, "nick": "Аня", "tag": "k2m9xq"},
                     {"n": 8, "hidden_for": b64.enc(me.current.pk), "hidden_blob": "AAAA", "url": "u8", "post_pk": pk7},
                     {"n": 9, "hidden_for": b64.enc(me.current.pk), "hidden_blob": b64.enc(blob), "url": "u9",
                      "post_pk": b64.enc(bytes([9]) * 32)}]  # тот же blob в чужом посте — не доставляется
    e.route(e.msg("/sync"))
    assert has(e, "№6") and has(e, "лично тебе") and e.store.get("feed_cursor") == 9
    sent = [p for m, p in e.tg.calls if m == "sendMessage" and "лично тебе" in p.get("text", "")]
    assert len(sent) == 1 and sent[0]["entities"][0]["type"] == "bold" and "от Аня·k2m9xq" in sent[0]["text"]


def test_deliver_private_files(tmp_path):
    """Файлы «лично для» прислал другой человек: бот предлагает кнопку, а не выгружает их сам; по кнопке — тем же
    видом, с безопасными именем и MIME."""
    e = Env(tmp_path)
    F = api.HiddenFile
    ev = api.FeedEvent("hidden", 9, None, "u", "", [], "", 2)
    e.run(e.ui._deliver_private(ev))
    assert e.tg.methods() == ["sendMessage"] and e.last_markup_data() == ["pf:9"] and has(e, "автора без подписи")
    files = {9: [F("photo", "a.jpg", "image/jpeg", b"1"), F("video", "b.mp4", "video/mp4", b"2")],
             10: [F("voice", "v\r\n.ogg", "audio/ogg\r\nX-Evil: 1", b"3")]}

    async def private_files(n):
        if n not in files:
            raise KeyError(n)
        if n == 11:
            raise ValueError("bad container")
        return files.pop(n)
    e.core.private_files = private_files
    e.route(e.press("pf:9"))
    assert "sendMediaGroup" in e.tg.methods() and "editMessageReplyMarkup" in e.tg.methods()
    e.tg.fail["sendVoice"] = (400, "bad")
    e.route(e.press("pf:10"))
    assert e.tg.methods()[-1] == "sendDocument"  # не принял как голосовое — уходит файлом
    # Имя и MIME от отправителя — без переводов строк: в части multipart не появляется чужой заголовок.
    assert e.tg.calls[-1][1]["_files"] == [("document", "v_.ogg", "audio/ogg")]
    assert b"X-Evil" not in e.tg.calls[-1][1]["_raw"]
    e.route(e.press("pf:10"))  # повторное нажатие: файлы уже присланы
    assert has(e, "уже не помнит")
    files[11] = []
    e.route(e.press("pf:11"))
    assert has(e, "Файлы к этому")


def test_background_loops_one_turn(tmp_path, monkeypatch):
    class Stop(Exception):
        pass
    n = {"i": 0}

    async def sleep_once(s):
        n["i"] += 1
        if n["i"] > 1:
            raise Stop
    monkeypatch.setattr(uibot.asyncio, "sleep", sleep_once)
    e = Env(tmp_path, identity=True)
    for loop in (e.ui._feed_loop(60), e.ui._daily_loop(), e.ui._wipe_loop()):
        n["i"] = 0
        with pytest.raises(Stop):
            asyncio.run(loop)
    e.store.put("b2b_error", True)
    n["i"] = 0
    with pytest.raises(Stop):
        asyncio.run(e.ui._feed_loop(60))


def test_run_loop_routes_updates(tmp_path):
    e = Env(tmp_path)
    e.tg.updates = [[e.msg("/help")]]
    e.tg.fail = {}
    calls = {"n": 0}
    real = e.bot.get_updates

    async def get_updates(offset, timeout=50, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise TelegramError("getUpdates", 502, "Bad Gateway")
        if calls["n"] > 3:
            raise asyncio.CancelledError
        return await real(offset, timeout, **kw)
    e.bot.get_updates = get_updates
    async def idle(*a):
        pass
    for name in ("setup", "_feed_loop", "_daily_loop", "_resume_scheduled", "_wipe_loop"):
        setattr(e.ui, name, idle)  # фоновые циклы проверяются отдельно (test_background_loops_one_turn)
    with pytest.raises(asyncio.CancelledError):
        e.run(e.ui.run())
    assert has(e, "Как пользоваться")


def test_texts_and_helpers():
    T = uibot.Texts(uibot.Path(__file__).resolve().parent.parent / "locales" / "ru.toml",
                    {"button.send": "Опубликовать"})
    assert T("button.send") == "Опубликовать" and T.has("text.help") and not T.has("text.nope")
    assert T("text.too_long", n="{__class__}") .count("{__class__}") == 1  # подстановка без format
    with pytest.raises(KeyError):
        uibot.Texts(uibot.Path(__file__).resolve().parent.parent / "locales" / "ru.toml", {"no.such": "x"})
    assert uibot.human_wait(40) == "40 с" and uibot.human_wait(300) == "5 мин"
    assert uibot.human_wait(3 * 3600) == "3 ч" and uibot.human_wait(3 * 3600 + 1200) == "3 ч 20 мин"


def test_export_and_import_commands(tmp_path):
    e = Env(tmp_path, identity=True)
    e.route(e.msg("/export"))
    assert has(e, "VEILIMP")
    e.route(e.msg("/export VEILIMP bad"))
    assert has(e, "Экспорт не сделан")
    e2 = Env(tmp_path / "dst")
    e2.route(e2.msg("/import"))
    key = e2.tg.texts()[-1]
    e.route(e.msg(f"/export {key}"))
    assert not [p for m, p in e.tg.calls if m == "sendDocument"] and "ex:ok" in e.last_markup_data()
    e.route(e.press("ex:ok"))
    doc = [p for m, p in e.tg.calls if m == "sendDocument"]
    assert doc and doc[-1].get("caption", "").startswith("Файл экспорта")
    assert e.store.get("wipe_at")
    # файл приходит документом
    e2.tg.files["F"] = b"VEILX1\x09junk"
    e2.route(e2.msg(None, document={"file_id": "F", "file_size": 10}))
    assert has(e2, "Импорт не сделан")


# --- «Отмена» везде, где бот задаёт вопрос или ждёт сообщение ---
@pytest.mark.parametrize("mine", [True, False])
def test_post_menu_cancel(tmp_path, mine):
    """Пересланный пост, свой и чужой: «Отмена» закрывает меню, ничего не ждём и не меняем."""
    e = Env(tmp_path)
    if mine:
        e.store.add_post(5, bytes([5]) * 32, "", "text")
    e.route(e.forwarded_post(5))
    assert "p:5:none" in e.last_markup_data()
    e.route(e.press("p:5:none", msg_id=77))
    assert e.tg.calls[-1][0] == "editMessageText" and e.tg.calls[-1][1]["text"] == "Отменено."
    assert e.store.get("await") is None and not e.server.ops


@pytest.mark.parametrize("action", ["reply", "append", "replace"])
def test_wait_after_post_menu_cancel(tmp_path, action):
    """После «Ответить»/«UPD»/«Исправить» бот ждёт сообщение — «Отмена» снимает ожидание: следующее сообщение
    становится обычным черновиком, а не ответом или правкой."""
    e = Env(tmp_path)
    e.store.add_post(5, bytes([5]) * 32, "", "text")
    e.route(e.press(f"p:5:{action}"))
    st = e.store.get("await")
    assert st["what"] == action and "aw:x" in e.last_markup_data()
    e.route(e.press("aw:x", msg_id=st["ask"]))
    assert e.store.get("await") is None and has(e, "Отменено.")
    e.route(e.msg("просто пост"))
    d = api.Draft.from_json(e.store.draft(e.draft_id()))
    assert d.reply_to is None and not any(op == "post.edit" for op, _ in e.server.ops)


def test_stale_cancel_does_not_drop_newer_wait(tmp_path):
    """Старая кнопка «Отмена» под прошлым вопросом не сбрасывает начатое позже ожидание."""
    e = Env(tmp_path)
    e.store.add_post(5, bytes([5]) * 32, "", "text")
    e.route(e.press("p:5:reply"))
    old = e.store.get("await")["ask"]
    e.route(e.press("p:5:append"))
    e.route(e.press("aw:x", msg_id=old))
    assert e.store.get("await")["what"] == "append"


def test_recipient_question_cancel(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("секрет"))
    i = e.draft_id()
    e.route(e.press(f"d:{i}:hto"))
    st = e.store.get("await")
    assert st["what"] == "to_nick" and "aw:x" in e.last_markup_data()
    e.route(e.press("aw:x", msg_id=st["ask"]))
    assert e.store.get("await") is None and e.store.draft(i) is not None  # черновик остаётся
    e.route(e.msg("Роза·abcdef"))
    assert not any(op == "nick.lookup" for op, _ in e.server.ops)  # это уже новый черновик, не «Кому?»


def test_import_wait_cancel(tmp_path):
    e = Env(tmp_path)
    e.route(e.msg("/import"))
    st = e.store.get("await")
    assert st["what"] == "import" and e.store.get("import_sk")
    e.route(e.press("aw:x", msg_id=st["ask"]))
    assert e.store.get("await") is None and e.store.get("import_sk") is None  # одноразовый ключ забыт


def test_token_give_cancel(tmp_path):
    e = Env(tmp_path)
    before = e.store.token_counts()[api.today()]
    e.route(e.press("tok:give"))
    assert "aw:x" in e.last_markup_data()
    e.route(e.press("aw:x", msg_id=55))
    assert has(e, "Отменено.") and e.store.token_counts()[api.today()] == before
