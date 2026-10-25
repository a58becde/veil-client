"""Секреты в чате (слова, VEILTOK, файл экспорта) удаляются надёжно: сбой удаления не теряет запись; _run_op при 429."""
import asyncio
import logging
import time

from harness import Env

from veil.core.transport.telegram import TelegramError


def scripted(e: Env, outcomes: dict, hook=None):
    """Подмена Bot.delete: outcomes[mid] — True/False или исключение; hook вызывается внутри удаления."""
    calls = []

    async def delete(chat, mid):
        calls.append(mid)
        if hook:
            hook(mid)
        out = outcomes.get(mid, True)
        if isinstance(out, Exception):
            raise out
        return out
    e.bot.delete = delete
    return calls


def net_error() -> TelegramError:
    return TelegramError("deleteMessage", 0, "ConnectError")


def test_wipe_due_keeps_failed_entry_and_goes_on(tmp_path):
    e = Env(tmp_path)
    past = int(time.time()) - 10
    e.store.put("wipe_at", [[1, 10, past], [1, 11, past], [1, 12, past], [1, 13, int(time.time()) + 3600]])
    calls = scripted(e, {10: net_error(), 11: True, 12: False})
    e.run(e.ui.wipe_due())
    assert calls == [10, 11, 12]  # неудача не держит остальные; срок у 13-го не наступил
    left = e.store.get("wipe_at")
    assert [w[1] for w in left] == [10, 13]


def test_wipe_due_everything_done_clears_key(tmp_path):
    e = Env(tmp_path)
    e.store.put("wipe_at", [[1, 10, int(time.time()) - 1]])
    scripted(e, {})
    e.run(e.ui.wipe_due())
    assert e.store.get("wipe_at") is None


def test_wipe_due_retries_on_next_pass(tmp_path):
    e = Env(tmp_path)
    e.store.put("wipe_at", [[1, 10, int(time.time()) - 1]])
    calls = scripted(e, {10: TelegramError("deleteMessage", 429, "x", 5)})
    e.run(e.ui.wipe_due())
    assert e.store.get("wipe_at") and calls == [10]
    scripted(e, {})
    e.run(e.ui.wipe_due())
    assert e.store.get("wipe_at") is None


def test_wipe_due_gives_up_after_deletion_window(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    e = Env(tmp_path)
    now = int(time.time())
    e.store.put("wipe_at", [[1, 10, now - e.ui.WIPE_GIVE_UP - 5], [1, 11, now - e.ui.WIPE_GIVE_UP + 60]])
    scripted(e, {10: net_error(), 11: net_error()})
    e.run(e.ui.wipe_due())
    assert [w[1] for w in e.store.get("wipe_at")] == [11]  # внутри окна — ещё пробуем, старше окна — снято
    assert any(r.levelno == logging.INFO and "giving up" in r.getMessage() for r in caplog.records)


def test_wipe_due_does_not_lose_entry_scheduled_during_pass(tmp_path):
    e = Env(tmp_path)
    past = int(time.time()) - 1
    e.store.put("wipe_at", [[1, 10, past], [1, 11, past]])
    scripted(e, {10: net_error()}, hook=lambda mid: e.ui.schedule_wipe(1, 500 + mid, 3600))
    e.run(e.ui.wipe_due())
    assert sorted(w[1] for w in e.store.get("wipe_at")) == [10, 510, 511]


def test_wipe_due_words_msg_cleared_only_when_entry_removed(tmp_path):
    e = Env(tmp_path)
    e.store.put("wipe_at", [[1, 10, int(time.time()) - 1]])
    e.store.put("words_msg", 10)
    scripted(e, {10: net_error()})
    e.run(e.ui.wipe_due())
    assert e.store.get("words_msg") == 10
    scripted(e, {})
    e.run(e.ui.wipe_due())
    assert e.store.get("words_msg") is None


def test_token_import_failed_delete_schedules_retry_and_goes_on(tmp_path):
    e = Env(tmp_path)
    scripted(e, {55: net_error()})
    m = {"chat": {"id": e.ui.owner}, "message_id": 55, "text": "VEILTOK junk"}
    e.run(e.ui._token_import(m))
    wipe = e.store.get("wipe_at")
    assert wipe and wipe[0][:2] == [e.ui.owner, 55] and wipe[0][2] <= int(time.time())
    assert e.tg.texts()  # импорт продолжился: владелец получил ответ


def test_import_file_failed_delete_schedules_retry_and_goes_on(tmp_path):
    e = Env(tmp_path)
    e.tg.files["F"] = b"VEILX1\x09junk"
    scripted(e, {56: net_error()})
    m = e.msg(None, document={"file_id": "F", "file_size": 10})["message"] | {"message_id": 56}
    e.run(e.ui._import_file(m))
    assert [w[1] for w in e.store.get("wipe_at")] == [56]
    assert any("Импорт не сделан" in t for t in e.tg.texts())


def test_import_file_delete_ok_leaves_no_schedule(tmp_path):
    e = Env(tmp_path)
    e.tg.files["F"] = b"VEILX1\x09junk"
    scripted(e, {})
    m = e.msg(None, document={"file_id": "F", "file_size": 10})["message"]
    e.run(e.ui._import_file(m))
    assert e.store.get("wipe_at") is None


def test_words_confirmed_but_delete_failed_keeps_record_and_says_gone(tmp_path):
    e = Env(tmp_path, pool={"identity": "words_once"})
    e.store.put("words_msg", 77)
    e.store.put("wipe_at", [[e.ui.owner, 77, int(time.time()) + 3000]])
    scripted(e, {77: net_error()})

    async def sync(quiet=False):
        return None
    e.ui._sync_identity = sync
    msg = {"chat": {"id": e.ui.owner}, "message_id": 5}
    e.run(e.ui._pool_identity("id:ok", msg))
    assert [w[1] for w in e.store.get("wipe_at")] == [77]
    assert any(e.ui.T("text.pool_words_gone") in t for t in e.tg.texts())


def test_words_confirmed_and_deleted_drops_record(tmp_path):
    e = Env(tmp_path, pool={"identity": "words_once"})
    e.store.put("words_msg", 77)
    e.store.put("wipe_at", [[e.ui.owner, 77, int(time.time()) + 3000]])
    scripted(e, {})

    async def sync(quiet=False):
        return None
    e.ui._sync_identity = sync
    e.run(e.ui._pool_identity("id:ok", {"chat": {"id": e.ui.owner}, "message_id": 5}))
    assert e.store.get("wipe_at") is None


def test_service_message_cleanup_failure_is_not_fatal(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    e = Env(tmp_path)
    scripted(e, {1: net_error(), 2: TelegramError("deleteMessage", 403, "x")})
    asyncio.run(e.ui._tidy(1, 1))
    asyncio.run(e.ui._tidy(1, 2))
    assert caplog.text.count("delete failed") == 2


# --- _run_op: лимит Telegram ---

def test_run_op_telegram_429_says_wait_and_not_internal(tmp_path):
    e = Env(tmp_path)

    async def op():
        raise TelegramError("sendMessage", 429, "Too Many Requests", 130)
    e.run(e.ui._run(op, lambda r: "ok", None))
    said = e.tg.texts()[-1]
    assert "Telegram просит подождать 2 мин" in said and "токен не потрачен" in said
    assert e.ui.T("text.internal") not in e.tg.texts()


def test_run_op_other_telegram_error_is_internal(tmp_path):
    e = Env(tmp_path)

    async def op():
        raise TelegramError("sendMessage", 502, "Bad Gateway")
    e.run(e.ui._run(op, lambda r: "ok", None))
    assert e.tg.texts()[-1] == e.ui.T("text.internal")


def test_run_op_429_returns_telegram_busy_kind(tmp_path):
    e = Env(tmp_path)

    async def op():
        raise TelegramError("sendMessage", 429, "x", 3)
    assert asyncio.run(e.ui._run_op(op, lambda r: "ok", None, False, None)) == "telegram_busy"
