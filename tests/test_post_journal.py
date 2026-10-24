"""Журнал отправки поста: выравнивание «лично для» в пределах сервера, секрет и конверт записываются до отправки,
итог дозапрашивается тем же конвертом, черновик переживает перезапуск во время случайной задержки."""
import pytest

from veil.core.protocol import hidden

SERVER_MAX_SEALED = hidden.MAX_PAYLOAD + 48  # предел сервера для шифрованного скрытого (spec/07)


def test_padded_never_exceeds_server_limit():
    """payload у самого предела — выравнивание не выводит blob за предел сервера: либо помещается, либо отказ
    на клиенте (а не E_TOO_LONG от сервера после «Отправить»)."""
    base = "一" * 4000
    checked = 0
    for url_len in range(1, 2000):
        ents = [{"type": "text_link", "offset": i, "length": 1, "url": "https://e.example/" + "x" * url_len}
                for i in range(10)]
        try:
            pl = hidden.payload(base, ents)
        except ValueError:
            break
        if len(pl) < hidden.MAX_PAYLOAD - 300:
            continue
        checked += 1
        try:
            sealed = len(hidden.padded(pl)) + 48
        except ValueError:
            continue  # клиент сам отказал: «сократите текст»
        assert sealed <= SERVER_MAX_SEALED
    assert checked > 0


def test_padded_rejects_without_assert():
    """проверка размера — исключением, а не assert (python -O её бы убрал)."""
    pl = hidden.payload("一" * 4000, [{"type": "text_link", "offset": 0, "length": 1,
                                       "url": "https://e.example/" + "x" * 1}])
    assert len(hidden.padded(pl)) % hidden.PAD_BLOCK == 0
    import inspect
    assert "assert " not in inspect.getsource(hidden.padded)
    with pytest.raises(ValueError):
        big = hidden.jcs.canonicalize({"text": "x" * (hidden.MAX_PAYLOAD - 12)})
        hidden.padded(big)


# --- секрет поста и конверт — до отправки; итог дозапрашивается тем же конвертом ---
import asyncio  # noqa: E402
from pathlib import Path  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from veil.core import api, privacy  # noqa: E402
from veil.core.store.db import Store  # noqa: E402
from veil.core.transport.exchange import NoReplyError  # noqa: E402
from veil.core.wallet.issue import Token as IssuedToken  # noqa: E402
from veil.ui import bot as uibot  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class _QueueExchange:
    """Сервер принял конверт, но ответа нет (очередь длиннее повторов); resume потом отдаёт итог."""

    def __init__(self):
        self.states, self.resumed = [], []

    async def request(self, op, auth_mode, auth_key, *, journal=None, **kw):
        journal({"op": op, "auth_mode": auth_mode, "id": "01JA00000000000000000QUEUE", "token": kw.get("token")})
        raise NoReplyError(op)

    async def resume(self, state, auth_key=None, resp_sk=None):
        self.resumed.append(state["id"])
        return {"n": 42, "url": "https://t.me/c/1/42"}


def _core(tmp_path, monkeypatch, ex):
    async def build(core, d, post_pk=None):
        return SimpleNamespace(hidden=None, shown=None, deliver=None)
    monkeypatch.setattr(privacy, "build", build)
    monkeypatch.setattr(api, "today", lambda: "2026-10-17")
    store = Store(tmp_path)
    store.add_tokens([IssuedToken("t1", "2026-10-17", bytes([1]) * 32, bytes(64))])
    core = api.Core(bot=None, store=store, exchange=ex, keys_doc={}, owner_id=1)
    monkeypatch.setattr(core, "nick", lambda: None)
    return core


def test_post_secret_saved_before_send(tmp_path, monkeypatch):
    """ответа нет — PostQueuedError, секрет сохранён, токен не вернулся в кошелёк; resume публикует итог."""
    ex = _QueueExchange()
    core = _core(tmp_path, monkeypatch, ex)
    journaled = []
    d = api.Draft(1, [{"message_id": 1, "text": "пост"}], anonymous=True)
    with pytest.raises(api.PostQueuedError):
        asyncio.run(core.create_post(d, on_journal=lambda: journaled.append(True)))
    assert journaled == [True]
    [(env_id, secret, kind, state, _)] = core.store.pending_posts()
    assert env_id == "01JA00000000000000000QUEUE" and len(secret) == 32
    assert core.store.token_counts() == {}  # токен закреплён за конвертом: не выдаётся другой операции
    events = asyncio.run(core.resume_pending())
    assert events == [("published", {"n": 42, "url": "https://t.me/c/1/42"})] and ex.resumed == [env_id]
    assert core.store.post_secret(42) == secret and core.store.pending_posts() == []


def test_resume_drops_after_ttl(tmp_path, monkeypatch):
    ex = _QueueExchange()
    core = _core(tmp_path, monkeypatch, ex)
    core.store.save_pending_post("01JA0000000000000000000OLD", bytes(32), "text", {"id": "x"})
    core.store.db.execute("UPDATE pending_posts SET created = created - ?", (api.Core.PENDING_TTL + 10,))
    assert asyncio.run(core.resume_pending()) == [("lost", None)] and ex.resumed == []


# --- черновик живёт до записи конверта; перезапуск во время задержки не теряет пост ---
class _Bot:
    def __init__(self):
        self.sent = []

    async def send(self, chat, text, **kw):
        self.sent.append(("send", text))
        return {"chat": {"id": chat}, "message_id": len(self.sent)}

    async def edit(self, chat, mid, text, **kw):
        self.sent.append(("edit", text))


def _ui(tmp_path, create_post):
    ui = uibot.UI.__new__(uibot.UI)
    ui.bot, ui.owner, ui.config_name = _Bot(), 1, "config.toml"
    ui.T = uibot.Texts(ROOT / "locales" / "ru.toml", {})
    ui.cfg = {"privacy": {"random_delay_seconds": [30, 30]}}
    ui.core = SimpleNamespace(store=Store(tmp_path), create_post=create_post)
    ui.plugins = uibot.plug.Registry()  # UI собран без __init__: плагинов нет
    return ui


def test_restart_during_delay_keeps_draft(tmp_path, monkeypatch):
    """остановка бота во время случайной задержки (задача отменена) — черновик со сроком остаётся."""
    async def create_post(d, on_journal=None):
        raise AssertionError("must not send during the delay")

    ui = _ui(tmp_path, create_post)
    i = ui.core.store.save_draft(api.Draft(1, [{"message_id": 1, "text": "отложенный"}]).to_json())

    async def stop(s):
        raise asyncio.CancelledError
    monkeypatch.setattr(uibot.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(ui._send_draft(i, api.Draft.from_json(ui.core.store.draft(i)),
                                   {"chat": {"id": 1}, "message_id": 5}, delay=True))
    [(j, raw)] = ui.core.store.scheduled_drafts()
    assert j == i and raw["send_at"] > 0 and raw["messages"][0]["text"] == "отложенный"


def test_scheduled_draft_sent_after_restart(tmp_path, monkeypatch):
    sent = []

    async def create_post(d, on_journal=None):
        on_journal()
        sent.append(d.messages[0]["text"])
        return {"n": 9, "url": ""}

    ui = _ui(tmp_path, create_post)
    d = api.Draft(1, [{"message_id": 1, "text": "отложенный"}], send_at=1, status={"chat": {"id": 1}, "message_id": 5})
    i = ui.core.store.save_draft(d.to_json())
    ui.core.resume_pending = None  # цикл дозапроса проверяется отдельно

    async def run_once():
        task = asyncio.create_task(ui._resume_scheduled())
        for _ in range(50):
            await asyncio.sleep(0.01)
            if sent:
                break
        task.cancel()
    asyncio.run(run_once())
    assert sent == ["отложенный"] and ui.core.store.draft(i) is None
    assert ("edit", "Опубликовано: №9\n") in ui.bot.sent


def test_send_at_saved_before_wait(tmp_path, monkeypatch):
    """срок отправки записывается в черновик до ожидания."""
    seen = {}

    async def fake_sleep(s):
        seen["draft"] = ui.core.store.draft(i)
    monkeypatch.setattr(uibot.asyncio, "sleep", fake_sleep)

    async def create_post(d, on_journal=None):
        on_journal()
        return {"n": 1, "url": ""}
    ui = _ui(tmp_path, create_post)
    i = ui.core.store.save_draft(api.Draft(1, [{"message_id": 1, "text": "x"}]).to_json())
    asyncio.run(ui._send_draft(i, api.Draft.from_json(ui.core.store.draft(i)), {"chat": {"id": 1}, "message_id": 5},
                               delay=True))
    assert seen["draft"]["send_at"] > 0 and seen["draft"]["status"]["message_id"] == 5
    assert ui.core.store.draft(i) is None  # после отправки черновика нет
