"""Перенос токенов между своими ботами: квота эмитента — на человека, второй бот на уже выданные дни токенов не
получит. Перенос не создаёт токенов: у отправителя они помечаются потраченными, сервер примет каждый один раз."""
import asyncio
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from veil.core import api
from veil.core.store.db import Store
from veil.core.wallet.issue import IssueFormatError, Token
from veil.ui import bot as uibot

ROOT = Path(__file__).resolve().parent.parent
TODAY = datetime.now(timezone.utc).date()


def day(k=0):
    return (TODAY + timedelta(days=k)).isoformat()


def core(tmp, name, kid="t1"):
    c = api.Core.__new__(api.Core)
    c.store = Store(tmp / name)
    c.issuer = lambda: (kid, bytes(32))
    return c


def fill(c, d, n, kid="t1"):
    import hashlib
    c.store.add_tokens([Token(kid, d, hashlib.sha256(f"{d}/{i}/{id(c)}".encode()).digest(), bytes([i]) * 64)
                        for i in range(n)])


def test_transfer_moves_not_copies(tmp_path):
    a, b = core(tmp_path, "a"), core(tmp_path, "b")
    fill(a, day(), 40)
    parts = a.export_tokens(day(), 25)
    assert parts and all(len(p) < 4096 for p in parts)
    assert a.store.token_counts()[day()] == 15  # отданные этот бот больше не использует
    res = None
    for p in parts:
        res = b.import_token_part(p)
    assert res == 25 and b.store.token_counts()[day()] == 25
    for p in parts:  # повторный приём тех же сообщений ничего не добавляет
        res = b.import_token_part(p)
    assert res == 0 and b.store.token_counts()[day()] == 25
    # отдавший бот не просит у эмитента повторно: эмитент эти токены уже выдал
    assert a.store.token_received()[day()] == 40


def test_transfer_rejects_foreign_issuer_and_old_days(tmp_path):
    a, b = core(tmp_path, "a", kid="evil"), core(tmp_path, "b")
    fill(a, day(), 3, kid="evil")
    with pytest.raises(IssueFormatError):
        for p in a.export_tokens(day(), 3):
            b.import_token_part(p)
    old = core(tmp_path, "c")
    fill(old, day(-1), 3)
    for p in old.export_tokens(day(-1), 3):
        assert b.import_token_part(p) == 0  # прошедший день — не принимается
    with pytest.raises(IssueFormatError):
        b.import_token_part("VEILTOK zzzzzzzz 1/1 AAAA")


def test_issuer_answer_for_other_bot_is_explained(tmp_path):
    b = core(tmp_path, "b")
    with pytest.raises(api.UnknownTokenRequest):
        b.accept_token_part("VEILRES 0123456789abcdef 1/2 AAAA")


class _Bot:
    def __init__(self):
        self.said, self.deleted = [], []

    async def send(self, chat, text, **kw):
        self.said.append(text)
        return {"message_id": len(self.said)}

    async def delete(self, chat, mid):
        self.deleted.append(mid)


def _ui(c):
    ui = uibot.UI.__new__(uibot.UI)
    ui.bot, ui.owner, ui.tasks, ui.core = _Bot(), 1, set(), c
    ui.T = uibot.Texts(ROOT / "locales" / "ru.toml", {})
    c.tokens_status = lambda: c.store.token_counts()
    return ui


def test_ui_transfer_flow(tmp_path):
    a, b = core(tmp_path, "a"), core(tmp_path, "b")
    fill(a, day(), 12)
    fill(b, day(5), 50)  # как у бота из пула: токены только на будущие дни
    ua, ub = _ui(a), _ui(b)

    async def flow():
        await ua._token_give("tok:give:10")
        for t in list(ua.tasks):
            t.cancel()
        parts = [t for t in ua.bot.said if t.startswith("VEILTOK ")]
        for i, p in enumerate(parts):
            await ub._token_import({"chat": {"id": 1}, "message_id": 100 + i, "text": p})
        return parts
    parts = asyncio.run(flow())
    assert "Перешлите следующие" in ua.bot.said[0] and len(parts) >= 1
    assert ub.bot.deleted == [100 + i for i in range(len(parts))]  # пересланный секрет удалён из чата
    assert "Принято токенов: 10" in ub.bot.said[-1] and b.store.token_counts()[day()] == 10
    assert a.store.token_counts()[day()] == 2


def test_no_tokens_today_explains_quota(tmp_path):
    b = core(tmp_path, "b")
    fill(b, day(5), 50)
    ub = _ui(b)
    text = ub._token_days()
    assert "На сегодня токенов нет" in text and "на все боты вместе" in text and "Передать" in text


def test_legacy_weekly_keys_only_for_their_week(tmp_path):
    """Токены прежнего недельного ключа того же эмитента переносятся только на дни своей недели (так же их принимает
    сервер); недельный ключ для дня другой недели — как чужой эмитент."""
    a, b = core(tmp_path, "a"), core(tmp_path, "b")
    y, w, _ = date.fromisoformat(day()).isocalendar()
    fill(a, day(), 5, kid=f"{y}-W{w:02d}")
    res = None
    for p in a.export_tokens(day(), 5):
        res = b.import_token_part(p)
    assert res == 5
    d, c = core(tmp_path, "d"), core(tmp_path, "c")
    fill(d, day(), 3, kid=f"{y}-W{(w % 52) + 1:02d}")  # ключ соседней недели
    parts = d.export_tokens(day(), 3)
    with pytest.raises(IssueFormatError, match="another issuer"):
        for p in parts:
            c.import_token_part(p)


def test_transfer_returns_to_sender(tmp_path):
    """Перенос не удался — те же VEILTOK, пересланные обратно, возвращают токены отдавшему боту."""
    a = core(tmp_path, "a")
    fill(a, day(), 10)
    parts = a.export_tokens(day(), 4)
    assert a.store.token_counts()[day()] == 6
    res = None
    for p in parts:
        res = a.import_token_part(p)
    assert res == 4 and a.store.token_counts()[day()] == 10
    for p in parts:  # второй раз — уже нечего возвращать
        res = a.import_token_part(p)
    assert res == 0 and a.store.token_counts()[day()] == 10


def test_spent_elsewhere_tokens_are_skipped(tmp_path, monkeypatch):
    """Одни и те же переданные токены в двух ботах: сервер примет каждый один раз. Бот пропускает уже потраченные
    другим ботом (помечает bad) и берёт следующий, а не сообщает «токенов нет» после трёх отказов."""
    from veil.core.transport.exchange import ServerError
    c = core(tmp_path, "a")
    monkeypatch.setattr(api, "today", lambda: day())
    fill(c, day(), 10)
    calls = []

    class Ex:
        async def request(self, op, *a, token=None, **kw):
            calls.append(token["input"])
            if len(calls) <= 6:
                raise ServerError("E_TOKEN_SPENT")
            return {"ok": 1}
    c.exchange = Ex()
    from nacl.signing import SigningKey
    assert asyncio.run(c._paid("post.delete", "post_secret", SigningKey.generate(), body={})) == {"ok": 1}
    assert len(calls) == 7 and len(set(calls)) == 7 and c.store.token_counts()[day()] == 3
