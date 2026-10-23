"""Что остаётся на диске бота: «забытые» секреты постов не находятся в файлах базы (spec/01), ссылка владельца — не
в журнале, чистка идёт и у бота, который работает без перезапуска."""
import asyncio
import os
import time

import pytest

from veil.core.store.db import Store

SECRET = bytes([0xAB]) * 32


def files_of(d) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(d.iterdir()) if p.is_file() and p.name.startswith("veil.db"))


@pytest.mark.parametrize("sealed", [False, True])
def test_forgotten_post_secret_not_on_disk(tmp_path, sealed):
    """После срока keep_posts_days секрет поста стирается без следов: secure_delete затирает строку, compact усекает
    журнал WAL (у бота в пуле — пересобирает зашифрованный снимок без свободных страниц)."""
    key = os.urandom(32) if sealed else None
    s = Store(tmp_path, key=key)
    s.add_post(5, SECRET, "u", "text")
    s.add_post(6, bytes([0xCD]) * 32, "u", "text")
    s.db.execute("UPDATE my_posts SET created = 0 WHERE n = 5")
    assert s.housekeeping(30) == 1 and s.my_numbers() == {6}
    if sealed:
        assert SECRET not in s.db._conn.serialize()
    else:
        s.db.close()
        assert SECRET not in files_of(tmp_path) and bytes([0xCD]) * 32 in files_of(tmp_path)


def test_daily_loop_forgets_old_posts(tmp_path, monkeypatch):
    """Бот, который месяцами не перезапускался, тоже забывает старые «мой пост ↔ секрет» (раз в сутки)."""
    from harness import Env

    from veil.ui import bot as uibot
    e = Env(tmp_path)
    e.store.add_post(5, SECRET, "u", "text")
    e.store.db.execute("UPDATE my_posts SET created = ?", (int(time.time()) - 31 * 86400,))
    turns = {"n": 0}

    class Stop(Exception):
        pass

    async def one_day(s):
        turns["n"] += 1
        if turns["n"] > 1:
            raise Stop
    monkeypatch.setattr(uibot.asyncio, "sleep", one_day)
    with pytest.raises(Stop):
        asyncio.run(e.ui._daily_loop())
    assert e.store.my_numbers() == set()


def test_claim_link_removed_after_claim(tmp_path):
    """Ссылка привязки владельца лежит в data/ только до привязки."""
    from harness import Env
    e = Env(tmp_path, owner=0)
    code = e.ui.claim_code()
    e.store.owner_link_path.write_text(f"https://t.me/x?start={code}\n")
    e.route(e.msg(f"/start {code}", **{"from": {"id": 777, "is_bot": False}}))
    assert e.ui.owner == 777 and not e.store.owner_link_path.exists()
