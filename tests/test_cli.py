"""Личность создаётся и восстанавливается только в консоли; 12 слов не хранятся и не проходят через Telegram
(spec/02)."""
import io
import json
import re
import sys
from pathlib import Path

import pytest

from veil import cli
from veil.core.crypto import bip39, keys
from veil.core.store.db import Store

ROOT = Path(__file__).resolve().parents[1]
WORDS = "legal winner thank year wave sausage worth useful legal winner thank yellow"


@pytest.fixture(autouse=True)
def fast_tag(monkeypatch):
    monkeypatch.setattr(keys, "tag", lambda pk: "abcdef")  # Argon2id ~0,2 с — в этих тестах не важен


def _run(monkeypatch, fn, stdin: str = "", **kw):
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    res = fn(**kw)
    return res, out.getvalue()


def test_init_batch_shows_words_once_and_stores_none(tmp_path, monkeypatch):
    st = Store(tmp_path)
    d, out = _run(monkeypatch, cli.init, store=st, batch=True)
    words = [w for _, w in sorted((int(n), w) for n, w in re.findall(r"(\d+)\. ([a-z]+)", out))]  # три колонки
    assert len(words) == 12 and bip39.validate(" ".join(words))
    saved = (tmp_path / "device.json").read_text()
    # слов на диске нет (base64 со словами не путаем)
    assert " ".join(words[:3]) not in saved and "mnemonic" not in saved
    assert set(json.loads(saved)) == {"v", "id_pk", "tag", "dev_sk", "seq", "dev_sig", "enc"}
    assert d.id_pk == bytes(keys.root_from_seed(bip39.to_seed(" ".join(words))).verify_key)
    with pytest.raises(SystemExit):  # повторный init без --force не затирает личность
        _run(monkeypatch, cli.init, store=st, batch=True)


def test_init_requires_terminal(tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as e:
        _run(monkeypatch, cli.init, store=Store(tmp_path))  # stdin/stdout не терминал
    assert "терминале" in str(e.value)


def test_restore_gives_same_identity_new_device(tmp_path, monkeypatch):
    st = Store(tmp_path)
    first, _ = _run(monkeypatch, cli.restore, store=st, batch=True, stdin=WORDS + "\n")
    again, _ = _run(monkeypatch, cli.restore, store=st, batch=True, force=True, stdin="  " + WORDS.upper() + " \n")
    assert first.id_pk == again.id_pk and first.dev_pk != again.dev_pk  # та же личность, новое устройство
    assert again.seq >= first.seq
    with pytest.raises(SystemExit):
        _run(monkeypatch, cli.restore, store=Store(tmp_path / "x"), batch=True, stdin="legal winner thank\n")


def test_migrate_wipes_words(tmp_path, monkeypatch):
    st = Store(tmp_path)
    (tmp_path / "identity.json").write_text(json.dumps({"v": 1, "mnemonic": WORDS}))
    d, out = _run(monkeypatch, cli.migrate, store=st, batch=True)
    assert not (tmp_path / "identity.json").exists() and "legal" not in out
    assert d.id_pk == bytes(keys.root_from_seed(bip39.to_seed(WORDS)).verify_key)
    with pytest.raises(SystemExit):
        _run(monkeypatch, cli.migrate, store=st, batch=True)


def test_telegram_ui_never_handles_words():
    """Интерфейс бота не создаёт и не принимает 12 слов: нет bip39, нет /restore. Показ слов в Telegram есть только у
    бота в пуле (spec/02, «Бот в пуле»): слова создаёт veil/pool.py, текст с ними — только ключ text.pool_words."""
    import tomllib
    ui = (ROOT / "veil/ui/bot.py").read_text()
    loc = tomllib.loads((ROOT / "locales/ru.toml").read_text())
    assert "bip39" not in ui and "mnemonic" not in ui and '"/restore"' not in ui
    with_words = [f"{sec}.{k}" for sec, kv in loc.items() for k, v in kv.items() if "{words}" in str(v)]
    assert with_words == ["text.pool_words"] and "restore" not in loc.get("commands", {})
    api = (ROOT / "veil/core/api.py").read_text()
    assert "bip39" not in api and "mnemonic" not in api
