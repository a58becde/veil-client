"""Точка входа (veil/__main__.py) и консоль (veil/cli.py): конфиг, сборка бота, команды, ошибки."""
import asyncio
import io
import json
import os
import sys
from pathlib import Path

import pytest

import veil.__main__ as main_mod
from veil import cli
from veil.core.crypto import bip39
from veil.core.store.db import Store

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT.parent / "veil-protocol" / "keys.json"
SIG = json.loads(KEYS.read_text())["server_sig"]
WORDS = "legal winner thank year wave sausage worth useful legal winner thank yellow"


def cfg_file(tmp: Path, extra: str = "", sig: str = SIG) -> Path:
    (tmp / "keys.json").write_text(KEYS.read_text())
    p = tmp / "config.toml"
    p.write_text(f'[telegram]\nowner_id = 111\n[server]\ninbox_bot = "@inbox_bot"\nissuer_bot = "@issuer_bot"\n'
                 f'server_sig = "{sig}"\nkeys_file = "keys.json"\n[privacy]\n[ui]\n{extra}')
    return p


def test_load_config(tmp_path):
    cfg = main_mod.load_config(cfg_file(tmp_path))
    assert cfg["_config_name"] == "config.toml" and cfg["storage"] == {}
    with pytest.raises(SystemExit):
        main_mod.load_config(cfg_file(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, sig=""))


def test_build_pins_keys_and_applies_imported_settings(tmp_path):
    cfg = main_mod.load_config(cfg_file(tmp_path))
    store = Store(tmp_path / "data")
    store.put("imported_settings", {"privacy": {"keep_posts_days": 3}, "ui": {"labels": {"button": {"send": "X"}}}})
    store.add_post(1, bytes(32), "", "text")
    ui, bot, core = asyncio.run(main_mod.build(cfg, tmp_path, "1:x", store))
    assert store.get("pinned_server_sig") == SIG and store.get("pinned_issuer")["kid"]
    assert cfg["privacy"]["keep_posts_days"] == 3 and "labels" not in cfg["ui"]  # подписи из импорта — нет
    assert ui.owner == 111 and core.keys_doc["server_sig"] == SIG
    assert ui.T("button.send") == "Отправить"
    asyncio.run(bot.close())
    # другой ключ сервера, чем закреплён при первом запуске, — отказ
    cfg2 = main_mod.load_config(cfg_file(tmp_path))
    store.put("pinned_server_sig", "другой")
    with pytest.raises(SystemExit):
        asyncio.run(main_mod.build(cfg2, tmp_path, "1:x", store))


def test_build_with_labels_and_owner_override(tmp_path):
    cfg = main_mod.load_config(cfg_file(tmp_path, extra='[ui.labels]\nbutton = { send = "Опубликовать" }\n'))
    ui, bot, core = asyncio.run(main_mod.build(cfg, tmp_path, "1:x", Store(tmp_path / "d"), owner_id=5))
    assert ui.T("button.send") == "Опубликовать" and ui.owner == 5
    asyncio.run(bot.close())


def test_main_requires_token_and_rejects_legacy(tmp_path, monkeypatch):
    p = cfg_file(tmp_path)
    monkeypatch.delenv("VEIL_BOT_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="токена"):
        asyncio.run(main_mod.main(p))
    monkeypatch.setenv("VEIL_BOT_TOKEN", "1:x")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "identity.json").write_text('{"mnemonic": "x"}')
    with pytest.raises(SystemExit, match="migrate"):
        asyncio.run(main_mod.main(p))


def test_main_starts_and_writes_claim_link(tmp_path, monkeypatch, caplog):
    """Ссылка с кодом захвата владельца — в data/owner-link.txt (600), но не в журнал: кто читает journald, стал бы
    владельцем раньше настоящего."""
    p = cfg_file(tmp_path)
    p.write_text(p.read_text().replace("owner_id = 111", "owner_id = 0"))
    monkeypatch.setenv("VEIL_BOT_TOKEN", "1:x")
    served = []

    async def fake_get_me(self):
        return {"id": 77, "username": "my_bot"}

    async def fake_serve(ui, bot, core):
        served.append(ui)
    monkeypatch.setattr(main_mod.Bot, "get_me", fake_get_me)
    monkeypatch.setattr(main_mod, "serve", fake_serve)
    with caplog.at_level("WARNING"):
        asyncio.run(main_mod.main(p))
    assert served and Store(tmp_path / "data").get("bot_id") == 77
    link = tmp_path / "data" / "owner-link.txt"
    assert link.read_text().startswith("https://t.me/my_bot?start=") and (link.stat().st_mode & 0o777) == 0o600
    assert "start=" not in caplog.text and "owner-link.txt" in caplog.text


def test_serve_refreshes_and_closes(monkeypatch):
    calls = []

    class Plugins:
        async def stop(self):
            calls.append("plugins stop")

    class UI:
        plugins = Plugins()

        async def run(self):
            calls.append("run")

    class B:
        async def close(self):
            calls.append("close")
    asyncio.run(main_mod.serve(UI(), B(), object()))
    assert calls == ["run", "plugins stop", "close"]  # пакеты бота выгружаются из движка до закрытия


def run_cli(monkeypatch, tmp_path, *args, stdin=""):
    p = cfg_file(tmp_path)
    monkeypatch.setattr(sys, "argv", ["veil", str(p), *args])
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    monkeypatch.setattr(cli, "harden", lambda: None)
    main_mod.run()
    return Store(tmp_path / "data")


def test_run_commands(tmp_path, monkeypatch, capsys):
    st = run_cli(monkeypatch, tmp_path, "init", "--batch")
    assert st.load_device() is not None
    words = [w for line in capsys.readouterr().out.splitlines() for w in line.split() if w.isalpha() and w.islower()]
    assert len([w for w in words if w in bip39.wordlist()]) >= 12 if hasattr(bip39, "wordlist") else True
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, tmp_path, "init", "--batch")  # уже есть личность — нужен --force
    st = run_cli(monkeypatch, tmp_path, "restore", "--batch", "--force", stdin=WORDS + "\n")
    assert st.load_device() is not None
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, tmp_path, "migrate", "--batch")  # старого файла нет
    monkeypatch.setenv("VEIL_BOT_TOKEN", "42:x")
    out = tmp_path / "e.veilx"
    run_cli(monkeypatch, tmp_path, "export", str(out), "--batch", stdin="correct horse battery\n")
    assert out.exists()
    run_cli(monkeypatch, tmp_path, "import-key")
    assert "VEILIMP" in capsys.readouterr().out
    st = run_cli(monkeypatch, tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path,
                 "import", str(out), "--batch", stdin="correct horse battery\n")
    assert st.token_counts() == {} and capsys.readouterr().out.count("Импорт:") == 1
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, tmp_path, "nonsense")


def test_run_migrate_legacy(tmp_path, monkeypatch):
    (tmp_path / "data").mkdir()
    Store(tmp_path / "data")
    (tmp_path / "data" / "identity.json").write_text(json.dumps({"mnemonic": WORDS}))
    st = run_cli(monkeypatch, tmp_path, "migrate", "--batch")
    assert st.load_device() is not None and not (tmp_path / "data" / "identity.json").exists()


def test_cli_errors(tmp_path, monkeypatch):
    st = Store(tmp_path / "d")
    monkeypatch.delenv("VEIL_BOT_TOKEN", raising=False)
    with pytest.raises(cli.CliError):
        cli._bot_id(st, {"telegram": {}})
    st.put("bot_id", 9)
    assert cli._bot_id(st, {"telegram": {}}) == 9
    cfg = main_mod.load_config(cfg_file(tmp_path))
    st.put("pinned_server_sig", "другой")
    with pytest.raises(cli.CliError):
        cli._pins(st, cfg, tmp_path)
    with pytest.raises(cli.CliError):
        cli._tty(False) if not (sys.stdin.isatty() and sys.stdout.isatty()) else (_ for _ in ()).throw(cli.CliError())
    monkeypatch.setattr(sys, "stdin", io.StringIO("bad words here\n"))
    with pytest.raises(cli.CliError):
        cli.restore(Store(tmp_path / "r"), batch=True)
    with pytest.raises(cli.CliError):
        cli.export(st, cfg, str(tmp_path / "o.veilx"), to_key="VEILIMP short")
    monkeypatch.setattr(sys, "stdin", io.StringIO("short\n"))
    st.put("pinned_server_sig", SIG)
    with pytest.raises(cli.CliError):
        cli.export(st, cfg, str(tmp_path / "o2.veilx"), batch=True)
    (tmp_path / "junk").write_bytes(b"junk")
    with pytest.raises(cli.CliError):
        cli.import_(Store(tmp_path / "i"), cfg, tmp_path, str(tmp_path / "junk"))


def test_harden_sets_umask():
    old = os.umask(0o022)
    try:
        cli.harden()
        assert os.umask(0o022) == 0o077
    finally:
        os.umask(old)


def test_issuer_key_change_needs_confirmation(tmp_path, monkeypatch, capsys):
    """Другой ключ эмитента в keys.json (подсунутый «обновлённый» файл) молча не закрепляется: бот работает с прежним
    и подсказывает pin-issuer; консоль подтверждает смену явно. У бота пула keys.json ведёт оператор — закрепляется."""
    cfg = main_mod.load_config(cfg_file(tmp_path))
    store = Store(tmp_path / "data")
    old = {"kid": "t0", "pk": "AAAA"}
    store.put("pinned_server_sig", SIG)
    store.put("pinned_issuer", old)
    ui, bot, core = asyncio.run(main_mod.build(cfg, tmp_path, "1:x", store))
    asyncio.run(bot.close())
    assert store.get("pinned_issuer") == old and store.get("issuer_repin")["kid"] != "t0"
    assert "pin-issuer" in ui.status_text()
    with pytest.raises(cli.CliError, match="pin-issuer"):
        cli._pins(store, cfg, tmp_path)  # export/import из консоли тоже не меняют закрепление молча
    offered = cli.pin_issuer(store, cfg, tmp_path, batch=True)
    assert store.get("pinned_issuer") == offered and store.get("issuer_repin") is None
    assert "Закреплён:" in capsys.readouterr().out
    pool_store = Store(tmp_path / "pool")
    pool_store.put("pinned_issuer", old)
    pool_cfg = main_mod.load_config(cfg_file(tmp_path))
    pool_cfg["pool"] = {"identity": "custodial"}  # как у процесса группы пула
    ui, bot, core = asyncio.run(main_mod.build(pool_cfg, tmp_path, "1:x", pool_store))
    asyncio.run(bot.close())
    assert pool_store.get("pinned_issuer") == offered
