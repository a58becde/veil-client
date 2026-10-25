"""Бот Veil.

  python -m veil [config.toml]                 запустить бота
  python -m veil [config.toml] init [--force]  новая личность: 12 слов — только в этом терминале (spec/02)
  python -m veil [config.toml] restore         восстановить личность по 12 словам на этом боте
  python -m veil [config.toml] migrate         перевести старый data/identity.json (слова на диске) на ключ устройства
  python -m veil [config.toml] export <файл> [--to=VEILIMP…]  выгрузить бота (docs/EXPORT.md)
  python -m veil [config.toml] import-key      ключ этой машины для файла, присланного через чат
  python -m veil [config.toml] import <файл> [--with-identity] [--force]   загрузить (личность — только по флагу)
  python -m veil [config.toml] pin-issuer      подтвердить смену ключа эмитента из keys.json (spec/03)
  python -m veil [config.toml] pin-market      подтвердить смену ключа каталога плагинов из config.toml (docs/MARKET.md)
  python -m veil [config.toml] engine status|fetch|trust   движок плагинов: проверить, скачать официальный, принять свой
  --batch: без терминала (автоматизация; init печатает слова в stdout, restore читает их из stdin)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from veil import cli, market, plugin_engine, plugins
from veil.core import api
from veil.core.protocol import b64, keysdoc
from veil.core.store.db import Store, _write_private
from veil.core.transport.exchange import Exchange
from veil.core.transport.telegram import Bot
from veil.ui.bot import UI, PluginHost, Texts

ROOT = Path(__file__).resolve().parent.parent


def load_config(path: Path) -> dict:
    cfg = tomllib.loads(path.read_text("utf-8"))
    for sec in ("telegram", "server", "storage", "privacy", "ui"):
        cfg.setdefault(sec, {})
    if not cfg["server"].get("server_sig"):
        raise SystemExit("config: server.server_sig не задан (ключ из keys.json сервера)")
    cfg["_config_name"] = path.name  # для подсказок владельцу: «python -m veil <конфиг> init»
    return cfg


async def build(cfg: dict, base: Path, token: str, store: Store, owner_id: int = 0,
                engine: plugin_engine.Engine | None = None,
                observer: Callable[[str, dict, Any], None] | None = None) -> tuple[UI, Bot, api.Core]:
    """Собрать бота: хранилище уже открыто. Общая часть для отдельного бота (main) и пула (veil.pool). engine — движок
    плагинов (у своего бота — свой, в пуле — общий для группы); без него плагинов нет. observer — наблюдатель
    успешных вызовов Bot API: observer(метод, параметры, результат); токена и адреса в нём нет."""
    store.release_reserved()
    keep = int(cfg["privacy"].get("keep_posts_days", 30))
    if n := store.housekeeping(keep):
        logging.info("forgot %d own posts older than %d days (privacy.keep_posts_days)", n, keep)

    # Настройки этого бота из импорта (docs/EXPORT.md) поверх общего конфига: у бота в пуле своего конфига нет.
    imported = store.get("imported_settings") or {}
    for sec in ("privacy", "ui"):
        for k, v in (imported.get(sec) or {}).items():
            if k != "labels":  # подписи кнопок из импорта не применяются никогда
                cfg[sec][k] = v
    pinned = cfg["server"]["server_sig"]
    # Ключ сервера закрепляется в данных бота при первом запуске. Конфиг (его могут подсунуть: «вот готовые
    # настройки») не может молча увести бота на другой сервер — иначе чужой сервер увидит, какой бот какие
    # анонимные посты отправляет.
    stored = store.get("pinned_server_sig")
    if stored is None:
        store.put("pinned_server_sig", pinned)
    elif stored != pinned:
        raise SystemExit("config: server.server_sig отличается от закреплённого при первом запуске. Если вы "
                         "действительно переходите на другой сервер, удалите data/ (или запись pinned_server_sig) "
                         f"и восстановите личность: python -m veil {cfg.get('_config_name', 'config.toml')} restore")
    # Ключ эмитента закрепляется из локального keys.json (его берут из публичного репозитория, а не у сервера):
    # иначе сервер мог бы выдать человеку свой ключ эмитента и узнавать его посты по токенам (spec/03). Смена уже
    # закреплённого ключа — только подтверждением владельца в терминале (pin-issuer): подсунутый keys.json
    # («вот обновлённый файл») с документом от утёкшего ключа сервера не должен менять закрепление молча.
    local = keysdoc.verify(json.loads((base / cfg["server"].get("keys_file", "keys.json")).read_text()), pinned)
    kid, ipk = keysdoc.issuer_key(local)
    offered, current = {"kid": kid, "pk": b64.enc(ipk)}, store.get("pinned_issuer")
    if current is None or (current != offered and cfg.get("pool")):  # бот пула: keys.json ведёт оператор пула
        if current is not None:
            logging.warning("issuer key re-pinned by the pool's keys.json: %s", kid)
        store.put("pinned_issuer", offered)
        store.put("issuer_repin", None)
    elif current != offered:
        logging.warning("keys.json offers another issuer key (%s, pinned %s): "
                        "confirm with `python -m veil %s pin-issuer`",
                        kid, current.get("kid"), cfg.get("_config_name", "config.toml"))
        store.put("issuer_repin", offered)
    else:
        store.put("issuer_repin", None)
    doc = store.get("keys_doc") or local
    doc = keysdoc.verify(doc, pinned)  # ключ подписи сервера закреплён в конфиге

    bot = Bot(token, proxy=cfg["telegram"].get("proxy") or None, observer=observer)
    core: api.Core
    exchange = Exchange(bot, cfg["server"]["inbox_bot"], b64.dec(pinned), lambda: keysdoc.inbox_key(core.keys_doc),
                        lambda: keysdoc.inbox_bots(core.keys_doc), lambda: keysdoc.inbox_names(core.keys_doc),
                        lambda flag: store.put("inbox_name_bad", flag))
    owner = owner_id or cfg["telegram"].get("owner_id") or store.get("owner_id") or 0
    core = api.Core(bot, store, exchange, doc, owner)
    labels = {}
    for sec, kv in (cfg["ui"].get("labels") or {}).items():
        labels.update({f"{sec}.{k}": v for k, v in kv.items()} if isinstance(kv, dict) else {sec: kv})
    texts = Texts(ROOT / "locales" / f"{cfg['ui'].get('locale', 'ru')}.toml", labels)
    ui = UI(core, bot, texts, cfg)
    if owner_id:
        ui.owner = owner_id
    # Плагины: пакеты из config.toml (у своего бота) и из маркета. Запускаются те, на чьи разрешения владелец уже
    # согласился; остальные бот спросит после запуска (UI.setup).
    mk = market.Market(store, store.dir, cfg.get("market") or {}, proxy=cfg["telegram"].get("proxy") or None) \
        if (cfg.get("market") or {}).get("key") else None
    ui.market_ui.market = mk
    ui.plugins = plugins.load(cfg, base, (mk.plugins_dir, mk.installed(), mk.revoked_installed()) if mk else None,
                              engine)
    ui.plugins.host = PluginHost(ui)
    await ui.plugins.start(store.get("plugin_grants"))
    return ui, bot, core


async def serve(ui: UI, bot: Bot, core: api.Core) -> None:
    """Цикл бота и обновление keys.json раз в 6 часов (ротация ключей inbox)."""
    async def refresh_later() -> None:
        while True:
            await asyncio.sleep(6 * 3600)
            try:
                await core.refresh_keys()
            except Exception as e:
                logging.warning("keys refresh: %s", e)

    t = asyncio.get_running_loop().create_task(refresh_later())  # первое обновление делает ui.setup()
    try:
        await ui.run()
    finally:
        t.cancel()
        await ui.plugins.stop()  # пакеты бота выгружаются из движка
        await bot.close()


async def main(cfg_path: Path) -> None:
    cfg = load_config(cfg_path)
    base = cfg_path.parent
    token = os.environ.get(cfg["telegram"].get("token_env", "VEIL_BOT_TOKEN"), "")
    if not token:
        raise SystemExit("нет токена бота в переменной окружения")
    store = Store(base / cfg["storage"].get("data_dir", "data"))
    if store.legacy_identity_path.exists():
        raise SystemExit("В data/identity.json лежат 12 слов открытым текстом (старый формат). "
                         "Переведите личность на ключ\n"
                         f"устройства: python -m veil {cfg_path.name} migrate — файл со словами будет затёрт.")
    engine = plugin_engine.make_engine(cfg, base, store.dir, store)
    ui, bot, core = await build(cfg, base, token, store, engine=engine)
    me = await bot.get_me()
    store.put("bot_id", me["id"])  # для export/import без токена в окружении
    logging.info("bot @%s started", me.get("username"))
    code = ui.claim_code()
    if code:  # owner_id не задан: владельцем станет тот, кто откроет эту ссылку (код — 128 случайных бит)
        # Ссылка — в файл данных (600) и в терминал, но не в журнал: кто читает journald или docker logs, тот иначе
        # успел бы стать владельцем раньше настоящего.
        link = f"https://t.me/{me.get('username')}?start={code}"
        _write_private(store.owner_link_path, link + "\n")
        logging.warning("ВЛАДЕЛЕЦ НЕ ЗАДАН: ссылка для привязки — в %s", store.owner_link_path)
        if sys.stderr.isatty():
            print(f"Откройте эту ссылку из своего аккаунта Telegram: {link}", file=sys.stderr)
    try:
        await serve(ui, bot, core)
    finally:
        await engine.stop()


def run() -> None:
    cli.harden()  # до любых секретов: umask 077, без дампов памяти
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # иначе в журнал попадёт URL с токеном
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    cfg_path = Path(args.pop(0) if args and args[0].endswith(".toml") else "config.toml").resolve()
    command = args[0] if args else "run"
    if command == "run":
        asyncio.run(main(cfg_path))
        return
    cfg = load_config(cfg_path)
    store = Store(cfg_path.parent / cfg["storage"].get("data_dir", "data"))
    batch, force = "--batch" in flags, "--force" in flags
    if command == "init":
        cli.init(store, batch=batch, force=force)
    elif command == "restore":
        cli.restore(store, batch=batch, force=force)
    elif command == "migrate":
        cli.migrate(store, batch=batch)
    elif command == "export" and len(args) > 1:
        to = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--to=")), None)
        cli.export(store, cfg, args[1], to_key=to, batch=batch, base=cfg_path.parent)
    elif command == "import-key":
        cli.import_key(store)
    elif command == "import" and len(args) > 1:
        cli.import_(store, cfg, cfg_path.parent, args[1], force=force, batch=batch,
                    with_identity="--with-identity" in flags)
    elif command == "pin-issuer":
        cli.pin_issuer(store, cfg, cfg_path.parent, batch=batch)
    elif command == "pin-market":
        cli.pin_market(store, cfg, batch=batch)
    elif command == "engine" and len(args) > 1:
        cli.engine(store, cfg, cfg_path.parent, args[1], batch=batch)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    run()
