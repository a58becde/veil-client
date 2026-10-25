"""Общее для тестов плагинов: пакет на диске, бот стенда с движком плагинов, ожидание событий.

Движок — engine/dist/veil-engine.wasm (нет — собирается engine/build.py), его машинный код кэшируется рядом. Каждый тест
поднимает свой процесс-хост в своём цикле событий и останавливает его в конце (shutdown)."""
from __future__ import annotations

import asyncio
import functools
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from harness import Env

from veil import plugin_engine, plugins
from veil.ui import bot as uibot

ROOT = Path(__file__).resolve().parent.parent
WASM = ROOT / "engine" / "dist" / "veil-engine.wasm"

BASE = """
id = "{id}"
name = "Тест"
version = "1.0.0"
api = 1
entry = "main"
description = "Плагин для теста"
author = "Автор"
license = "MIT"
"""


@functools.cache
def engine_sha() -> str:
    if not WASM.exists():
        subprocess.run([sys.executable, str(ROOT / "engine" / "build.py")], check=True)
    return plugin_engine.sha256_file(WASM)


def new_engine(**kw) -> plugin_engine.Engine:
    """Движок для теста: эта сборка движка принята явно (официальный хеш у локальной сборки другой)."""
    return plugin_engine.Engine(WASM, WASM.parent, {engine_sha()}, **kw)


def manifest(id_: str = "probe", **extra) -> str:
    text = BASE.format(id=id_)
    for k, v in extra.items():
        text += f"{k} = {json.dumps(v, ensure_ascii=False)}\n"
    return text


def package(base: Path, id_: str, code: str, **extra) -> Path:
    d = base / "plugins" / id_
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(base / "plugins", 0o700)
    os.chmod(d, 0o700)
    (d / "plugin.toml").write_text(manifest(id_, **extra))
    (d / "main.py").write_text(textwrap.dedent(code))
    return d


def bot(tmp: Path, enabled: list[str], engine: plugin_engine.Engine | None = None,
        **conf) -> tuple[Env, plugins.Registry]:
    e = Env(tmp / "data")
    reg = plugins.load({"plugins": {"enabled": enabled, **conf}}, tmp, None, engine or new_engine())
    e.ui.plugins = reg
    reg.host = uibot.PluginHost(e.ui)
    return e, reg


async def start_all(reg: plugins.Registry) -> None:
    await reg.start({p.name: p.manifest.grant() for p in reg.packages})


async def shutdown(*regs: plugins.Registry) -> None:
    engines = {id(r.engine): r.engine for r in regs if r.engine}
    for r in regs:
        await r.stop()
    for eng in engines.values():
        await eng.stop()


async def settle(e: Env) -> None:
    """Дождаться задач бота и событий плагинов (действия плагина бот выполняет, пока ждёт ответа на событие)."""
    for _ in range(200):
        pending = [t for t in list(e.ui.tasks) + list(e.ui.plugins.tasks) if not t.done()]
        if not pending:
            return
        await asyncio.wait(pending, timeout=0.5)


async def go(e: Env, *updates) -> None:
    for u in updates:
        e.ui.handle_update(u)
        await settle(e)


def texts(e: Env) -> list[str]:
    return e.tg.texts()


def has(e: Env, fragment: str) -> bool:
    return any(fragment in t for t in e.tg.texts())


def stored(e: Env, plugin: str) -> dict:
    """Хранилище плагина — у бота, в его данных."""
    return e.store.get(plugins.storage_key(plugin)) or {}
