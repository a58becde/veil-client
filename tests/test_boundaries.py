"""Проверка границ модулей: контракты import-linter (pyproject.toml) действительно ловят нарушения.

Для каждого контракта — проба: копия пакета с дописанным запрещённым импортом должна дать ненулевой код и имя
контракта в выводе. Контрольный прогон на чистой копии должен пройти: пробы падают из-за пробы, а не окружения.
"""
import ast
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NO_LINTER = "нет lint-imports: pip install --require-hashes -r requirements-dev.lock"

# имя контракта (name в pyproject.toml, для поиска в выводе) → (файл, дописываемый запрещённый импорт)
PROBES = {
    "Слои ядра: протокол и криптография внизу, api наверху":
        ("core/protocol/jcs.py", "from veil.core.transport import telegram"),
    "Слои бота: вызовы только сверху вниз": ("core/api.py", "from veil import plugins"),
    "Интерфейс — только через veil.core.api и veil.core.export": ("ui/bot.py", "from veil.core.store import db"),
    "12 слов не попадают в код бота": ("ui/bot.py", "from veil.core.crypto import bip39"),
    "Плагины и движок не видят ядро": ("plugins.py", "from veil.core import api"),
    "Процесс-хост движка: без сети и без кода бота": ("plugin_host.py", "import httpx"),
    "Процесс-хост и wasmtime — только через plugin_engine": ("market.py", "import wasmtime"),
    "Маркет: из ядра только протокол и криптография": ("market.py", "from veil.core.store import db"),
    "Ядро: Telegram — только transport": ("core/crypto/keys.py", "import httpx"),
    "sqlite3 — только veil.core.store": ("core/privacy.py", "import sqlite3"),
}


def _linter() -> str:
    exe = Path(sys.executable).parent / "lint-imports"
    if not exe.exists():
        pytest.fail(NO_LINTER)
    return str(exe)


def _run(tmp_path: Path, probe: tuple[str, str] | None) -> subprocess.CompletedProcess:
    """Копия veil/ и pyproject.toml во временный каталог (пробу дописываем туда), запуск линтера оттуда."""
    shutil.copytree(ROOT / "veil", tmp_path / "veil", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    if probe:
        target = tmp_path / "veil" / probe[0]
        target.write_text(target.read_text(encoding="utf-8") + f"\n{probe[1]}\n", encoding="utf-8")
    env = {**os.environ, "COLUMNS": "200", "NO_COLOR": "1"}  # длинные строки вывода не переносятся
    return subprocess.run([_linter(), "--no-cache"], cwd=tmp_path, env=env, capture_output=True, text=True,
                          timeout=120, check=False)


def test_contracts_kept(tmp_path):
    r = _run(tmp_path, None)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 broken" in r.stdout


@pytest.mark.parametrize("name", list(PROBES))
def test_contracts_catch(tmp_path, name):
    r = _run(tmp_path, PROBES[name])
    assert r.returncode != 0, f"проба не поймана: {name}\n{r.stdout}"
    broken = [ln for ln in r.stdout.splitlines() if name in ln and "BROKEN" in ln]
    assert broken, f"контракт «{name}» не назван сломанным:\n{r.stdout}"


def test_every_contract_has_probe():
    import tomllib
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    names = {c["name"] for c in cfg["tool"]["importlinter"]["contracts"]}
    assert names == set(PROBES)


def test_guest_imports():
    """Гостевой SDK движка тянет только stdlib, привязки WIT и свой veil.plugins (иначе в сборке чужой пакет)."""
    allowed = set(sys.stdlib_module_names) | {"wit_world", "componentize_py_types", "veil"}
    files = sorted((ROOT / "engine" / "guest").rglob("*.py"))
    assert files
    bad = []
    for f in files:
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                mods = [node.module or ""]
                if node.module == "veil":  # from veil import X — это модуль veil.X
                    mods = [f"veil.{a.name}" for a in node.names]
            else:
                continue
            for m in mods:
                top = m.split(".")[0]
                if top not in allowed:
                    bad.append(f"{f.relative_to(ROOT)}: {m}")
                elif top == "veil" and m.split(".")[:2] != ["veil", "plugins"]:
                    bad.append(f"{f.relative_to(ROOT)}: {m}")
    assert not bad, bad
