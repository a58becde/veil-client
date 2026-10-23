"""Сборка движка плагинов: engine/guest (CPython + SDK) → engine/dist/veil-engine.wasm (docs/PLUGINS.md, «Движок»).

    python3 engine/build.py [--out=путь]

Сборщик — componentize-py из engine/requirements-build.lock (с хешами), в отдельном venv engine/.build/: боту он не
нужен. Сборка неповторяема (снимок памяти CPython каждый раз немного другой), поэтому официальный движок — файл из
релиза с SHA-256, закреплённым в veil/plugin_engine.py (ENGINE_SHA256). Свою сборку бот примет только после
подтверждения хеша в терминале: python -m veil <конфиг> engine trust.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    out = Path(next((a.split("=", 1)[1] for a in argv if a.startswith("--out=")), HERE / "dist" / "veil-engine.wasm"))
    venv = HERE / ".build" / "venv"
    tool = venv / "bin" / "componentize-py"
    # Команды ниже — свои пути и закреплённый по хешам сборщик, ввода извне нет (S603).
    if not tool.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)  # noqa: S603
        subprocess.run([str(venv / "bin" / "pip"), "install", "-q", "--require-hashes", "-r",  # noqa: S603
                        str(HERE / "requirements-build.lock")], check=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    subprocess.run([str(tool), "-q", "-d", str(HERE / "wit"), "-w", "engine", "componentize", "-p",  # noqa: S603
                    str(HERE / "guest"), "app", "-o", str(tmp)], check=True)
    tmp.replace(out)
    print(f"{out}\nSHA-256 {hashlib.sha256(out.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
