#!/bin/sh
# Проверки veil-client: один скрипт для локальных ворот и для CI.
#   sh tools/check.sh           — все проверки (по умолчанию, режим all)
#   sh tools/check.sh vectors   — только эталонные векторы протокола
# Интерпретатор — $VEIL_PY (по умолчанию .venv/bin/python); все инструменты берутся из его окружения.
# Рядом с клиентом должен лежать veil-protocol (векторы, keys.json). Выходы: 0 — прошло, 1 — проверка не
# прошла, 2 — неверный вызов или нет окружения.
set -eu
cd "$(dirname "$0")/.."

mode="${1:-all}"
[ "$#" -le 1 ] || { echo "использование: sh tools/check.sh [all|vectors]" >&2; exit 2; }
case "$mode" in
all | vectors) ;;
*)
	echo "неизвестный режим: $mode (допустимо: all, vectors)" >&2
	exit 2
	;;
esac

py="${VEIL_PY:-.venv/bin/python}"
[ -d ../veil-protocol ] || { echo "нет ../veil-protocol: положите репозиторий протокола рядом с клиентом" >&2; exit 2; }
command -v "$py" >/dev/null 2>&1 || [ -x "$py" ] || { echo "нет интерпретатора: $py (задайте VEIL_PY)" >&2; exit 2; }

step() { printf '\n== veil-client: %s\n' "$1"; }
# Консольные команды (lint-imports) лежат рядом с интерпретатором.
bindir=$(dirname "$(command -v "$py" 2>/dev/null || echo "$py")")

if [ "$mode" = vectors ]; then
	step "эталонный клиент проходит векторы"
	"$py" -m pytest -q -W ignore -p no:cacheprovider \
		tests/test_vectors.py tests/test_poprf_rfc9497.py tests/test_issue.py
	exit 0
fi

step "ruff: стиль PEP 8 и ошибки (правила — pyproject.toml)"
"$py" -m ruff check -q veil tools engine
"$py" -m ruff check -q --select F,E,W,I tests
step "bandit"
"$py" -m bandit -q -r veil engine/guest -s B101,B105,B107
step "import-linter: границы модулей (контракты — pyproject.toml)"
"$bindir/lint-imports" --no-cache
step "тесты"
[ -f engine/dist/veil-engine.wasm ] || "$py" engine/build.py
"$py" -m pytest -q -W ignore -p no:cacheprovider
