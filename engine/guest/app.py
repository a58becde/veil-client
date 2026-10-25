"""Движок плагинов Veil — точка входа компонента (engine/wit/plugin.wit, docs/PLUGINS.md, «Движок»).

Хост вызывает describe или handle и передаёт пакет целиком: файлы приходят строками, на диске их нет. Модуль плагина
исполняется заново при каждом вызове, вывод print собирается в "log" ответа (бот пишет его в свой журнал).
"""
import importlib.abc
import importlib.util
import sys
import traceback

# isort: split
# Стандартная библиотека для плагинов. В движок попадает только то, что импортировано при сборке (снимок памяти
# CPython), — поэтому список явный и он же в docs/PLUGINS.md. Сети, процессов, потоков и файлов в нём нет.
# F401: модули импортируются ради снимка памяти, самим движком не используются.
import base64  # noqa: F401
import binascii  # noqa: F401
import bisect  # noqa: F401
import calendar  # noqa: F401
import codecs  # noqa: F401
import collections  # noqa: F401
import collections.abc  # noqa: F401
import copy  # noqa: F401
import csv  # noqa: F401
import dataclasses  # noqa: F401
import datetime  # noqa: F401
import decimal  # noqa: F401
import difflib  # noqa: F401
import enum  # noqa: F401
import fractions  # noqa: F401
import functools  # noqa: F401
import hashlib  # noqa: F401
import heapq  # noqa: F401
import hmac  # noqa: F401
import html  # noqa: F401
import html.parser  # noqa: F401
import io  # noqa: F401
import ipaddress  # noqa: F401
import itertools  # noqa: F401
import json  # noqa: F401
import math  # noqa: F401
import operator  # noqa: F401
import random  # noqa: F401
import re  # noqa: F401
import secrets  # noqa: F401
import statistics  # noqa: F401
import string  # noqa: F401
import struct  # noqa: F401
import textwrap  # noqa: F401
import time  # noqa: F401
import typing  # noqa: F401
import unicodedata  # noqa: F401
import urllib.parse  # noqa: F401
import uuid  # noqa: F401
import zlib  # noqa: F401

from componentize_py_types import Err
from wit_world import WitWorld as _World

from veil import plugins

LOG_LINES, LOG_LINE = 100, 500


class _NoModule(importlib.abc.MetaPathFinder):
    """Последний в поиске: модуля нет в движке — сказать, что есть."""

    def find_spec(self, fullname, path=None, target=None):
        raise ModuleNotFoundError(f"модуля {fullname} нет в движке плагинов (сторонних библиотек нет, стандартная — "
                                  "по списку из docs/PLUGINS.md)", name=fullname)


class _Log:
    """stdout и stderr плагина: строки уходят боту в ответе, а не в никуда."""

    def __init__(self):
        self.lines: list[str] = []
        self.part = ""

    def write(self, s: str) -> int:
        self.part += str(s)
        while "\n" in self.part:
            line, self.part = self.part.split("\n", 1)
            if len(self.lines) < LOG_LINES:
                self.lines.append(line[:LOG_LINE])
        return len(s)

    def flush(self) -> None:
        pass

    def take(self) -> list[str]:
        if self.part and len(self.lines) < LOG_LINES:
            self.lines.append(self.part[:LOG_LINE])
        self.part = ""
        return self.lines


class _Package(importlib.abc.MetaPathFinder, importlib.abc.InspectLoader):
    """Модули пакета из присланных строк: точка входа — veil_plugin_<id>, остальные .py — по имени файла."""

    def __init__(self, pkg: dict):
        self.files = {name[:-3]: text for name, text in pkg["files"].items() if name.endswith(".py")}
        self.entry, self.entry_file = f"veil_plugin_{pkg['id']}", pkg["entry"]
        self.files[self.entry] = self.files[pkg["entry"]]

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.files:
            return importlib.util.spec_from_loader(fullname, self, origin=f"{self._file(fullname)}.py")
        return None

    def get_source(self, fullname: str) -> str:
        return self.files[fullname]

    def _file(self, fullname: str) -> str:
        return self.entry_file if fullname == self.entry else fullname

    def get_code(self, fullname: str):
        return compile(self.files[fullname], f"{self._file(fullname)}.py", "exec")

    def is_package(self, fullname: str) -> bool:
        return False


def _load(raw: str) -> plugins._Plugin:
    pkg = json.loads(raw)
    finder = _Package(pkg)
    sys.meta_path.insert(0, finder)
    sys.meta_path.append(_NoModule())
    plugins._plugin = plugins._Plugin(pkg.get("settings") or {})
    plugins._loading = True
    try:
        __import__(finder.entry)
    finally:
        plugins._loading = False
    return plugins._plugin


def _error(e: BaseException) -> str:
    tb = traceback.extract_tb(e.__traceback__)
    where = next((f"{f.filename}:{f.lineno}" for f in reversed(tb) if not f.filename.startswith("/")), "")
    return f"{type(e).__name__}: {e}"[:300] + (f" ({where})" if where else "")


def _guard(fn):
    log = _Log()
    sys.stdout = sys.stderr = log
    try:
        value = fn()
    except Exception as e:  # noqa: BLE001 — ошибка плагина уходит боту словами, движок не падает
        print(traceback.format_exc(limit=-8), end="")
        raise Err(json.dumps({"error": _error(e), "log": log.take()}, ensure_ascii=False)) from None
    return json.dumps({**value, "log": log.take()}, ensure_ascii=False)


class WitWorld(_World):
    def describe(self, pkg: str) -> str:
        return _guard(lambda: _load(pkg).describe())

    def handle(self, pkg: str, event: str) -> str:
        def go():
            p = _load(pkg)
            return {"value": plugins.dispatch(p, json.loads(event))}
        return _guard(go)
