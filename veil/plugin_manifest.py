"""Манифест пакета плагина plugin.toml (docs/MARKET.md, «Пакет плагина»): строгая проверка, разрешения, хеш пакета.

Формат общий для локального пакета, каталога и платных плагинов.
"""
from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

API = 1
MANIFEST = "plugin.toml"
ID = re.compile(r"[a-z][a-z0-9_]{0,31}")
VERSION = re.compile(r"(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})")
MODULE = re.compile(r"[a-z_][a-z0-9_]{0,63}")
HOST = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
B64_ED25519 = re.compile(r"[A-Za-z0-9_-]{43}")
SPDX = re.compile(r"[A-Za-z0-9.+-]{1,64}")

# Разрешение → что оно даёт (docs/MARKET.md, таблица разрешений).
PERMISSIONS = ("replies", "private", "published", "before_send", "errors", "tokens", "commands", "notify", "drafts",
               "net")
SENSITIVE = frozenset({"private", "published", "before_send"})  # читает ваше: текст постов, «лично для», номера
EVENT_PERMISSION = {"start": None, "reply": "replies", "hidden_for_me": "private", "post_published": "published",
                    "error": "errors", "tokens_low": "tokens", "before_send": "before_send"}
CALL_PERMISSION = {"notify": "notify", "propose": "drafts", "tokens_today": "tokens", "http": "net",
                   "show": "notify", "edit": "notify", "ask": "commands"}
# Интерфейс плагина в чате владельца (кнопки, вопросы, кнопки у ссылок) — разрешение commands: всё это запускает только
# сам владелец, нажатием. Кнопки в сообщении плагина (show/edit) тоже требуют commands.
UI_PERMISSION = "commands"

MAX_FILES, MAX_PACKAGE = 64, 1 << 20  # файлов в пакете и байт всего: только код и README


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class Manifest:
    id: str
    name: str
    version: str
    api: int
    entry: str
    description: str
    author: str
    license: str
    permissions: tuple[str, ...]
    network: tuple[str, ...]
    price_stars: int
    author_pk: str

    @property
    def sensitive(self) -> tuple[str, ...]:
        return tuple(p for p in self.permissions if p in SENSITIVE)

    @property
    def leaks_to_network(self) -> bool:
        """Читает ваше и ходит в сеть: может унести текст анонимного поста вместе с IP вашей машины."""
        return bool(self.sensitive) and "net" in self.permissions

    def grant(self) -> dict:
        """То, на что соглашается владелец: разрешения, хосты и ключ автора (не версия — обновление того же автора
        с теми же правами согласия не просит; другой автор под тем же id — просит)."""
        return {"permissions": sorted(self.permissions), "network": sorted(self.network), "author_pk": self.author_pk}

    def covered_by(self, grant: dict | None) -> bool:
        return bool(grant) and set(self.permissions) <= set(grant.get("permissions", ())) \
            and set(self.network) <= set(grant.get("network", ())) and grant.get("author_pk", "") == self.author_pk

    def to_json(self) -> dict:
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in self.__dict__.items()}


_FIELDS = {"id": str, "name": str, "version": str, "api": int, "entry": str, "description": str, "author": str,
           "license": str, "permissions": list, "network": list, "price_stars": int, "author_pk": str}
_REQUIRED = ("id", "name", "version", "api", "entry", "description", "author", "license", "permissions")


def _text(d: dict, key: str, limit: int) -> str:
    v = d[key]
    if not v.strip() or len(v) > limit or any(ord(c) < 0x20 and c != "\n" for c in v):
        raise ManifestError(f"{key}: от 1 до {limit} символов, без управляющих")
    return v


def parse(text: str) -> Manifest:
    try:
        d = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ManifestError(f"plugin.toml: {e}") from None
    return from_fields(d)


def from_fields(d: dict) -> Manifest:
    """Проверка полей манифеста — одна и для plugin.toml, и для записи индекса каталога (veil.market)."""
    unknown = set(d) - set(_FIELDS)
    if unknown:
        raise ManifestError(f"неизвестные поля: {', '.join(sorted(unknown))}")
    for k in _REQUIRED:
        if k not in d:
            raise ManifestError(f"нет поля {k}")
    for k, t in _FIELDS.items():
        if k in d and (type(d[k]) is not t):
            raise ManifestError(f"{k}: неверный тип")
    if not ID.fullmatch(d["id"]):
        raise ManifestError("id: a-z, 0-9, _ (до 32, с буквы)")
    if not VERSION.fullmatch(d["version"]):
        raise ManifestError("version: X.Y.Z")
    if d["api"] != API:
        raise ManifestError(f"api {d['api']} не поддерживается (бот знает api {API}) — обновите бота или плагин")
    if not MODULE.fullmatch(d["entry"]):
        raise ManifestError("entry: имя модуля Python")
    if not SPDX.fullmatch(d["license"]):
        raise ManifestError("license: идентификатор SPDX")
    perms = d["permissions"]
    if any(p not in PERMISSIONS for p in perms) or len(set(perms)) != len(perms):
        raise ManifestError(f"permissions: только {', '.join(PERMISSIONS)}, без повторов")
    net = d.get("network", [])
    if any(not isinstance(h, str) or not HOST.fullmatch(h) for h in net) or len(set(net)) != len(net) or len(net) > 16:
        raise ManifestError("network: до 16 имён хостов (api.example.com), без схем, портов и масок")
    if bool(net) != ("net" in perms):
        raise ManifestError("network задаётся вместе с разрешением net, и наоборот")
    price = d.get("price_stars", 0)
    if not 0 <= price <= 100_000:
        raise ManifestError("price_stars: от 0 до 100000")
    pk = d.get("author_pk", "")
    if pk and not B64_ED25519.fullmatch(pk):
        raise ManifestError("author_pk: ключ Ed25519 в base64url")
    return Manifest(d["id"], _text(d, "name", 64), d["version"], d["api"], d["entry"], _text(d, "description", 500),
                    _text(d, "author", 64), d["license"], tuple(perms), tuple(net), price, pk)


def package_files(pdir: Path) -> list[Path]:
    """Файлы пакета в стабильном порядке. Только обычные файлы .py, plugin.toml и README.md, без ссылок и подкаталогов:
    то, что в пакете, должно быть видно ревьюеру целиком."""
    out = []
    for p in sorted(pdir.iterdir(), key=lambda x: x.name):
        if p.is_symlink() or not p.is_file():
            if p.name == "__pycache__" and p.is_dir() and not p.is_symlink():
                continue
            raise ManifestError(f"{p.name}: в пакете только файлы, без ссылок и подкаталогов")
        if not (p.suffix == ".py" or p.name in (MANIFEST, "README.md")):
            raise ManifestError(f"{p.name}: в пакете только .py, plugin.toml и README.md")
        out.append(p)
    if len(out) > MAX_FILES or sum(p.stat().st_size for p in out) > MAX_PACKAGE:
        raise ManifestError(f"пакет больше {MAX_FILES} файлов или {MAX_PACKAGE >> 20} МиБ")
    return out


def read_package(pdir: Path) -> tuple[dict[str, bytes], str]:
    """Файлы пакета и SHA-256 содержимого (имена и байты) — из одного чтения:
    в движок уходит ровно то, что посчитано."""
    files, h = {}, hashlib.sha256()
    for p in package_files(pdir):
        data = p.read_bytes()
        h.update(f"{p.name}\0{len(data)}\0".encode())
        h.update(data)
        files[p.name] = data
    return files, h.hexdigest()


def package_hash(pdir: Path) -> str:
    """SHA-256 содержимого пакета. О любой смене кода бот сообщает владельцу."""
    return read_package(pdir)[1]


def load(pdir: Path) -> Manifest:
    m = parse((pdir / MANIFEST).read_text(encoding="utf-8"))
    if m.id != pdir.name:
        raise ManifestError(f"id {m.id} не совпадает с каталогом {pdir.name}")
    if not (pdir / f"{m.entry}.py").is_file():
        raise ManifestError(f"нет модуля {m.entry}.py")
    package_files(pdir)
    return m
