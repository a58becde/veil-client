"""Инструмент каталога плагинов (docs/MARKET.md, «Каталог»): для авторов и для ревьюера каталога.

  python -m veil.market_tool keygen <файл ключа>                    ключ автора или каталога (Ed25519), права 600
  python -m veil.market_tool pack <каталог плагина> <архив.zip>     детерминированный архив пакета
  python -m veil.market_tool sign <архив.zip> <ключ автора>         подпись автора → <архив.zip>.sig
  python -m veil.market_tool add <каталог> <архив.zip> [--reviewed=ГГГГ-ММ-ДД] [--keys=<каталог ключей>]
                                                                   принять пакет после ревью; платный — шифруется,
                                                                   ключ версии — в --keys (перенести на сервер)
  python -m veil.market_tool set-shop <каталог> <@бот> <kid> <ключ>  магазин платных плагинов (публичный ключ магазина)
  python -m veil.market_tool revoke <каталог> <sha256> <причина>    отозвать сборку (боты выключат её у себя)
  python -m veil.market_tool delist <каталог> <id>                  убрать плагин из списка (установленные остаются)
  python -m veil.market_tool sign-index <каталог> <ключ каталога>   подписать index.json — последним шагом
  python -m veil.market_tool verify <каталог> <ключ каталога, публичный> [--keys=<каталог ключей>]
                                                                   проверить всё так же, как бот

Порядок у автора: keygen (один раз; author_pk — в plugin.toml) → pack → sign → pull request с архивом и .sig.
У ревьюера: ревью кода → add → sign-index → verify → коммит. Формат подписей и проверки — veil.market.
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

from nacl.signing import SigningKey

from veil import market
from veil import plugin_manifest as pm
from veil.core.protocol import b64

KEY_PREFIX = "VEILKEY1 "


class ToolError(Exception):
    pass


def keygen(path: Path) -> str:
    if path.exists():
        raise ToolError(f"{path} уже есть — ключ не перезаписываю")
    sk = SigningKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(KEY_PREFIX + b64.enc(bytes(sk)) + "\n")
    return b64.enc(bytes(sk.verify_key))


def load_key(path: Path) -> SigningKey:
    text = path.read_text().strip()
    if not text.startswith(KEY_PREFIX):
        raise ToolError(f"{path}: не файл ключа veil.market_tool")
    if os.stat(path).st_mode & 0o077:
        raise ToolError(f"{path}: ключ доступен другим пользователям (chmod 600)")
    return SigningKey(b64.dec(text[len(KEY_PREFIX):]))


def inspect(data: bytes) -> pm.Manifest:
    """Манифест из архива — после тех же проверок архива и пакета, что у бота."""
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / "pkg"
        market.unpack(data, staged)
        m = pm.parse((staged / pm.MANIFEST).read_text("utf-8"))
        real = Path(tmp) / m.id  # pm.load сверяет id с именем каталога
        staged.rename(real)
        return pm.load(real)


def sign(zip_path: Path, key_path: Path) -> str:
    data = zip_path.read_bytes()
    m = inspect(data)
    sk = load_key(key_path)
    if m.author_pk != b64.enc(bytes(sk.verify_key)):
        raise ToolError("author_pk в plugin.toml не от этого ключа")
    sig = market.sign_plugin(sk, m.id, m.version, hashlib.sha256(data).hexdigest())
    zip_path.with_name(zip_path.name + ".sig").write_text(sig + "\n")
    return sig


def _read_index(cat: Path) -> dict:
    p = cat / market.INDEX
    if not p.exists():
        return {"v": 1, "seq": 0, "generated": "1970-01-01", "plugins": [], "revoked": [], "shop": None}
    return json.loads(p.read_text("utf-8"))


def _write_index(cat: Path, d: dict) -> None:
    d["seq"] += 1
    d["generated"] = datetime.date.today().isoformat()
    d["plugins"].sort(key=lambda e: e["id"])
    raw = (json.dumps(d, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode()
    market.parse_index(raw)  # то, что не примет бот, не пишем
    (cat / market.INDEX).write_bytes(raw)
    (cat / market.INDEX_SIG).unlink(missing_ok=True)  # старая подпись к новому индексу не подходит


def add(cat: Path, zip_path: Path, reviewed: str | None = None, keys_dir: Path | None = None) -> dict:
    data = zip_path.read_bytes()
    m = inspect(data)
    if not m.author_pk:
        raise ToolError("в plugin.toml нет author_pk — автор должен подписывать пакет")
    sig_file = zip_path.with_name(zip_path.name + ".sig")
    if not sig_file.exists():
        raise ToolError(f"нет подписи автора {sig_file.name}")
    sig, digest = sig_file.read_text().strip(), hashlib.sha256(data).hexdigest()
    if not market.verify_plugin(m.author_pk, m.id, m.version, digest, sig):
        raise ToolError("подпись автора не сошлась")
    d = _read_index(cat)
    old = next((e for e in d["plugins"] if e["id"] == m.id), None)
    if old:
        if old["author_pk"] != m.author_pk:
            raise ToolError("у плагина уже другой ключ автора: обновление чужим ключом не принимается")
        if market.version_key(m.version) <= market.version_key(old["version"]):
            raise ToolError(f"версия {m.version} не новее {old['version']}")
        d["plugins"].remove(old)
    rel = f"packages/{m.id}/{m.version}.zip"
    (cat / rel).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sig_file, cat / (rel + ".sig"))
    published = data
    if m.price_stars:  # платный: в каталог — только шифротекст, ключ версии — оператору сервера
        if keys_dir is None:
            raise ToolError("платный плагин: укажите --keys=<каталог> — туда ляжет ключ версии для сервера")
        key = secrets.token_bytes(32)
        published = market.encrypt_blob(data, key, m.id, m.version)
        keys_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(keys_dir / f"{m.id}@{m.version}.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key.hex() + "\n")
        rel += ".enc"
    (cat / rel).write_bytes(published)
    entry = {"id": m.id, "name": m.name, "version": m.version, "description": m.description, "author": m.author,
             "author_pk": m.author_pk, "license": m.license, "permissions": list(m.permissions),
             "network": list(m.network), "price_stars": m.price_stars, "file": rel,
             "sha256": hashlib.sha256(published).hexdigest(), "size": len(published), "zip_sha256": digest,
             "encrypted": bool(m.price_stars), "author_sig": sig,
             "reviewed": reviewed or datetime.date.today().isoformat()}
    d["plugins"].append(entry)
    _write_index(cat, d)
    return entry


def revoke(cat: Path, sha256: str, reason: str) -> None:
    d = _read_index(cat)
    if not market.SHA256.fullmatch(sha256):
        raise ToolError("sha256: 64 шестнадцатеричных символа")
    if any(r["sha256"] == sha256 for r in d["revoked"]):
        raise ToolError("уже отозвана")
    d["revoked"].append({"sha256": sha256, "reason": reason[:300]})
    d["plugins"] = [e for e in d["plugins"] if e["zip_sha256"] != sha256]  # отозванную сборку больше не предлагать
    _write_index(cat, d)


def set_shop(cat: Path, bot: str, kid: str, pk: str) -> None:
    d = _read_index(cat)
    d["shop"] = {"bot": bot, "kid": kid, "pk": pk}
    _write_index(cat, d)  # формат проверит parse_index


def delist(cat: Path, id_: str) -> None:
    d = _read_index(cat)
    if not any(e["id"] == id_ for e in d["plugins"]):
        raise ToolError(f"{id_} нет в каталоге")
    d["plugins"] = [e for e in d["plugins"] if e["id"] != id_]
    _write_index(cat, d)


def sign_index(cat: Path, key_path: Path) -> str:
    raw = (cat / market.INDEX).read_bytes()
    market.parse_index(raw)
    sig = market.sign_index(load_key(key_path), raw)
    (cat / market.INDEX_SIG).write_text(sig + "\n")
    return sig


def verify(cat: Path, market_pk: str, keys_dir: Path | None = None) -> list[str]:
    """Каталог глазами бота: подпись индекса, каждый пакет — скачать (из каталога), сверить, распаковать, сравнить
    манифест. Возвращает список проверенных плагинов; первая ошибка — исключение."""
    class _Store(dict):
        def put(self, k, v):
            self[k] = v
    with tempfile.TemporaryDirectory() as tmp:
        mk = market.Market(_Store(), Path(tmp), {"urls": [cat.resolve().as_uri()], "key": market_pk})

        async def run() -> list[str]:
            idx = await mk.refresh(force=True)
            out = []
            for e in idx.plugins.values():
                key = None
                if e.encrypted:
                    if (cat / "packages" / e.id / f"{e.version}.zip").exists():  # купить было бы незачем
                        raise market.MarketError(f"{e.id} {e.version}: в каталоге открытый архив платного плагина")
                    kf = (keys_dir / f"{e.id}@{e.version}.key") if keys_dir else None
                    if kf is None or not kf.exists():
                        if not market.verify_plugin(e.author_pk, e.id, e.version, e.zip_sha256, e.author_sig):
                            raise market.MarketError(f"{e.id}: подпись автора не сошлась")
                        out.append(f"{e.id} {e.version} {e.zip_sha256[:12]} (зашифрован, без ключа: только подпись) ✓")
                        continue
                    key = bytes.fromhex(kf.read_text().strip())
                pdir, m = await mk.fetch_package(e, key)
                out.append(f"{m.id} {m.version} {e.zip_sha256[:12]} ✓")
                shutil.rmtree(pdir.parent)
            return out
        return asyncio.run(run())


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = dict(a[2:].split("=", 1) for a in argv if a.startswith("--") and "=" in a)
    try:
        cmd = args[0] if args else ""
        if cmd == "keygen" and len(args) == 2:
            print("публичный ключ:", keygen(Path(args[1])))
        elif cmd == "pack" and len(args) == 3:
            data = market.pack(Path(args[1]))
            Path(args[2]).write_bytes(data)
            print(f"{args[2]}: {len(data)} байт, sha256 {hashlib.sha256(data).hexdigest()}")
        elif cmd == "sign" and len(args) == 3:
            print("подпись автора:", sign(Path(args[1]), Path(args[2])))
        elif cmd == "add" and len(args) == 3:
            e = add(Path(args[1]), Path(args[2]), flags.get("reviewed"),
                    Path(flags["keys"]) if flags.get("keys") else None)
            print(f"принят {e['id']} {e['version']} ({e['sha256'][:12]}). Подпишите индекс: sign-index")
        elif cmd == "revoke" and len(args) == 4:
            revoke(Path(args[1]), args[2], args[3])
            print("отозвано. Подпишите индекс: sign-index")
        elif cmd == "delist" and len(args) == 3:
            delist(Path(args[1]), args[2])
            print("убран из списка. Подпишите индекс: sign-index")
        elif cmd == "sign-index" and len(args) == 3:
            sign_index(Path(args[1]), Path(args[2]))
            print("index.json подписан")
        elif cmd == "set-shop" and len(args) == 5:
            set_shop(Path(args[1]), args[2], args[3], args[4])
            print("магазин записан. Подпишите индекс: sign-index")
        elif cmd == "verify" and len(args) == 3:
            for line in verify(Path(args[1]), args[2], Path(flags["keys"]) if flags.get("keys") else None):
                print(line)
            print("каталог в порядке")
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (ToolError, market.MarketError, pm.ManifestError, OSError) as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main(sys.argv[1:]))
