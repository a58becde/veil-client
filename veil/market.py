"""Маркет плагинов, этап 2 (docs/MARKET.md, «Каталог»): подписанный индекс, пакеты с подписью автора, отзыв, установка.

Каталог — публичный репозиторий `veil-plugins`: `index.json` (все плагины и отозванные сборки), `index.json.sig`
(подпись ключом каталога) и `packages/<id>/<version>.zip`. Бот скачивает индекс целиком и пакеты — с адресов из
config.toml (`[market] urls`), а не с сервера Veil. Ключ каталога бот закрепляет из config.toml при первом
использовании, как ключ сервера: подменённый конфиг не уведёт бота на чужой каталог молча.

Проверки пакета перед установкой: размер, SHA-256 из индекса, подпись автора (`author_pk` из индекса и из манифеста —
один и тот же ключ), сборка не отозвана, архив без каталогов, ссылок и посторонних файлов, манифест совпадает с
индексом. Обновление чужим ключом автора — отказ. Форматы подписей — здесь же; ими пользуется и инструмент каталога
(veil.market_tool).

Платные плагины (этап 3, spec/10): пакет в каталоге зашифрован ключом версии. Лицензия — слепая подпись магазина
(POPRF, как токены эмитента, с info «veil/v1/license/<id>»): бот ослепляет случайный вход, владелец пересылает запрос
VEILLIC боту-магазину и платит Stars, ответ VEILLICRES бот проверяет (DLEQ) и получает лицензию. Затем анонимно
активирует её на сервере (market.redeem) на свой ключ установки и получает сертификат и ключ версии; ключи следующих
версий — market.key с сертификатом. Магазин знает, кто заплатил, сервер — какая установка; связать их нельзя.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import secrets
import shutil
import stat
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

import httpx
import nacl.bindings
import nacl.utils
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.signing import SigningKey, VerifyKey

from veil import plugin_manifest as pm
from veil.core.crypto import poprf
from veil.core.protocol import b64, jcs

INDEX, INDEX_SIG = "index.json", "index.json.sig"
CTX_INDEX = b"veil/v1/market-index\n"
CTX_PLUGIN = b"veil/v1/plugin\n"
CTX_CERT = b"veil/v1/license-cert\n"   # сервер: лицензия плагина активирована на ключ установки
CTX_PROOF = b"veil/v1/license-key\n"   # установка: прошу ключ версии
LICENSE_INFO = b"veil/v1/license/"      # + id плагина: публичный параметр POPRF лицензии
# зашифрованный пакет: MAGIC || nonce 24 || XChaCha20-Poly1305(zip, aad=id\nверсия)
BLOB_MAGIC = b"VEILPKG1"
REQ_PREFIX, RESP_PREFIX = "VEILLIC", "VEILLICRES"
DEFAULT_URLS = ("https://raw.githubusercontent.com/a58becde/veil-plugins/main/",)
INDEX_MAX, ZIP_MAX = 2 << 20, 2 << 20   # байт: индекс и архив пакета
REFRESH_EVERY = 600                     # с: индекс — не чаще раза в 10 минут без явной просьбы
STALE_DAYS = 60                         # индекс старше — владельцу предупреждение (каталог могли «заморозить»)
FILE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
SHA256 = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SIG = re.compile(r"[A-Za-z0-9_-]{86}")


class MarketError(Exception):
    """Каталог или пакет не прошли проверку; текст — для владельца."""


# --- подписи (одни и те же у бота и у инструмента каталога) ---
def plugin_message(id_: str, version: str, sha256: str) -> bytes:
    return CTX_PLUGIN + f"{id_}\n{version}\n{sha256}".encode()


def sign_plugin(sk: SigningKey, id_: str, version: str, sha256: str) -> str:
    return b64.enc(sk.sign(plugin_message(id_, version, sha256)).signature)


def verify_plugin(author_pk: str, id_: str, version: str, sha256: str, sig: str) -> bool:
    try:
        VerifyKey(b64.dec(author_pk)).verify(plugin_message(id_, version, sha256), b64.dec(sig))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def sign_index(sk: SigningKey, raw: bytes) -> str:
    return b64.enc(sk.sign(CTX_INDEX + raw).signature)


def verify_index_sig(market_pk: str, raw: bytes, sig: str) -> bool:
    try:
        VerifyKey(b64.dec(market_pk)).verify(CTX_INDEX + raw, b64.dec(sig.strip()))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def cert_message(plugin: str, lic_pk: bytes) -> bytes:
    return CTX_CERT + plugin.encode() + b"\n" + lic_pk


def proof_message(plugin: str, version: str) -> bytes:
    return CTX_PROOF + f"{plugin}\n{version}".encode()


def encrypt_blob(zip_bytes: bytes, key: bytes, id_: str, version: str, nonce: bytes | None = None) -> bytes:
    nonce = nonce or nacl.utils.random(24)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(zip_bytes, f"{id_}\n{version}".encode(), nonce, key)
    return BLOB_MAGIC + nonce + ct


def decrypt_blob(blob: bytes, key: bytes, id_: str, version: str) -> bytes:
    if not blob.startswith(BLOB_MAGIC) or len(blob) < len(BLOB_MAGIC) + 24 + 16 or len(key) != 32:
        raise MarketError("зашифрованный пакет повреждён")
    nonce, ct = blob[len(BLOB_MAGIC):len(BLOB_MAGIC) + 24], blob[len(BLOB_MAGIC) + 24:]
    try:
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, f"{id_}\n{version}".encode(), nonce, key)
    except CryptoError:
        raise MarketError("пакет не расшифровался ключом из лицензии") from None


def version_key(v: str) -> tuple[int, int, int]:
    a, b, c = v.split(".")
    return int(a), int(b), int(c)


# --- индекс ---
@dataclass(frozen=True)
class Entry:
    id: str
    name: str
    version: str
    description: str
    author: str
    author_pk: str
    license: str
    permissions: tuple[str, ...]
    network: tuple[str, ...]
    price_stars: int
    file: str
    sha256: str
    size: int
    author_sig: str
    reviewed: str
    zip_sha256: str   # SHA-256 самого zip: его подписывает автор, по нему отзывают; у бесплатного = sha256
    encrypted: bool   # платный: файл — зашифрованный пакет, ключ даёт лицензия

    def manifest_fields(self) -> dict:
        """Поля, которые обязаны совпасть с plugin.toml пакета (списки — списками, как в манифесте)."""
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in
                ((k, getattr(self, k)) for k in ("id", "name", "version", "description", "author", "author_pk",
                                                 "license", "permissions", "network", "price_stars"))}


@dataclass(frozen=True)
class Shop:
    bot: str     # @бот-магазин
    kid: str
    pk: bytes    # публичный ключ POPRF магазина


@dataclass(frozen=True)
class Index:
    seq: int
    generated: str
    plugins: dict[str, Entry]
    revoked: dict[str, str]  # sha256 zip → причина
    shop: Shop | None = None


_ENTRY = {"id": str, "name": str, "version": str, "description": str, "author": str, "author_pk": str, "license": str,
          "permissions": list, "network": list, "price_stars": int, "file": str, "sha256": str, "size": int,
          "author_sig": str, "reviewed": str, "zip_sha256": str, "encrypted": bool}


def parse_index(raw: bytes) -> Index:
    """Строгий разбор index.json: лишние или пропущенные поля, неверные типы и форматы — отказ целиком."""
    try:
        d = jcs.strict_loads(raw)
    except ValueError as e:
        raise MarketError(f"index.json: {e}") from None
    if not isinstance(d, dict) or set(d) != {"v", "seq", "generated", "plugins", "revoked", "shop"} or d["v"] != 1:
        raise MarketError("index.json: неизвестный формат")
    shop = None
    if d["shop"] is not None:
        sh = d["shop"]
        if not isinstance(sh, dict) or set(sh) != {"bot", "kid", "pk"} or not isinstance(sh["bot"], str) \
                or not re.fullmatch(r"@[A-Za-z0-9_]{5,32}", sh["bot"]) or not isinstance(sh["kid"], str) \
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", sh["kid"]) or not isinstance(sh["pk"], str):
            raise MarketError("index.json: shop")
        try:
            pk = b64.dec(sh["pk"])
        except ValueError:
            raise MarketError("index.json: shop") from None
        if len(pk) != 32:
            raise MarketError("index.json: shop")
        shop = Shop(sh["bot"], sh["kid"], pk)
    if type(d["seq"]) is not int or d["seq"] < 1 or not isinstance(d["generated"], str) \
            or not DATE.fullmatch(d["generated"]):
        raise MarketError("index.json: seq и generated")
    plugins: dict[str, Entry] = {}
    for e in d["plugins"] if isinstance(d["plugins"], list) else [None]:
        if not isinstance(e, dict) or set(e) != set(_ENTRY) or any(type(e[k]) is not t for k, t in _ENTRY.items()):
            raise MarketError("index.json: неверная запись плагина")
        try:  # поля манифеста — по тем же правилам, что plugin.toml
            m = pm.from_fields({**{k: e[k] for k in ("id", "name", "version", "description", "author", "author_pk",
                                                     "license", "permissions", "network", "price_stars")},
                                "api": pm.API, "entry": "main"})  # api и entry — только в самом пакете
        except pm.ManifestError as err:
            raise MarketError(f"index.json, {e.get('id')}: {err}") from None
        if not m.author_pk:
            raise MarketError(f"index.json, {m.id}: нет ключа автора")
        enc = e["encrypted"]
        if enc != (m.price_stars > 0) or e["file"] != f"packages/{m.id}/{m.version}.zip" + (".enc" if enc else "") \
                or not SHA256.fullmatch(e["sha256"]) or not SHA256.fullmatch(e["zip_sha256"]) \
                or (not enc and e["zip_sha256"] != e["sha256"]) \
                or not 0 < e["size"] <= ZIP_MAX or not SIG.fullmatch(e["author_sig"]) \
                or not DATE.fullmatch(e["reviewed"]):
            raise MarketError(f"index.json, {m.id}: file, sha256, size, encrypted, author_sig или reviewed")
        if m.id in plugins:
            raise MarketError(f"index.json: {m.id} дважды")
        plugins[m.id] = Entry(m.id, m.name, m.version, m.description, m.author, m.author_pk, m.license, m.permissions,
                              m.network, m.price_stars, e["file"], e["sha256"], e["size"], e["author_sig"],
                              e["reviewed"], e["zip_sha256"], enc)
    revoked: dict[str, str] = {}
    for r in d["revoked"] if isinstance(d["revoked"], list) else [None]:
        if not isinstance(r, dict) or set(r) != {"sha256", "reason"} or not isinstance(r["sha256"], str) \
                or not SHA256.fullmatch(r["sha256"]) or not isinstance(r["reason"], str) or len(r["reason"]) > 300:
            raise MarketError("index.json: неверная запись отзыва")
        revoked[r["sha256"]] = r["reason"]
    return Index(d["seq"], d["generated"], plugins, revoked, shop)


# --- архив пакета ---
def unpack(data: bytes, dest: Path) -> None:
    """Распаковать zip пакета в пустой каталог dest. Только плоский список разрешённых файлов, без ссылок, шифрования и
    повторов, всего не больше лимита пакета — иначе отказ до записи на диск."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise MarketError("архив пакета повреждён") from None
    infos = z.infolist()
    names = [i.filename for i in infos]
    if not infos or len(infos) > pm.MAX_FILES or len(set(names)) != len(names):
        raise MarketError("в архиве пакета нет файлов, их слишком много или есть повторы")
    total = 0
    for i in infos:
        mode = (i.external_attr >> 16) & 0o170000
        if not FILE.fullmatch(i.filename) or i.is_dir() or i.flag_bits & 0x1 or mode not in (0, stat.S_IFREG) \
                or not (i.filename.endswith(".py") or i.filename in (pm.MANIFEST, "README.md")):
            raise MarketError(f"{i.filename!r}: в пакете только .py, plugin.toml и README.md, без каталогов и ссылок")
        total += i.file_size
    if total > pm.MAX_PACKAGE:
        raise MarketError("пакет больше 1 МиБ")
    dest.mkdir(mode=0o700)
    for i in infos:
        with z.open(i) as src:
            body = src.read(pm.MAX_PACKAGE + 1)  # file_size в архиве может врать: читаем не больше лимита
        if len(body) != i.file_size:
            raise MarketError(f"{i.filename}: размер не совпадает с заявленным")
        fd = os.open(dest / i.filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(body)


def pack(pdir: Path) -> bytes:
    """Детерминированный zip пакета: файлы по имени, одна дата, права 600 — одинаковый код даёт одинаковый SHA-256."""
    files = pm.package_files(pdir)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            info = zipfile.ZipInfo(f.name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, f.read_bytes())
    return buf.getvalue()


# --- лицензии платных плагинов (этап 3) ---
class LicenseMixin:
    """Лицензии платных плагинов (spec/10). store: market_orders {id: незавершённая покупка — kid, ключ магазина,
    вход и ослепление}, market_licenses {id: kid, input, output, lic_sk (ключ установки), cert (сертификат сервера)}."""

    store: object
    index: "Index | None"

    def licenses(self) -> dict[str, dict]:
        return dict(self.store.get("market_licenses") or {})

    def start_purchase(self, e: Entry) -> str:
        """Ослеплённый запрос лицензии VEILLIC для бота-магазина. Ослепление хранится до ответа магазина. Повторное
        «Купить» даёт тот же запрос: иначе оплата по первому сообщению не сошлась бы с сохранённым ослеплением."""
        shop = self.index.shop if self.index else None
        if shop is None:
            raise MarketError("в каталоге нет магазина — платные плагины пока не продаются")
        orders = dict(self.store.get("market_orders") or {})
        o = orders.get(e.id)
        if o and o["kid"] == shop.kid and o["pk"] == b64.enc(shop.pk):
            st = poprf.blind(b64.dec(o["input"]), int(o["blind"], 16))
        else:
            st = poprf.blind(secrets.token_bytes(32))
            orders[e.id] = {"kid": shop.kid, "pk": b64.enc(shop.pk), "input": b64.enc(st.input),
                            "blind": format(st.blind, "x"), "at": int(time.time())}
            self.store.put("market_orders", orders)
        body = jcs.canonicalize({"v": 1, "plugin": e.id, "kid": shop.kid, "blinded": b64.enc(st.blinded)})
        return f"{REQ_PREFIX} {b64.enc(body)}"

    def accept_license(self, text: str) -> str:
        """Ответ магазина VEILLICRES → проверенная (DLEQ) лицензия. Возвращает id плагина."""
        payload = text.strip()
        if not payload.startswith(RESP_PREFIX + " "):
            raise MarketError("это не ответ магазина")
        try:
            d = jcs.strict_loads(b64.dec(payload[len(RESP_PREFIX) + 1:].strip()))
            ok = isinstance(d, dict) and set(d) == {"v", "plugin", "kid", "evaluated", "proof"} and d["v"] == 1
            plugin = d["plugin"] if ok else ""
            evaluated, proof = b64.dec(d["evaluated"]), b64.dec(d["proof"])
        except (ValueError, KeyError, TypeError):
            raise MarketError("ответ магазина повреждён — перешлите его целиком") from None
        orders = dict(self.store.get("market_orders") or {})
        o = orders.get(plugin) if ok else None
        if o is None or d["kid"] != o["kid"]:
            raise MarketError("это ответ не на запрос этого бота (или на уже принятый)")
        st = poprf.blind(b64.dec(o["input"]), int(o["blind"], 16))
        try:
            out = poprf.finalize_batch([st], [evaluated], proof, b64.dec(o["pk"]), LICENSE_INFO + plugin.encode())[0]
        except (poprf.ProofError, ValueError):
            raise MarketError("ответ магазина не прошёл проверку подписи (DLEQ) — лицензия не принята") from None
        lic = self.licenses()
        lic[plugin] = {"kid": o["kid"], "input": o["input"], "output": b64.enc(out),
                       "lic_sk": b64.enc(bytes(SigningKey.generate())), "cert": None}
        self.store.put("market_licenses", lic)  # до активации: сбой связи после оплаты лицензию не теряет
        orders.pop(plugin)
        self.store.put("market_orders", orders or None)
        return plugin

    async def license_key(self, request, e: Entry, server_pk: bytes) -> bytes:
        """Ключ версии по лицензии. Первый раз — активация market.redeem на ключ установки (сертификат сервера
        проверяется и сохраняется), дальше — market.key с сертификатом и подписью ключом установки.
        request(op, body) — анонимный запрос к серверу (бот передаёт свой обмен)."""
        lic = self.licenses().get(e.id)
        if not lic:
            raise MarketError("лицензии на этот плагин нет — купите его в /market")
        sk = SigningKey(b64.dec(lic["lic_sk"]))
        lic_pk = bytes(sk.verify_key)
        if not lic.get("cert"):
            res = await request("market.redeem", {"plugin": e.id, "version": e.version, "kid": lic["kid"],
                                                  "input": lic["input"], "output": lic["output"],
                                                  "lic_pk": b64.enc(lic_pk)})
            try:
                VerifyKey(server_pk).verify(cert_message(e.id, lic_pk), b64.dec(res["cert"]))
            except (BadSignatureError, ValueError, KeyError, TypeError):
                raise MarketError("сертификат лицензии не от сервера Veil") from None
            all_ = self.licenses()
            all_[e.id] = {**lic, "cert": res["cert"]}
            self.store.put("market_licenses", all_)
        else:
            res = await request("market.key", {"plugin": e.id, "version": e.version, "lic_pk": b64.enc(lic_pk),
                                               "cert": lic["cert"],
                                               "proof": b64.enc(sk.sign(proof_message(e.id, e.version)).signature)})
        try:
            key = b64.dec(res["key"])
        except (ValueError, KeyError, TypeError):
            key = b""
        if len(key) != 32:
            raise MarketError("сервер вернул неверный ключ пакета")
        return key


# --- бот: каталог, установка, отзыв ---
class Market(LicenseMixin):
    """Маркет одного бота. Данные — в data/market/: кэш индекса, установленные пакеты, временные файлы.

    store — хранилище бота: market_seq (наибольший виденный seq), market_installed {id: {version, sha256,
    author_pk}}, pinned_market (закреплённый ключ каталога)."""

    def __init__(self, store, data_dir: Path, conf: dict, *, proxy: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.store, self.root = store, Path(data_dir) / "market"
        self.urls = tuple(conf.get("urls") or DEFAULT_URLS)
        self.key = conf.get("key") or ""
        self.proxy, self.transport = proxy, transport
        self.index: Index | None = None
        self.fetched = 0.0

    @property
    def plugins_dir(self) -> Path:
        return self.root / "plugins"

    def pinned_key(self) -> str:
        """Ключ каталога: из конфига, закреплённый при первом использовании. Смена — только командой pin-market."""
        if not self.key:
            raise MarketError("в config.toml нет ключа каталога ([market] key)")
        pinned = self.store.get("pinned_market")
        if pinned is None:
            self.store.put("pinned_market", self.key)
            return self.key
        if pinned != self.key:
            raise MarketError("ключ каталога в config.toml отличается от закреплённого. Если проект объявил смену "
                              "ключа — подтвердите её в терминале: python -m veil <конфиг> pin-market")
        return pinned

    def installed(self) -> dict[str, dict]:
        return dict(self.store.get("market_installed") or {})

    # --- сеть ---
    async def _get(self, path: str, limit: int) -> bytes:
        """Файл каталога по первому ответившему адресу из [market] urls. file:// — для локального каталога."""
        errors = []
        for base in self.urls:
            url = base.rstrip("/") + "/" + path
            try:
                if url.startswith("file://"):
                    p = Path(unquote(url[len("file://"):]))
                    if p.stat().st_size > limit:
                        raise MarketError(f"{path}: больше {limit >> 20} МиБ")
                    return p.read_bytes()
                async with httpx.AsyncClient(timeout=30, proxy=self.proxy, trust_env=self.proxy is None,
                                             follow_redirects=True, transport=self.transport) as c:
                    async with c.stream("GET", url) as r:
                        if r.status_code != 200:
                            raise MarketError(f"{path}: HTTP {r.status_code}")
                        data = bytearray()
                        async for chunk in r.aiter_bytes():
                            data += chunk
                            if len(data) > limit:
                                raise MarketError(f"{path}: больше {limit >> 20} МиБ")
                        return bytes(data)
            except (OSError, httpx.HTTPError, MarketError) as e:
                errors.append(f"{base}: {e}")
        raise MarketError("каталог недоступен: " + "; ".join(errors)[:500])

    async def refresh(self, force: bool = False) -> Index:
        """Свежий индекс (не чаще раза в 10 минут без force): подпись ключом каталога, seq не меньше виденного —
        старый подписанный индекс (без новых отзывов) подсунуть нельзя."""
        if self.index and not force and time.monotonic() - self.fetched < REFRESH_EVERY:
            return self.index
        key = self.pinned_key()
        raw = await self._get(INDEX, INDEX_MAX)
        sig = (await self._get(INDEX_SIG, 1024)).decode("ascii", "replace")
        if not verify_index_sig(key, raw, sig):
            raise MarketError("подпись каталога не сошлась — индекс не от проекта или повреждён")
        idx = parse_index(raw)
        seen = int(self.store.get("market_seq") or 0)
        if idx.seq < seen:
            raise MarketError(f"каталог старее уже виденного (seq {idx.seq} < {seen}) — возможна подмена")
        self.store.put("market_seq", idx.seq)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write(self.root / INDEX, raw)
        _write(self.root / INDEX_SIG, sig.encode())
        self.index, self.fetched = idx, time.monotonic()
        return idx

    def cached(self) -> Index | None:
        """Последний проверенный индекс с диска (без сети) — для отзыва при запуске."""
        if self.index:
            return self.index
        try:
            raw, sig = (self.root / INDEX).read_bytes(), (self.root / INDEX_SIG).read_text("ascii")
            if self.key and verify_index_sig(self.pinned_key(), raw, sig):
                self.index = parse_index(raw)
        except (OSError, MarketError):
            return None
        return self.index

    def stale(self) -> bool:
        idx = self.index
        if not idx:
            return False
        y, m, d = map(int, idx.generated.split("-"))
        return time.time() - time.mktime((y, m, d, 0, 0, 0, 0, 0, -1)) > STALE_DAYS * 86400

    # --- установка ---
    async def fetch_package(self, e: Entry, key: bytes | None = None) -> tuple[Path, pm.Manifest]:
        """Скачать и проверить пакет; вернуть распакованный каталог во временной папке и его манифест. Платный — с
        ключом версии из лицензии."""
        if e.zip_sha256 in (self.index.revoked if self.index else {}):
            raise MarketError("эта сборка отозвана каталогом")
        if not verify_plugin(e.author_pk, e.id, e.version, e.zip_sha256, e.author_sig):
            raise MarketError("подпись автора не сошлась")
        if e.encrypted and key is None:
            raise MarketError("платный плагин: нужна лицензия")
        had = self.installed().get(e.id)
        if had and had.get("author_pk") != e.author_pk:
            raise MarketError("обновление подписано другим автором — его не ставлю (возможен захват плагина). "
                              "Если автор сменил ключ, удалите плагин и поставьте заново")
        data = await self._get(e.file, min(e.size, ZIP_MAX))
        if len(data) != e.size or hashlib.sha256(data).hexdigest() != e.sha256:
            raise MarketError("архив не совпал с каталогом (размер или SHA-256)")
        if e.encrypted:
            data = decrypt_blob(data, key, e.id, e.version)
            if hashlib.sha256(data).hexdigest() != e.zip_sha256:
                raise MarketError("расшифрованный пакет не совпал с подписью автора")
        tmp = self.root / "tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(mode=0o700, parents=True)
        pdir = tmp / e.id
        unpack(data, pdir)
        try:
            m = pm.load(pdir)
        except pm.ManifestError as err:
            raise MarketError(f"манифест пакета: {err}") from None
        want = e.manifest_fields()
        if {k: v for k, v in m.to_json().items() if k in want} != want:
            raise MarketError("манифест пакета не совпадает с каталогом")
        return pdir, m

    def install(self, staged: Path, e: Entry) -> Path:
        """Поставить проверенный пакет: заменить прежнюю версию целиком (каталог состояния плагина не трогается)."""
        self.plugins_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        dest = self.plugins_dir / e.id
        old = self.plugins_dir / f".{e.id}.old"
        shutil.rmtree(old, ignore_errors=True)
        if dest.exists():
            dest.rename(old)
        staged.rename(dest)
        shutil.rmtree(old, ignore_errors=True)
        inst = self.installed()
        # tree — хеш распакованных файлов: при запуске бот сверяет его, правка файлов после установки — отказ.
        inst[e.id] = {"version": e.version, "sha256": e.zip_sha256, "author_pk": e.author_pk,
                      "tree": pm.package_hash(dest)}
        self.store.put("market_installed", inst)
        return dest

    def remove(self, id_: str) -> None:
        shutil.rmtree(self.plugins_dir / id_, ignore_errors=True)
        inst = self.installed()
        inst.pop(id_, None)
        self.store.put("market_installed", inst or None)

    def updates(self) -> list[Entry]:
        idx = self.index
        if not idx:
            return []
        return [idx.plugins[i] for i, v in self.installed().items()
                if i in idx.plugins and version_key(idx.plugins[i].version) > version_key(v["version"])]

    def revoked_installed(self) -> dict[str, str]:
        """Установленные сборки, отозванные каталогом: id → причина."""
        idx = self.cached()
        if not idx:
            return {}
        return {i: idx.revoked[v["sha256"]] for i, v in self.installed().items() if v.get("sha256") in idx.revoked}


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
