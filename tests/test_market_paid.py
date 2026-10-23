"""Маркет, этап 3 (spec/10): платные плагины — шифрованные пакеты, слепая лицензия магазина, анонимная активация.

Магазин и сервер здесь — тестовые, на тех же примитивах (POPRF ristretto255, Ed25519): магазин отвечает с настоящим
доказательством DLEQ, сервер проверяет лицензию и выдаёт ключ версии. Совместимость с сервером проекта
проверяют общие векторы (license-cross.json)."""
import asyncio
import hashlib
import json
import secrets

import pytest
from nacl.signing import SigningKey, VerifyKey
from plugkit import shutdown
from test_market import Catalog, bot, buttons, go, said, settle  # noqa: F401 — общий стенд маркета

from veil import market
from veil import market_tool as tool
from veil.core.crypto import poprf
from veil.core.crypto import ristretto as r255
from veil.core.protocol import b64, jcs
from veil.core.transport.exchange import ServerError
from veil.ui import bot as uibot

lp = poprf._lp


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    async def no_sleep(s):
        pass
    monkeypatch.setattr(uibot.asyncio, "sleep", no_sleep)


class Shop:
    """Магазин: ключ POPRF и выдача ответа VEILLICRES на запрос VEILLIC (после «оплаты»)."""

    def __init__(self, kid: str = "s1"):
        self.kid = kid
        self.sk = secrets.randbelow(r255.L - 1) + 1
        self.pk = r255.mul_base(self.sk)

    def tweak(self, plugin: str) -> int:
        return (self.sk + poprf._info_scalar(market.LICENSE_INFO + plugin.encode())) % r255.L

    def answer(self, request: str, *, prover: "Shop | None" = None) -> str:
        d = jcs.strict_loads(b64.dec(request.split(" ", 1)[1]))
        blinded = b64.dec(d["blinded"])
        t = self.tweak(d["plugin"])
        ev = r255.mul(r255.scalar_invert(t), blinded)
        # Доказательство DLEQ: B = t·G и D = t·C (RFC 9497, GenerateProof); prover — чужой ключ, для подделки.
        tp = (prover or self).tweak(d["plugin"])
        T, G = r255.mul_base(tp), r255.mul_base(1)
        M, Z = poprf._composites(T, [ev], [blinded])
        r = secrets.randbelow(r255.L - 1) + 1
        t2, t3 = r255.mul(r, G), r255.mul(r, M)
        c = poprf.hash_to_scalar(lp(T) + lp(M) + lp(Z) + lp(t2) + lp(t3) + b"Challenge")
        proof = r255.scalar_to_bytes(c) + r255.scalar_to_bytes((r - c * tp) % r255.L)
        body = jcs.canonicalize({"v": 1, "plugin": d["plugin"], "kid": d["kid"], "evaluated": b64.enc(ev),
                                 "proof": b64.enc(proof)})
        return f"{market.RESP_PREFIX} {b64.enc(body)}"

    def output_ok(self, plugin: str, inp: bytes, out: bytes) -> bool:
        n = r255.mul(r255.scalar_invert(self.tweak(plugin)), poprf.hash_to_group(inp))
        return hashlib.sha512(lp(inp) + lp(market.LICENSE_INFO + plugin.encode()) + lp(n) + b"Finalize").digest() == out


class Server:
    """Сервер Veil для market.redeem и market.key (логика — по spec/10)."""

    def __init__(self, shop: Shop, catalog: Catalog):
        self.shop, self.catalog = shop, catalog
        self.sig = SigningKey.generate()
        self.spent: dict[bytes, bytes] = {}
        self.calls: list[str] = []

    def handle(self, op: str, body: dict) -> dict:
        self.calls.append(op)
        plugin, version = body["plugin"], body["version"]
        try:
            key = self.catalog.pkg_key(plugin, version)
        except FileNotFoundError:
            raise ServerError("E_NOT_FOUND") from None
        lic_pk = b64.dec(body["lic_pk"])
        if op == "market.redeem":
            inp = b64.dec(body["input"])
            if not self.shop.output_ok(plugin, inp, b64.dec(body["output"])):
                raise ServerError("E_TOKEN_INVALID")
            h = hashlib.sha256(inp).digest()
            if self.spent.setdefault(h, lic_pk) != lic_pk:
                raise ServerError("E_TOKEN_SPENT")
            cert = self.sig.sign(market.cert_message(plugin, lic_pk)).signature
            return {"cert": b64.enc(cert), "key": b64.enc(key)}
        try:
            self.sig.verify_key.verify(market.cert_message(plugin, lic_pk), b64.dec(body["cert"]))
            VerifyKey(lic_pk).verify(market.proof_message(plugin, version), b64.dec(body["proof"]))
        except Exception:  # noqa: BLE001
            raise ServerError("E_TOKEN_INVALID") from None
        return {"key": b64.enc(key)}


def paid_catalog(tmp_path, shop: Shop) -> Catalog:
    c = Catalog(tmp_path)
    tool.set_shop(c.root, "@veil_shop_bot", shop.kid, b64.enc(shop.pk))
    c.publish(c.plugin(price_stars=50))
    return c


def wire(e, server: Server) -> None:
    """Обмен бота с сервером: операции маркета — тестовому серверу, ключ сервера закреплён его."""
    orig = e.server.request

    async def request(op, auth_mode, auth_key, *, body=None, **kw):
        if op.startswith("market."):
            return server.handle(op, body)
        return await orig(op, auth_mode, auth_key, body=body, **kw)
    e.server.request = request
    e.store.put("pinned_server_sig", b64.enc(bytes(server.sig.verify_key)))


def last_text(e, prefix: str) -> str:
    return next(t for t in reversed(e.tg.texts()) if t.startswith(prefix))


# --- формат ---
def test_catalog_keeps_only_ciphertext(tmp_path):
    shop = Shop()
    c = paid_catalog(tmp_path, shop)
    e = market.parse_index((c.root / "index.json").read_bytes()).plugins["hello"]
    assert e.encrypted and e.file.endswith(".zip.enc") and e.zip_sha256 != e.sha256
    assert not (c.root / "packages" / "hello" / "1.0.0.zip").exists()        # открытого пакета в каталоге нет
    assert oct((c.pkg_keys / "hello@1.0.0.key").stat().st_mode & 0o777) == "0o600"
    blob = (c.root / e.file).read_bytes()
    with pytest.raises(market.MarketError):
        market.decrypt_blob(blob, bytes(32), "hello", "1.0.0")              # чужой ключ
    with pytest.raises(market.MarketError):
        market.decrypt_blob(blob, c.pkg_key("hello", "1.0.0"), "hello", "2.0.0")  # ключ к другой версии не подходит
    assert hashlib.sha256(market.decrypt_blob(blob, c.pkg_key("hello", "1.0.0"), "hello", "1.0.0")).hexdigest() \
        == e.zip_sha256
    lines = tool.verify(c.root, c.market_pk)                                 # без ключей — только подпись автора
    assert "без ключа" in lines[0]
    assert tool.verify(c.root, c.market_pk, c.pkg_keys)[0].startswith("hello 1.0.0")
    with pytest.raises(tool.ToolError, match="--keys"):
        tool.add(c.root, c.plugin(version="1.1.0", price_stars=50))
    (c.root / "packages" / "hello" / "1.0.0.zip").write_bytes(b"leak")     # открытый архив рядом с платным
    with pytest.raises(market.MarketError, match="открытый архив"):
        tool.verify(c.root, c.market_pk)


def test_index_shop_and_encryption_rules(tmp_path):
    shop = Shop()
    c = paid_catalog(tmp_path, shop)
    d = json.loads((c.root / "index.json").read_text())
    assert d["shop"] == {"bot": "@veil_shop_bot", "kid": "s1", "pk": b64.enc(shop.pk)}
    for broken in ({**d, "shop": {"bot": "veil_shop_bot", "kid": "s1", "pk": d["shop"]["pk"]}},
                   {**d, "plugins": [{**d["plugins"][0], "encrypted": False}]},
                   {**d, "plugins": [{**d["plugins"][0], "file": "packages/hello/1.0.0.zip"}]}):
        with pytest.raises(market.MarketError):
            market.parse_index(json.dumps(broken).encode())


# --- лицензия ---
def test_license_response_checked(tmp_path):
    """Ответ магазина принимается, только если доказательство DLEQ от ключа магазина из каталога и ответ — на запрос
    этого бота; один раз."""
    shop = Shop()
    c = paid_catalog(tmp_path, shop)
    from test_market import Store, mk
    m = mk(c, tmp_path, Store())
    idx = asyncio.run(m.refresh())
    assert idx.shop.pk == shop.pk
    req = m.start_purchase(idx.plugins["hello"])
    assert m.start_purchase(idx.plugins["hello"]) == req                     # повторное «Купить» — тот же запрос
    forged = shop.answer(req, prover=Shop())                                 # подписано не тем ключом
    with pytest.raises(market.MarketError, match="DLEQ"):
        m.accept_license(forged)
    good = shop.answer(req)
    assert m.accept_license(good) == "hello"
    lic = m.licenses()["hello"]
    assert shop.output_ok("hello", b64.dec(lic["input"]), b64.dec(lic["output"])) and lic["cert"] is None
    with pytest.raises(market.MarketError, match="не на запрос"):
        m.accept_license(good)                                               # повтор того же ответа
    with pytest.raises(market.MarketError):
        m.accept_license("VEILLICRES мусор")


def test_buy_install_update_in_bot(tmp_path):
    shop = Shop()
    c = paid_catalog(tmp_path, shop)
    e = bot(tmp_path, c)
    server = Server(shop, c)
    wire(e, server)
    m = e.ui.market_ui.market

    async def scenario():
        try:
            await e.ui.market_ui.open()
            await go(e, e.press("mk:v:hello"))
            assert said(e, "Платный плагин: ⭐ 50") and "mk:b:hello" in buttons(e) and "mk:i:hello" not in buttons(e)
            await go(e, e.press("mk:i:hello"))                       # кнопку подделали — без лицензии не ставится
            assert said(e, "лицензии на этот плагин нет") and not m.installed()
            await go(e, e.press("mk:b:hello"))
            assert said(e, "боту-магазину @veil_shop_bot")
            request = last_text(e, "VEILLIC ")
            await go(e, e.msg(shop.answer(request)))                        # владелец переслал ответ магазина
            assert said(e, "Лицензия на «Привет» получена")
            assert server.calls == ["market.redeem"]                         # активация — на сервере, анонимно
            ok = next(b for b in buttons(e) if b.startswith("mk:ok:hello:"))
            await go(e, e.press(ok))
            assert said(e, "установлен и работает") and m.installed()["hello"]["version"] == "1.0.0"
            await go(e, e.msg("/hello мир"))
            assert said(e, "🧩 Привет: привет мир")

            c.publish(c.plugin(version="1.1.0", price_stars=50))             # обновление: ключ — по сертификату
            await e.ui.market_ui.daily()
            await e.ui.market_ui.open()
            await go(e, e.press("mk:u:hello"))
            assert server.calls == ["market.redeem", "market.key"] and m.installed()["hello"]["version"] == "1.1.0"
        finally:
            await shutdown(e.ui.plugins)
    asyncio.run(scenario())


def test_license_used_elsewhere(tmp_path):
    """Одна лицензия — одна установка: та же лицензия в другом боте (другой ключ установки) — понятный отказ."""
    shop = Shop()
    c = paid_catalog(tmp_path, shop)
    server = Server(shop, c)
    a, b = bot(tmp_path / "a", c), bot(tmp_path / "b", c)
    for x in (a, b):
        wire(x, server)
        x.store.put("pinned_server_sig", b64.enc(bytes(server.sig.verify_key)))

    async def scenario():
        await a.ui.market_ui.open()
        await go(a, a.press("mk:b:hello"))
        answer = shop.answer(last_text(a, "VEILLIC "))
        lic = None
        await go(a, a.msg(answer))
        lic = a.store.get("market_licenses")["hello"]
        b.store.put("market_licenses",
                    {"hello": {**lic, "lic_sk": b64.enc(bytes(SigningKey.generate())), "cert": None}})
        await b.ui.market_ui.open()
        await go(b, b.press("mk:i:hello"))
        assert said(b, "уже активирована в другой установке")
    asyncio.run(scenario())


def test_forged_server_cert_rejected(tmp_path):
    """Сертификат активации проверяется закреплённым ключом сервера: подменённый ответ «сервера» не сохраняется."""
    shop = Shop()
    c = paid_catalog(tmp_path, shop)
    e = bot(tmp_path, c)
    server = Server(shop, c)
    wire(e, server)
    e.store.put("pinned_server_sig", b64.enc(bytes(SigningKey.generate().verify_key)))  # другой сервер

    async def scenario():
        await e.ui.market_ui.open()
        await go(e, e.press("mk:b:hello"))
        await go(e, e.msg(shop.answer(last_text(e, "VEILLIC "))))
        assert said(e, "сертификат лицензии не от сервера Veil")
        assert e.store.get("market_licenses")["hello"]["cert"] is None
    asyncio.run(scenario())
