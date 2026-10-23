"""Маркет плагинов, этап 2 (docs/MARKET.md, «Каталог»): инструмент автора и ревьюера, подписи, отзыв, установка и
обновление в боте. Каталог — локальный (file://), как его видит бот после скачивания."""
import asyncio
import io
import json
import os
import stat
import textwrap
import zipfile
from pathlib import Path

import pytest
from harness import Env
from plugkit import new_engine, shutdown

from veil import market, plugins
from veil import market_tool as tool
from veil.ui import bot as uibot
from veil.ui.market_ui import MarketUI


class Store(dict):
    def put(self, k, v):
        self[k] = v


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    async def no_sleep(s):
        pass
    monkeypatch.setattr(uibot.asyncio, "sleep", no_sleep)


class Catalog:
    """Каталог veil-plugins во временной папке: ключ каталога, ключ автора, пакеты."""

    def __init__(self, tmp: Path):
        self.root = tmp / "catalog"
        self.root.mkdir()
        self.keys = tmp / "keys"
        self.keys.mkdir(mode=0o700)
        self.market_pk = tool.keygen(self.keys / "index-signing.key")
        self.author_pk = tool.keygen(self.keys / "author.key")
        self.work = tmp / "work"
        self.work.mkdir()
        self.pkg_keys = tmp / "pkgkeys"   # ключи версий платных пакетов: их оператор кладёт на сервер

    def plugin(self, id_="hello", version="1.0.0", permissions=("commands", "notify"), code=None, author="author.key",
               **extra) -> Path:
        pk = self.author_pk if author == "author.key" else tool.load_key(self.keys / author).verify_key
        pk = pk if isinstance(pk, str) else market.b64.enc(bytes(pk))
        d = self.work / version / id_
        d.mkdir(parents=True)
        fields = {"id": id_, "name": "Привет", "version": version, "api": 1, "entry": "main",
                  "description": "Здоровается", "author": "Автор", "license": "MIT",
                  "permissions": list(permissions), "author_pk": pk, **extra}
        (d / "plugin.toml").write_text(
            "".join(f"{k} = {json.dumps(v, ensure_ascii=False)}\n" for k, v in fields.items()))
        (d / "main.py").write_text(textwrap.dedent(code or """
            from veil import plugins
            @plugins.on_command("hello", "Поздороваться")
            async def hello(arg):
                await plugins.notify_owner("привет " + arg)
        """))
        z = self.work / f"{id_}-{version}.zip"
        z.write_bytes(market.pack(d))
        tool.sign(z, self.keys / author)
        return z

    def publish(self, *zips: Path) -> None:
        for z in zips:
            tool.add(self.root, z, "2026-10-20", self.pkg_keys)
        tool.sign_index(self.root, self.keys / "index-signing.key")

    def pkg_key(self, id_: str, version: str) -> bytes:
        return bytes.fromhex((self.pkg_keys / f"{id_}@{version}.key").read_text().strip())

    def conf(self) -> dict:
        return {"urls": [self.root.as_uri()], "key": self.market_pk}


# --- инструмент и формат ---
def test_tool_flow_and_verify(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    idx = market.parse_index((c.root / "index.json").read_bytes())
    assert tool.verify(c.root, c.market_pk) == [f"hello 1.0.0 {idx.plugins['hello'].sha256[:12]} ✓"]
    assert idx.seq == 1 and idx.plugins["hello"].author_pk == c.author_pk
    assert (c.root / "packages" / "hello" / "1.0.0.zip").exists()
    assert market.pack(c.work / "1.0.0" / "hello") == market.pack(c.work / "1.0.0" / "hello")  # детерминированно


def test_tool_refuses_bad_submissions(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    with pytest.raises(tool.ToolError, match="не новее"):
        tool.add(c.root, c.work / "hello-1.0.0.zip")              # та же версия ещё раз
    tool.keygen(c.keys / "thief.key")
    with pytest.raises(tool.ToolError, match="другой ключ автора"):
        tool.add(c.root, c.plugin(version="2.0.0", author="thief.key"))
    z = c.plugin(version="1.1.0")
    z.with_name(z.name + ".sig").write_text(market.sign_plugin(tool.load_key(c.keys / "author.key"), "hello", "9.9.9",
                                                               "0" * 64))
    with pytest.raises(tool.ToolError, match="подпись автора"):
        tool.add(c.root, z)
    os.chmod(c.keys / "author.key", 0o644)
    with pytest.raises(tool.ToolError, match="chmod 600"):
        tool.load_key(c.keys / "author.key")


@pytest.mark.parametrize("bad", ["dir", "symlink", "traversal", "binary", "bomb", "duplicate"])
def test_unpack_refuses_dangerous_archives(tmp_path, bad):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("plugin.toml", "x")
        if bad == "dir":
            z.writestr("sub/", "")
        elif bad == "symlink":
            info = zipfile.ZipInfo("link.py")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "/etc/passwd")
        elif bad == "traversal":
            z.writestr("../evil.py", "x")
        elif bad == "binary":
            z.writestr("lib.so", b"\x7fELF")
        elif bad == "bomb":
            z.writestr("big.py", "#" * (2 << 20), compress_type=zipfile.ZIP_DEFLATED)
        elif bad == "duplicate":
            z.writestr("plugin.toml", "y")
    with pytest.raises(market.MarketError):
        market.unpack(buf.getvalue(), tmp_path / "out")
    assert not (tmp_path / "evil.py").exists()


# --- бот: проверки при скачивании ---
def mk(c: Catalog, tmp: Path, store=None, **conf) -> market.Market:
    return market.Market(store if store is not None else Store(), tmp / "data", {**c.conf(), **conf})


def test_index_signature_and_rollback(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    old = ((c.root / "index.json").read_bytes(), (c.root / "index.json.sig").read_bytes())
    m = mk(c, tmp_path)
    assert asyncio.run(m.refresh()).seq == 1
    c.publish(c.plugin(version="1.1.0"))
    assert asyncio.run(m.refresh(force=True)).seq == 2
    (c.root / "index.json").write_bytes(old[0])
    (c.root / "index.json.sig").write_bytes(old[1])
    with pytest.raises(market.MarketError, match="старее"):
        asyncio.run(m.refresh(force=True))                        # старый подписанный индекс без новых отзывов
    raw = (c.root / "index.json").read_bytes().replace(b'"seq": 1', b'"seq": 9')
    (c.root / "index.json").write_bytes(raw)
    with pytest.raises(market.MarketError, match="подпись каталога"):
        asyncio.run(m.refresh(force=True))


def test_market_key_pinned(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    store = Store()
    asyncio.run(mk(c, tmp_path, store).refresh())
    other = tool.keygen(c.keys / "other.key")
    with pytest.raises(market.MarketError, match="pin-market"):
        asyncio.run(mk(c, tmp_path, store, key=other).refresh())  # подменённый конфиг не уводит на чужой каталог
    from veil import cli
    cli.pin_market(store, {"market": {"key": other}}, batch=True)
    assert store["pinned_market"] == other and store.get("market_seq") is None


def test_package_checks(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    m = mk(c, tmp_path)
    idx = asyncio.run(m.refresh())
    e = idx.plugins["hello"]
    pdir, man = asyncio.run(m.fetch_package(e))
    assert man.id == "hello" and (pdir / "main.py").exists()
    zpath = c.root / e.file
    good = zpath.read_bytes()
    zpath.write_bytes(good[:-1] + bytes([good[-1] ^ 1]))
    with pytest.raises(market.MarketError, match="SHA-256"):
        asyncio.run(m.fetch_package(e))                            # архив подменили на зеркале
    zpath.write_bytes(good)
    with pytest.raises(market.MarketError, match="подпись автора"):
        asyncio.run(m.fetch_package(market.Entry(**{**e.__dict__, "author_sig": "A" * 86})))
    revoked = market.Index(idx.seq, idx.generated, idx.plugins, {e.sha256: "вредоносный"})
    m.index = revoked
    with pytest.raises(market.MarketError, match="отозвана"):
        asyncio.run(m.fetch_package(e))


def test_manifest_must_match_index(tmp_path):
    """Каталог (или тот, кто украл его ключ) не может объявить меньше разрешений, чем просит сам пакет."""
    c = Catalog(tmp_path)
    c.publish(c.plugin(permissions=("commands", "notify", "before_send")))
    d = json.loads((c.root / "index.json").read_text())
    d["plugins"][0]["permissions"] = ["commands", "notify"]
    raw = json.dumps(d, ensure_ascii=False, indent=1, sort_keys=True).encode()
    (c.root / "index.json").write_bytes(raw)
    tool.sign_index(c.root, c.keys / "index-signing.key")
    m = mk(c, tmp_path)
    idx = asyncio.run(m.refresh())
    with pytest.raises(market.MarketError, match="не совпадает с каталогом"):
        asyncio.run(m.fetch_package(idx.plugins["hello"]))


def test_update_by_other_author_refused(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    m = mk(c, tmp_path)
    e = asyncio.run(m.refresh()).plugins["hello"]
    m.install(asyncio.run(m.fetch_package(e))[0], e)
    thief = tool.keygen(c.keys / "thief.key")  # украденный ключ каталога: запись подписана правильно, но чужим автором
    sig = market.sign_plugin(tool.load_key(c.keys / "thief.key"), e.id, "2.0.0", e.sha256)
    forged = market.Entry(**{**e.__dict__, "author_pk": thief, "version": "2.0.0", "author_sig": sig})
    with pytest.raises(market.MarketError, match="другим автором"):
        asyncio.run(m.fetch_package(forged))


# --- бот целиком ---
def bot(tmp: Path, c: Catalog, pool=None) -> Env:
    e = Env(tmp / "botdata", pool=pool)
    m = market.Market(e.store, e.store.dir, c.conf())
    e.ui.market_ui = MarketUI(e.ui, m)
    e.ui.plugins = plugins.load({"pool": pool} if pool else {}, tmp,
                                (m.plugins_dir, m.installed(), m.revoked_installed()), new_engine())
    e.ui.plugins.host = uibot.PluginHost(e.ui)
    return e


async def settle(e: Env) -> None:
    for _ in range(100):
        pending = [t for t in list(e.ui.tasks) + list(e.ui.plugins.tasks) if not t.done()]
        if not pending:
            return
        await asyncio.wait(pending, timeout=0.5)


async def go(e: Env, *updates) -> None:
    for u in updates:
        e.ui._route(u)
        await settle(e)


def buttons(e: Env) -> list[str]:
    return e.last_markup_data()


def said(e: Env, fragment: str) -> bool:
    return any(fragment in t for t in e.tg.texts())


def test_install_update_remove_in_bot(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    e = bot(tmp_path, c)
    m = e.ui.market_ui.market

    async def scenario():
        try:
            await go(e, e.msg("/market"))
            assert said(e, "Маркет плагинов") and said(e, "Привет 1.0.0") and "mk:v:hello" in buttons(e)
            await go(e, e.press("mk:v:hello"))
            assert said(e, "Автор: Автор") and "mk:i:hello" in buttons(e)
            await go(e, e.press("mk:i:hello"))
            ok = next(b for b in buttons(e) if b.startswith("mk:ok:hello:"))  # сначала — согласие на разрешения
            assert said(e, "свои команды в меню бота") and not e.ui.plugins.loaded
            await go(e, e.press(ok))
            assert said(e, "установлен и работает") and [p.name for p in e.ui.plugins.loaded] == ["hello"]
            await go(e, e.msg("/hello мир"))
            assert said(e, "🧩 Привет: привет мир")

            c.publish(c.plugin(version="1.1.0"))                  # те же разрешения — без повторного вопроса
            await e.ui.market_ui.daily()
            assert said(e, "Вышла версия 1.1.0")
            await go(e, e.press("mk:v:hello"))
            await go(e, e.press("mk:u:hello"))
            assert said(e, "«Привет» 1.1.0 установлен") and m.installed()["hello"]["version"] == "1.1.0"

            c.publish(c.plugin(version="1.2.0", permissions=("commands", "notify", "before_send"),
                               code="""
                from veil import plugins
                @plugins.before_send
                async def check(out):
                    return None
                @plugins.on_command("hello", "Поздороваться")
                async def hello(arg):
                    await plugins.notify_owner("v2 " + arg)
            """))
            await e.ui.market_ui.open()
            await go(e, e.press("mk:u:hello"))
            assert any(b.startswith("mk:ok:hello:") for b in buttons(e))  # просит больше — снова согласие
            await go(e, e.press(next(b for b in buttons(e) if b.startswith("mk:ok:hello:"))))
            assert m.installed()["hello"]["version"] == "1.2.0"

            await go(e, e.press("mk:r:hello"), e.press("mk:rok:hello"))
            assert said(e, "удалён вместе с данными") and not e.ui.plugins.loaded and not m.installed()
            assert not (m.plugins_dir / "hello").exists() and "hello" not in (e.store.get("plugin_grants") or {})
        finally:
            await shutdown(e.ui.plugins)
    asyncio.run(scenario())


def test_delisted_plugin_still_removable(tmp_path):
    """Плагин убрали из каталога (автор отозвал заявку, демо): у владельца он работает дальше, но виден в /market с
    пометкой и удаляется кнопкой."""
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    e = bot(tmp_path, c)
    m = e.ui.market_ui.market

    async def scenario():
        try:
            await e.ui.market_ui.open()
            await go(e, e.press("mk:i:hello"))
            await go(e, e.press(next(b for b in buttons(e) if b.startswith("mk:ok:hello:"))))
            assert m.installed()
            tool.delist(c.root, "hello")
            tool.sign_index(c.root, c.keys / "index-signing.key")
            await go(e, e.msg("/market"))
            assert said(e, "hello 1.0.0 — убран из каталога") and "mk:v:hello" in buttons(e)
            await go(e, e.press("mk:v:hello"))
            assert said(e, "убран из каталога. Установленная версия продолжает работать")
            assert buttons(e) == ["mk:r:hello"]
            await go(e, e.press("mk:r:hello"), e.press("mk:rok:hello"))
            assert said(e, "удалён вместе с данными") and not m.installed() and not e.ui.plugins.loaded
        finally:
            await shutdown(e.ui.plugins)
    asyncio.run(scenario())


def test_revoked_plugin_stopped_and_removed(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    e = bot(tmp_path, c)
    m = e.ui.market_ui.market

    async def scenario():
        try:
            await e.ui.market_ui.open()
            await go(e, e.press("mk:i:hello"))
            await go(e, e.press(next(b for b in buttons(e) if b.startswith("mk:ok:"))))
            assert e.ui.plugins.loaded
            tool.revoke(c.root, m.installed()["hello"]["sha256"], "крадёт черновики")
            tool.sign_index(c.root, c.keys / "index-signing.key")
            await e.ui.market_ui.daily()
            assert said(e, "Каталог отозвал плагин «hello»: крадёт черновики")  # в каталоге его уже нет — имя по id
            assert not e.ui.plugins.loaded and not m.installed()
        finally:
            await shutdown(e.ui.plugins)
    asyncio.run(scenario())


def test_tampered_or_revoked_install_not_loaded(tmp_path):
    c = Catalog(tmp_path)
    c.publish(c.plugin())
    store = Store()
    m = mk(c, tmp_path, store)
    e = asyncio.run(m.refresh()).plugins["hello"]
    dest = m.install(asyncio.run(m.fetch_package(e))[0], e)
    reg = plugins.load({}, tmp_path, (m.plugins_dir, m.installed(), {}))
    assert [p.name for p in reg.packages] == ["hello"]
    (dest / "main.py").write_text("# подмена\n")
    reg = plugins.load({}, tmp_path, (m.plugins_dir, m.installed(), {}))
    assert not reg.packages and "изменены после установки" in dict(reg.failed)["hello"]
    reg = plugins.load({}, tmp_path, (m.plugins_dir, m.installed(), {"hello": "вредоносный"}))
    assert "отозвана каталогом: вредоносный" in dict(reg.failed)["hello"]


def test_market_in_pool(tmp_path):
    """Бот пула ставит плагин из маркета так же, как свой бот: согласие владельца, работа в движке, удаление.
    Хранилище плагина — в зашифрованных данных бота пула."""
    c = Catalog(tmp_path)
    c.publish(c.plugin(code="""
        from veil import plugins
        STORE = plugins.storage()
        @plugins.on_command("hello", "Поздороваться")
        async def hello(arg):
            STORE.put("said", "привет")
            await plugins.notify_owner("привет из пула")
    """))
    e = bot(tmp_path, c, pool={"identity": "custodial"})
    m = e.ui.market_ui.market

    async def scenario():
        try:
            await go(e, e.msg("/market"))
            assert said(e, "Маркет плагинов") and "mk:v:hello" in buttons(e)
            await go(e, e.press("mk:i:hello"))
            await go(e, e.press(next(b for b in buttons(e) if b.startswith("mk:ok:hello:"))))
            assert [p.name for p in e.ui.plugins.loaded] == ["hello"]
            await go(e, e.msg("/hello"))
            assert said(e, "🧩 Привет: привет из пула")
            await go(e, e.press("mk:r:hello"), e.press("mk:rok:hello"))
            assert not m.installed() and e.store.get(plugins.storage_key("hello")) is None
        finally:
            await shutdown(e.ui.plugins)
    asyncio.run(scenario())
