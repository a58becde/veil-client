"""Движок плагинов (docs/PLUGINS.md, «Движок»; docs/MARKET.md): манифест, разрешения, согласие владельца, лимиты и то,
чего плагин сделать не может, — на настоящем движке (WASM в процессе-хосте)."""
import asyncio
import importlib.util
import json
import shutil
import sys

import httpx
import pytest

from veil import plugin_engine, plugin_manifest as pm, plugins, seccomp
from veil.ui import bot as uibot

from plugkit import ROOT, WASM, bot, engine_sha, go, manifest, new_engine, package, settle, shutdown, start_all, \
    stored, texts

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="защита ОС хоста — только Linux")


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    async def no_sleep(s):
        pass
    monkeypatch.setattr(uibot.asyncio, "sleep", no_sleep)


def run(reg, body):
    async def go_():
        await start_all(reg)
        try:
            return await body()
        finally:
            await shutdown(reg)
    return asyncio.run(go_())


# --- манифест и пакет ---
def test_manifest_strict():
    m = pm.parse(manifest(permissions=["replies", "net"], network=["api.example.com"], price_stars=50))
    assert m.permissions == ("replies", "net") and m.network == ("api.example.com",) and m.price_stars == 50
    bad = [
        manifest() + 'extra = "x"\n',                                   # неизвестное поле
        manifest().replace('id = "probe"', 'id = "Probe"'),
        manifest(permissions=["net"]),                                  # net без network
        manifest(permissions=[], network=["a.example.com"]),            # network без net
        manifest(permissions=["root"]),
        manifest(permissions=["net"], network=["http://a.example.com"]),
        manifest(permissions=["net"], network=["*.example.com"]),
        manifest(price_stars=-1),
        manifest(author_pk="short"),
        manifest().replace("api = 1", "api = 2"),
        manifest().replace('version = "1.0.0"', 'version = "1.0"'),
        manifest().replace('name = "Тест"', 'name = "a\\u0007b"'),
    ]
    for text in bad:
        with pytest.raises(pm.ManifestError):
            pm.parse(text)


def test_sensitive_with_network_is_flagged_and_grants_are_exact():
    m = pm.parse(manifest(permissions=["before_send", "net"], network=["api.example.com"]))
    assert m.sensitive == ("before_send",) and m.leaks_to_network
    assert not pm.parse(manifest(permissions=["replies", "net"], network=["a.example.com"])).leaks_to_network
    g = m.grant()
    assert m.covered_by(g) and not m.covered_by(None)
    more = pm.parse(manifest(permissions=["before_send", "net", "private"], network=["api.example.com"]))
    assert not more.covered_by(g)                                       # просит больше — снова спросить
    other_host = pm.parse(manifest(permissions=["before_send", "net"], network=["evil.example.com"]))
    assert not other_host.covered_by(g)
    other_author = pm.parse(manifest(permissions=["before_send", "net"], network=["api.example.com"],
                                     author_pk="A" * 43))
    assert not other_author.covered_by(g)                               # другой автор под тем же id


def test_package_contents_checked(tmp_path):
    d = package(tmp_path, "probe", "X = 1\n")
    h = pm.package_hash(d)
    files, digest = pm.read_package(d)
    assert digest == h and set(files) == {"main.py", "plugin.toml"}     # в движок уходит ровно посчитанное
    (d / "helper.py").write_text("Y = 2\n")
    assert pm.package_hash(d) != h                                      # любая правка кода меняет хеш
    (d / "data.bin").write_bytes(b"\0")
    with pytest.raises(pm.ManifestError):
        pm.load(d)
    (d / "data.bin").unlink()
    (d / "sub").mkdir()
    with pytest.raises(pm.ManifestError):
        pm.load(d)
    (d / "sub").rmdir()
    (d / "plugin.toml").write_text(manifest("other"))
    with pytest.raises(pm.ManifestError):
        pm.load(d)                                                      # id не совпадает с каталогом


def test_seccomp_only_known_arches():
    assert len(seccomp.program("x86_64")) == len(seccomp.program("aarch64"))
    with pytest.raises(seccomp.SeccompError):
        seccomp.program("riscv64")


def test_package_changed_after_check_not_started(tmp_path):
    d = package(tmp_path, "probe", "X = 1\n", permissions=[])
    e, reg = bot(tmp_path, ["probe"])
    (d / "main.py").write_text("X = 2\n")                               # подмена между проверкой и запуском
    run(reg, lambda: asyncio.sleep(0))
    assert not reg.loaded and "изменились после проверки" in dict(reg.failed)["probe"]


# --- чего плагин не может ---
PROBE = """
import os, time, random
from veil import plugins

STORE = plugins.storage()

def attempt(fn):
    try:
        return ["ok", repr(fn())[:80]]
    except Exception as e:
        return [type(e).__name__, str(e)[:120]]

@plugins.on_command("probe", "Что можно в движке")
async def probe(arg):
    r = {
        "read_bot_file": attempt(lambda: open(arg).read()),
        "list_root": attempt(lambda: os.listdir("/")),
        "write_file": attempt(lambda: open("/tmp/x", "w").write("x")),
        "env": dict(os.environ),
        "time": time.time() > 1.7e9,
        "random": 0 <= random.random() < 1,
    }
    for mod in ("socket", "subprocess", "threading", "ctypes", "asyncio", "ssl", "urllib.request"):
        r["import_" + mod] = attempt(lambda: __import__(mod))
    for mod in ("json", "re", "datetime", "html", "urllib.parse", "hashlib", "zlib"):
        r["stdlib_" + mod] = attempt(lambda: __import__(mod))[0]
    STORE.put("result", r)
    await plugins.notify_owner("done")
"""


def _probe(tmp_path, monkeypatch, engine=None):
    monkeypatch.setenv("VEIL_BOT_TOKEN", "123:SECRET")
    package(tmp_path, "probe", PROBE, permissions=["commands", "notify"])
    e, reg = bot(tmp_path, ["probe"], engine)
    secret = e.store.dir / "secret.txt"
    secret.write_text("ключ")
    out = {}

    async def body():
        assert [p.name for p in reg.loaded] == ["probe"], reg.failed
        await go(e, e.msg(f"/probe {secret}"))
        out["os_sandbox"] = reg.engine.os_sandbox
        out["pid"] = reg.engine.proc.pid
    run(reg, body)
    return e, stored(e, "probe")["result"], out


def _assert_confined(e, r):
    assert r["read_bot_file"][0] in ("FileNotFoundError", "PermissionError") and r["list_root"][0] != "ok"
    assert r["write_file"][0] != "ok" and r["env"] == {} and r["time"] and r["random"]
    for mod in ("socket", "subprocess", "threading", "ctypes", "asyncio", "ssl", "urllib.request"):
        assert r["import_" + mod][0] == "ModuleNotFoundError" and "нет в движке" in r["import_" + mod][1], mod
    assert all(r["stdlib_" + m] == "ok" for m in ("json", "re", "datetime", "html", "urllib.parse", "hashlib", "zlib"))
    assert any("🧩 Тест: done" in t for t in texts(e))                  # сообщение плагина подписано его именем


def test_engine_confines_plugin(tmp_path, monkeypatch):
    """Плагин не читает файлы бота и вообще файлы, ничего не пишет, не видит окружения (токена бота), не открывает
    сокеты и не запускает процессы: таких модулей в движке нет. Стандартная библиотека для данных — есть."""
    e, r, out = _probe(tmp_path, monkeypatch)
    _assert_confined(e, r)
    assert out["os_sandbox"] is sys.platform.startswith("linux")


def test_wasm_alone_confines_plugin(tmp_path, monkeypatch):
    """Как в macOS (защиты ОС нет): плагина держит один WASM — и этого достаточно для тех же запретов. Владелец видит
    в запросе разрешений, что защиты ОС нет."""
    e, r, out = _probe(tmp_path, monkeypatch, new_engine(confine=False))
    _assert_confined(e, r)
    assert out["os_sandbox"] is False
    monkeypatch.setattr(plugin_engine, "os_sandbox", lambda: "нет seccomp и Landlock")
    m = pm.parse(manifest(permissions=["commands"]))
    assert "только движком WebAssembly" in e.ui.grant_text(m)


@linux
def test_host_process_confined(tmp_path, monkeypatch):
    """Хост движка в Linux: seccomp-фильтр, без новых привилегий, память и окружение процесса не читает никто."""
    e, r, out = _probe(tmp_path, monkeypatch)
    assert out["os_sandbox"] is True


@linux
def test_host_process_flags(tmp_path):
    package(tmp_path, "probe", "X = 1\n", permissions=[])
    e, reg = bot(tmp_path, ["probe"])

    async def body():
        pid = reg.engine.proc.pid
        status = open(f"/proc/{pid}/status").read()
        assert "Seccomp:\t2" in status and "NoNewPrivs:\t1" in status
        with pytest.raises(PermissionError):
            open(f"/proc/{pid}/environ").read()                         # PR_SET_DUMPABLE = 0
    run(reg, body)


def test_permissions_enforced(tmp_path):
    """Подписка на событие без разрешения — плагин не запускается; действие без разрешения — отказ внутри плагина."""
    package(tmp_path, "peek", """
        from veil import plugins
        @plugins.on_hidden_for_me
        async def read(p):
            pass
    """, permissions=["replies"])
    package(tmp_path, "quiet", """
        from veil import plugins
        STORE = plugins.storage()
        @plugins.on_reply
        async def r(reply):
            try:
                await plugins.notify_owner("hi")
                STORE.put("notify", "ok")
            except plugins.PluginError as e:
                STORE.put("notify", str(e))
    """, permissions=["replies"])
    e, reg = bot(tmp_path, ["peek", "quiet"])

    async def body():
        assert [p.name for p in reg.loaded] == ["quiet"]
        assert "без разрешения private" in dict(reg.failed)["peek"]
        reg.fire("reply", plugins.Reply(7, 5, "ответ", ""))
        await settle(e)
    run(reg, body)
    assert stored(e, "quiet")["notify"] == "нет разрешения notify" and not any("hi" in t for t in texts(e))


FETCHER = """
from veil import plugins
STORE = plugins.storage()
@plugins.on_command("fetch", "Сходить в сеть")
async def fetch(arg):
    out = {}
    for url in ("https://api.example.com/v1", "https://api.example.com/big", "https://api.example.com/huge",
                "https://evil.example.net/", "http://api.example.com/", "https://api.example.com:8443/"):
        try:
            r = await plugins.http("GET", url)
            out[url] = [r.status, len(r.body), r.json() if url.endswith("v1") else None]
        except plugins.PluginError as e:
            out[url] = str(e)
    STORE.put("out", out)
"""


def test_network_only_to_manifest_hosts(tmp_path):
    """Сеть — только через бота, только https и хосты манифеста, без порта; ответ до 4 МиБ доходит до плагина
    (регрессия: ответ больше ~750 КБ ронял процесс плагина — строка протокола была ограничена 1 МиБ)."""
    package(tmp_path, "fetcher", FETCHER, permissions=["commands", "net"], network=["api.example.com"])
    e, reg = bot(tmp_path, ["fetcher"])
    seen = []

    def handler(req):
        seen.append(str(req.url))
        if req.url.path == "/big":
            return httpx.Response(200, content=b"x" * (3 << 20))
        if req.url.path == "/huge":
            return httpx.Response(200, content=b"x" * ((4 << 20) + 1))
        return httpx.Response(200, json={"ok": 1})
    reg.host.http_transport = httpx.MockTransport(handler)

    async def body():
        await go(e, e.msg("/fetch"))
    run(reg, body)
    out = stored(e, "fetcher")["out"]
    assert out["https://api.example.com/v1"] == [200, 8, {"ok": 1}] and out["https://api.example.com/big"][1] == 3 << 20
    assert "больше 4 МиБ" in out["https://api.example.com/huge"]
    assert "нет в network" in out["https://evil.example.net/"] and "только https" in out["http://api.example.com/"]
    assert "без порта" in out["https://api.example.com:8443/"]
    assert seen == ["https://api.example.com/v1", "https://api.example.com/big", "https://api.example.com/huge"]


def test_net_gate_shared_by_all_bots():
    """Лимит на сайт общий для всех плагинов всех ботов процесса (в пуле все ходят с одного IP)."""
    gate = plugin_engine.NetGate(per_minute=2, parallel=1)

    async def go_():
        for _ in range(2):
            async with gate.take("api.example.com"):
                pass
        with pytest.raises(plugins.PluginError, match="слишком много запросов"):
            gate.take("api.example.com")
        async with gate.take("other.example.com"):                      # другой сайт — свой счёт
            pass
    asyncio.run(go_())


def test_owner_consent_before_start(tmp_path):
    """Без согласия пакет не запускается: бот перечисляет разрешения (чтение + сеть — с предупреждением) и ждёт кнопки;
    согласие запоминается и включает плагин и его команды."""
    package(tmp_path, "helper", """
        from veil import plugins
        @plugins.before_send
        async def check(out):
            return None
        @plugins.on_command("hello", "Поздороваться")
        async def hello(arg):
            await plugins.notify_owner("привет")
    """, permissions=["before_send", "commands", "notify", "net"], network=["api.example.com"])
    e, reg = bot(tmp_path, ["helper"])

    async def body():
        await reg.start(e.store.get("plugin_grants"))
        try:
            assert not reg.loaded and [p.name for p in reg.pending] == ["helper"]
            await e.ui._announce_plugins()
            ask = next(t for t in texts(e) if "просит" in t)
            assert "читать текст поста до отправки" in ask and "api.example.com" in ask and "IP этой машины" in ask
            assert "pg:helper:ok" in e.last_markup_data()
            await go(e, e.press("pg:helper:ok"))
            assert [p.name for p in reg.loaded] == ["helper"] and "hello" in reg.commands
            await go(e, e.msg("/hello"))
            assert any("привет" in t for t in texts(e))
            assert "Плагины: helper" in e.ui.status_text()
        finally:
            await shutdown(reg)
    asyncio.run(body())
    assert e.store.get("plugin_grants")["helper"]["permissions"] == ["before_send", "commands", "net", "notify"]


# --- лимиты и сбои ---
def test_time_and_memory_limits(tmp_path, monkeypatch):
    """Вечный цикл обрывается по времени, захват памяти — на лимите; движок и бот работают дальше."""
    monkeypatch.setattr(plugins, "COMMAND_TIMEOUT", 1.0)
    package(tmp_path, "heavy", """
        from veil import plugins
        @plugins.on_command("spin", "Цикл")
        async def spin(arg):
            while True:
                pass
        @plugins.on_command("eat", "Память")
        async def eat(arg):
            x = []
            while True:
                x.append(bytearray(1 << 20))
        @plugins.on_command("ok", "Норма")
        async def ok(arg):
            await plugins.notify_owner("жив")
    """, permissions=["commands", "notify"])
    e, reg = bot(tmp_path, ["heavy"], new_engine(memory_mb=48))

    async def body():
        t = asyncio.get_running_loop().time()
        await go(e, e.msg("/spin"))
        assert asyncio.get_running_loop().time() - t < 5
        await go(e, e.msg("/eat"))
        await go(e, e.msg("/ok"))
    run(reg, body)
    reports = [t for t in texts(e) if "Плагин heavy: сбой" in t]
    assert any("/spin (TimeoutError)" in t for t in reports) and any("/eat (MemoryError)" in t for t in reports)
    assert any("жив" in t for t in texts(e))


def test_slow_or_broken_check_blocks_post(tmp_path, monkeypatch):
    monkeypatch.setattr(plugins, "SEND_TIMEOUT", 0.5)
    package(tmp_path, "slow", """
        from veil import plugins
        @plugins.before_send
        async def wait(out):
            while True:
                pass
    """, permissions=["before_send"])
    e, reg = bot(tmp_path, ["slow"])
    why = run(reg, lambda: reg.check_send(plugins.Outgoing("text", "пост", False, "", None, "")))
    assert "проверка не выполнилась (TimeoutError)" in why


def test_waiting_inside_plugin_refused(tmp_path):
    """Вызовы бота синхронны: обработчику ждать нечего, ожидание чужого — ошибка словами, а не зависание."""
    package(tmp_path, "waiter", """
        from veil import plugins
        STORE = plugins.storage()
        class Later:
            def __await__(self):
                yield "что-то"
        @plugins.on_command("wait", "Подождать")
        async def wait(arg):
            await Later()
    """, permissions=["commands"])
    e, reg = bot(tmp_path, ["waiter"])
    run(reg, lambda: go(e, e.msg("/wait")))
    assert any("Плагин waiter: сбой в /wait (PluginError)" in t for t in texts(e))


def test_load_error_reported_in_words(tmp_path):
    package(tmp_path, "broken", "raise ValueError('сломан')\n", permissions=[])
    e, reg = bot(tmp_path, ["broken"])
    run(reg, lambda: asyncio.sleep(0))
    assert not reg.loaded and "ValueError: сломан" in dict(reg.failed)["broken"]


def test_engine_crash_restarts_then_gives_up(tmp_path):
    """Хост упал (убит) — следующее событие поднимает его заново, пакеты загружаются снова; больше трёх раз в час —
    движок выключен до перезапуска бота, владелец получает сообщение."""
    package(tmp_path, "echo", """
        from veil import plugins
        @plugins.on_command("echo", "Эхо")
        async def echo(arg):
            await plugins.notify_owner("эхо")
    """, permissions=["commands", "notify"])
    e, reg = bot(tmp_path, ["echo"])

    async def body():
        for _ in range(plugin_engine.RESTARTS_PER_HOUR + 1):
            reg.engine.proc.kill()
            await reg.engine.proc.wait()
            await go(e, e.msg("/echo"))
    run(reg, body)
    assert sum(t == "🧩 Тест: эхо" for t in texts(e)) == plugin_engine.RESTARTS_PER_HOUR
    assert len(reg.engine.restarts) == plugin_engine.RESTARTS_PER_HOUR
    assert any("Плагин echo: сбой" in t for t in texts(e))


def test_host_protocol_garbage_stops_engine(tmp_path, monkeypatch):
    """Хост, который пишет в канал протокола мусор, останавливается; плагин не запускается, бот работает."""
    monkeypatch.setattr(plugin_engine, "BOOT", "print('{not json')")
    package(tmp_path, "probe", "X = 1\n", permissions=[])
    e, reg = bot(tmp_path, ["probe"])
    run(reg, lambda: asyncio.sleep(0))
    assert not reg.loaded and "движок плагинов завершился" in dict(reg.failed)["probe"]


def test_storage_limits_and_isolation(tmp_path):
    package(tmp_path, "a", """
        from veil import plugins
        STORE = plugins.storage()
        @plugins.on_command("fill", "Заполнить")
        async def fill(arg):
            STORE.put("mine", "a")
            for name, call in (("big", lambda: STORE.put("big", "x" * (3 << 19))),  # 1,5 МиБ: хост пропустит, бот — нет
                               ("key", lambda: STORE.put(5, 1)),
                               ("value", lambda: STORE.put("v", object()))):
                try:
                    call()
                except plugins.PluginError as e:
                    STORE.put(name, str(e))
            STORE.delete("nothing")
    """, permissions=["commands"])
    package(tmp_path, "b", """
        from veil import plugins
        STORE = plugins.storage()
        @plugins.on_command("look", "Посмотреть")
        async def look(arg):
            STORE.put("saw", STORE.get("mine"))
    """, permissions=["commands"])
    e, reg = bot(tmp_path, ["a", "b"])

    async def body():
        await go(e, e.msg("/fill"), e.msg("/look"))
    run(reg, body)
    a, b = stored(e, "a"), stored(e, "b")
    assert a["mine"] == "a" and "больше 1 МиБ" in a["big"] and "строка" in a["key"] and "только JSON" in a["value"]
    assert b == {"saw": None}                                           # чужое хранилище не видно


def test_unsupported_platform_refuses(monkeypatch, tmp_path):
    """Без движка пакет не запускается — «запустить как есть» не предусмотрено."""
    monkeypatch.setattr(plugin_engine.sys, "platform", "win32")
    package(tmp_path, "probe", "X = 1\n", permissions=[])
    e, reg = bot(tmp_path, ["probe"])
    run(reg, lambda: asyncio.sleep(0))
    assert not reg.loaded and "Linux и macOS" in dict(reg.failed)["probe"]


def test_engine_file_checks(tmp_path):
    """Движок — только официальный или принятый владельцем; нет машинного кода там, где компилировать нельзя
    (сервер пула), — понятная причина, а не попытка компиляции."""
    other = tmp_path / "e" / "veil-engine.wasm"
    other.parent.mkdir()
    shutil.copy(WASM, other)
    with open(other, "ab") as f:
        f.write(b"\0")                                                  # чужая сборка: другой хеш
    cases = [
        (plugin_engine.Engine(tmp_path / "none.wasm", tmp_path, set()), "нет файла движка"),
        (plugin_engine.Engine(other, tmp_path, set()), "не совпадает с официальной сборкой"),
        (plugin_engine.Engine(WASM, tmp_path / "empty", {engine_sha()}, compile_ok=False), "нет скомпилированного"),
    ]
    for eng, why in cases:
        package(tmp_path, "probe", "X = 1\n", permissions=[])
        e, reg = bot(tmp_path, ["probe"], eng)
        run(reg, lambda: asyncio.sleep(0))
        assert why in dict(reg.failed)["probe"], (why, reg.failed)


def test_describe_checked_by_bot(tmp_path):
    """Что вернул движок при загрузке, бот проверяет сам: события и интерфейс — по манифесту, имена — по правилам."""
    package(tmp_path, "probe", "X = 1\n", permissions=["replies"])
    e, reg = bot(tmp_path, ["probe"])
    r = reg.engine.runner(reg, reg.packages[0], {})
    bad_ready = [("x", []), (["private"], []), (["nope"], []), ([], [["go", "Описание"]])]
    for events, commands in bad_ready:
        with pytest.raises(plugins.PluginError):
            r._check_ready(events, commands)
    r.m = pm.parse(manifest(permissions=["commands"]))
    for cmd in (["start", "Описание"], ["Go", "Описание"], ["go", "a"], ["go"]):
        with pytest.raises(plugins.PluginError):
            r._check_ready([], [cmd])
    bad_ui = [{"buttons": ["Bad"]}, {"buttons": ["a", "a"]}, {"links": [{"hosts": ["*.x.com"], "label": "abc"}]},
              {"links": [{"hosts": ["x.com"], "label": "a"}]}, {"links": [{"hosts": ["x.com"], "label": "abc"}] * 11},
              {"inputs": "a"}]
    for msg in bad_ui:
        with pytest.raises(plugins.PluginError):
            r._check_ui(msg)
    r.m = pm.parse(manifest(permissions=["notify"]))
    with pytest.raises(plugins.PluginError, match="commands"):
        r._check_ui({"buttons": ["ok"]})


def test_sdk_matches_bot():
    """SDK внутри движка и бот описывают одно и то же: имена, лимиты, поля событий (регрессия расхождения копий)."""
    spec = importlib.util.spec_from_file_location("guest_sdk", ROOT / "engine" / "guest" / "veil" / "plugins.py")
    sdk = importlib.util.module_from_spec(spec)
    sys.modules["guest_sdk"] = sdk  # dataclass с отложенными аннотациями ищет свой модуль
    try:
        spec.loader.exec_module(sdk)
    finally:
        del sys.modules["guest_sdk"]
    assert sdk.BUILTIN == plugins.BUILTIN and sdk.COMMAND.pattern == plugins.COMMAND.pattern
    assert sdk.ACTION.pattern == plugins.ACTION.pattern and sdk.HOST.pattern == pm.HOST.pattern
    assert sdk.ID.pattern == pm.ID.pattern
    assert (sdk.BUTTON_TEXT_MAX, sdk.BUTTON_DATA_MAX, sdk.BUTTONS_MAX, sdk.LINK_LABEL, sdk.LINK_HOSTS_MAX) == \
        (plugins.BUTTON_TEXT_MAX, plugins.BUTTON_DATA_MAX, plugins.BUTTONS_MAX, plugins.LINK_LABEL, plugins.LINK_HOSTS_MAX)
    assert set(sdk.EVENT_TYPES) == set(pm.EVENT_PERMISSION)
    for name in ("Reply", "Private", "Published", "Failure", "Outgoing", "Press", "Link"):
        assert list(getattr(sdk, name).__dataclass_fields__) == list(getattr(plugins, name).__dataclass_fields__), name
    with pytest.raises(sdk.PluginError):
        sdk.rows([sdk.Button("", "a")])
    with pytest.raises(sdk.PluginError):
        sdk.rows([sdk.Button(str(i), "a") for i in range(sdk.BUTTONS_MAX + 1)])
    assert sdk.rows([sdk.Button("a", "x", "1"), [sdk.Button("b", "y"), sdk.Button("c", "z")]]) == \
        [[["a", "x", "1"]], [["b", "y", ""], ["c", "z", ""]]]
    with pytest.raises(RuntimeError, match="только внутри движка"):
        sdk._call("notify")


def test_engine_shared_by_two_bots(tmp_path):
    """Один движок на несколько ботов (как группа пула): одинаковый пакет загружается в хост один раз, хранилища
    раздельные, снятый у одного бота плагин у другого продолжает работать."""
    code = """
        from veil import plugins
        STORE = plugins.storage()
        @plugins.on_command("mark", "Отметить")
        async def mark(arg):
            STORE.put("n", STORE.get("n", 0) + 1)
    """
    package(tmp_path / "one", "shared", code, permissions=["commands"])
    package(tmp_path / "two", "shared", code, permissions=["commands"])
    eng = new_engine()
    e1, r1 = bot(tmp_path / "one", ["shared"], eng)
    e2, r2 = bot(tmp_path / "two", ["shared"], eng)

    async def body():
        await start_all(r1)
        await start_all(r2)
        try:
            assert len(eng.packages) == 1 and next(iter(eng.packages.values()))[1] == 2
            await go(e1, e1.msg("/mark"))
            await go(e2, e2.msg("/mark"), e2.msg("/mark"))
            await r1.remove("shared")
            await go(e2, e2.msg("/mark"))
            assert len(eng.packages) == 1
        finally:
            await shutdown(r1, r2)
    asyncio.run(body())
    assert stored(e1, "shared") == {"n": 1} and stored(e2, "shared") == {"n": 3}


def test_engine_problem_texts_have_commands():
    """Причины отказа подсказывают, что сделать (команды существуют)."""
    eng = plugin_engine.Engine(ROOT / "nope.wasm", ROOT, set())
    assert "engine fetch" in eng.problem()
    assert json.dumps(plugin_engine.ENGINE_URL).startswith('"https://')


def test_stdlib_list_documented_and_available(tmp_path):
    """Список стандартной библиотеки в движке — один: тот, что импортирует engine/guest/app.py при сборке, он же в
    docs/PLUGINS.md; каждый модуль из него плагин действительно импортирует."""
    import re
    app = (ROOT / "engine" / "guest" / "app.py").read_text()
    block = app.split("# Стандартная библиотека для плагинов.", 1)[1].split("\nfrom componentize_py_types", 1)[0]
    built = {m.strip() for line in block.splitlines() if line.startswith("import ")
             for m in line.split("#")[0][len("import "):].split(",")}
    doc = (ROOT / "docs" / "PLUGINS.md").read_text()
    section = doc.split("**Только стандартная библиотека, и не вся**", 1)[1].split("Сторонних пакетов", 1)[0]
    documented = set(re.findall(r"`([a-z0-9_.]+)`", section))
    assert documented == built, documented ^ built
    package(tmp_path, "stdlib", f"""
        from veil import plugins
        STORE = plugins.storage()
        @plugins.on_command("load", "Модули")
        async def load(arg):
            import importlib
            STORE.put("ok", [m for m in {sorted(built)!r} if importlib.import_module(m)])
    """, permissions=["commands"])
    e, reg = bot(tmp_path, ["stdlib"])
    run(reg, lambda: go(e, e.msg("/load")))
    assert sorted(stored(e, "stdlib")["ok"]) == sorted(built)


def test_fetch_engine_only_official(tmp_path, monkeypatch):
    """engine fetch: файл принимается, только если SHA-256 совпал с закреплённым в коде; иначе прежний файл цел."""
    official = WASM.read_bytes()
    monkeypatch.setattr(plugin_engine, "ENGINE_SHA256", engine_sha())  # локальная сборка — за официальную
    dest = tmp_path / "e" / "veil-engine.wasm"

    def serve(body, status=200):
        return httpx.MockTransport(lambda req: httpx.Response(status, content=body))
    assert asyncio.run(plugin_engine.fetch_engine(dest, transport=serve(official))) == plugin_engine.ENGINE_SHA256
    assert dest.read_bytes() == official
    for body, status, why in ((official + b"\0", 200, "не совпал"), (b"", 404, "HTTP 404")):
        with pytest.raises(plugins.PluginError, match=why):
            asyncio.run(plugin_engine.fetch_engine(dest, transport=serve(body, status)))
    assert dest.read_bytes() == official


def test_cli_engine_status_and_trust(tmp_path, capsys):
    """Своя сборка движка: бот её не примет, пока владелец не подтвердит хеш в терминале (engine trust)."""
    from veil import cli
    own = tmp_path / "own.wasm"
    own.write_bytes(WASM.read_bytes() + b"\0")

    class Store(dict):
        def put(self, k, v):
            self[k] = v
    store, cfg = Store(), {"plugins": {"engine": "own.wasm"}}
    cli.engine(store, cfg, tmp_path, "status")
    assert "НЕ ПРИНЯТ" in capsys.readouterr().out
    eng = plugin_engine.make_engine(cfg, tmp_path, tmp_path / "data", store)
    assert "не совпадает с официальной" in eng.problem()
    sha = cli.engine(store, cfg, tmp_path, "trust", batch=True)
    assert store["engine_trusted"] == [sha] and "своя сборка, подтверждена" in (cli.engine(store, cfg, tmp_path, "status")
                                                                              and capsys.readouterr().out)
    assert plugin_engine.make_engine(cfg, tmp_path, tmp_path / "data", store).problem() is None
    with pytest.raises(cli.CliError):
        cli.engine(store, {}, tmp_path, "nope")


def test_engine_limits_hold_even_if_plugin_rewrites_engine(tmp_path, caplog):
    """Плагин исполняется в одном CPython с кодом движка и может переписать его ограничения. Ограничения вывода
    держит хост: огромный ответ, длинный журнал и гигантские аргументы не рвут канал и не роняют хост (в пуле это
    выключило бы плагины всей группы)."""
    package(tmp_path, "rogue", """
        import sys
        from veil import plugins
        app = sys.modules["app"]
        app.LOG_LINES, app.LOG_LINE = 10 ** 9, 10 ** 9
        STORE = plugins.storage()

        @plugins.on_command("big", "Большой ответ")
        async def big(arg):
            return "x" * (3 << 20)

        @plugins.on_command("noisy", "Длинный журнал")
        async def noisy(arg):
            for _ in range(5000):
                print("y" * 2000)

        @plugins.on_command("args", "Большие аргументы")
        async def args(arg):
            try:
                plugins._call("notify", text="z" * (3 << 20))  # мимо SDK, который обрезал бы текст
            except plugins.PluginError as e:
                STORE.put("args", str(e))

        @plugins.on_command("ok", "Проверка")
        async def ok(arg):
            await plugins.notify_owner("жив")
    """, permissions=["commands", "notify"])
    e, reg = bot(tmp_path, ["rogue"])

    async def body():
        pid = reg.engine.proc.pid
        for cmd in ("big", "noisy", "args", "ok"):
            await go(e, e.msg("/" + cmd))
        assert reg.engine.proc.pid == pid and not reg.engine.restarts    # хост тот же: не падал
    import logging
    with caplog.at_level(logging.INFO, logger="veil.plugins"):
        run(reg, body)
    assert "больше 2 МиБ" in stored(e, "rogue")["args"] and any("жив" in t for t in texts(e))
    assert any("Плагин rogue: сбой в /big" in t for t in texts(e))
    assert sum(r.getMessage().startswith("plugin rogue: y") for r in caplog.records) <= 100
    assert all(len(r.getMessage()) < 600 for r in caplog.records if r.getMessage().startswith("plugin rogue:"))
