"""veil.plugin_dev: пакет плагина проверяется без бота и сервера — в том же движке, с консолью вместо Telegram."""
import asyncio
import textwrap
from pathlib import Path

from veil import plugin_dev

from plugkit import ROOT, WASM, engine_sha


def package(tmp_path, code: str, permissions=("commands", "notify")) -> Path:
    d = tmp_path / "pkg" / "probe"
    d.mkdir(parents=True)
    (d / "plugin.toml").write_text(textwrap.dedent(f"""\
        id = "probe"
        name = "Проба"
        version = "0.1.0"
        api = 1
        entry = "main"
        description = "Проверка инструмента разработчика"
        author = "Тест"
        license = "MIT"
        permissions = {list(permissions)!r}
        """).replace("'", '"'))
    (d / "main.py").write_text(textwrap.dedent(code))
    return d


def drive(pdir: Path, script: list[str], data: Path, **kw) -> tuple[int, list[str]]:
    out: list[str] = []

    async def lines():
        for s in script:
            yield s
    engine_sha()  # движок собран
    rc = asyncio.run(plugin_dev.run(pdir, settings=kw.get("settings", {}), data=data, tokens=kw.get("tokens", 50),
                                    lines=lines(), out=out.append, engine=kw.get("engine", WASM)))
    return rc, out


def test_example_plugin_driven_from_console(tmp_path):
    rc, out = drive(ROOT / "examples/plugins/reply_digest", ["reply 5 a", "reply 5 b", "reply 9 c", "/digest",
                                                             "tokens 2", "/nope", "квак"], tmp_path)
    text = "\n".join(out)
    assert rc == 0 and "Работает в движке. Команды: /digest" in text
    assert "№5: 2\n№9: 1" in text and "Токенов на сегодня осталось: 2" in text
    assert "команды /nope у плагина нет" in text and "не понял «квак»" in text


def test_settings_storage_and_draft(tmp_path):
    pdir = package(tmp_path, """
        from veil import plugins
        CONF = plugins.settings()
        STORE = plugins.storage()

        @plugins.on_command("hi", "Поздороваться")
        async def hi(arg):
            n = STORE.get("n", 0) + 1
            STORE.put("n", n)
            await plugins.notify_owner(f"{CONF.get('greeting', '?')} {arg} #{n} токенов {await plugins.tokens_today()}")
            await plugins.propose_draft("черновик от плагина", reply_to=3)
        """, permissions=("commands", "notify", "drafts", "tokens"))
    data = tmp_path / "data"
    rc, out = drive(pdir, ["/hi мир"], data, settings={"greeting": "привет"}, tokens=7)
    assert rc == 0 and "→ владельцу: 🧩 Проба: привет мир #1 токенов 7" in out
    assert "→ черновик (ответ на №3): черновик от плагина" in out
    rc, out = drive(pdir, ["/hi снова"], data, settings={"greeting": "привет"})  # --data: хранилище переживает запуск
    assert "#2" in "\n".join(out)


def test_failing_handler_and_forbidden_event(tmp_path):
    pdir = package(tmp_path, """
        from veil import plugins

        @plugins.on_command("boom", "Упасть")
        async def boom(arg):
            raise RuntimeError("сломался")

        @plugins.on_command("net", "В сеть без разрешения")
        async def net(arg):
            await plugins.http("GET", "https://example.com/")
        """)
    rc, out = drive(pdir, ["/boom", "/net"], tmp_path / "d")
    assert rc == 1 and any(s.startswith("✗ probe: /boom") for s in out)  # причина — в журнале бота
    assert any("/net" in s and "✗" in s for s in out)  # http без разрешения net — отказ внутри плагина

    bad = package(tmp_path / "b", """
        from veil import plugins

        @plugins.on_reply
        async def r(reply):
            pass
        """, permissions=("notify",))
    rc, out = drive(bad, [], tmp_path / "d2")
    assert rc == 1 and any("Не запустился" in s and "replies" in s for s in out)


def test_bad_package_rejected(tmp_path):
    pdir = package(tmp_path, "x = 1\n")
    (pdir / "plugin.toml").write_text('id = "probe"\n')
    rc, out = drive(pdir, [], tmp_path / "d")
    assert rc == 1 and out[0].startswith("Пакет не принят")
    rc, out = drive(pdir, [], tmp_path / "d", engine=tmp_path / "нет.wasm")
    assert rc == 1 and "Нет движка" in out[0] and "plugin_engine fetch" in out[0]


def test_cli_usage(capsys):
    assert plugin_dev.main([]) == 2 and "python -m veil.plugin_dev" in capsys.readouterr().out


def test_buttons_questions_and_links_in_console(tmp_path):
    pdir = package(tmp_path, """
        from veil import plugins

        @plugins.on_command("pin", "Пост из пина")
        async def pin(arg):
            await plugins.show("Откуда взять пин?", [plugins.Button("Прислать ссылку", "ask")])

        @plugins.on_button("ask")
        async def ask(press):
            await plugins.edit(press.message, "Жду ссылку", [])
            await plugins.ask("Пришлите ссылку на пин", "url")

        @plugins.on_input("url")
        async def got(text):
            await plugins.notify_owner("получил " + text)

        @plugins.on_link("pinterest.com", label="Пост из пина")
        async def link(link):
            await plugins.notify_owner("ссылка " + link.url)
        """)
    rc, out = drive(pdir, ["/pin", "press 1", "input https://pin.it/x", "link https://ru.pinterest.com/pin/1/",
                           "link https://example.com/", "press 9", "input лишнее"], tmp_path / "d")
    text = "\n".join(out)
    assert rc == 0 and "→ сообщение #1: 🧩" not in text  # консоль печатает текст плагина без подписи бота
    assert "→ сообщение #1: Откуда взять пин?\n   [1] Прислать ссылку" in text
    assert "→ правка #1: Жду ссылку" in text and "→ вопрос: Пришлите ссылку на пин" in text
    assert "получил https://pin.it/x" in text and "ссылка https://ru.pinterest.com/pin/1/" in text
    assert "кнопки плагина не будет" in text and "нет кнопки 9" in text and "ни о чём не спрашивал" in text


def test_precompiled_cache_never_compiles(tmp_path):
    """--cache: машинный код берётся готовым (сервер пула); нет его — понятный отказ, а не компиляция на ~350 МБ."""
    import shutil
    from veil import plugin_host
    pdir = package(tmp_path, """
        from veil import plugins
        @plugins.on_command("hi", "Привет")
        async def hi(arg):
            await plugins.notify_owner("ок")
        """)
    ready = tmp_path / "ready"
    ready.mkdir()
    shutil.copy(WASM.parent / plugin_host.cwasm_name(WASM), ready)
    out = []

    async def lines():
        yield "/hi"
    rc = asyncio.run(plugin_dev.run(pdir, settings={}, data=tmp_path / "d", tokens=1, lines=lines(), out=out.append,
                                    engine=WASM, cache=ready))
    assert rc == 0 and "→ владельцу: 🧩 Проба: ок" in out
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = asyncio.run(plugin_dev.run(pdir, settings={}, data=tmp_path / "d", tokens=1, lines=lines(), out=out.append,
                                    engine=WASM, cache=empty))
    assert rc == 1 and "нет скомпилированного движка" in out[-1] and not list(empty.iterdir())
