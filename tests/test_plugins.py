"""Плагины бота (docs/PLUGINS.md): загрузка только явно включённых пакетов владельца, события бота, отмена отправки,
команды, черновик от плагина; сбой плагина не роняет бота. Всё — через настоящий движок (WASM в процессе-хосте)."""
import asyncio
import json
import os
from pathlib import Path

import pytest
from harness import Env
from plugkit import go, has, new_engine, package, settle, shutdown, start_all, stored

from veil import plugins
from veil.ui import bot as uibot

SPY = """
from veil import plugins
STORE = plugins.storage()

def seen(*x):
    STORE.put("seen", STORE.get("seen", []) + [list(x)])

@plugins.on_post_published
async def published(p):
    seen("published", p.n, p.anonymous)

@plugins.on_reply
async def reply(r):
    seen("reply", r.n, r.to, r.text)

@plugins.on_error
async def error(f):
    seen("error", f.op, f.code)

@plugins.on_tokens_low
async def low(n):
    seen("tokens_low", n)

@plugins.on_start
async def start():
    seen("start")
"""
SPY_PERMS = ["published", "replies", "errors", "tokens"]


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    async def no_sleep(s):
        pass
    monkeypatch.setattr(uibot.asyncio, "sleep", no_sleep)


def attach(e: Env, base: Path, enabled: list[str], **conf) -> plugins.Registry:
    reg = plugins.load({"plugins": {"enabled": enabled, **conf}}, base, None, new_engine())
    e.ui.plugins = reg
    reg.host = uibot.PluginHost(e.ui)
    return reg


def scenario(e: Env, reg: plugins.Registry, body):
    """Пакеты стартуют в том же цикле событий, где идёт сценарий; движок останавливается в конце."""
    async def run():
        await start_all(reg)
        try:
            await body()
        finally:
            await shutdown(reg)
    asyncio.run(run())


async def publish(e: Env, text: str = "пост") -> None:
    await go(e, e.msg(text))
    await go(e, e.press(f"d:{e.draft_id()}:send"))


def seen(e: Env, name: str = "spy") -> list:
    return [tuple(x) for x in stored(e, name).get("seen", [])]


# --- загрузка ---
def test_only_enabled_owner_packages_load(tmp_path):
    base = tmp_path / "cfg"
    for name in ("good", "other", "shared"):
        package(base, name, "VALUE = 1\n", permissions=[])
    os.chmod(base / "plugins" / "shared" / "main.py", 0o664)                 # группа может менять — отказ
    (base / "plugins" / "linked").symlink_to(base / "plugins" / "good")
    (base / "plugins" / "legacy.py").write_text("VALUE = 1\n")               # плагин-файл: режима больше нет
    reg = plugins.load({"plugins": {"enabled": ["good", "shared", "linked", "missing", "Bad-Name", "legacy"]}}, base)
    assert [p.name for p in reg.packages] == ["good"]                         # other не включён — не проверяется
    why = dict(reg.failed)
    assert set(why) == {"shared", "linked", "missing", "Bad-Name", "legacy"}
    assert "go-w" in why["shared"] and "нет пакета" in why["linked"] and "нет пакета" in why["legacy"]
    os.chmod(base / "plugins", 0o777)
    reg = plugins.load({"plugins": {"enabled": ["good"]}}, base)
    assert not reg.packages and "каталог плагинов" in reg.failed[0][1]


def test_pool_runs_only_market_plugins(tmp_path):
    """В пуле каталог plugins/ оператора не попадает ко всем ботам: только плагины из маркета."""
    base = tmp_path / "cfg"
    package(base, "good", "VALUE = 1\n", permissions=[])
    reg = plugins.load({"pool": {"identity": "custodial"}, "plugins": {"enabled": ["good"]}}, base)
    assert not reg.packages and not reg.failed


def test_broken_plugin_leaves_nothing(tmp_path):
    """Ошибка в коде плагина или синхронный обработчик: бот работает без него, обработчиков от него не остаётся."""
    base = tmp_path / "cfg"
    package(base, "broken", """
        from veil import plugins
        @plugins.on_reply
        async def r(x):
            pass
        raise ValueError("oops")
    """, permissions=["replies"])
    package(base, "sync_handler", """
        from veil import plugins
        @plugins.on_reply
        def r(x):
            pass
    """, permissions=["replies"])
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["broken", "sync_handler"])

    async def body():
        assert not reg.loaded and not reg.handlers["reply"]
        why = dict(reg.failed)
        assert "ValueError: oops (main.py:6)" in why["broken"] and "async def" in why["sync_handler"]
    scenario(e, reg, body)


def test_settings_and_command_rules(tmp_path):
    base = tmp_path / "cfg"
    package(base, "conf", """
        from veil import plugins
        CONF = plugins.settings()
        STORE = plugins.storage()
        @plugins.on_start
        async def start():
            STORE.put("conf", CONF)
    """, permissions=[])
    package(base, "clash", """
        from veil import plugins
        @plugins.on_command("start", "Своя команда start")
        async def c(arg):
            pass
    """, permissions=["commands"])
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["conf", "clash"], settings={"conf": {"limit": 3}})

    async def body():
        reg.fire("start")
        await settle(e)
        assert "встроенной команды" in dict(reg.failed)["clash"]
    scenario(e, reg, body)
    assert stored(e, "conf")["conf"] == {"limit": 3}


# --- события ---
def test_events_reach_plugins(tmp_path):
    base = tmp_path / "cfg"
    package(base, "spy", SPY, permissions=SPY_PERMS)
    e = Env(tmp_path / "data", tokens=2)
    reg = attach(e, base, ["spy"], tokens_low=1)

    async def body():
        await e.ui.setup()
        await settle(e)
        await publish(e)
        await publish(e, "второй")                     # токенов не осталось
        e.store.add_post(5, bytes(32), "", "text")
        e.server.feed = [{"n": 7, "reply_to": 5, "excerpt": "ответ", "url": "https://t.me/c/1/7"}]
        await e.ui._sync_once()
        await settle(e)
    scenario(e, reg, body)
    events = seen(e)
    assert ("start",) in events
    assert [x for x in events if x[0] == "published"] == [("published", 101, False), ("published", 102, False)]
    assert [x for x in events if x[0] == "tokens_low"] == [("tokens_low", 1)]  # раз в сутки, а не после каждого
    assert ("reply", 7, 5, "ответ") in events


def test_error_event_carries_protocol_code(tmp_path):
    base = tmp_path / "cfg"
    package(base, "spy", SPY, permissions=SPY_PERMS)
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["spy"])

    async def body():
        e.server.fail("post.create", "E_RATE", retry_after=60)
        await publish(e)
    scenario(e, reg, body)
    assert ("error", "post.create", "E_RATE") in seen(e)


def test_before_send_can_stop_a_post(tmp_path):
    base = tmp_path / "cfg"
    package(base, "guard", """
        from veil import plugins
        @plugins.before_send
        async def no_links(out):
            if "http" in out.text:
                return "без ссылок"
    """, permissions=["before_send"])
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["guard"])

    async def body():
        await publish(e, "смотри http://example.com")
        assert has(e, "его остановил плагин: guard: без ссылок") and "post.create" not in [op for op, _ in e.server.ops]
        await publish(e, "обычный текст")
        assert "post.create" in [op for op, _ in e.server.ops]
    scenario(e, reg, body)


def test_failing_check_blocks_the_post(tmp_path):
    """Проверка, которая упала, — не повод отправить пост без проверки."""
    base = tmp_path / "cfg"
    package(base, "guard", """
        from veil import plugins
        @plugins.before_send
        async def broken(out):
            raise RuntimeError("bug")
    """, permissions=["before_send"])
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["guard"])

    async def body():
        await publish(e)
    scenario(e, reg, body)
    assert has(e, "проверка не выполнилась (RuntimeError)") and "post.create" not in [op for op, _ in e.server.ops]


def test_plugin_failure_reported_once(tmp_path):
    base = tmp_path / "cfg"
    package(base, "bad", """
        from veil import plugins
        @plugins.on_reply
        async def r(x):
            raise KeyError("x")
    """, permissions=["replies"])
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["bad"])

    async def body():
        e.store.add_post(5, bytes(32), "", "text")
        e.server.feed = [{"n": 7, "reply_to": 5, "excerpt": "а"}, {"n": 8, "reply_to": 5, "excerpt": "б"}]
        await e.ui._sync_once()
        await settle(e)
    scenario(e, reg, body)
    reports = [t for t in e.tg.texts() if "Плагин bad: сбой" in t]
    assert len(reports) == 1 and "KeyError" in reports[0]
    assert sum("Ответ" in t or "ответ" in t for t in e.tg.texts()) >= 2  # владелец получил оба ответа


def test_command_and_proposed_draft(tmp_path):
    """Команда плагина — в меню бота; плагин предлагает черновик, но публикует его только владелец кнопкой."""
    base = tmp_path / "cfg"
    package(base, "helper", """
        from veil import plugins
        @plugins.on_command("draft", "Черновик от плагина")
        async def draft(arg):
            await plugins.propose_draft(f"Предлагаю: {arg or 'текст'}", reply_to=5)
            await plugins.notify_owner(f"токенов сегодня: {await plugins.tokens_today()}")
    """, permissions=["commands", "drafts", "notify", "tokens"])
    e = Env(tmp_path / "data", tokens=3)
    reg = attach(e, base, ["helper"])

    async def body():
        await e.ui.setup()
        menu = next(p for m, p in e.tg.calls if m == "setMyCommands")
        cmds = menu["commands"] if isinstance(menu["commands"], list) else json.loads(menu["commands"])
        assert {"command": "draft", "description": "Черновик от плагина"} in cmds
        await go(e, e.msg("/draft"))
        assert has(e, "Предлагаю: текст") and has(e, "токенов сегодня: 3")
        assert "post.create" not in [op for op, _ in e.server.ops]
        await go(e, e.press(f"d:{e.draft_id()}:send"))
        created = [b for op, b in e.server.ops if op == "post.create"]
        assert created and created[0].get("reply_to") == 5
        await go(e, e.msg("/nosuch"))
        assert has(e, "Не понял")
    scenario(e, reg, body)


def test_owner_told_about_plugin_code_changes(tmp_path):
    base = tmp_path / "cfg"
    d = package(base, "spy", SPY, permissions=SPY_PERMS)
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["spy"])

    async def body():
        await e.ui._announce_plugins()
        assert sum("Изменился код плагинов" in t for t in e.tg.texts()) == 1 and has(e, "+ spy")
        await e.ui._announce_plugins()
        assert sum("Изменился код плагинов" in t for t in e.tg.texts()) == 1  # без изменений — без сообщения
    scenario(e, reg, body)
    (d / "main.py").write_text(SPY + "\n# правка\n")
    reg = attach(e, base, ["spy"])

    async def again():
        await e.ui._announce_plugins()
        assert has(e, "~ spy") and "Плагины: spy" in e.ui.status_text()
    scenario(e, reg, again)


def test_examples_work(tmp_path):
    """Примеры из examples/plugins — пакеты: работают в движке и делают то, что обещают."""
    e = Env(tmp_path / "data")
    ex = Path(__file__).resolve().parent.parent / "examples" / "plugins"
    reg = attach(e, tmp_path, ["reply_digest", "link_guard"], dir=str(ex), settings={"reply_digest": {"keep": 10}})

    async def body():
        assert [p.name for p in reg.loaded] == ["reply_digest", "link_guard"], reg.failed
        e.store.add_post(5, bytes(32), "", "text")
        e.server.feed = [{"n": 7, "reply_to": 5, "excerpt": "а"}, {"n": 8, "reply_to": 5, "excerpt": "б"}]
        await e.ui._sync_once()
        await settle(e)
        await go(e, e.msg("/digest"))
        assert has(e, "№5: 2")
        await go(e, e.msg("мой сайт https://example.com"))
        await go(e, e.press(f"d:{e.draft_id()}:send"))
        assert has(e, "открытая ссылка") and "post.create" not in [op for op, _ in e.server.ops]
    scenario(e, reg, body)
    assert stored(e, "reply_digest")  # хранилище — у бота, в его данных


def test_module_runs_anew_for_each_event(tmp_path):
    """Каждое событие — новый экземпляр движка: переменные модуля не переживают событие, хранилище — переживает.
    Классы и dataclass в модуле плагина работают (модуль виден себе при загрузке, как при обычном импорте)."""
    base = tmp_path / "cfg"
    package(base, "counter", """
        import sys
        from dataclasses import dataclass
        from veil import plugins

        @dataclass
        class Note:
            text: str

        STORE = plugins.storage()
        HITS = []

        @plugins.on_command("hit", "Посчитать")
        async def hit(arg):
            HITS.append(1)
            STORE.put("runs", STORE.get("runs", []) + [len(HITS)])
            STORE.put("note", Note("a").text + str(sys.modules[__name__] is not None))
    """, permissions=["commands"])
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["counter"])

    async def body():
        for _ in range(3):
            await reg.run_command("hit", "")
    scenario(e, reg, body)
    assert stored(e, "counter") == {"runs": [1, 1, 1], "note": "aTrue"}


def test_events_of_one_plugin_run_in_order(tmp_path):
    """Одновременные события одного плагина у одного бота идут по очереди: запись в хранилище не теряется
    (регрессия: каждый экземпляр движка читал хранилище сам, и параллельные обработчики затирали друг друга)."""
    base = tmp_path / "cfg"
    package(base, "spy", SPY, permissions=SPY_PERMS)
    e = Env(tmp_path / "data")
    reg = attach(e, base, ["spy"])

    async def body():
        for i in range(20):
            reg.fire("tokens_low", i)
        await settle(e)
    scenario(e, reg, body)
    assert sorted(x[1] for x in seen(e) if x[0] == "tokens_low") == list(range(20))
