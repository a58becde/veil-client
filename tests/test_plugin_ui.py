"""Интерфейс плагина в чате (docs/PLUGINS.md, «Кнопки и вопросы»): сообщения с кнопками, правка на месте, вопрос
с ответом следующим сообщением, кнопка под черновиком со ссылкой, меню /plugins. И то, чего плагин не может: подделать
кнопку бота, спросить без действия владельца, нажать чужую кнопку."""
import asyncio
import json
import re

import pytest

from veil import plugins
from veil.ui import bot as uibot

from plugkit import bot, package, settle, shutdown, start_all, stored, texts

CODE = """
    from veil import plugins
    STORE = plugins.storage()

    @plugins.on_command("menu", "Меню пробы")
    async def menu(arg):
        await plugins.show("Что сделать?", [[plugins.Button("Спросить имя", "ask_name"),
                                             plugins.Button("Счёт", "count", "x")]])

    @plugins.on_button("count")
    async def count(press):
        n = STORE.get("n", 0) + 1
        STORE.put("n", n)
        await plugins.edit(press.message, f"Нажато {n} ({press.data})", [plugins.Button("Ещё", "count", "y")])

    @plugins.on_button("ask_name")
    async def ask_name(press):
        await plugins.ask("Как вас зовут?", "name")

    @plugins.on_input("name")
    async def got(text):
        await plugins.notify_owner(f"Привет, {text}")

    @plugins.on_link("pinterest.com", "pin.it", label="Пост из пина")
    async def pin(link):
        await plugins.notify_owner("ссылка " + link.url)

    @plugins.on_start
    async def start():
        try:
            await plugins.ask("Без спроса?", "name")
        except plugins.PluginError as e:
            STORE.put("ask_on_start", str(e))
"""


def kb(e) -> list[tuple[str, str]]:
    for m, p in reversed(e.tg.calls):
        mk = p.get("reply_markup")
        mk = json.loads(mk) if isinstance(mk, str) else mk
        if mk and mk.get("inline_keyboard"):
            return [(b["text"], b["callback_data"]) for row in mk["inline_keyboard"] for b in row]
    return []


def last_id(e) -> int:
    return e.tg.mid


@pytest.fixture
def probe(tmp_path):
    package(tmp_path, "probe", CODE, permissions=["commands", "notify"])
    e, reg = bot(tmp_path, ["probe"])
    return e, reg


async def go(e, *updates):
    for u in updates:
        e.ui._route(u)
        await settle(e)


def test_buttons_edit_and_question(probe):
    e, reg = probe

    async def scenario():
        await start_all(reg)
        try:
            reg.fire("start")
            await settle(e)
            await go(e, e.msg("/menu"))
            assert texts(e)[-1] == "🧩 Тест: Что сделать?"
            (ask_text, ask_cb), (cnt_text, cnt_cb) = kb(e)
            assert (ask_text, cnt_text) == ("Спросить имя", "Счёт") and ask_cb.startswith("pb:")
            assert re.fullmatch(r"pb:[A-Za-z0-9_-]{8}:1", cnt_cb)  # действие и данные кнопки — у бота, не в Telegram
            menu_id = last_id(e)

            await go(e, e.press(cnt_cb, menu_id))
            assert texts(e)[-1] == "🧩 Тест: Нажато 1 (x)" and e.tg.calls[-1][0] == "editMessageText"
            (more, more_cb), = kb(e)
            await go(e, e.press(more_cb, menu_id))
            assert texts(e)[-1] == "🧩 Тест: Нажато 2 (y)"
            await go(e, e.press(cnt_cb, menu_id))  # кнопка с прошлого экрана: такой больше нет
            assert "устарела" in texts(e)[-1]

            await go(e, e.press(ask_cb, menu_id + 99))  # кнопка не из своего сообщения — не нажимается
            assert "устарела" in texts(e)[-1]

            await go(e, e.msg("/menu"))
            menu2 = last_id(e)
            ask_cb2 = kb(e)[0][1]
            await go(e, e.press(ask_cb2, menu2))
            assert "Как вас зовут?" in texts(e)[-1] and "получит плагин «Тест»" in texts(e)[-1]
            await go(e, e.msg("Вася"))  # ответ уходит плагину, а не в черновик поста
            assert texts(e)[-1] == "🧩 Тест: Привет, Вася" and not any("Черновик" in t for t in texts(e))
            await go(e, e.msg("а это уже пост"))
            assert any("Черновик" in t for t in texts(e))
        finally:
            await shutdown(reg)
    asyncio.run(scenario())
    assert "в ответ на действие владельца" in stored(e, "probe")["ask_on_start"]  # спросить сам плагин не может


def test_link_button_under_draft(probe):
    e, reg = probe

    async def scenario():
        await start_all(reg)
        try:
            url = "https://ru.pinterest.com/pin/123/"
            await go(e, e.msg(f"смотри {url}", entities=[{"type": "url", "offset": 7, "length": len(url)}]))
            buttons = kb(e)
            assert ("🧩 Пост из пина", f"pl:{e.draft_id()}:0") in buttons
            await go(e, e.press(f"pl:{e.draft_id()}:0"))
            assert texts(e)[-1] == f"🧩 Тест: ссылка {url}"
            await go(e, e.msg("без ссылок на пины https://example.com",
                              entities=[{"type": "url", "offset": 18, "length": 19}]))
            assert not any(cb.startswith("pl:") for _, cb in kb(e))
        finally:
            await shutdown(reg)
    asyncio.run(scenario())


def test_plugins_menu_and_cancel(probe):
    e, reg = probe

    async def scenario():
        await start_all(reg)
        try:
            await go(e, e.msg("/plugins"))
            assert "• Тест 1.0.0" in texts(e)[-1] and ("🧩 Меню пробы", "pc:menu") in kb(e)
            await go(e, e.press("pc:menu"))
            assert texts(e)[-1] == "🧩 Тест: Что сделать?"
            mid = last_id(e)
            await go(e, e.press(kb(e)[0][1], mid))
            ask_id = last_id(e)
            await go(e, e.press("aw:x", ask_id))  # «Отмена» под вопросом
            await go(e, e.msg("Пётр"))
            assert not any("Привет, Пётр" in t for t in texts(e)) and any("Черновик" in t for t in texts(e))
        finally:
            await shutdown(reg)
    asyncio.run(scenario())


def test_button_needs_handler_and_permission(tmp_path):
    package(tmp_path, "noui", """
        from veil import plugins
        STORE = plugins.storage()
        @plugins.on_reply
        async def r(reply):
            for name, call in (("show_no_commands", lambda: plugins.show("x", [plugins.Button("a", "a")])),):
                try:
                    await call()
                except plugins.PluginError as e:
                    STORE.put(name, str(e))
    """, permissions=["replies", "notify"])
    package(tmp_path, "nohandler", """
        from veil import plugins
        STORE = plugins.storage()
        @plugins.on_command("go", "Попробовать")
        async def go(arg):
            try:
                await plugins.show("x", [plugins.Button("a", "nobody")])
            except plugins.PluginError as e:
                STORE.put("err", str(e))
    """, permissions=["commands", "notify"])
    package(tmp_path, "sneaky", """
        from veil import plugins
        @plugins.on_button("x")
        async def x(p):
            pass
    """, permissions=["notify"])
    e, reg = bot(tmp_path, ["noui", "nohandler", "sneaky"])

    async def scenario():
        await start_all(reg)
        try:
            assert "без разрешения commands" in dict(reg.failed)["sneaky"]
            reg.fire("reply", plugins.Reply(7, 5, "ответ", ""))
            await settle(e)
            await reg.run_command("go", "")
            await settle(e)
        finally:
            await shutdown(reg)
    asyncio.run(scenario())
    s1, s2 = stored(e, "noui"), stored(e, "nohandler")
    assert "без разрешения commands" in s1["show_no_commands"] and "без обработчика" in s2["err"]


def test_bot_rebuilds_buttons_and_matches_hosts():
    """Кнопки от плагина бот проверяет сам (SDK движка проверяет их раньше — test_plugin_engine)."""
    for raw in ([[["", "a", ""]]], [[["ok", "Bad Action", ""]]], [[[str(i), "a", ""] for i in range(25)]],
                [[["ok", "a", "x" * 257]]]):
        with pytest.raises(plugins.PluginError):
            plugins.check_rows(raw)
    for raw in ("x", [["a"]], [[]], [[["a", "b"]]]):
        with pytest.raises((ValueError, TypeError)):
            plugins.check_rows(raw)
    assert plugins.check_rows([[["a", "x", "1"]], [["b", "y", ""], ["c", "z", ""]]]) == \
        [[["a", "x", "1"]], [["b", "y", ""], ["c", "z", ""]]]
    assert plugins.host_matches("https://ru.pinterest.com/pin/1", ("pinterest.com",))
    assert not plugins.host_matches("https://pinterest.com.evil.io/", ("pinterest.com",))
    assert not plugins.host_matches("https://notpinterest.com/", ("pinterest.com",))


def test_draft_urls():
    text = "a https://x.com/1 и 😀 https://y.org"
    msgs = [{"text": text, "entities": [
        {"type": "url", "offset": 2, "length": 15},
        {"type": "url", "offset": 23, "length": 13},  # 😀 — две позиции UTF-16
        {"type": "text_link", "offset": 0, "length": 1, "url": "https://z.net/"}]}]
    assert uibot.draft_urls(msgs) == ["https://x.com/1", "https://y.org", "https://z.net/"]
