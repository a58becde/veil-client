"""Тексты интерфейса: каждая ошибка сервера объясняется словами, коды пользователю не показываются."""
from pathlib import Path

from veil.core.protocol.errors import __dict__ as errors_module
from veil.core.transport.exchange import ServerError
from veil.ui.bot import UI, Texts, human_wait

ROOT = Path(__file__).resolve().parents[1]


def test_human_wait():
    assert human_wait(12000) == "3 ч 20 мин" and human_wait(3600) == "1 ч" and human_wait(300) == "5 мин"
    assert human_wait(0) == "1 с"


def test_every_server_error_has_explanation():
    t = Texts(ROOT / "locales" / "ru.toml", {})
    ui = UI.__new__(UI)
    ui.T = t
    codes = [v for k, v in errors_module.items() if k.startswith("E_") and isinstance(v, str)]
    assert codes
    skip = set()  # даже коды, которые не должны доходить до владельца, объясняются словами
    for code in codes:
        if code in skip:  # не доходят до владельца: ядро повторяет с другим токеном или это ошибка клиента
            continue
        msg = ui.explain(ServerError(code, retry_after=600))
        assert "E_" not in msg and "{" not in msg, (code, msg)
    assert "10 мин" in ui.explain(ServerError("E_NICK_COOLDOWN", retry_after=600))
    assert "E_" not in ui.explain(ServerError("E_SOMETHING_NEW"))


class _Bot:
    def __init__(self):
        self.edits, self.sent = [], []

    async def edit(self, chat, mid, text, markup=None):
        self.edits.append(text)

    async def send(self, chat, text, **kw):
        self.sent.append(text)
        return {"message_id": 1}


def _ui():
    import types
    ui = UI.__new__(UI)
    ui.T = Texts(ROOT / "locales" / "ru.toml", {})
    ui.bot, ui.owner = _Bot(), 1
    ui.cfg = {"privacy": {}}
    ui.config_name = "config.toml"
    ui.core = types.SimpleNamespace()
    from veil import plugins
    ui.plugins = plugins.Registry()
    return ui


def test_status_never_hangs():
    """Любая ошибка операции превращает «Отправляю…» в объяснение (регрессия 2026-10-15)."""
    import asyncio
    from veil.core import api
    status = {"chat": {"id": 1}, "message_id": 5}
    for exc, expect in [(RuntimeError("boom"), "Внутренняя ошибка"), (api.NoIdentity(), "config.toml init"),
                        (api.DeviceRevoked(), "восстановлена"), (api.OtherBot(), "config.toml restore"),
                        (ServerError("E_NICK_COOLDOWN", retry_after=90), "1 мин")]:
        ui = _ui()

        async def op(e=exc):
            raise e
        asyncio.run(ui._run(op, lambda r: "ok", status=status))
        assert len(ui.bot.edits) == 1 and expect in ui.bot.edits[0], (exc, ui.bot.edits)


def test_draft_without_send_when_problem():
    """Черновик, который не пройдёт, показывается без «Отправить» и с объяснением (регрессия: «сократите на 27»
    появлялось только после нажатия)."""
    import asyncio
    from veil.core import api
    ui = _ui()
    ui.bot.sent_markups = []

    async def send(chat, text, markup=None, **kw):
        ui.bot.sent.append(text)
        ui.bot.sent_markups.append(markup)
        return {"message_id": 1}
    ui.bot.send = send

    async def check(d):
        return [("text.too_long", {"n": 27})]
    ui.core.check_draft = check
    ui.core.nick = lambda: None
    d = api.Draft(chat_id=1, messages=[{"message_id": 1, "text": "x"}])
    asyncio.run(ui._show_draft(5, d))
    assert "сократите на 27" in ui.bot.sent[0]
    buttons = [b["callback_data"] for row in ui.bot.sent_markups[0]["inline_keyboard"] for b in row]
    assert "d:5:send" not in buttons and "d:5:x" in buttons

    async def ok(d):
        return []
    ui.core.check_draft = ok
    asyncio.run(ui._show_draft(5, d))
    assert "d:5:send" in [b["callback_data"] for row in ui.bot.sent_markups[1]["inline_keyboard"] for b in row]


def test_telegram_split_text_becomes_one_draft():
    import asyncio
    ui = _ui()
    ui.split_buf = None
    drafts = []

    async def new_draft(msgs, **kw):
        drafts.append(msgs)
    ui._new_draft = new_draft
    ui.core.store = type("S", (), {"get": lambda self, k: None, "put": lambda self, k, v: None})()
    import veil.ui.bot as botmod
    botmod.SPLIT_WAIT = 0.05

    async def scenario():
        ui.tasks = set()
        assert ui._split_part({"message_id": 1, "text": "я" * 4096})
        assert ui._split_part({"message_id": 2, "text": "хвост"})
        await asyncio.sleep(0.3)
    asyncio.run(scenario())
    assert len(drafts) == 1 and [m["message_id"] for m in drafts[0]] == [1, 2]
    assert not ui._split_part({"message_id": 3, "text": "короткое"})


def test_texts_format_is_safe():
    """Переопределённый текст не может достать внутренности процесса через {x.__class__…}."""
    t = Texts(ROOT / "locales" / "ru.toml", {"text.unknown": "{err.__class__.__mro__} {n}"})
    assert t("text.unknown", err=ValueError("x"), n=5) == "{err.__class__.__mro__} 5"


def test_locale_has_no_orphans_and_no_gaps():
    """Каждый ключ локали, который упоминает код, есть в ru.toml, и каждый текст ru.toml кому-то нужен: осиротевшие
    тексты (например, после удаления режима или функции) не копятся. Семейства с ключом из переменной: commands.<команда>,
    perm.<разрешение>, error.<код протокола>."""
    import ast
    import tomllib
    from veil import plugin_manifest as pm
    from veil.core.protocol.errors import __dict__ as errs
    data = tomllib.loads((ROOT / "locales" / "ru.toml").read_text("utf-8"))
    keys = {f"{sec}.{k}" for sec, kv in data.items() for k in kv}
    used = set()
    for f in (ROOT / "veil").rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text("utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "." in node.value \
                    and node.value.split(".", 1)[0] in data and " " not in node.value and not node.value.endswith("."):
                used.add(node.value)
    family = {f"perm.{p}" for p in pm.PERMISSIONS} | {f"commands.{k}" for k in data["commands"]} | \
        {f"error.{v}" for k, v in errs.items() if k.startswith("E_") and isinstance(v, str)} | {"error.default"}
    assert used - keys == set(), "в коде есть ключи, которых нет в ru.toml"
    assert keys - used - family == set(), "в ru.toml есть тексты, которые код не использует"
