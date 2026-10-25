"""SDK плагинов Veil (docs/PLUGINS.md): то, что импортирует код плагина, — `from veil import plugins`.

Работает внутри движка (WebAssembly): каждый вызов — новый экземпляр, модуль плагина исполняется заново, поэтому
данные между событиями — только в storage(). Наружу — только host.call: что можно плагину, решает бот, здесь лишь
ранние проверки, чтобы автор узнал об ошибке сразу. Обработчики — async def; вызовы бота возвращаются сразу, ждать
asyncio (sleep, задачи) внутри плагина нечего и нельзя.

    from veil import plugins

    @plugins.on_reply
    async def notify(reply):
        await plugins.notify_owner(f"Ответ на №{reply.to}: {reply.text[:100]}")
"""
from __future__ import annotations

import base64
import inspect
import json
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

try:  # привязки компонента есть только внутри движка; вне его SDK можно импортировать для проверок
    from componentize_py_types import Err as _Err
    from wit_world.imports import host as _host
except ImportError:
    _Err, _host = Exception, None

ID = re.compile(r"[a-z][a-z0-9_]{0,31}")
HOST = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
COMMAND = re.compile(r"[a-z0-9_]{1,32}")
ACTION = re.compile(r"[a-z0-9_]{1,32}")
BUILTIN = frozenset({"start", "help", "tokens", "nick", "sync", "export", "import", "cancel", "leave", "market",
                     "plugins"})
BUTTON_TEXT_MAX, BUTTON_DATA_MAX, BUTTONS_MAX = 64, 256, 24
LINK_LABEL = (3, 40)
LINK_HOSTS_MAX = 10


class PluginError(Exception):
    """Действие не выполнено: нет разрешения, слишком часто, неверные аргументы — текст для автора."""


# --- что получают обработчики ---
@dataclass(frozen=True)
class Reply:
    """Ответ на ваш пост в группе."""
    n: int
    to: int
    text: str
    url: str


@dataclass(frozen=True)
class Private:
    """«Лично для» вас: текст уже расшифрован."""
    n: int
    url: str
    text: str
    sender: str
    file_count: int


@dataclass(frozen=True)
class Published:
    n: int
    url: str
    anonymous: bool | None
    reply_to: int | None


@dataclass(frozen=True)
class Failure:
    op: str
    code: str


@dataclass(frozen=True)
class Outgoing:
    """Черновик перед отправкой — только для чтения: изменить пост плагин не может, только остановить отправку."""
    kind: str
    text: str
    anonymous: bool
    hide: str
    reply_to: int | None
    to: str


@dataclass(frozen=True)
class Button:
    text: str
    action: str
    data: str = ""


@dataclass(frozen=True)
class Press:
    action: str
    data: str
    message: int


@dataclass(frozen=True)
class Link:
    url: str


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


EVENT_TYPES: dict[str, type | None] = {"start": None, "reply": Reply, "hidden_for_me": Private,
                                       "post_published": Published, "error": Failure, "tokens_low": int,
                                       "before_send": Outgoing}

Handler = Callable[..., Awaitable[Any]]


class _Plugin:
    """Что плагин объявил при загрузке модуля."""

    def __init__(self, settings: dict):
        self.settings = settings
        self.events: dict[str, list[Handler]] = {e: [] for e in EVENT_TYPES}
        self.commands: dict[str, tuple[str, Handler]] = {}
        self.buttons: dict[str, Handler] = {}
        self.inputs: dict[str, Handler] = {}
        self.links: list[tuple[tuple[str, ...], str, Handler]] = []

    def describe(self) -> dict:
        return {"events": [e for e, hs in self.events.items() if hs],
                "commands": [[name, desc] for name, (desc, _) in sorted(self.commands.items())],
                "buttons": sorted(self.buttons), "inputs": sorted(self.inputs),
                "links": [{"hosts": list(hosts), "label": label} for hosts, label, _ in self.links]}


_plugin: _Plugin | None = None   # заполняется движком перед загрузкой модуля
_loading = False                 # обработчики объявляются только при загрузке


def _target() -> _Plugin:
    if _plugin is None or not _loading:
        raise RuntimeError("обработчики объявляются только при загрузке плагина (на верхнем уровне модуля)")
    return _plugin


def _async(fn: Handler) -> Handler:
    if not inspect.iscoroutinefunction(fn):
        raise PluginError(f"{getattr(fn, '__name__', fn)}: обработчик должен быть async def")
    return fn


def _event(name: str) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        _target().events[name].append(_async(fn))
        return fn
    return register


on_start = _event("start")                    # бот запущен и связался с сервером
on_reply = _event("reply")                    # (Reply) — разрешение replies
on_hidden_for_me = _event("hidden_for_me")    # (Private) — разрешение private
on_post_published = _event("post_published")  # (Published) — разрешение published
on_error = _event("error")                    # (Failure) — разрешение errors
on_tokens_low = _event("tokens_low")          # (int) сколько токенов осталось на сегодня — разрешение tokens
before_send = _event("before_send")           # (Outgoing) → None | True | False | str — разрешение before_send


def on_command(name: str, description: str) -> Callable[[Handler], Handler]:
    """Команда /name в меню бота — вход в плагин (разрешение commands). Аргументов у команды нет: дальше — кнопки."""
    if not COMMAND.fullmatch(name) or name in BUILTIN:
        raise PluginError(f"команда /{name}: нужны a-z, 0-9, _ (до 32) и не имя встроенной команды")
    if not 3 <= len(description) <= 256:
        raise PluginError(f"команда /{name}: описание — от 3 до 256 символов")

    def register(fn: Handler) -> Handler:
        p = _target()
        if name in p.commands:
            raise PluginError(f"команда /{name} объявлена дважды")
        p.commands[name] = (description, _async(fn))
        return fn
    return register


def _ui_handler(table: str, action: str) -> Callable[[Handler], Handler]:
    if not ACTION.fullmatch(action):
        raise PluginError(f"действие {action!r}: a-z, 0-9, _ (до 32)")

    def register(fn: Handler) -> Handler:
        handlers = getattr(_target(), table)
        if action in handlers:
            raise PluginError(f"действие {action} объявлено дважды")
        handlers[action] = _async(fn)
        return fn
    return register


def on_button(action: str) -> Callable[[Handler], Handler]:
    """Нажата кнопка плагина с этим действием (разрешение commands): получает Press(action, data, message)."""
    return _ui_handler("buttons", action)


def on_input(action: str) -> Callable[[Handler], Handler]:
    """Владелец ответил на ask(…, action) (разрешение commands): получает текст."""
    return _ui_handler("inputs", action)


def on_link(*hosts: str, label: str) -> Callable[[Handler], Handler]:
    """Кнопка плагина под черновиком со ссылкой на эти сайты (и поддомены) — разрешение commands. Плагин получает
    Link(url), только если владелец нажмёт кнопку; сам черновик ему не виден."""
    hs = tuple(h.lower() for h in hosts)
    if not hs or len(hs) > LINK_HOSTS_MAX or not all(HOST.fullmatch(h) for h in hs):
        raise PluginError("on_link: от 1 до 10 доменов вида example.com")
    if not LINK_LABEL[0] <= len(label) <= LINK_LABEL[1]:
        raise PluginError(f"on_link: подпись кнопки — от {LINK_LABEL[0]} до {LINK_LABEL[1]} символов")

    def register(fn: Handler) -> Handler:
        _target().links.append((hs, label, _async(fn)))
        return fn
    return register


# --- действия: всё через бота ---
def _call(fn: str, **args) -> Any:
    if _host is None:
        raise RuntimeError("SDK плагинов работает только внутри движка")
    try:
        return json.loads(_host.call(fn, json.dumps(args, ensure_ascii=False)))
    except _Err as e:
        raise PluginError(str(e.value)) from None


def settings() -> dict:
    """Настройки плагина из config.toml бота ([plugins.settings.<id>])."""
    if _plugin is None:
        raise RuntimeError("плагин не загружен")
    return dict(_plugin.settings)


class Storage:
    """Своё хранилище плагина: ключи — строки, значения — JSON, всего до 1 МиБ. Хранит бот; переживает перезапуски."""

    def __init__(self):
        self._data: dict | None = None

    def _load(self) -> dict:
        if self._data is None:
            got = _call("storage_get")
            self._data = got if isinstance(got, dict) else {}
        return self._data

    def get(self, key: str, default: Any = None) -> Any:
        return self._load().get(key, default)

    def put(self, key: str, value: Any) -> None:
        if not isinstance(key, str):
            raise PluginError("ключ хранилища — строка")
        try:
            value = json.loads(json.dumps(value, ensure_ascii=False))
        except (TypeError, ValueError):
            raise PluginError(f"{key}: значение хранилища — только JSON (числа, строки, списки, словари)") from None
        _call("storage_put", key=key, value=value)
        self._load()[key] = value

    def delete(self, key: str) -> None:
        _call("storage_delete", key=str(key))
        self._load().pop(key, None)


def storage() -> Storage:
    """Хранилище плагина: STORE = plugins.storage() на верхнем уровне модуля."""
    return Storage()


async def notify_owner(text: str) -> None:
    """Сообщение владельцу (до 4096 символов, подпись «🧩 Имя плагина:»). Разрешение notify."""
    _call("notify", text=str(text)[:4096])


async def propose_draft(text: str, reply_to: int | None = None) -> None:
    """Черновик поста из текста с обычными кнопками черновика: опубликует его только владелец, кнопкой «Отправить».
    Разрешение drafts."""
    _call("propose", text=str(text)[:4096], reply_to=reply_to if type(reply_to) is int else None)


def rows(buttons) -> list[list[list[str]]]:
    """Кнопки для show/edit: ряды Button или плоский список (по одной в ряд) → [[[подпись, действие, данные]]]."""
    if not buttons:
        return []
    raw = [b if isinstance(b, (list, tuple)) else [b] for b in buttons]
    out = [[[str(b.text), str(b.action), str(b.data)] for b in row] for row in raw]
    flat = [b for row in out for b in row]
    if len(flat) > BUTTONS_MAX or any(not row for row in out):
        raise PluginError(f"кнопок — не больше {BUTTONS_MAX}, ряды не пустые")
    for text, action, data in flat:
        if not 1 <= len(text) <= BUTTON_TEXT_MAX or not ACTION.fullmatch(action) or len(data) > BUTTON_DATA_MAX:
            raise PluginError(f"кнопка {text[:20]!r}: подпись 1–{BUTTON_TEXT_MAX} символов, действие a-z0-9_, "
                              f"данные до {BUTTON_DATA_MAX}")
    return out


async def show(text: str, buttons=None) -> int:
    """Сообщение владельцу с кнопками плагина → номер сообщения (для edit). Разрешение notify, кнопки — commands."""
    return int(_call("show", text=str(text)[:4000], buttons=rows(buttons)))


async def edit(message: int, text: str, buttons=None) -> None:
    """Поправить своё сообщение — экран меняется на месте, а не копится."""
    _call("edit", message=int(message), text=str(text)[:4000], buttons=rows(buttons))


async def ask(prompt: str, action: str) -> None:
    """Спросить текст: следующее сообщение владельца получит @on_input(action). Только в ответ на действие владельца
    (команда, кнопка, ссылка, прошлый ответ). Разрешение commands."""
    if not ACTION.fullmatch(action):
        raise PluginError(f"действие {action!r}: a-z, 0-9, _ (до 32)")
    _call("ask", prompt=str(prompt)[:1000], action=action)


async def tokens_today() -> int:
    """Сколько токенов на сегодня. Разрешение tokens."""
    return int(_call("tokens_today"))


async def http(method: str, url: str, *, headers: dict | None = None, body: bytes | str | None = None,
               timeout: float = 20.0) -> Response:
    """HTTPS-запрос через бота — только к хостам из network манифеста (разрешение net), без перехода по
    перенаправлениям; ответ до 4 МиБ."""
    if isinstance(body, str):
        body = body.encode()
    v = _call("http", method=str(method).upper(), url=str(url),
              headers={str(k): str(x) for k, x in (headers or {}).items()},
              body=base64.b64encode(body or b"").decode(), timeout=float(timeout))
    return Response(int(v["status"]), dict(v["headers"]), base64.b64decode(v["body"]))


# --- исполнение (вызывает движок) ---
def _arg(ev: str, data: Any) -> tuple:
    t = EVENT_TYPES[ev]
    if t is None:
        return ()
    if t is int:
        if type(data) is not int:
            raise PluginError(f"{ev}: ждали число")
        return (data,)
    return (t(**data),)


def run(coro) -> Any:
    """Довести обработчик до конца. Вызовы бота синхронны, поэтому обработчик не должен ничего ждать: ожидание
    asyncio (sleep, задачи) здесь не наступит никогда."""
    try:
        while True:
            if coro.send(None) is not None:
                coro.close()
                raise PluginError("в плагине нельзя ждать asyncio (sleep, задачи): вызовы бота возвращаются сразу")
    except StopIteration as stop:
        return stop.value


def dispatch(p: _Plugin, msg: dict) -> Any:
    """Событие, команда или действие владельца → обработчики плагина. before_send — первый отказ."""
    if msg.get("t") == "command":
        return run(p.commands[str(msg["name"])][1](str(msg.get("arg", ""))))
    ev, data = str(msg.get("ev")), msg.get("data")
    if ev == "button":
        return run(p.buttons[str(data["action"])](Press(str(data["action"]), str(data["data"]), int(data["message"]))))
    if ev == "input":
        return run(p.inputs[str(data["action"])](str(data["text"])))
    if ev == "link":
        return run(p.links[int(data["k"])][2](Link(str(data["url"]))))
    args = _arg(ev, data)
    for fn in p.events[ev]:
        verdict = run(fn(*args))
        if ev == "before_send" and (verdict is False or isinstance(verdict, str)):
            return verdict
    return None

