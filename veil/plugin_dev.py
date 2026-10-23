"""Проверка пакета плагина без бота и без сервера — в том же движке, что у бота (docs/PLUGINS.md, «Проверка»).

  python -m veil.plugin_dev <каталог пакета> [--settings=<файл.toml>] [--data=<каталог>] [--tokens=<n>]
                            [--script=<файл>] [--engine=<движок.wasm>] [--cache=<каталог машинного кода>]

Бот здесь — консоль: notify_owner и propose_draft печатаются, tokens_today возвращает --tokens (50), http — настоящий
запрос к хостам манифеста. Движок — официальный (python -m veil.plugin_engine fetch) или свой (--engine); машинный код
движка кэшируется рядом с ним, а с --cache берётся готовым из каталога и не компилируется (сервер пула: проверить
движок там, где компилировать нельзя). События подаются командами — из консоли или файла --script, по одной в строке:
  start                          on_start
  reply <на №> <текст>           on_reply (номер ответа — следующий по счёту)
  private <текст>                on_hidden_for_me (подпись отправителя — «Тест·abc123»)
  published <№> [signed]         on_post_published
  error <операция> <код>         on_error, например: error post.create E_RATE
  tokens <осталось>              on_tokens_low
  send <текст>                   before_send: пропустит ли плагин такой пост
  /команда                       команда плагина (как нажатие в меню)
  press <n> [сообщение]          нажать кнопку n последнего сообщения плагина (или сообщения с этим номером)
  input <текст>                  ответить на вопрос плагина (ask)
  link <адрес>                   прислать ссылку и нажать кнопку плагина под черновиком (on_link)
  # …                            комментарий
  quit
Хранилище плагина — во временном каталоге (или --data, тогда переживает запуски). С --script код возврата 1, если
пакет не запустился или обработчик упал.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sys
import tempfile
import time
import tomllib
from pathlib import Path

from veil import plugin_engine, plugins

USAGE = __doc__.split("\n\nБот здесь")[0]


class ConsoleHost:
    """Исполнитель действий плагина: вместо Telegram — печать."""

    proxy = None
    http_transport = None

    def __init__(self, tokens: int, data: Path, out=print):
        self.tokens, self.data, self.out, self.errors = tokens, data, out, 0
        self.msgs: dict[int, list] = {}      # № сообщения → кнопки (подпись, действие, данные) по порядку
        self.last = 0
        self.question: tuple[str, str] | None = None  # (плагин, действие) — ждёт input
        self.turn = 0.0                      # до какого времени плагин отвечает на действие владельца

    def _buttons(self, rows: list) -> None:
        flat = [b for row in rows for b in row]
        if flat:
            self.out("   " + "  ".join(f"[{i}] {b[0]}" for i, b in enumerate(flat, 1)))

    async def show(self, plugin: str, text: str, rows: list) -> int:
        n = max(self.msgs, default=0) + 1
        self.msgs[n], self.last = [b for row in rows for b in row], n
        self.out(f"→ сообщение #{n}: {text}")
        self._buttons(rows)
        return n

    async def edit(self, plugin: str, message: int, text: str, rows: list) -> None:
        if message not in self.msgs:
            raise plugins.PluginError("edit: это не сообщение плагина")
        self.msgs[message], self.last = [b for row in rows for b in row], message
        self.out(f"→ правка #{message}: {text}")
        self._buttons(rows)

    async def ask(self, plugin: str, prompt: str, action: str) -> None:
        if self.turn < time.monotonic():
            raise plugins.PluginError("ask: спросить можно только в ответ на действие владельца")
        self.question = (plugin, action)
        self.out(f"→ вопрос: {prompt} (ответ: input <текст>)")

    async def notify(self, text: str) -> None:
        self.out(f"→ владельцу: {text}")

    async def propose(self, text: str, reply_to: int | None, source: str | None = None) -> None:
        self.out(f"→ черновик{f' (ответ на №{reply_to})' if reply_to else ''}: {text}")

    async def tokens_today(self) -> int:
        return self.tokens

    def storage_load(self, plugin: str) -> dict:
        f = self.data / plugin / "storage.json"
        return json.loads(f.read_text("utf-8")) if f.exists() else {}

    def storage_save(self, plugin: str, data: dict) -> None:
        f = self.data / plugin / "storage.json"
        f.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        f.write_text(json.dumps(data, ensure_ascii=False), "utf-8")

    async def report(self, plugin: str, event: str, err: str) -> None:
        self.errors += 1
        self.out(f"✗ {plugin}: {event} — {err} (подробности — выше, в журнале)")


class Session:
    """Один запущенный пакет и подача ему событий."""

    def __init__(self, reg: plugins.Registry, host: ConsoleHost, plugin: str):
        self.reg, self.host, self.n, self.plugin = reg, host, 100, plugin

    def _turn(self) -> None:
        self.host.turn = time.monotonic() + plugins.COMMAND_TIMEOUT

    async def _settle(self) -> None:
        while self.reg.tasks:  # события идут фоном, как в боте: дождаться, чтобы вывод шёл по порядку
            await asyncio.gather(*list(self.reg.tasks), return_exceptions=True)

    async def line(self, s: str) -> bool:
        """Выполнить строку. False — конец."""
        s = s.strip()
        if not s or s.startswith("#"):
            return True
        word, _, rest = s.partition(" ")
        out = self.host.out
        try:
            if word == "quit":
                return False
            if word.startswith("/"):
                self._turn()
                if not await self.reg.run_command(word[1:], rest):
                    known = ", ".join("/" + c for c, _ in self.reg.menu()) or "нет"
                    out(f"? команды {word} у плагина нет; есть: {known}")
            elif word == "start":
                self.reg.fire("start")
            elif word == "reply":
                to, _, text = rest.partition(" ")
                self.n += 1
                self.reg.fire("reply", plugins.Reply(self.n, int(to), text, f"https://t.me/c/1/{self.n}"))
            elif word == "private":
                self.n += 1
                self.reg.fire("hidden_for_me", plugins.Private(self.n, f"https://t.me/c/1/{self.n}", rest,
                                                               "Тест·abc123", 0))
            elif word == "published":
                n, _, how = rest.partition(" ")
                self.reg.fire("post_published", plugins.Published(int(n), f"https://t.me/c/1/{n}",
                                                                  how.strip() != "signed", None))
            elif word == "error":
                op, _, code = rest.partition(" ")
                self.reg.fire("error", plugins.Failure(op, code.strip()))
            elif word == "tokens":
                self.reg.fire("tokens_low", int(rest))
            elif word == "press":
                k, _, msg = rest.partition(" ")
                n = int(msg) if msg.strip() else self.host.last
                flat = self.host.msgs.get(n, [])
                if not 1 <= int(k) <= len(flat):
                    out(f"? у сообщения #{n} нет кнопки {k}")
                else:
                    _, action, data = flat[int(k) - 1]
                    self._turn()
                    await self.reg.press(self.plugin, plugins.Press(action, data, n))
            elif word == "input":
                if self.host.question is None:
                    out("? плагин ни о чём не спрашивал")
                else:
                    (plugin, action), self.host.question = self.host.question, None
                    self._turn()
                    await self.reg.answer(plugin, action, rest)
            elif word == "link":
                found = self.reg.link_buttons([rest.strip()])
                if not found:
                    out("? под черновиком с такой ссылкой кнопки плагина не будет")
                else:
                    plugin, k, label, url = found[0]
                    out(f"→ под черновиком кнопка «🧩 {label}» — нажата")
                    self._turn()
                    await self.reg.open_link(plugin, k, url)
            elif word == "send":
                why = await self.reg.check_send(plugins.Outgoing("text", rest, True, "", None, ""))
                out("→ отправка: можно" if why is None else f"→ отправка: нельзя — {why}")
            else:
                out(f"? не понял «{word}»: start, reply, private, published, error, tokens, send, /команда, press, "
                    "input, link, quit")
        except ValueError:
            out(f"? неверные аргументы: {s}")
        await self._settle()
        return True


async def run(pdir: Path, *, settings: dict, data: Path, tokens: int, lines, out=print,
              engine: Path = plugin_engine.DEFAULT_ENGINE, cache: Path | None = None) -> int:
    if why := plugin_engine.unsupported():
        out(f"Движок плагинов здесь не запустить: {why}.")
        return 1
    if not engine.is_file():
        out(f"Нет движка {engine}: python -m veil.plugin_engine fetch (или свой — --engine=…).")
        return 1
    pdir = pdir.resolve()
    try:
        p = plugins.load_package(pdir.parent, pdir.name)
    except plugins.PluginError as e:
        out(f"Пакет не принят: {e}")
        return 1
    m = p.manifest
    out(f"{m.name} ({m.id}) {m.version}, API {m.api}" + (f", ⭐ {m.price_stars}" if m.price_stars else ""))
    out(f"Разрешения: {', '.join(m.permissions) or 'нет'}" + (f"; сеть: {', '.join(m.network)}" if m.network else ""))
    sha = plugin_engine.sha256_file(engine)
    out(f"Движок: {engine.name} ({'официальный' if sha == plugin_engine.ENGINE_SHA256 else 'своя сборка'})")
    host = ConsoleHost(tokens, data, out)
    eng = plugin_engine.Engine(engine, cache or engine.parent, {sha}, compile_ok=cache is None)
    reg = plugins.Registry(settings={m.id: settings}, host=host, engine=eng)
    try:
        if not await reg.start_package(p):
            out(f"Не запустился: {reg.failed[-1][1]}")
            return 1
        r = reg.runners[m.id]
        out(f"Работает в движке{'' if eng.os_sandbox else ' (без защиты ОС)'}. Команды: "
            f"{', '.join('/' + c for c, _ in reg.menu()) or 'нет'}; события: {', '.join(r.events) or 'нет'}"
            + (f"; ссылки: {', '.join(h for ln in r.ui['links'] for h in ln['hosts'])}" if r.ui["links"] else ""))
        s = Session(reg, host, m.id)
        async for line in lines:
            if not await s.line(line):
                break
    finally:
        await reg.stop()
        await eng.stop()
    return 1 if host.errors else 0


async def _stdin():
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            return
        yield line


async def _file(path: Path):
    for line in path.read_text("utf-8").splitlines():
        print(f"» {line}")
        yield line


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = dict(a[2:].split("=", 1) for a in argv if a.startswith("--") and "=" in a)
    if len(args) != 1:
        print(USAGE)
        return 2
    # Журнал бота: здесь причины сбоев обработчиков и всё, что плагин печатает (print уходит в журнал).
    logging.basicConfig(level=logging.INFO, format="  журнал: %(message)s")
    settings = tomllib.loads(Path(flags["settings"]).read_text("utf-8")) if "settings" in flags else {}
    tmp = None
    if "data" in flags:
        data = Path(flags["data"])
        data.mkdir(mode=0o700, parents=True, exist_ok=True)
    else:
        tmp = data = Path(tempfile.mkdtemp(prefix="veil-plugin-dev-"))
    try:
        lines = _file(Path(flags["script"])) if "script" in flags else _stdin()
        if "script" not in flags:
            print("Команды: /команда, press <n>, input <текст>, link <адрес>, start, reply <№> <текст>, "
                  "private <текст>, published <№>, error <op> <код>, tokens <n>, send <текст>, quit")
        return asyncio.run(run(Path(args[0]), settings=settings, data=data, tokens=int(flags.get("tokens", 50)),
                               lines=lines, engine=Path(flags.get("engine") or plugin_engine.DEFAULT_ENGINE),
                               cache=Path(flags["cache"]) if "cache" in flags else None))
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
