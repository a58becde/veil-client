"""Стенд для сквозных тестов бота: настоящие UI, Core, Store и Bot; Telegram — httpx.MockTransport, сервер Veil —
FakeServer (операции протокола со сценариями ошибок). Так проверяется весь путь «апдейт → кнопки → ядро → Bot API»
без сети."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
from nacl.signing import SigningKey

from veil.core import api
from veil.core.crypto import keys
from veil.core.protocol import b64
from veil.core.store.db import Store
from veil.core.transport.exchange import ServerError
from veil.core.transport.telegram import Bot
from veil.core.wallet.issue import Token
from veil.ui import bot as uibot

ROOT = Path(__file__).resolve().parent.parent
KEYS_DOC = json.loads((ROOT.parent / "veil-protocol" / "keys.json").read_text())
OWNER = 111
BOT_ID = 4242


class FakeTelegram:
    """Bot API: запоминает вызовы (метод, параметры), отвечает правдоподобно; fail[метод] = (код, описание)."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.fail: dict[str, tuple[int, str]] = {}
        self.files: dict[str, bytes] = {}
        self.updates: list[list[dict]] = []
        self.mid = 1000

    def _msg(self, p: dict) -> dict:
        self.mid += 1
        m = {"message_id": self.mid, "chat": {"id": p.get("chat_id"), "type": "private"}, "date": 0}
        if "text" in p:
            m["text"] = p["text"]
            if p.get("entities"):
                m["entities"] = p["entities"]
        return m

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if "/file/bot" in path:
            name = path.rsplit("/", 1)[1]
            return httpx.Response(200, content=self.files.get(name, b""))
        method = path.rsplit("/", 1)[1]
        ctype = req.headers.get("content-type", "")
        if ctype.startswith("application/json"):
            p = json.loads(req.content or b"{}")
        else:
            p = {"_multipart": True, "_files": [], "_raw": req.content}
            body = req.content.decode("utf-8", errors="replace")
            for part in body.split("Content-Disposition: form-data; name=\"")[1:]:
                name, _, rest = part.partition("\"")
                head = rest.split("\r\n\r\n", 1)[0]
                if "filename=" not in rest[:80]:
                    p[name] = rest.split("\r\n\r\n", 1)[1].rsplit("\r\n", 1)[0].split("\r\n--")[0]
                else:  # файл: имя и Content-Type части — как их увидит Telegram
                    fname = head.split('filename="', 1)[1].split('"', 1)[0]
                    ctype_ = head.split("Content-Type: ", 1)[1].split("\r\n", 1)[0] if "Content-Type: " in head else ""
                    p["_files"].append((name, fname, ctype_))
        self.calls.append((method, p))
        if method in self.fail:
            code, desc = self.fail[method]
            return httpx.Response(200, json={"ok": False, "error_code": code, "description": desc,
                                             "parameters": {"retry_after": 1} if code == 429 else {}})
        result: object = True
        if method in ("sendMessage", "sendDocument", "sendPhoto", "sendVideo", "sendAudio", "sendAnimation",
                      "sendVoice", "sendVideoNote", "sendSticker"):
            result = self._msg(p)
        elif method == "copyMessage":
            self.mid += 1
            result = {"message_id": self.mid}
        elif method == "copyMessages":
            result = [{"message_id": self.mid + i + 1} for i, _ in enumerate(p["message_ids"])]
            self.mid += len(p["message_ids"])
        elif method == "sendMediaGroup":
            media = p["media"] if isinstance(p.get("media"), list) else json.loads(p["media"])
            result = [self._msg({"chat_id": p.get("chat_id")})
                      | {"photo": [{"file_id": f"f{i}", "file_unique_id": f"u{i}"}]}
                      for i, _ in enumerate(media)]
        elif method == "getFile":
            fid = p["file_id"]
            result = {"file_id": fid, "file_path": f"d/{fid}", "file_size": len(self.files.get(fid, b""))}
        elif method == "getMe":
            result = {"id": BOT_ID, "is_bot": True, "username": "test_veil_bot"}
        elif method == "getUpdates":
            result = self.updates.pop(0) if self.updates else []
        return httpx.Response(200, json={"ok": True, "result": result})

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]

    def texts(self) -> list[str]:
        return [p.get("text", "") for m, p in self.calls if m in ("sendMessage", "editMessageText")]

    def take(self) -> list[tuple[str, dict]]:
        c, self.calls = self.calls, []
        return c


class FakeServer:
    """Сервер Veil на уровне Exchange: операции протокола; errors[op] — ServerError (одноразово, если once)."""

    inbox = "@inbox_bot"

    def __init__(self):
        self.server_sig_pk = b64.dec(KEYS_DOC["server_sig"])
        self.ops: list[tuple[str, dict]] = []
        self.errors: dict[str, list[Exception]] = {}
        self.n = 100
        self.registered: dict[bytes, dict] = {}   # dev_pk → состояние
        self.people: list[dict] = []              # записи nick.lookup
        self.feed: list[dict] = []
        self.overflow = 0
        self.attach: list[dict] = []

    def fail(self, op: str, code: str, times: int = 1, **kw) -> None:
        self.errors.setdefault(op, []).extend([ServerError(code, **kw)] * times)

    def is_inbox(self, sender: dict) -> bool:
        return sender.get("username") == "inbox_bot"

    def on_inbox_message(self, m: dict) -> None:
        self.ops.append(("inbox_message", m))

    async def resume(self, state, auth_key=None, resp_sk=None):
        self.n += 1
        return {"n": self.n, "url": f"https://t.me/c/1/{self.n}"}

    async def request(self, op, auth_mode, auth_key, *, body=None, token=None, content=None, deliver=None,
                      attachments=None, journal=None, to=None, resp_sk=None):
        self.last_to = to
        self.last_resp_sk = resp_sk
        if deliver:
            await deliver()
        if journal:  # журнал без ключей: их выводят из post_secret (spec/05)
            journal({"op": op, "id": f"01JA{self.n:022d}"[:26], "auth_mode": auth_mode})
        self.ops.append((op, body or {}))
        if self.errors.get(op):
            raise self.errors[op].pop(0)
        dev_pk = bytes(auth_key.verify_key)
        if op == "post.check":
            return {"overflow": self.overflow}
        if op == "post.create":
            self.n += 1
            return {"n": self.n, "url": f"https://t.me/c/1/{self.n}"}
        if op == "post.edit":
            return {"n": body["n"], "edits_left": 4}
        if op == "post.delete":
            return {"n": body["n"], "deleted": True}
        if op == "device.get":
            st = self.registered.get(dev_pk)
            if st is None:
                raise ServerError("E_DEVICE")
            return st
        if op == "device.set":
            st = {"id_pk": body["id_pk"], "seq": body["seq"], "nick": None, "enc_pk": body["enc_pk"],
                  "enc_exp": body["enc_exp"], "tag": "tagtag"}
            self.registered[dev_pk] = st
            return st
        if op == "enc.set":
            return {}
        if op == "nick.set":
            st = self.registered.get(dev_pk) or {}
            st["nick"] = body["nick"]
            return {"nick": body["nick"], "tag": st.get("tag", "tagtag")}
        if op == "keys.get":
            return KEYS_DOC
        if op == "nick.lookup":  # как сервер: промах — E_NOT_FOUND (identity.nickLookup)
            found = [m for m in self.people if m["nick"].lower() == body["nick"].lower()]
            if not found:
                raise ServerError("E_NOT_FOUND")
            return {"matches": found}
        if op == "feed.get":
            posts = [p for p in self.feed if p["n"] > body.get("since", 0)]
            return {"posts": posts, "next": None}
        if op == "hidden.file":
            if attachments is not None:
                attachments.extend(self.attach)
            return {}
        return {}


def person(nick: str) -> tuple[keys.Device, dict]:
    """Другой человек с личностью: устройство и его запись nick.lookup (подписи настоящие)."""
    d = keys.issue_device(SigningKey.generate())
    return d, {"id_pk": b64.enc(d.id_pk), "nick": nick, "dev_pk": b64.enc(d.dev_pk), "seq": d.seq,
               "dev_sig": b64.enc(d.dev_sig), **d.enc_body()}


class Env:
    def __init__(self, tmp: Path, *, owner: int = OWNER, pool: dict | None = None, tokens: int = 10,
                 delay=(0, 0), identity: bool = False):
        self.tg = FakeTelegram()
        self.bot = Bot("1:x", base_url="https://tg.test")
        self.bot._http = httpx.AsyncClient(transport=httpx.MockTransport(self.tg.handler))
        self.server = FakeServer()
        self.store = Store(tmp)
        from veil.core.protocol import keysdoc
        kid, ipk = keysdoc.issuer_key(KEYS_DOC)
        self.store.put("pinned_issuer", {"kid": kid, "pk": b64.enc(ipk)})
        self.store.put("bot_id", BOT_ID)
        self.store.put("pinned_server_sig", KEYS_DOC["server_sig"])  # как после первого запуска (build)
        self.store.add_tokens([Token(kid, api.today(), bytes([i]) * 32, bytes([i]) * 64) for i in range(tokens)])
        if identity:
            self.store.save_device(keys.issue_device(SigningKey.generate()))
        self.core = api.Core(self.bot, self.store, self.server, KEYS_DOC, owner)
        cfg = {"telegram": {"owner_id": owner},
               "server": {"issuer_bot": "@issuer_bot", "server_sig": KEYS_DOC["server_sig"]},
               "privacy": {"random_delay_seconds": list(delay)}, "ui": {}, "_config_name": "config.toml"}
        if pool is not None:
            cfg["pool"] = pool
        self.cfg = cfg
        self.ui = uibot.UI(self.core, self.bot, uibot.Texts(ROOT / "locales" / "ru.toml", {}), cfg)
        self.mid = 1

    def msg(self, text: str | None = None, **extra) -> dict:
        self.mid += 1
        m = {"message_id": self.mid, "chat": {"id": self.ui.owner or OWNER, "type": "private"},
             "from": {"id": self.ui.owner or OWNER, "is_bot": False}, "date": 0}
        if text is not None:
            m["text"] = text
        m.update(extra)
        return {"update_id": self.mid, "message": m}

    def forwarded_post(self, n: int, nick: str = "Роза·tagtag", text: str = "текст") -> dict:
        """Пост из группы, пересланный владельцем: шапка как у сервера — «ник·метка» жирным во всю строку,
        затем «№N»."""
        return self.msg(f"{nick}\n№{n}\n\n{text}", forward_origin={"type": "hidden_user"},
                        entities=[{"type": "bold", "offset": 0, "length": len(nick.encode("utf-16-le")) // 2}])

    def press(self, data: str, msg_id: int = 1) -> dict:
        self.mid += 1
        return {"update_id": self.mid, "callback_query": {
            "id": str(self.mid), "from": {"id": self.ui.owner}, "data": data,
            "message": {"message_id": msg_id, "chat": {"id": self.ui.owner, "type": "private"}}}}

    async def drain(self) -> None:
        for _ in range(50):
            if not self.ui.tasks:
                return
            await asyncio.gather(*list(self.ui.tasks), return_exceptions=True)

    def route(self, *updates) -> None:
        async def go():
            for u in updates:
                self.ui._route(u)
                await self.drain()
        asyncio.run(go())

    def run(self, coro):
        async def go():
            r = await coro
            await self.drain()
            return r
        return asyncio.run(go())

    def last_markup_data(self) -> list[str]:
        for m, p in reversed(self.tg.calls):
            mk = p.get("reply_markup")
            if isinstance(mk, str):
                mk = json.loads(mk)
            if mk:
                return [b["callback_data"] for row in mk.get("inline_keyboard", []) for b in row
                        if "callback_data" in b]
        return []

    def draft_id(self) -> int:
        for d in self.last_markup_data():
            if d.startswith("d:"):
                return int(d.split(":")[1])
        raise AssertionError("no draft keyboard")
