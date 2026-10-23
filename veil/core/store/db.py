"""Локальное хранилище бота: SQLite в data/veil.db и ключи устройства в data/device.json (права 600).

Здесь лежит всё, что делает бота «вашим»: ключ устройства и его сертификат, ключи шифрования, токены, секреты
своих постов. **12 слов здесь нет** (spec/02): они у владельца, а ключ устройства можно отозвать восстановлением.
Сервер этого не знает (вариант Б анонимности), поэтому потеря каталога data/ означает потерю права править
свои посты; личность восстанавливается по 12 словам.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import nacl.secret

from veil.core.crypto.keys import Device
from veil.core.protocol import b64
from veil.core.wallet.issue import SCHEME

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY, kid TEXT NOT NULL, day TEXT NOT NULL,
    input BLOB NOT NULL UNIQUE, output BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('ready', 'reserved', 'spent', 'bad')),
    origin TEXT NOT NULL DEFAULT ''  -- '' — от эмитента; иначе id переноса VEILTOK (токены другого бота)
);
CREATE INDEX IF NOT EXISTS tokens_day ON tokens (day, status);
CREATE TABLE IF NOT EXISTS issue_requests (req_id TEXT PRIMARY KEY, state TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS issue_parts (
    req_id TEXT NOT NULL, i INTEGER NOT NULL, n INTEGER NOT NULL, text TEXT NOT NULL, PRIMARY KEY (req_id, i)
);
CREATE TABLE IF NOT EXISTS my_posts (
    n INTEGER PRIMARY KEY, post_secret BLOB NOT NULL, url TEXT, kind TEXT,
    created INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS drafts (id INTEGER PRIMARY KEY, data TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pending_posts (
    id TEXT PRIMARY KEY, post_secret BLOB NOT NULL, kind TEXT, state TEXT NOT NULL, created INTEGER NOT NULL
);
"""


def _write_private(path: Path, text: str | bytes) -> None:
    """Атомарная запись файла с правами 600."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(text.encode() if isinstance(text, str) else text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _shred(path: Path) -> None:
    """Затереть и удалить файл. Только на уровне файла: SSD и файловые системы с копированием при записи (btrfs, zfs)
    могут хранить прежние блоки — поэтому секреты на диске держатся как можно меньше, а не «стираются потом»."""
    if path.exists():
        size = path.stat().st_size
        with open(path, "r+b") as f:
            f.write(os.urandom(max(size, 1)))
            f.flush()
            os.fsync(f.fileno())
        path.unlink()


def _no_wal(image: bytes) -> bytes:
    """Снимок базы с флагом WAL в заголовке (байты 18–19 = 2) база в памяти не открывает: «unable to open database
    file». Такой снимок получался при переводе базы из режима WAL; флаг меняется на обычный журнал (1)."""
    if len(image) > 20 and image[18:20] == b"\x02\x02":
        return image[:18] + b"\x01\x01" + image[20:]
    return image


class _Sealed:
    """Соединение SQLite в памяти, которое после каждой завершённой записи сохраняет на диск зашифрованный снимок
    базы (бот в пуле, docs/POOL.md). Шифруется весь файл: не только секреты, но и номера своих постов, время,
    закрепления — по ним тоже видно, какие анонимные посты чьи."""

    def __init__(self, store: "Store"):
        self._store = store
        self._conn = sqlite3.connect(":memory:", isolation_level=None)
        self._flushed = 0

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def _after(self, cur):
        if not self._conn.in_transaction and self._conn.total_changes != self._flushed:
            try:
                self._store._flush()
            except OSError:
                # Диск полон или недоступен: в памяти запись уже есть, на диске — нет. Ошибка уходит
                # вызывающему (действие не подтверждается владельцу), а снимок повторится при следующей записи:
                # _flushed не сдвигается.
                logging.getLogger("veil.store").error("encrypted snapshot not written")
                raise
            self._flushed = self._conn.total_changes
        return cur

    def execute(self, *a, **kw):
        return self._after(self._conn.execute(*a, **kw))

    def close(self):
        self._conn.close()

    def executemany(self, *a, **kw):
        return self._after(self._conn.executemany(*a, **kw))

    def executescript(self, *a, **kw):
        return self._after(self._conn.executescript(*a, **kw))


@dataclass
class Token:
    id: int
    kid: str
    day: str
    input: bytes
    output: bytes
    origin: str = ""

    def envelope(self) -> dict:
        return {"scheme": SCHEME, "kid": self.kid, "day": self.day,
                "input": b64.enc(self.input), "output": b64.enc(self.output)}


class Store:
    def __init__(self, data_dir: str | Path, key: bytes | None = None):
        """key — 32 байта: данные хранятся на диске только зашифрованными (veil.db.enc, device.json.enc); прежние
        открытые файлы шифруются при первом открытии и затираются. Без ключа — обычные файлы (локальный бот)."""
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self._box = None
        if key is not None:
            self._box = nacl.secret.SecretBox(key)
            self._open_sealed()
            return
        path = self.dir / "veil.db"
        new = not path.exists()
        self.db = sqlite3.connect(path, isolation_level=None)  # автокоммит; транзакции — явно
        if new:
            os.chmod(path, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self._prepare()

    def _prepare(self) -> None:
        """Схема и удаление без следов: secure_delete затирает нулями удалённые строки (секреты постов, черновики),
        иначе они остаются в свободных страницах файла — «забытые» посты узнавались бы по файлам (spec/01). Сборки
        SQLite из апстрима по умолчанию его не включают."""
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(tokens)")}
        if "origin" not in cols:  # база до 2026-10-19
            self.db.execute("ALTER TABLE tokens ADD COLUMN origin TEXT NOT NULL DEFAULT ''")

    # --- шифрование на диске (бот в пуле) ---
    @property
    def _db_enc(self) -> Path:
        return self.dir / "veil.db.enc"

    def _open_sealed(self) -> None:
        self.db = _Sealed(self)
        plain = self.dir / "veil.db"
        if self._db_enc.exists():
            self.db._conn.deserialize(_no_wal(self._box.decrypt(self._db_enc.read_bytes())))
        elif plain.exists():  # перевод открытых данных: прочитать, сохранить зашифрованно, затереть открытые
            src = sqlite3.connect(plain)
            src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            src.execute("PRAGMA journal_mode=DELETE")  # снимок в памяти не может быть в режиме WAL
            src.backup(self.db._conn)
            src.close()
        self._prepare()
        self.db._conn.execute("VACUUM")  # снимок без свободных страниц со старыми данными
        self._flush()
        dev = self.dir / "device.json"
        if dev.exists() and not self._dev_enc.exists():
            _write_private(self._dev_enc, self._box.encrypt(dev.read_bytes()))
        for f in (plain, self.dir / "veil.db-wal", self.dir / "veil.db-shm", dev):
            _shred(f)

    def _flush(self) -> None:
        _write_private(self._db_enc, self._box.encrypt(self.db._conn.serialize()))

    def compact(self) -> None:
        """После чистки секретов: журнал WAL усекается (в нём остаются прежние версии страниц), снимок пула
        пересобирается без свободных страниц."""
        if self._box:
            self.db._conn.execute("VACUUM")
            self._flush()
        else:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    @property
    def _dev_enc(self) -> Path:
        return self.dir / "device.json.enc"

    # --- личность (устройство) ---
    @property
    def device_path(self) -> Path:
        return self.dir / "device.json"

    @property
    def owner_link_path(self) -> Path:
        """Ссылка привязки владельца (код захвата): пока владелец не задан. В журнал она не пишется."""
        return self.dir / "owner-link.txt"

    @property
    def legacy_identity_path(self) -> Path:
        """Старый формат (до 2026-10-16): 12 слов открытым текстом. Переводится командой migrate."""
        return self.dir / "identity.json"

    def load_device(self) -> Device | None:
        try:
            if self._box:
                raw = json.loads(self._box.decrypt(self._dev_enc.read_bytes()))
            else:
                raw = json.loads(self.device_path.read_text())
        except FileNotFoundError:
            return None
        d = Device.from_json(raw)
        if d.tag != raw.get("tag"):  # метка пересчитана под новую длину — сохранить, чтобы не считать при каждом запуске
            self.save_device(d)
        return d

    def save_device(self, device) -> None:
        data = json.dumps(device.to_json())
        if self._box:
            _write_private(self._dev_enc, self._box.encrypt(data.encode()))
        else:
            _write_private(self.device_path, data)

    def load_legacy_mnemonic(self) -> str | None:
        try:
            return json.loads(self.legacy_identity_path.read_text())["mnemonic"]
        except FileNotFoundError:
            return None

    def wipe_legacy_identity(self) -> None:
        """Затирает и удаляет старый файл со словами (см. _shred)."""
        _shred(self.legacy_identity_path)

    # --- meta ---
    def get(self, key: str, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key: str, value) -> None:
        if value is None:
            self.db.execute("DELETE FROM meta WHERE key = ?", (key,))
        else:
            self.db.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                            (key, json.dumps(value, ensure_ascii=False)))

    # --- токены ---
    def add_tokens(self, toks, origin: str = "") -> int:
        """origin — id переноса VEILTOK, если токены пришли от другого бота (их тратят после своих)."""
        n = 0
        for t in toks:
            cur = self.db.execute("INSERT OR IGNORE INTO tokens (kid, day, input, output, origin) VALUES (?, ?, ?, ?, ?)",
                                  (t.kid, t.day, t.input, t.output, origin))
            n += cur.rowcount
        return n

    def take_token(self, day: str) -> Token | None:
        """Резервирует готовый токен на день (атомарно). Сначала свои (от эмитента), затем перенесённые: их значения
        знает отдавший, и проверить их можно только тратой."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT id, kid, day, input, output, origin FROM tokens WHERE day = ? AND status = 'ready' "
                                  "ORDER BY origin != '', id LIMIT 1", (day,)).fetchone()
            if row:
                self.db.execute("UPDATE tokens SET status = 'reserved' WHERE id = ?", (row[0],))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return Token(*row) if row else None

    def give_tokens(self, day: str, count: int) -> list[Token]:
        """Отдать до count готовых токенов дня другому своему боту: атомарно помечаются потраченными здесь, чтобы этот
        бот их больше не использовал. Сервер всё равно примет каждый токен только один раз (spec/03)."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            rows = self.db.execute("SELECT id, kid, day, input, output FROM tokens WHERE day = ? AND status = 'ready' "
                                   "LIMIT ?", (day, count)).fetchall()
            self.db.executemany("UPDATE tokens SET status = 'spent' WHERE id = ?", [(r[0],) for r in rows])
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return [Token(*r) for r in rows]

    def revive_tokens(self, ids: list[int]) -> int:
        """Вернуть отданные токены (перенос не состоялся): только те, что этот бот сам отдал (give_tokens)."""
        return sum(self.db.execute("UPDATE tokens SET status = 'ready' WHERE id = ? AND status = 'spent'", (i,)).rowcount
                   for i in ids)

    def finish_token(self, tok: Token, status: str) -> None:
        """status: spent (операция выполнена), bad (сервер отверг токен), ready (не потрачен, вернуть)."""
        self.db.execute("UPDATE tokens SET status = ? WHERE id = ?", (status, tok.id))

    def drop_transfer(self, origin: str, day: str) -> int:
        """Сервер отверг перенесённый токен — остальные из того же переноса на этот день тоже под подозрением: их
        больше не берём (иначе мусорный перенос стоил бы по обмену с сервером на каждый токен)."""
        return self.db.execute("UPDATE tokens SET status = 'bad' WHERE origin = ? AND day = ? AND status = 'ready'",
                               (origin, day)).rowcount

    def token_counts(self) -> dict[str, int]:
        return dict(self.db.execute("SELECT day, count(*) FROM tokens WHERE status = 'ready' GROUP BY day").fetchall())

    def token_received(self) -> dict[str, int]:
        """Сколько токенов получено на каждый день за всё время (в любом статусе) — это эмитент и так знает."""
        return dict(self.db.execute("SELECT day, count(*) FROM tokens GROUP BY day").fetchall())

    def release_reserved(self) -> None:
        """При старте: резервы прошлого запуска — операции не завершились, токены снова готовы."""
        self.db.execute("UPDATE tokens SET status = 'ready' WHERE status = 'reserved'")

    def drop_old_tokens(self, today: str) -> None:
        self.db.execute("DELETE FROM tokens WHERE day < ?", (today,))

    # --- запросы токенов ---
    def save_issue_request(self, req_id: str, state: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO issue_requests VALUES (?, ?, ?)", (req_id, json.dumps(state), int(time.time())))

    def issue_request(self, req_id: str) -> dict | None:
        row = self.db.execute("SELECT state FROM issue_requests WHERE req_id = ?", (req_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def add_issue_part(self, req_id: str, i: int, n: int, text: str) -> list[str] | None:
        """Сохраняет часть VEILRES; возвращает все части, когда собраны."""
        self.db.execute("INSERT OR REPLACE INTO issue_parts VALUES (?, ?, ?, ?)", (req_id, i, n, text))
        rows = self.db.execute("SELECT i, text FROM issue_parts WHERE req_id = ? AND n = ? ORDER BY i", (req_id, n)).fetchall()
        return [t for _, t in rows] if len(rows) == n else None

    def drop_stale_issue_requests(self, days: int = 9) -> int:
        """Запросы токенов хранят секреты ослепления; ответ на них старше окна выдачи (8 дней) уже бесполезен."""
        old = [r[0] for r in self.db.execute("SELECT req_id FROM issue_requests WHERE created < ?",
                                             (int(time.time()) - days * 86400,))]
        for r in old:
            self.forget_issue(r)
        return len(old)

    def forget_issue(self, req_id: str) -> None:
        self.db.execute("DELETE FROM issue_parts WHERE req_id = ?", (req_id,))
        self.db.execute("DELETE FROM issue_requests WHERE req_id = ?", (req_id,))

    # --- свои посты ---
    def add_post(self, n: int, secret: bytes, url: str, kind: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO my_posts (n, post_secret, url, kind, created) VALUES (?, ?, ?, ?, ?)",
                        (n, secret, url, kind, int(time.time())))

    def post_secret(self, n: int) -> bytes | None:
        row = self.db.execute("SELECT post_secret FROM my_posts WHERE n = ? AND deleted = 0", (n,)).fetchone()
        return row[0] if row else None

    def mark_deleted(self, n: int) -> None:
        self.db.execute("UPDATE my_posts SET deleted = 1 WHERE n = ?", (n,))

    def my_numbers(self) -> set[int]:
        return {r[0] for r in self.db.execute("SELECT n FROM my_posts")}

    def housekeeping(self, keep_days: int) -> int:
        """При запуске и раз в сутки: забыть старые «мой пост ↔ секрет», брошенные черновики и запросы токенов, затем
        убрать их следы из файлов (compact). Возвращает, сколько постов забыто."""
        n = self.forget_old_posts(keep_days)
        self.drop_stale_drafts()
        self.drop_stale_issue_requests()
        self.compact()
        return n

    def forget_old_posts(self, keep_days: int) -> int:
        """Хранение «мой пост ↔ секрет» ограничено (spec/01): кто получит data/, увидит, какие анонимные посты ваши,
        только за этот срок. 0 — хранить всегда. Старше срока — ни правки, ни удаления, ни уведомлений об ответах."""
        if keep_days <= 0:
            return 0
        return self.db.execute("DELETE FROM my_posts WHERE created < ?", (int(time.time()) - keep_days * 86400,)).rowcount

    # --- отправленные, но не подтверждённые посты ---
    def save_pending_post(self, env_id: str, secret: bytes, kind: str, state: dict) -> None:
        """Секрет поста и конверт сохраняются до отправки: если ответ не придёт (перезапуск, очередь длиннее
        повторов), тот же конверт дозапросит результат, и право править и удалять пост не потеряется."""
        self.db.execute("INSERT OR REPLACE INTO pending_posts (id, post_secret, kind, state, created) VALUES (?, ?, ?, ?, ?)",
                        (env_id, secret, kind, json.dumps(state, ensure_ascii=False), int(time.time())))

    def pending_posts(self) -> list[tuple[str, bytes, str, dict, int]]:
        return [(r[0], r[1], r[2], json.loads(r[3]), r[4]) for r in
                self.db.execute("SELECT id, post_secret, kind, state, created FROM pending_posts ORDER BY created")]

    def drop_pending_post(self, env_id: str) -> None:
        self.db.execute("DELETE FROM pending_posts WHERE id = ?", (env_id,))

    # --- черновики ---
    def save_draft(self, data: dict, draft_id: int | None = None) -> int:
        if draft_id is None:
            return self.db.execute("INSERT INTO drafts (data, created) VALUES (?, ?)",
                                   (json.dumps(data, ensure_ascii=False), int(time.time()))).lastrowid
        self.db.execute("UPDATE drafts SET data = ? WHERE id = ?", (json.dumps(data, ensure_ascii=False), draft_id))
        return draft_id

    def draft(self, draft_id: int) -> dict | None:
        row = self.db.execute("SELECT data FROM drafts WHERE id = ?", (draft_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def drop_draft(self, draft_id: int) -> None:
        self.db.execute("DELETE FROM drafts WHERE id = ?", (draft_id,))
        self.drop_stale_drafts()

    def scheduled_drafts(self) -> list[tuple[int, dict]]:
        """Черновики, отправка которых началась (send_at), но не дошла до конверта — например, перезапуск во время
        случайной задержки."""
        return [(i, d) for i, d in ((r[0], json.loads(r[1])) for r in self.db.execute("SELECT id, data FROM drafts"))
                if d.get("send_at")]

    def drop_stale_drafts(self) -> None:
        """Черновики содержат текст постов: брошенные удаляются через сутки."""
        self.db.execute("DELETE FROM drafts WHERE created < ?", (int(time.time()) - 86400,))
