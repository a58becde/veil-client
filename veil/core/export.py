"""Экспорт и импорт бота (docs/EXPORT.md): перенос на другую машину, из пула к себе, данных в другой бот.

Файл: `VEILX1` + режим + шифротекст. Режим 1 — пароль (Argon2id + XSalsa20-Poly1305), режим 2 — sealed box на ключ
целевой машины (`VEILIMP …`), чтобы файл можно было передать через чат, не показывая там пароль.
Расшифрованный JSON на диск не пишется. При импорте применяется только то, что не может действовать от имени
владельца: владелец, закрепления сервера и эмитента и журнал неподтверждённых постов не переносятся никогда.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import nacl.pwhash
import nacl.secret
import nacl.utils
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

from veil.core.crypto import keys
from veil.core.protocol import b64, jcs
from veil.core.wallet.issue import Token
from veil.core.wallet.issue import week_kid_covers as issue_week_kid_covers

MAGIC = b"VEILX1"
MODE_PASSWORD, MODE_RECIPIENT = 1, 2
MAX_FILE = 8 << 20
MIN_PASSWORD = 12
OPS_MIN, MEM_MIN = nacl.pwhash.argon2id.OPSLIMIT_MODERATE, nacl.pwhash.argon2id.MEMLIMIT_MODERATE
OPS_MAX, MEM_MAX = nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE, nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE
IMPORT_KEY_PREFIX = "VEILIMP "
LIMITS = {"tokens": 50 * 8 * 4, "posts": 100_000, "contacts": 10_000, "contact_seq": 10_000, "licenses": 1000,
          "license_orders": 1000}
DAYS_AHEAD = 7
SEQ_AHEAD = 86400  # seq сертификата не дальше суток в будущее — так же принимает сервер (identity.SeqAhead)

# Настройки, которые переносятся: (раздел, ключ) → проверка значения.
SETTINGS = {
    ("privacy", "random_delay_seconds"): lambda v: (isinstance(v, list) and len(v) == 2 and
                                                    all(isinstance(x, int) and 0 <= x <= 3600 for x in v) and v[0] <= v[1]),
    ("privacy", "keep_posts_days"): lambda v: isinstance(v, int) and 0 <= v <= 3650,
    ("privacy", "auto_sync_feed_seconds"): lambda v: isinstance(v, int) and (v == 0 or 30 <= v <= 86400),
    ("ui", "locale"): lambda v: isinstance(v, str) and re.fullmatch(r"[a-z]{2}", v) is not None,
}


def _not_weaker(key: tuple[str, str], new, current: dict) -> bool:
    """Настройку приватности из чужого файла принимаем, только если она не слабее текущей: задержка
    не короче, связи «пост → секрет» хранятся не дольше. Ослабить приватность можно только своим конфигом."""
    cur = (current.get(key[0]) or {}).get(key[1])
    if key == ("privacy", "random_delay_seconds"):
        cur = cur or [15, 90]
        return new[0] >= cur[0] and new[1] >= cur[1]
    if key == ("privacy", "keep_posts_days"):
        cur = 30 if cur is None else cur
        return new != 0 and (cur == 0 or new <= cur)
    return True


class ExportError(ValueError):
    """Файл не подходит: понятная причина для владельца."""


# --- сбор ---
def collect(store, bot_id: int, cfg: dict) -> dict:
    if store.pending_posts():
        raise ExportError("есть посты, итог которых бот ещё ждёт; дождитесь их (или суток) и повторите")
    pinned = store.get("pinned_server_sig")
    if not pinned:  # иначе файл не примет ни один бот: «файл с другого сервера»
        raise ExportError("ключ сервера не закреплён — запустите бота хотя бы раз")
    issuer = store.get("pinned_issuer") or {}
    dev = store.load_device()
    tokens = store.db.execute("SELECT day, kid, input, output FROM tokens WHERE status = 'ready'").fetchall()
    posts = store.db.execute("SELECT n, post_secret, url, kind, created, deleted FROM my_posts").fetchall()
    settings: dict = {"privacy": {}, "ui": {}}
    for (sec, k), ok in SETTINGS.items():
        v = (cfg.get(sec) or {}).get(k)
        if v is not None and ok(v):
            settings[sec][k] = v
    return {"v": 1, "created": int(time.time()), "bot_id": int(bot_id), "server_sig": pinned,
            "issuer_kid": issuer.get("kid"), "device": dev.to_json() if dev else None,
            "tokens": [[d, k, b64.enc(i), b64.enc(o)] for d, k, i, o in tokens],
            "posts": [[n, b64.enc(s), u or "", k or "", c, dl] for n, s, u, k, c, dl in posts],
            "contacts": store.get("contacts") or {}, "contact_seq": store.get("contact_seq") or {},
            "nick": store.get("nick"), "feed_cursor": store.get("feed_cursor"), "settings": settings,
            "licenses": store.get("market_licenses") or {}, "license_orders": store.get("market_orders") or {}}


# --- шифрование ---
def seal_password(bundle: dict, password: str) -> bytes:
    if len(password) < MIN_PASSWORD:
        raise ExportError(f"пароль короче {MIN_PASSWORD} символов")
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    key = nacl.pwhash.argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode(), salt, OPS_MIN, MEM_MIN)
    box = nacl.secret.SecretBox(key).encrypt(json.dumps(bundle, separators=(",", ":")).encode())
    return MAGIC + bytes([MODE_PASSWORD]) + salt + OPS_MIN.to_bytes(8, "big") + MEM_MIN.to_bytes(8, "big") + bytes(box)


def new_import_key() -> tuple[str, bytes]:
    """Ключ целевой машины: (строка VEILIMP для показа, секрет — хранить у себя до импорта)."""
    sk = PrivateKey.generate()
    return IMPORT_KEY_PREFIX + b64.enc(bytes(sk.public_key)), bytes(sk)


def parse_import_key(text: str) -> bytes:
    m = re.fullmatch(r"VEILIMP ([A-Za-z0-9_-]{43})", text.strip())
    if not m or len(pk := b64.dec(m.group(1))) != 32:
        raise ExportError("это не ключ VEILIMP")
    return pk


def seal_recipient(bundle: dict, recipient_pk: bytes) -> bytes:
    return MAGIC + bytes([MODE_RECIPIENT]) + SealedBox(PublicKey(recipient_pk)).encrypt(
        json.dumps(bundle, separators=(",", ":")).encode())


def open_file(data: bytes, *, password: str | None = None, recipient_sk: bytes | None = None) -> dict:
    if len(data) > MAX_FILE or not data.startswith(MAGIC) or len(data) < len(MAGIC) + 2:
        raise ExportError("это не файл экспорта Veil")
    mode, body = data[len(MAGIC)], data[len(MAGIC) + 1:]
    try:
        if mode == MODE_PASSWORD:
            if password is None:
                raise ExportError("файл зашифрован паролем")
            salt, ops, mem = body[:16], int.from_bytes(body[16:24], "big"), int.from_bytes(body[24:32], "big")
            if not (OPS_MIN <= ops <= OPS_MAX and MEM_MIN <= mem <= MEM_MAX):
                raise ExportError("параметры пароля вне допустимых")
            key = nacl.pwhash.argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode(), salt, ops, mem)
            plain = nacl.secret.SecretBox(key).decrypt(body[32:])
        elif mode == MODE_RECIPIENT:
            if recipient_sk is None:
                raise ExportError("файл зашифрован на ключ VEILIMP другой машины или бота")
            plain = SealedBox(PrivateKey(recipient_sk)).decrypt(body)
        else:
            raise ExportError("неизвестный режим файла")
    except CryptoError:
        raise ExportError("не расшифровать: неверный пароль или ключ, либо файл повреждён") from None
    try:  # строгий разбор, как у протокола (docs/EXPORT.md): дубли ключей, дробные и огромные числа — отказ
        bundle = jcs.strict_loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ExportError("файл повреждён") from None
    if not isinstance(bundle, dict) or bundle.get("v") != 1:
        raise ExportError("неизвестная версия файла экспорта")
    return bundle


# --- проверка и применение ---
def _check_device(d: dict) -> keys.Device:
    try:
        dev = keys.Device.from_json(d)
        dev.tag = keys.tag(dev.id_pk)  # метку не верим файлу — пересчёт
        now = int(time.time())
        cur = dev.current
        keys.verify_lookup_match({"id_pk": b64.enc(dev.id_pk), "nick": "", "dev_pk": b64.enc(dev.dev_pk),
                                  "seq": dev.seq, "dev_sig": b64.enc(dev.dev_sig), **dev.enc_body()},
                                 dev.tag, now=min(now, cur.exp - 1), tag_fn=lambda pk: dev.tag)
        for k in dev.enc:
            if bytes(PrivateKey(k.sk).public_key) != k.pk:
                raise ExportError("ключ шифрования не совпадает со своей парой")
    except ExportError:
        raise
    except Exception as e:  # noqa: BLE001 — любая ошибка разбора или подписи — отказ
        raise ExportError("сертификат устройства не прошёл проверку") from e
    return dev


def checked_device(bundle: dict) -> keys.Device | None:
    """Устройство из файла после проверки сертификата; None — его нет."""
    return _check_device(bundle["device"]) if bundle.get("device") else None


def apply(store, bundle: dict, *, bot_id: int, issuer_kid: str, force: bool = False, accept_device: bool = False,
          current: dict | None = None, locales: set[str] | None = None) -> dict:
    """Применить проверенный файл к хранилищу целевого бота. Возвращает отчёт: что принято и что пропущено.

    Сначала проверяется весь файл, потом всё записывается одной транзакцией: ошибка в середине файла не оставляет
    половину импорта. Личность (ключ устройства) применяется только при accept_device: файл мог собрать кто угодно
    под ID чужого бота. Бот в чате сначала спрашивает сервер, привязана ли эта личность к нему (device.get), консоль —
    по явному флагу владельца."""
    pinned = store.get("pinned_server_sig")
    if pinned and bundle.get("server_sig") != pinned:
        raise ExportError("файл с другого сервера Veil: закреплённый ключ сервера не совпадает")
    for name, lim in LIMITS.items():
        if len(bundle.get(name) or []) > lim:
            raise ExportError(f"слишком много записей: {name}")
    report: dict = {"device": "нет в файле", "tokens": 0, "posts": 0, "contacts": 0, "licenses": 0, "settings": {}}

    device = None
    dev_raw = bundle.get("device")
    if dev_raw:
        dev = _check_device(dev_raw)
        if int(bundle.get("bot_id", 0)) != int(bot_id):
            report["device"] = "пропущен: личность привязана к прежнему боту — перенесите её restore по 12 словам"
        elif not accept_device:
            report["device"] = f"не применён: личность {dev.tag} принимается только подтверждённой"
        elif store.load_device() is not None and not force:
            report["device"] = "пропущен: у этого бота уже есть личность (замена — с --force)"
        else:
            device = dev
            report["device"] = f"перенесён, метка {dev.tag}"

    start = datetime.now(timezone.utc).date()
    days = {(start + timedelta(days=k)).isoformat() for k in range(DAYS_AHEAD + 1)}
    toks = []
    for r in bundle.get("tokens") or []:
        if not (isinstance(r, list) and len(r) == 4 and all(isinstance(x, str) for x in r)):
            raise ExportError("токен в неверном формате")
        day, kid, inp, out = r
        if day not in days:
            continue
        if kid != issuer_kid and not issue_week_kid_covers(kid, day):
            raise ExportError("токены другого эмитента")
        i, o = b64.dec(inp), b64.dec(out)
        if len(i) != 32 or len(o) != 64:
            raise ExportError("токен в неверном формате")
        toks.append(Token(kid, day, i, o))

    known = store.my_numbers()
    posts = []
    for r in bundle.get("posts") or []:
        if not (isinstance(r, list) and len(r) == 6 and isinstance(r[0], int) and r[0] > 0):
            raise ExportError("пост в неверном формате")
        n, secret, url, kind, created, deleted = r
        s = b64.dec(secret) if isinstance(secret, str) else b""
        if len(s) != 32 or not isinstance(url, str) or len(url) > 200 or not isinstance(kind, str) or len(kind) > 20 \
                or not isinstance(created, int):
            raise ExportError("пост в неверном формате")
        if n not in known:  # свои уже известные посты не перезаписываются
            posts.append((n, s, url, kind, created, 1 if deleted else 0))

    contacts = bundle.get("contacts") or {}
    seqs = bundle.get("contact_seq") or {}
    if not isinstance(contacts, dict) or not isinstance(seqs, dict):
        raise ExportError("закрепления в неверном формате")
    mine = dict(store.get("contacts") or {})
    for label, id_pk in contacts.items():
        if not (isinstance(label, str) and len(label) <= 200 and isinstance(id_pk, str) and len(b64.dec(id_pk)) == 32):
            raise ExportError("закрепления в неверном формате")
        if label not in mine:  # своё закрепление важнее пришедшего
            mine[label] = id_pk
            report["contacts"] += 1
    # seq — время выпуска сертификата: из будущего (дальше, чем принимает сервер) его быть не может. Иначе подложенный
    # файл навсегда пометил бы настоящее устройство контакта «отозванным», и «лично для» ему стало бы невозможно.
    seen = dict(store.get("contact_seq") or {})
    limit = int(time.time()) + SEQ_AHEAD
    for id_pk, seq in seqs.items():
        if isinstance(id_pk, str) and isinstance(seq, int) and not isinstance(seq, bool) and 0 < seq <= limit:
            seen[id_pk] = max(int(seen.get(id_pk, 0)), seq)

    # Лицензии платных плагинов (spec/10): купленное переезжает вместе с ботом. Своя лицензия на тот же плагин важнее.
    licenses = bundle.get("licenses") or {}
    if not isinstance(licenses, dict):
        raise ExportError("лицензии в неверном формате")
    my_lic = dict(store.get("market_licenses") or {})
    for pid, lic in licenses.items():
        if not _license_ok(pid, lic):
            raise ExportError("лицензии в неверном формате")
        if pid not in my_lic:
            my_lic[pid] = {k: lic[k] for k in ("kid", "input", "output", "lic_sk", "cert")}
            report["licenses"] += 1
    # Незавершённые покупки: оплаченный в старом боте запрос VEILLIC новый бот примет, только зная его ослепление.
    orders = bundle.get("license_orders") or {}
    if not isinstance(orders, dict):
        raise ExportError("лицензии в неверном формате")
    my_orders = dict(store.get("market_orders") or {})
    for pid, o in orders.items():
        if not _order_ok(pid, o):
            raise ExportError("лицензии в неверном формате")
        if pid not in my_orders and pid not in my_lic:
            my_orders[pid] = {k: o[k] for k in ("kid", "pk", "input", "blind", "at")}

    settings = bundle.get("settings") or {}
    out: dict = {}
    skipped = []
    for (sec, k), ok in SETTINGS.items():
        v = (settings.get(sec) or {}).get(k)
        if v is None or not ok(v) or (k == "locale" and locales is not None and v not in locales):
            continue
        if not _not_weaker((sec, k), v, current or {}):
            skipped.append(f"{sec}.{k}")
            continue
        out.setdefault(sec, {})[k] = v
    # Подписи кнопок из файла не принимаются никогда: подложенный файл менял бы смысл кнопок («Анонимно: да» на
    # подписанном посте). Свои подписи задаются в своём конфиге.
    if (settings.get("ui") or {}).get("labels"):
        skipped.append("ui.labels")

    store.db.execute("BEGIN IMMEDIATE")
    try:
        report["tokens"] = store.add_tokens(toks)
        store.db.executemany("INSERT INTO my_posts (n, post_secret, url, kind, created, deleted) VALUES (?, ?, ?, ?, ?, ?)",
                             posts)
        report["posts"] = len(posts)
        store.put("contacts", mine)
        store.put("contact_seq", seen)
        if isinstance(bundle.get("feed_cursor"), int) and not store.get("feed_cursor"):
            store.put("feed_cursor", bundle["feed_cursor"])
        store.put("imported_settings", out or None)
        if report["licenses"]:
            store.put("market_licenses", my_lic)
        if my_orders:
            store.put("market_orders", my_orders)
        store.db.execute("COMMIT")
    except BaseException:
        store.db.execute("ROLLBACK")
        raise
    if device is not None:  # файл устройства — после базы: отказ записи выше не оставит личность без её данных
        store.save_device(device)
    report["settings"] = out
    report["skipped_settings"] = skipped
    return report


def _license_ok(pid, lic) -> bool:
    try:
        return isinstance(pid, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,31}", pid) is not None \
            and isinstance(lic, dict) and set(lic) == {"kid", "input", "output", "lic_sk", "cert"} \
            and isinstance(lic["kid"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,32}", lic["kid"]) is not None \
            and len(b64.dec(lic["input"])) == 32 and len(b64.dec(lic["output"])) == 64 \
            and len(b64.dec(lic["lic_sk"])) == 32 and (lic["cert"] is None or len(b64.dec(lic["cert"])) == 64)
    except (TypeError, ValueError):
        return False


def _order_ok(pid, o) -> bool:
    try:
        return isinstance(pid, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,31}", pid) is not None \
            and isinstance(o, dict) and set(o) == {"kid", "pk", "input", "blind", "at"} \
            and isinstance(o["kid"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,32}", o["kid"]) is not None \
            and len(b64.dec(o["pk"])) == 32 and len(b64.dec(o["input"])) == 32 \
            and isinstance(o["blind"], str) and re.fullmatch(r"[0-9a-f]{1,64}", o["blind"]) is not None \
            and isinstance(o["at"], int) and not isinstance(o["at"], bool)
    except (TypeError, ValueError):
        return False


def available_locales() -> set[str]:
    """Языки интерфейса (locales/*.toml): настройка ui.locale из файла принимается, только если такой есть."""
    return {p.stem for p in (Path(__file__).resolve().parents[2] / "locales").glob("*.toml")}


def format_report(r: dict) -> str:
    s = r.get("settings") or {}
    skipped = r.get("skipped_settings") or []
    out = (f"Импорт: личность — {r['device']}; токенов {r['tokens']}; постов {r['posts']}; закреплений {r['contacts']};"
           f" лицензий {r.get('licenses', 0)};"
           f" настройки — {', '.join(f'{a}.{b}' for a, kv in s.items() for b in kv) or 'нет'}.")
    if skipped:
        out += f"\nНе приняты (ослабили бы приватность или меняют кнопки): {', '.join(skipped)}."
    if s:
        out += "\nНастройки вступят в силу после перезапуска бота."
    return out
