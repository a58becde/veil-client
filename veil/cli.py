"""Команды консоли для личности (spec/02): init, restore, migrate.

12 слов существуют только здесь — в терминале машины, где запущен бот. Бот их не хранит и в Telegram не показывает
и не принимает. Корень личности живёт в памяти, пока выдаётся сертификат устройству, затем ссылки на него
отпускаются (Python не умеет гарантированно стирать память; дамп памяти процесса запрещён, см. harden()).
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from veil.core import export as ex
from veil.core.crypto import bip39, keys
from veil.core.protocol import b64, keysdoc
from veil.core.store.db import Store

CLEAR = "\033[3J\033[2J\033[H"  # очистить экран и прокрутку терминала


class CliError(SystemExit):
    pass


def harden() -> None:
    """Файлы — только владельцу; без дампа памяти; другие процессы того же пользователя не читают память
    через ptrace (Linux, PR_SET_DUMPABLE). Ошибки не фатальны: на другой ОС этих механизмов может не быть."""
    os.umask(0o077)
    try:
        import resource  # noqa: PLC0415 — только Unix
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            import ctypes  # noqa: PLC0415 — только Linux
            ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 4
        except (OSError, AttributeError):
            pass


def _tty(batch: bool) -> None:
    if not batch and not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise CliError("Команду нужно выполнить в терминале: 12 слов показываются и вводятся только там.\n"
                       "Для автоматизации есть --batch (вы сами отвечаете за то, куда попадёт вывод).")


def _show_words(words: list[str]) -> None:
    rows = (len(words) + 2) // 3
    for r in range(rows):
        print("   " + "".join(f"{i + 1:>2}. {words[i]:<12}" for i in (r, r + rows, r + 2 * rows) if i < len(words)))


def _confirm(words: list[str]) -> None:
    """Владелец вводит два случайных слова: так он точно их записал, а не пролистал."""
    picks = sorted(secrets.SystemRandom().sample(range(len(words)), 2))
    for i in picks:
        for _attempt in range(3):
            got = input(f"Проверка: введите слово №{i + 1} (Enter — показать слова ещё раз): ").strip().lower()
            if got == words[i]:
                break
            if not got:
                _show_words(words)
                continue
            print("Не то слово. Сверьтесь с записью.")
        else:
            raise CliError("Слова не подтверждены. Личность не создана — запустите init ещё раз.")


def _save_new_device(store: Store, root, replace: bool) -> keys.Device:
    if store.load_device() is not None and not replace:
        raise CliError("На этом боте уже есть личность (data/device.json). Чтобы заменить её, добавьте --force.\n"
                       "Без 12 слов прежней личности её будет не вернуть.")
    print("Считаю метку личности (около секунды)…")
    d = keys.issue_device(root)
    store.save_device(d)
    return d


def init(store: Store, batch: bool = False, force: bool = False) -> keys.Device:
    _tty(batch)
    if store.load_device() is not None and not force:
        raise CliError("На этом боте уже есть личность (data/device.json). Новая заменит её — добавьте --force.")
    mnemonic = bip39.generate()
    words = mnemonic.split()
    print("\nНовая личность Veil.\n\n12 слов ниже — единственный способ вернуть личность или отозвать украденный бот.\n"
          "Запишите их на бумагу. Не фотографируйте, не отправляйте в мессенджеры и облако. Бот их не сохранит.\n")
    _show_words(words)
    print()
    if not batch:
        _confirm(words)
        print(CLEAR, end="")
    d = _save_new_device(store, keys.root_from_seed(bip39.to_seed(mnemonic)), replace=True)
    del mnemonic, words
    print(f"Готово. Метка вашей личности: {d.tag}. Ключ устройства сохранён в {store.device_path}.\n"
          "Запустите бота — при первом запуске он зарегистрирует устройство на сервере (1 токен).")
    return d


def _read_words(batch: bool) -> str:
    if batch:
        return sys.stdin.readline()
    return getpass.getpass("12 слов через пробел (ввод не отображается): ")


def restore(store: Store, batch: bool = False, force: bool = False) -> keys.Device:
    _tty(batch)
    if store.load_device() is not None and not force:
        raise CliError("На этом боте уже есть личность (data/device.json). "
                       "Восстановление заменит её — добавьте --force.")
    print("Восстановление личности по 12 словам. Новое устройство отзовёт прежнее (например, украденное).")
    for _attempt in range(3):
        try:
            mnemonic = bip39.validate(_read_words(batch))
            break
        except bip39.MnemonicError as e:
            print(f"Не подходит: {e}.")
            if batch:
                raise CliError("12 слов не прошли проверку.") from None
    else:
        raise CliError("12 слов не прошли проверку.")
    root = keys.root_from_seed(bip39.to_seed(mnemonic))
    del mnemonic
    if not batch:
        print("Считаю метку…")
        t = keys.tag(bytes(root.verify_key))
        if input(f"Метка этой личности: {t}. Это ваша метка? [д/N] ").strip().lower() not in ("д", "да", "y", "yes"):
            raise CliError("Отменено. Если метка не ваша, в словах ошибка (порядок или похожее слово).")
    d = _save_new_device(store, root, replace=True)
    del root
    print(f"Готово: личность {d.tag} на новом устройстве. При запуске бот зарегистрирует его (1 токен),\n"
          "прежнее устройство этой личности будет отозвано. Если бот прежде работал на другом боте Telegram,\n"
          "личность перейдёт на этот.")
    return d


def migrate(store: Store, batch: bool = False) -> keys.Device:
    """Старый формат (12 слов в data/identity.json) → устройство; файл со словами затирается."""
    mnemonic = store.load_legacy_mnemonic()
    if mnemonic is None:
        raise CliError("Старого файла со словами (data/identity.json) нет — переводить нечего.")
    if store.load_device() is not None:
        raise CliError("data/device.json уже есть. Удалите data/identity.json вручную, если он больше не нужен.")
    root = keys.root_from_seed(bip39.to_seed(bip39.validate(mnemonic)))
    d = _save_new_device(store, root, replace=False)
    del root
    if not batch and sys.stdin.isatty() and sys.stdout.isatty():
        if input("12 слов больше не будут храниться на диске. Показать их в последний раз? [д/N] ").strip().lower() \
                in ("д", "да", "y", "yes"):
            _show_words(mnemonic.split())
            input("Запишите и нажмите Enter — экран очистится.")
            print(CLEAR, end="")
    del mnemonic
    store.wipe_legacy_identity()
    print(f"Готово: личность {d.tag} переведена на ключ устройства, файл со словами затёрт и удалён.\n"
          "При запуске бот зарегистрирует устройство (1 токен).")
    return d


# --- экспорт и импорт (docs/EXPORT.md) ---
def _bot_id(store: Store, cfg: dict) -> int:
    """ID бота: из токена в окружении (до двоеточия) или из данных, если бот уже запускался."""
    token = os.environ.get(cfg["telegram"].get("token_env", "VEIL_BOT_TOKEN"), "")
    head = token.split(":", 1)[0]
    if head.isdigit():
        return int(head)
    if store.get("bot_id"):
        return int(store.get("bot_id"))
    raise CliError("Не знаю ID бота: задайте токен в окружении (как для запуска) или запустите бота один раз.")


def _offered_issuer(cfg: dict, base) -> dict:
    """Ключ эмитента из локального keys.json (подпись — закреплённым ключом сервера из конфига)."""
    local = keysdoc.verify(json.loads((Path(base) / cfg["server"].get("keys_file", "keys.json")).read_text()),
                           cfg["server"]["server_sig"])
    kid, ipk = keysdoc.issuer_key(local)
    return {"kid": kid, "pk": b64.enc(ipk)}


def _pins(store: Store, cfg: dict, base) -> str:
    """Закрепления целевого бота из его конфига (как при запуске), а не из файла экспорта. Возвращает kid эмитента.
    Уже закреплённый другой ключ эмитента молча не меняется — только pin-issuer."""
    pinned = cfg["server"]["server_sig"]
    if store.get("pinned_server_sig") not in (None, pinned):
        raise CliError("server_sig в конфиге не совпадает с закреплённым в data/ — сначала разберитесь с конфигом.")
    store.put("pinned_server_sig", pinned)
    offered, current = _offered_issuer(cfg, base), store.get("pinned_issuer")
    if current not in (None, offered):
        raise CliError("Ключ эмитента в keys.json отличается от закреплённого. Если проект объявил смену ключа, "
                       "подтвердите её: python -m veil <конфиг> pin-issuer.")
    store.put("pinned_issuer", offered)
    return offered["kid"]


def _fingerprint(pk_b64: str) -> str:
    return hashlib.sha256(b64.dec(pk_b64)).hexdigest()[:16]


def pin_issuer(store: Store, cfg: dict, base, batch: bool = False) -> dict:
    """Подтвердить смену ключа эмитента из keys.json. Ключ меняется только при компрометации, и проект объявляет это в
    публичном репозитории (spec/03): ключ, который подсунули, позволил бы сопоставлять ваши токены с выдачей."""
    offered, current = _offered_issuer(cfg, base), store.get("pinned_issuer")
    if current == offered:
        print(f"Ключ эмитента {offered['kid']} ({_fingerprint(offered['pk'])}) уже закреплён.")
        return offered
    if current:
        print(f"Закреплён:     {current.get('kid')} ({_fingerprint(current['pk'])})")
    print(f"В keys.json:   {offered['kid']} ({_fingerprint(offered['pk'])})\n"
          "Меняйте закрепление, только если смену ключа эмитента объявил сам проект (репозиторий veil-protocol). "
          "Ключ из\n"
          "подсунутого файла позволил бы тому, кто его выдал, узнавать ваши анонимные посты по токенам.")
    if not batch:
        _tty(False)
        if input("Закрепить новый ключ эмитента? [д/N] ").strip().lower() not in ("д", "да", "y", "yes"):
            raise CliError("Отменено: закреплён прежний ключ.")
    store.put("pinned_issuer", offered)
    store.put("issuer_repin", None)
    print(f"Готово: закреплён ключ эмитента {offered['kid']}.")
    return offered


def pin_market(store: Store, cfg: dict, batch: bool = False) -> str:
    """Подтвердить смену ключа каталога плагинов ([market] key в config.toml). Подменённый ключ дал бы чужому каталогу
    ставить вам свои «обновления» плагинов (docs/MARKET.md)."""
    offered, current = (cfg.get("market") or {}).get("key") or "", store.get("pinned_market")
    if not offered:
        raise CliError("В config.toml нет [market] key.")
    if current == offered:
        print(f"Ключ каталога ({_fingerprint(offered)}) уже закреплён.")
        return offered
    if current:
        print(f"Закреплён:       {_fingerprint(current)}")
    print(f"В config.toml:   {_fingerprint(offered)}\n"
          "Меняйте закрепление, только если смену ключа каталога объявил сам проект (репозиторий veil-plugins).")
    if not batch:
        _tty(False)
        if input("Закрепить новый ключ каталога? [д/N] ").strip().lower() not in ("д", "да", "y", "yes"):
            raise CliError("Отменено: закреплён прежний ключ.")
    store.put("pinned_market", offered)
    store.put("market_seq", None)  # новый каталог — своя нумерация индексов
    print("Готово: закреплён новый ключ каталога.")
    return offered


def engine(store: Store, cfg: dict, base, action: str, batch: bool = False) -> str:
    """Движок плагинов (docs/PLUGINS.md, «Движок»): status — какой файл и принят ли он; fetch — скачать официальную
    сборку (хеш закреплён в коде); trust — принять свою сборку. Своя сборка неповторяема (у каждой свой хеш), поэтому
    подтверждается здесь, в терминале, а не настройкой: подсунутый конфиг не подменит движок молча."""
    import asyncio  # noqa: PLC0415 — нужен только fetch

    from veil import plugin_engine as pe  # noqa: PLC0415
    path = pe.engine_path(cfg, Path(base))
    if action == "fetch":
        try:
            sha = asyncio.run(pe.fetch_engine(path, (cfg.get("telegram") or {}).get("proxy") or None))
        except Exception as e:  # noqa: BLE001 — сеть, хеш: сказать словами
            raise CliError(f"Движок не скачан: {e}") from None
        print(f"Готово: официальный движок {path} (SHA-256 {sha[:16]}…).")
        return sha
    if not path.is_file():
        raise CliError(f"Файла движка нет: {path}. Скачайте официальный: python -m veil <конфиг> engine fetch")
    sha = pe.sha256_file(path)
    trusted = list(store.get("engine_trusted") or [])
    if action == "status":
        state = "официальная сборка" if sha == pe.ENGINE_SHA256 else \
            "своя сборка, подтверждена" if sha in trusted else "НЕ ПРИНЯТ: не официальный и не подтверждён"
        print(f"{path}\nSHA-256 {sha}\n{state}")
        return sha
    if action != "trust":
        raise CliError("engine: status | fetch | trust")
    if sha == pe.ENGINE_SHA256 or sha in trusted:
        print("Этот движок уже принят.")
        return sha
    print(f"{path}\nSHA-256 {sha}\nЭто не официальная сборка. Принимайте её, только если собрали сами (python3 "
          "engine/build.py) из кода, которому доверяете: движок исполняет плагины и видит всё, что им разрешено.")
    if not batch:
        _tty(False)
        if input("Принять этот движок? [д/N] ").strip().lower() not in ("д", "да", "y", "yes"):
            raise CliError("Отменено.")
    store.put("engine_trusted", trusted + [sha])
    print("Готово: движок принят.")
    return sha


def _password(batch: bool, confirm: bool) -> str:
    if batch:
        return sys.stdin.readline().rstrip("\n")
    p = getpass.getpass("Пароль файла экспорта (не короче 12 символов, ввод не отображается): ")
    if confirm and getpass.getpass("Повторите пароль: ") != p:
        raise CliError("Пароли не совпали.")
    return p


def export(store: Store, cfg: dict, path: str, to_key: str | None = None, batch: bool = False, base=None) -> None:
    if base is not None:
        _pins(store, cfg, base)  # бот мог ни разу не запускаться (сразу после init): закрепления — из конфига
    try:
        bundle = ex.collect(store, _bot_id(store, cfg), cfg)
        data = ex.seal_recipient(bundle, ex.parse_import_key(to_key)) if to_key else \
            ex.seal_password(bundle, _password(batch, confirm=True))
    except ex.ExportError as e:
        raise CliError(f"Экспорт не сделан: {e}.") from None
    out = Path(path)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    del bundle
    print(f"Готово: {out} ({len(data)} байт, права 600). В файле ключ устройства, токены и секреты ваших постов —\n"
          "храните его как 12 слов и удалите после переноса. Не запускайте бота одновременно на двух машинах.")


def import_key(store: Store) -> str:
    """Ключ этой машины для файла, который придёт через чат (сценарий «пул → своя машина»)."""
    text, sk = ex.new_import_key()
    store.put("import_sk", b64.enc(sk))
    print("Отправьте боту, из которого переносите данные, команду:\n\n"
          f"/export {text}\n\nОн пришлёт файл; скачайте его и выполните здесь: python -m veil <конфиг> import <файл>.\n"
          "Ключ одноразовый: после импорта он стирается.")
    return text


def import_(store: Store, cfg: dict, base, path: str, force: bool = False, batch: bool = False,
            with_identity: bool = False) -> dict:
    data = Path(path).read_bytes()
    kid = _pins(store, cfg, base)
    sk = store.get("import_sk")
    try:
        mode = data[len(ex.MAGIC)] if data.startswith(ex.MAGIC) and len(data) > len(ex.MAGIC) else 0
        bundle = ex.open_file(data, recipient_sk=b64.dec(sk) if sk else None,
                              password=_password(batch, confirm=False) if mode == ex.MODE_PASSWORD else None)
        if with_identity and bundle.get("device"):
            print("Внимание: личность из файла принимается без проверки сервером. Делайте так только со своим файлом:\n"
                  "ключ устройства из чужого файла остаётся у его автора.")
        report = ex.apply(store, bundle, bot_id=_bot_id(store, cfg), issuer_kid=kid, force=force,
                          accept_device=with_identity, current=cfg, locales=ex.available_locales())
    except ex.ExportError as e:
        raise CliError(f"Импорт не сделан: {e}.") from None
    if mode == ex.MODE_RECIPIENT:
        store.put("import_sk", None)
    print(ex.format_report(report))
    return report
