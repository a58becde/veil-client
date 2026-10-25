"""keys.json: публичные ключи сервера, подписанные server_sig (spec/02).

Ключ эмитента клиент закрепляет при первом запуске из файла публичного репозитория и дальше не меняет по
keys.get: иначе сервер мог бы выдать человеку свой ключ эмитента и узнавать его посты по токенам (spec/03).
"""
from __future__ import annotations

import re

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from . import b64
from .envelope import signing_input

CTX_KEYS = b"veil/v1/keys\n"


class KeysError(ValueError):
    pass


def verify(doc: dict, pinned_server_sig: str | None = None) -> dict:
    """Проверяет подпись keys.json. Если server_sig закреплён у клиента, документ обязан ему соответствовать."""
    sig_pk = doc.get("server_sig")
    if pinned_server_sig is not None and sig_pk != pinned_server_sig:
        raise KeysError("server_sig не совпадает с закреплённым")
    try:
        VerifyKey(b64.dec(sig_pk)).verify(signing_input(doc, CTX_KEYS), b64.dec(doc["sig"]))
    except (BadSignatureError, ValueError, KeyError, TypeError) as e:
        raise KeysError("неверная подпись keys.json") from e
    return doc


def kid_order(kid: str) -> tuple:
    """Порядок kid «буквы + номер» по числу: i9 < i10 (строкой было бы наоборот), как у сервера."""
    m = re.fullmatch(r"(.*?)(\d*)", kid)
    prefix, num = m.group(1), m.group(2).lstrip("0")
    return (prefix, len(num), num, kid)


def inbox_key(doc: dict) -> tuple[str, bytes]:
    """Самый новый ключ inbox_enc (по kid, с числовым порядком номера)."""
    k = max(doc["inbox_enc"], key=lambda k: kid_order(k["kid"]))
    return k["kid"], b64.dec(k["pk"])


def inbox_bots(doc: dict) -> list[int]:
    """ID приёмных ботов. Пусто — сервер их не публикует (старый документ): клиент пишет по @username."""
    ids = doc.get("inbox_bots") or []
    if not isinstance(ids, list) or not all(isinstance(i, int) and not isinstance(i, bool) and i > 0 for i in ids):
        raise KeysError("inbox_bots в keys.json испорчен")
    return ids


INBOX_USERNAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,28}[Bb][Oo][Tt]")


def inbox_names(doc: dict) -> dict[int, str]:
    """@username приёмных ботов (без @, строчными) по их ID. Пусто — сервер имён не публикует.

    Правила spec/02: список объектов ровно с ключами id и username; id — целое из inbox_bots без повторов;
    username по шаблону (5–32 знака, оканчивается на bot, только ASCII). Любое нарушение — KeysError."""
    if "inbox_names" not in doc:
        return {}
    names = doc["inbox_names"]
    ids = inbox_bots(doc)
    if not isinstance(names, list) or (names and not ids):
        raise KeysError("inbox_names в keys.json испорчен")
    out: dict[int, str] = {}
    for item in names:
        if not isinstance(item, dict) or set(item) != {"id", "username"}:
            raise KeysError("inbox_names в keys.json испорчен")
        bot_id, name = item["id"], item["username"]
        if (not isinstance(bot_id, int) or isinstance(bot_id, bool) or bot_id not in ids or bot_id in out
                or not isinstance(name, str) or not INBOX_USERNAME.fullmatch(name)):
            raise KeysError("inbox_names в keys.json испорчен")
        out[bot_id] = name.lower()
    return out


def issuer_key(doc: dict) -> tuple[str, bytes]:
    """Действующий ключ эмитента документа (spec/02, 03): один, долгоживущий."""
    ks = doc.get("issuer_poprf") or []
    if not ks:
        raise KeysError("в keys.json нет ключа эмитента")
    k = ks[0]
    pk = b64.dec(k["pk"])
    if len(pk) != 32 or not isinstance(k.get("kid"), str):
        raise KeysError("ключ эмитента в keys.json испорчен")
    return k["kid"], pk
