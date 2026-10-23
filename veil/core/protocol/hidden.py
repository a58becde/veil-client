"""Скрытый контент (veil-protocol/spec/07).

hidden_payload = JCS({"text": ..., "entities": [...]}), текст 1…4096 UTF-16 единиц, не больше MAX_PAYLOAD байт.
«Лично для» выравнивается полем "pad" (пробелы) до кратного PAD_BLOCK байт, контейнер файлов — по схеме Padmé:
длина видна серверу и всем по ленте только с точностью до корзины.
«Для всех»: blob = nonce[24] || XChaCha20-Poly1305(K, nonce, payload, aad="veil/v1/hidden"); K уходит
серверу в body.hidden.key и живёт в кнопке «Показать».
«Для ника»: blob = crypto_box_seal(payload, enc_pk получателя); сервер его не читает. В payload — "post_pk" поста:
получатель сверяет его с post_pk записи ленты, и blob, скопированный в чужой пост, не выдаётся за его сообщение.
Медиа «для ника» (любые виды, альбомы): клиент шифрует файлы в контейнер
container = nonce[24] || XChaCha20-Poly1305(file_key, nonce, файл1 || файл2 || …, aad="veil/v1/file"),
отправляет его серверу документом, а в payload кладёт "files" (вид, имя, mime, размер — по порядку)
и "file_key". Сервер контейнер не публикует и не может прочитать; получатель забирает его по hidden.file.
"""
from __future__ import annotations

import secrets

from nacl.bindings import (crypto_aead_xchacha20poly1305_ietf_decrypt,
                           crypto_aead_xchacha20poly1305_ietf_encrypt)
from nacl.public import PrivateKey, PublicKey, SealedBox

from . import b64, jcs

AAD = b"veil/v1/hidden"
FILE_AAD = b"veil/v1/file"
MAX_TEXT_UNITS = 4096  # как сообщение Telegram
MAX_PAYLOAD = 24 * 1024  # байт JSON: запись ленты с таким blob помещается в ответ feed.get (spec/07)
PAD_BLOCK = 256
MAX_CONTAINER = 20 * 1024 * 1024 - 64  # Bot API отдаёт ботам файлы до 20 МБ; запас на nonce и тег


def padme(n: int) -> int:
    """Padmé (Nikitin et al., PETS 2019): длина округляется так, что раскрывается O(log log n) бит, запас ≤ 12%."""
    if n < 2:
        return n
    e = n.bit_length() - 1
    s = e.bit_length()
    mask = (1 << (e - s)) - 1
    return (n + mask) & ~mask


def utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def payload(text: str, entities: list[dict] | None = None, *, allow_empty: bool = False,
            files: list[dict] | None = None, file_key: bytes | None = None, post_pk: str | None = None) -> bytes:
    """post_pk — у «лично для»: ключ поста, к которому привязано сообщение (spec/07)."""
    if (not text and not allow_empty and not files) or utf16_len(text) > MAX_TEXT_UNITS:
        raise ValueError("hidden text must be 1..4096 UTF-16 units")
    obj: dict = {"text": text}
    if entities:
        obj["entities"] = entities
    if files:
        obj["files"] = files
        obj["file_key"] = b64.enc(file_key)
    if post_pk:
        obj["post_pk"] = post_pk
    out = jcs.canonicalize(obj)
    if len(out) > MAX_PAYLOAD:
        raise ValueError("hidden payload too big")
    return out


def padded(pl: bytes) -> bytes:
    """payload «лично для» с полем pad до кратного PAD_BLOCK. Получатель поле pad игнорирует.

    Предел MAX_PAYLOAD действует и после выравнивания: сервер принимает blob не больше MAX_PAYLOAD + 48.
    MAX_PAYLOAD кратен PAD_BLOCK, поэтому выравнивание не отнимает у текста больше одного блока."""
    obj = jcs.strict_loads(pl.decode("utf-8"))
    extra = len(b',"pad":""')
    target = -(-(len(pl) + extra) // PAD_BLOCK) * PAD_BLOCK
    obj["pad"] = " " * (target - len(pl) - extra)
    out = jcs.canonicalize(obj)
    if len(out) != target:  # не assert: при python -O проверка исчезла бы
        raise ValueError("padding mismatch")
    if len(out) > MAX_PAYLOAD:
        raise ValueError("hidden payload too big")
    return out


def seal_files(files: list[bytes]) -> tuple[bytes, bytes]:
    """Контейнер файлов «лично для»: (зашифрованный контейнер, file_key)."""
    data = b"".join(files)
    if len(data) > MAX_CONTAINER:
        raise ValueError("container too big")
    data += bytes(min(padme(len(data)), MAX_CONTAINER) - len(data))  # нули в конце; размеры файлов — в payload
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(24)
    return nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(data, FILE_AAD, nonce, key), key


def open_files(container: bytes, key: bytes, sizes: list[int]) -> list[bytes]:
    """Расшифровать контейнер и разрезать по размерам из payload. Подмена — исключение."""
    data = crypto_aead_xchacha20poly1305_ietf_decrypt(container[24:], FILE_AAD, container[:24], key)
    total = sum(sizes)
    if total > len(data) or any(n < 0 for n in sizes) or any(data[total:]):
        raise ValueError("container does not match manifest")
    out, pos = [], 0
    for n in sizes:
        out.append(data[pos:pos + n])
        pos += n
    return out


def seal_all(pl: bytes, key: bytes | None = None, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    key = key or secrets.token_bytes(32)
    nonce = nonce or secrets.token_bytes(24)
    return nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(pl, AAD, nonce, key), key


def open_all(blob: bytes, key: bytes) -> dict:
    pt = crypto_aead_xchacha20poly1305_ietf_decrypt(blob[24:], AAD, blob[:24], key)
    return jcs.strict_loads(pt.decode("utf-8"))


def seal_to(pl: bytes, enc_pk: bytes) -> bytes:
    return SealedBox(PublicKey(enc_pk)).encrypt(pl)


def open_to(blob: bytes, enc_sk: bytes) -> dict:
    return jcs.strict_loads(SealedBox(PrivateKey(enc_sk)).decrypt(blob).decode("utf-8"))


def body_all(text: str, entities: list[dict] | None = None, *, media: bool = False) -> dict:
    """media=True — «скрыть всё» у медиа: в группе только шапка с кнопкой, медиа и подпись — по нажатию."""
    blob, key = seal_all(payload(text, entities, allow_empty=media))
    body = {"mode": "all", "blob": b64.enc(blob), "key": b64.enc(key)}
    if media:
        body["media"] = True
    return body


def body_to(text: str, enc_pk: bytes, entities: list[dict] | None = None, *, post_pk: str | None = None) -> dict:
    pl = padded(payload(text, entities, post_pk=post_pk))
    return {"mode": "to", "to_pk": b64.enc(enc_pk), "blob": b64.enc(seal_to(pl, enc_pk))}


def callback_data(n: int, key: bytes) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    s = ""
    while n:
        n, r = divmod(n, 36)
        s = digits[r] + s
    return f"h:{s or '0'}:{b64.enc(key)}"
