"""Ключи (spec/02): корень личности из 12 слов, ключ устройства, ключ шифрования, медленная метка, ключ поста.

Корень на машине бота не живёт: он нужен только чтобы выдать сертификат устройству (init / restore), дальше
бот действует ключом устройства. Ключ шифрования случайный и меняется раз в 7 дней — из 12 слов он не выводится.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field

from nacl import pwhash
from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey

from veil.core.protocol import b64

SALT = b"veil/v1"
INFO_ID = b"veil/v1/identity/ed25519"
INFO_POST = b"veil/v1/post"
DEVICE_CTX = b"veil/v1/device\n"
ENC_KEY_CTX = b"veil/v1/enc-key\n"
CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz"
TAG_SEP = "·"
TAG_CHARS = 6  # 30 бит (spec/02; было 4 до 2026-10-17)
# Медленная метка: Argon2id (RFC 9106) через libsodium crypto_pwhash (p = 1), ~0,2 с и 64 МиБ.
TAG_SALT = b"veil/v1/tag/a2id"  # ровно 16 байт (crypto_pwhash_SALTBYTES)
TAG_OPS = 3
TAG_MEM = 64 << 20

ENC_LIFETIME = 14 * 86400  # exp ключа шифрования от выпуска
ENC_ROTATE = 7 * 86400     # новый ключ, когда текущему столько
ENC_KEEP = 30 * 86400      # секретные ключи хранятся после exp (пришедшее, пока бот был выключен)


def hkdf_sha256(ikm: bytes, info: bytes, salt: bytes = SALT, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869); проверено векторами RFC 5869 A.1–A.3 (tests/test_vectors.py)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t = b"", b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def root_from_seed(seed: bytes) -> SigningKey:
    """Корневой ключ личности из BIP-39 seed (64 байта)."""
    if len(seed) != 64:
        raise ValueError("BIP-39 seed must be 64 bytes")
    return SigningKey(hkdf_sha256(seed, INFO_ID))


def post_signing_key(post_secret: bytes) -> SigningKey:
    if len(post_secret) != 32:
        raise ValueError("post_secret must be 32 bytes")
    return SigningKey(hkdf_sha256(post_secret, INFO_POST))


def tag(id_pk: bytes) -> str:
    """TAG_CHARS символов Crockford Base32: старшие 5·TAG_CHARS бит
    Argon2id(id_pk, "veil/v1/tag/a2id", t=3, m=64 МиБ, p=1)."""
    h = pwhash.argon2id.kdf(32, id_pk, TAG_SALT, opslimit=TAG_OPS, memlimit=TAG_MEM)
    bits = int.from_bytes(h[:4], "big") >> (32 - 5 * TAG_CHARS)
    return "".join(CROCKFORD[(bits >> (5 * i)) & 31] for i in range(TAG_CHARS - 1, -1, -1))


def display_name(nick: str, tag_: str) -> str:
    """Подпись поста «ник·метка» — единственное место, где собирается разделитель."""
    return f"{nick}{TAG_SEP}{tag_}"


def device_message(id_pk: bytes, dev_pk: bytes, seq: int) -> bytes:
    return DEVICE_CTX + id_pk + dev_pk + seq.to_bytes(8, "big")


def enc_message(id_pk: bytes, enc_pk: bytes, exp: int) -> bytes:
    return ENC_KEY_CTX + id_pk + enc_pk + exp.to_bytes(8, "big")


def _b64(b: bytes) -> str:
    return b64.enc(b)


def _unb64(s: str) -> bytes:
    return b64.dec(s)


@dataclass
class EncKey:
    sk: bytes
    pk: bytes
    exp: int
    sig: bytes
    created: int

    def to_json(self) -> dict:
        return {"sk": _b64(self.sk), "pk": _b64(self.pk), "exp": self.exp, "sig": _b64(self.sig),
                "created": self.created}

    @classmethod
    def from_json(cls, d: dict) -> "EncKey":
        return cls(_unb64(d["sk"]), _unb64(d["pk"]), int(d["exp"]), _unb64(d["sig"]), int(d["created"]))


@dataclass
class Device:
    """Устройство личности (data/device.json): ключ устройства, его сертификат от корня и ключи шифрования."""
    id_pk: bytes
    tag: str
    dev_sk: SigningKey
    seq: int
    dev_sig: bytes
    enc: list[EncKey] = field(default_factory=list)  # по возрастанию exp, текущий — последний

    @property
    def dev_pk(self) -> bytes:
        return bytes(self.dev_sk.verify_key)

    @property
    def current(self) -> EncKey:
        return self.enc[-1]

    def enc_secret(self, pk: bytes) -> bytes | None:
        """Секретный ключ шифрования по открытому (текущий или хранимый прежний)."""
        return next((k.sk for k in self.enc if hmac.compare_digest(k.pk, pk)), None)

    def new_enc(self, now: int | None = None) -> EncKey:
        now = int(time.time()) if now is None else now
        sk = PrivateKey.generate()
        pk = bytes(sk.public_key)
        exp = now + ENC_LIFETIME
        k = EncKey(bytes(sk), pk, exp, self.dev_sk.sign(enc_message(self.id_pk, pk, exp)).signature, now)
        self.enc.append(k)
        return k

    def needs_rotation(self, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        return not self.enc or now - self.current.created >= ENC_ROTATE or self.current.exp <= now

    def prune(self, now: int | None = None) -> None:
        """Удаляет секретные ключи шифрования, которым больше exp + 30 дней (текущий не трогается)."""
        now = int(time.time()) if now is None else now
        self.enc = [k for k in self.enc[:-1] if k.exp + ENC_KEEP > now] + self.enc[-1:]

    def device_body(self) -> dict:
        """Тело device.set (spec/05): сертификат и текущий ключ шифрования."""
        return {"id_pk": _b64(self.id_pk), "seq": self.seq, "dev_sig": _b64(self.dev_sig), **self.enc_body()}

    def enc_body(self) -> dict:
        k = self.current
        return {"enc_pk": _b64(k.pk), "enc_exp": k.exp, "enc_sig": _b64(k.sig)}

    def to_json(self) -> dict:
        return {"v": 2, "id_pk": _b64(self.id_pk), "tag": self.tag, "dev_sk": _b64(bytes(self.dev_sk)),
                "seq": self.seq, "dev_sig": _b64(self.dev_sig), "enc": [k.to_json() for k in self.enc]}

    @classmethod
    def from_json(cls, d: dict) -> "Device":
        if d.get("v") != 2:
            raise ValueError("device.json: unknown version")
        id_pk = _unb64(d["id_pk"])
        t = d["tag"] if len(d["tag"]) == TAG_CHARS else tag(id_pk)  # метка прежней длины (4 → 6, 2026-10-17)
        return cls(id_pk, t, SigningKey(_unb64(d["dev_sk"])), int(d["seq"]), _unb64(d["dev_sig"]),
                   [EncKey.from_json(k) for k in d["enc"]])


def issue_device(root: SigningKey, now: int | None = None, tag_fn=tag) -> Device:
    """Новое устройство под корнем (init / restore): случайный ключ устройства, сертификат с seq = now
    (больше прежнего — прежнее устройство отзывается, spec/02), первый ключ шифрования."""
    now = int(time.time()) if now is None else now
    id_pk = bytes(root.verify_key)
    dev = SigningKey(secrets.token_bytes(32))
    sig = root.sign(device_message(id_pk, bytes(dev.verify_key), now)).signature
    d = Device(id_pk, tag_fn(id_pk), dev, now, sig)
    d.new_enc(now)
    return d


class KeyMismatchError(ValueError):
    pass


@dataclass
class Verified:
    """Получатель после проверки цепочки (spec/02, «Проверка получателя»)."""
    id_pk: bytes
    enc_pk: bytes
    seq: int
    nick: str


def verify_lookup_match(match: dict, expected_tag: str, now: int | None = None, tag_fn=tag) -> Verified:
    """Проверяет запись nick.lookup: сертификат устройства подписан корнем id_pk, ключ шифрования — ключом
    устройства и не просрочен, метка выведена из id_pk. Закрепление (TOFU) и seq проверяет вызывающий."""
    now = int(time.time()) if now is None else now
    try:
        id_pk, dev_pk, dev_sig, enc_pk, enc_sig = (_unb64(match[k])
                                                   for k in ("id_pk", "dev_pk", "dev_sig", "enc_pk", "enc_sig"))
        seq, exp = int(match["seq"]), int(match["enc_exp"])
        if len(id_pk) != 32 or len(dev_pk) != 32 or len(enc_pk) != 32 or seq <= 0:
            raise ValueError("size")
        VerifyKey(id_pk).verify(device_message(id_pk, dev_pk, seq), dev_sig)
        VerifyKey(dev_pk).verify(enc_message(id_pk, enc_pk, exp), enc_sig)
    except (KeyError, ValueError, TypeError, BadSignatureError) as e:
        raise KeyMismatchError("подпись ключей получателя неверна") from e
    if exp <= now:
        raise KeyMismatchError("ключ шифрования получателя просрочен")
    if tag_fn(id_pk) != expected_tag:
        raise KeyMismatchError("метка не совпадает с ключом личности")
    return Verified(id_pk, enc_pk, seq, str(match.get("nick") or ""))
