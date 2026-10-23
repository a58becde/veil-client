"""Данные бота в пуле на диске — только зашифрованные: база целиком (номера своих постов тоже раскрывают анонимность),
ключ устройства; открытые данные при первом открытии шифруются и затираются."""
import os

import pytest
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey

from veil.core.crypto import keys
from veil.core.store.db import Store
from veil.core.wallet.issue import Token

KEY = os.urandom(32)
SECRET = b"\x5a" * 32


def fill(s):
    s.add_post(4242, SECRET, "https://t.me/c/1/4242", "text")
    s.add_tokens([Token("t1", "2026-10-17", b"\x11" * 32, b"\x22" * 64)])
    s.put("contacts", {"ромашка·k7m2qa": "AAAA"})
    s.save_device(keys.issue_device(SigningKey.generate()))


def test_nothing_plain_on_disk_and_survives_restart(tmp_path):
    s = Store(tmp_path, key=KEY)
    fill(s)
    dev = s.load_device().to_json()
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["device.json.enc", "veil.db.enc"]
    blob = b"".join(p.read_bytes() for p in tmp_path.iterdir())
    for plain in (SECRET, b"\x11" * 32, "роза".encode(), b"4242", b"t.me", b"SQLite format"):
        assert plain not in blob
    assert all(p.stat().st_mode & 0o077 == 0 for p in tmp_path.iterdir())
    s2 = Store(tmp_path, key=KEY)
    assert s2.post_secret(4242) == SECRET and s2.token_counts() == {"2026-10-17": 1}
    assert s2.get("contacts") == {"ромашка·k7m2qa": "AAAA"} and s2.load_device().to_json() == dev


def test_transaction_flushed_on_commit(tmp_path):
    s = Store(tmp_path, key=KEY)
    fill(s)
    t = s.take_token("2026-10-17")  # BEGIN IMMEDIATE … COMMIT
    assert t is not None
    assert Store(tmp_path, key=KEY).token_counts() == {}  # резерв уже на диске


def test_wrong_key_fails(tmp_path):
    fill(Store(tmp_path, key=KEY))
    with pytest.raises(CryptoError):
        Store(tmp_path, key=os.urandom(32))


def test_plain_data_migrated_and_shredded(tmp_path):
    plain = Store(tmp_path)
    fill(plain)
    dev = plain.load_device().to_json()
    plain.db.close()
    s = Store(tmp_path, key=KEY)
    assert s.post_secret(4242) == SECRET and s.load_device().to_json() == dev
    assert not (tmp_path / "veil.db").exists() and not (tmp_path / "device.json").exists()
    assert not (tmp_path / "veil.db-wal").exists()
    s.db._conn.close()
    again = Store(tmp_path, key=KEY)  # перезапуск после перевода: снимок из базы в режиме WAL должен открываться
    assert again.post_secret(4242) == SECRET and again.load_device().to_json() == dev


def test_local_store_unchanged(tmp_path):
    s = Store(tmp_path)
    fill(s)
    assert (tmp_path / "veil.db").exists() and (tmp_path / "device.json").exists()


def test_old_snapshot_with_wal_flag_opens(tmp_path):
    """Снимок, записанный до исправления (флаг WAL в заголовке, как на сервере после первого перевода), открывается."""
    import nacl.secret
    s = Store(tmp_path, key=KEY)
    fill(s)
    box = nacl.secret.SecretBox(KEY)
    img = bytearray(s.db._conn.serialize())
    img[18:20] = b"\x02\x02"
    s.db._conn.close()
    (tmp_path / "veil.db.enc").write_bytes(box.encrypt(bytes(img)))
    assert Store(tmp_path, key=KEY).post_secret(4242) == SECRET
