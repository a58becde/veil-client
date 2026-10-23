"""Эталонный клиент обязан проходить общие векторы veil-protocol/test-vectors/veil-v1.json."""
import json
from pathlib import Path

import pytest
from nacl.public import PrivateKey

from veil.core.crypto import bip39, keys
from veil.core.identity import nick
from veil.core.protocol import b64, content, envelope, jcs
from veil.core.protocol.errors import ProtocolError

V = json.loads((Path(__file__).parents[2] / "veil-protocol/test-vectors/veil-v1.json").read_text("utf-8"))


@pytest.mark.parametrize("c", V["jcs"])
def test_jcs(c):
    assert jcs.canonicalize(jcs.strict_loads(c["input"])).decode() == c["canonical"]


@pytest.mark.parametrize("s", V["json_reject"])
def test_json_reject(s):
    with pytest.raises(ValueError):
        jcs.canonicalize(jcs.strict_loads(s))


def test_b64():
    for c in V["base64url"]["valid"]:
        assert b64.dec(c["b64"]).hex() == c["hex"] and b64.enc(bytes.fromhex(c["hex"])) == c["b64"]
    for s in V["base64url"]["reject"]:
        with pytest.raises(ValueError):
            b64.dec(s)


def test_identity():
    for c in V["identity"]:
        m = bip39.from_entropy(bytes.fromhex(c["entropy"]))
        assert m == c["mnemonic"] and bip39.validate(m) == m
        seed = bip39.to_seed(m)
        assert seed.hex() == c["seed"]
        id_pk = bytes(keys.root_from_seed(seed).verify_key)
        assert (b64.enc(id_pk), keys.tag(id_pk)) == (c["id_pk"], c["tag"])
    for m in V["bip39_reject"]:
        with pytest.raises(bip39.MnemonicError):
            bip39.validate(m)
    for c in V["tag"]:
        assert keys.tag(b64.dec(c["id_pk"])) == c["tag"]
    for c in V["post_key"]:
        assert b64.enc(bytes(keys.post_signing_key(bytes.fromhex(c["post_secret"])).verify_key)) == c["post_pk"]


def test_device_chain():
    """Цепочка «корень → устройство → ключ шифрования» (spec/02): байты сообщений, проверка и подделки."""
    d = V["device"]
    m = d["match"]
    assert keys.device_message(b64.dec(m["id_pk"]), b64.dec(m["dev_pk"]), m["seq"]).hex() == d["device_message"]
    assert keys.enc_message(b64.dec(m["id_pk"]), b64.dec(m["enc_pk"]), m["enc_exp"]).hex() == d["enc_message"]
    v = keys.verify_lookup_match(m, d["tag"], now=d["now"])
    assert v.enc_pk == b64.dec(m["enc_pk"]) and v.seq == m["seq"]
    for r in d["reject"]:
        with pytest.raises(keys.KeyMismatch):
            keys.verify_lookup_match(r["match"], d["tag"], now=d["now"])


# --- официальные векторы внешних стандартов (reference.json): своё сверяется с эталоном ---
R = json.loads((Path(__file__).parents[2] / "veil-protocol/test-vectors/reference.json").read_text("utf-8"))


@pytest.mark.parametrize("c", R["bip39_trezor"]["cases"])
def test_bip39_trezor(c):
    m = bip39.from_entropy(bytes.fromhex(c["entropy"]))
    assert m == c["mnemonic"] and bip39.validate(m) == m
    assert bip39.to_seed(m, R["bip39_trezor"]["passphrase"]).hex() == c["seed"]


@pytest.mark.parametrize("c", R["hkdf_rfc5869"]["cases"])
def test_hkdf_rfc5869(c):
    got = keys.hkdf_sha256(bytes.fromhex(c["ikm"]), bytes.fromhex(c["info"]), salt=bytes.fromhex(c["salt"]),
                           length=c["length"])
    assert got.hex() == c["okm"]


@pytest.mark.parametrize("c", R["jcs_rfc8785"]["cases"], ids=lambda c: c["name"])
def test_jcs_rfc8785(c):
    assert jcs.canonicalize(jcs.strict_loads(c["input"])).decode() == c["canonical"]


@pytest.mark.parametrize("c", R["jcs_rfc8785"]["reject"], ids=lambda c: c["name"])
def test_jcs_rfc8785_floats_rejected(c):
    with pytest.raises(ValueError):
        jcs.strict_loads(c["input"])


def test_text_hash():
    for c in V["text_sha256"]:
        assert content.text_sha256(c["text"]) == c["sha256"]
    for c in V["entities_sha256"]:
        assert content.entities_sha256(c["entities"]) == c["sha256"]
    # Описание контента включает форматирование: подмена адреса ссылки меняет хеш (spec/04).
    m = {"message_id": 1, "text": "смотри сюда", "entities": [{"type": "text_link", "offset": 7, "length": 4, "url": "https://a"}]}
    evil = dict(m, entities=[dict(m["entities"][0], url="https://b")])
    assert content.describe([m])["entities_sha256"] != content.describe([evil])["entities_sha256"]


def test_envelope():
    e = V["envelope"]
    sk = PrivateKey(bytes.fromhex(e["inbox_sk"]))
    assert envelope.signing_input(e["object"]).decode() == e["signing_input"]
    assert envelope.open_envelope(e["sealed"], sk, now=e["now"]) == e["object"]
    for r in V["envelope_reject"]:
        with pytest.raises(ProtocolError) as ex:
            envelope.open_envelope(r["sealed"], sk, now=e["now"])
        assert ex.value.code == r["code"], r["why"]


def test_response_parts():
    r, p = V["response"], V["response_parts"]
    parts = p["parts"]
    assert len(parts) > 1 and all(len(x) <= 4096 for x in parts)
    text = envelope.join_response(parts[::-1])
    got = envelope.open_response(text, PrivateKey(bytes.fromhex(r["resp_sk"])),
                                 envelope.b64.dec(r["server_sig_pk"]), p["object"]["re"])
    assert got == p["object"]
    with pytest.raises(envelope.ProtocolError):
        envelope.join_response(parts[1:])


def test_response():
    r = V["response"]
    got = envelope.open_response(r["sealed"], PrivateKey(bytes.fromhex(r["resp_sk"])),
                                 b64.dec(r["server_sig_pk"]), r["object"]["re"])
    assert got == r["object"]
    with pytest.raises(ProtocolError):
        envelope.open_response(r["sealed"], PrivateKey(bytes.fromhex(r["resp_sk"])), bytes(32), r["object"]["re"])


@pytest.mark.parametrize("c", V["nick"], ids=lambda c: repr(c["input"]))
def test_nick(c):
    if c["ok"]:
        assert nick.normalize(c["input"]) == c["normalized"]
    else:
        with pytest.raises(nick.NickError):
            nick.normalize(c["input"])


def test_hidden():
    from veil.core.protocol import hidden
    a = V["hidden_all"]
    key = envelope.b64.dec(a["key"])
    assert hidden.open_all(envelope.b64.dec(a["blob"]), key) == json.loads(a["payload"])
    assert hidden.callback_data(a["callback_n"], key) == a["callback_data"] and len(a["callback_data"]) <= 64
    t = V["hidden_to"]
    assert hidden.open_to(envelope.b64.dec(t["blob"]), bytes.fromhex(t["enc_sk"])) == json.loads(t["payload"])
    with pytest.raises(ValueError):
        hidden.payload("я" * 4097)




def test_limits_single_source():
    """Константы клиента совпадают с общим вектором limits (его же проверяет сервер): изменение лимита в одном месте
    без другого ломает тесты, а не пользователей («эффект бабочки», docs/CHANGE_IMPACT.md)."""
    from veil.core import api
    from veil.core.wallet import issue
    L = V["limits"]
    assert api.TOKENS_PER_DAY == issue.MAX_PER_DAY == L["tokens_per_day"]
    assert envelope.MAX_PLAINTEXT == L["envelope_json_max"] and envelope.CLOCK_SKEW == L["clock_skew_seconds"]
    assert envelope.RESP_PART_CHARS == L["response_part_chars"] and envelope.MAX_RESP_PARTS == L["response_parts_max"]
    assert [nick.MIN_GRAPHEMES, nick.MAX_GRAPHEMES] == L["nick_graphemes"] and keys.TAG_CHARS == L["tag_chars"]
    assert issue.MAX_DAYS == L["issue_days_max"]
    from veil.core.protocol import errors
    assert list(errors.CODES) == V["error_codes"]  # коды ответа — тот же список, что у сервера (protocol.Codes)
    assert envelope.KID_PATTERN == V["formats"]["kid"]


# --- маркет плагинов (spec/10) ---
def test_market_vectors():
    from nacl.signing import SigningKey

    from veil import market
    from veil.core.crypto import poprf
    m = V["market"]
    idx = market.parse_index(m["index"]["raw"].encode())
    assert market.verify_index_sig(m["index"]["catalog_pk"], m["index"]["raw"].encode(), m["index"]["sig"])
    e = idx.plugins["hello"]
    assert e.encrypted and idx.shop.kid == "s1" and idx.seq == 7
    p = m["package"]
    zip_bytes = market.decrypt_blob(bytes.fromhex(p["blob"]), bytes.fromhex(p["key"]), "hello", "1.2.3")
    assert zip_bytes.hex() == p["zip"] and market.plugin_message("hello", "1.2.3", e.zip_sha256).hex() == p["author_message"]
    assert market.verify_plugin(e.author_pk, "hello", "1.2.3", e.zip_sha256, e.author_sig)
    assert market.encrypt_blob(zip_bytes, bytes.fromhex(p["key"]), "hello", "1.2.3", bytes.fromhex(p["nonce"])).hex() == p["blob"]
    lic = m["license"]
    st = poprf.blind(bytes.fromhex(lic["input"]), int.from_bytes(bytes.fromhex(lic["blind"]), "little"))
    assert st.blinded.hex() == lic["blinded"] and (market.LICENSE_INFO + b"hello").decode() == lic["info"]
    c, pr = m["cert"], m["proof"]
    lic_sk, srv_sk = SigningKey(bytes.fromhex(c["lic_seed"])), SigningKey(bytes.fromhex(c["server_sig_seed"]))
    assert market.cert_message("hello", bytes(lic_sk.verify_key)).hex() == c["message"]
    assert b64.enc(srv_sk.sign(bytes.fromhex(c["message"])).signature) == c["sig"]
    assert market.proof_message("hello", "1.2.3").hex() == pr["message"]
    assert b64.enc(lic_sk.sign(bytes.fromhex(pr["message"])).signature) == pr["sig"]


def test_license_cross():
    """license-cross.json — ответ бота-магазина сервера проекта: бот обязан принять его ответ VEILLICRES."""
    from veil import market
    lic = V["market"]["license"]
    res = json.loads((Path(__file__).parents[2] / "veil-protocol/test-vectors/license-cross.json").read_text())

    class Store(dict):
        def get(self, k, default=None):
            return super().get(k, default)

        def put(self, k, v):
            self[k] = v

    mixin = market.LicenseMixin()
    mixin.store = Store(market_orders={"hello": {"kid": res["kid"], "pk": res["pk"],
                                                 "input": b64.enc(bytes.fromhex(lic["input"])),
                                                 "blind": format(int.from_bytes(bytes.fromhex(lic["blind"]), "little"), "x")}})
    assert mixin.accept_license(res["response"]) == "hello"
    assert b64.dec(mixin.licenses()["hello"]["output"]).hex() == res["output"]


def test_market_index_rejects():
    from veil import market
    for r in V["market"]["reject"]:
        assert market.verify_index_sig(V["market"]["index"]["catalog_pk"], r["raw"].encode(), r["sig"])
        with pytest.raises(market.MarketError):
            market.parse_index(r["raw"].encode())


def test_hide_table_and_albums():
    """Таблица скрытия и состав альбома — одни на клиент и сервер (сервер проверяет те же векторы в posts)."""
    from veil.core import privacy
    link = [{"type": "url", "offset": 0, "length": 19}]

    def sample(k):
        f = {"file_id": "f", "file_unique_id": "u"}
        if k == "text":
            return {"text": "https://example.com", "entities": link}
        if k == "poll":
            return {"poll": {"question": "?", "type": "regular"}}
        body = {"photo": [f]} if k == "photo" else {k: f}
        return body if k in ("video_note", "sticker") else {**body, "caption": "https://example.com",
                                                            "caption_entities": link}
    for r in V["hide_table"]:
        msgs = [sample("photo"), sample("video")] if r["draft"] == "album" else [sample(r["draft"])]
        assert (r["hide"] in privacy.modes(msgs)) == r["offered"], r
    for a in V["album_kinds"]:
        assert privacy.album_ok(a["kinds"]) == a["ok"], a
