import json
from pathlib import Path

from veil.core.crypto import poprf

VEC = json.loads((Path(__file__).parents[2] / "veil-protocol/test-vectors/rfc9497-poprf-ristretto255-sha512.json").read_text())


def _split(h):
    return [bytes.fromhex(x) for x in h.split(",")]


def test_rfc9497_vectors():
    pk = bytes.fromhex(VEC["pkSm"])
    for v in VEC["vectors"]:
        info = bytes.fromhex(v["Info"])
        inputs, blinds = _split(v["Input"]), _split(v["Blind"])
        states = [poprf.blind(i, int.from_bytes(b, "little")) for i, b in zip(inputs, blinds)]
        assert [s.blinded for s in states] == _split(v["BlindedElement"])
        out = poprf.finalize_batch(states, _split(v["EvaluationElement"]), bytes.fromhex(v["Proof"]["proof"]), pk, info)
        assert out == _split(v["Output"])


def test_bad_proof_rejected():
    v = VEC["vectors"][0]
    pk = bytes.fromhex(VEC["pkSm"])
    st = [poprf.blind(bytes.fromhex(v["Input"]), int.from_bytes(bytes.fromhex(v["Blind"]), "little"))]
    proof = bytearray(bytes.fromhex(v["Proof"]["proof"]))
    proof[0] ^= 1
    try:
        poprf.finalize_batch(st, [bytes.fromhex(v["EvaluationElement"])], bytes(proof), pk, bytes.fromhex(v["Info"]))
    except poprf.ProofError:
        return
    raise AssertionError("bad proof accepted")


def test_wrong_info_rejected():
    v = VEC["vectors"][0]
    pk = bytes.fromhex(VEC["pkSm"])
    st = [poprf.blind(bytes.fromhex(v["Input"]), int.from_bytes(bytes.fromhex(v["Blind"]), "little"))]
    try:
        poprf.finalize_batch(st, [bytes.fromhex(v["EvaluationElement"])], bytes.fromhex(v["Proof"]["proof"]), pk, b"other day")
    except poprf.ProofError:
        return
    raise AssertionError("proof for other info accepted")


def test_cross_with_go_issuer():
    """poprf-cross.json — ответы эмитента сервера проекта. Python-клиент должен принять доказательство
    и получить те же выходы, что сервер считает при проверке токена."""
    root = Path(__file__).parents[2] / "veil-protocol/test-vectors"
    req = json.loads((root / "veil-v1.json").read_text())["poprf_cross_request"]
    res = json.loads((root / "poprf-cross.json").read_text())
    states = [poprf.blind(bytes.fromhex(i), int.from_bytes(bytes.fromhex(b), "little"))
              for i, b in zip(req["inputs"], req["blinds"])]
    assert [s.blinded.hex() for s in states] == req["blinded"]
    out = poprf.finalize_batch(states, [bytes.fromhex(e) for e in res["evaluated"]], bytes.fromhex(res["proof"]),
                               bytes.fromhex(res["pk"]), req["info"].encode())
    assert [o.hex() for o in out] == res["outputs"]


def test_scalar_invert_constant_time_matches_pow():
    """Обращение ослепляющего скаляра — libsodium (за постоянное время), результат как у pow(s, -1, L)."""
    import secrets
    import pytest
    from veil.core.crypto import ristretto as r255
    for _ in range(50):
        s = secrets.randbelow(r255.L - 1) + 1
        assert r255.scalar_invert(s) == pow(s, -1, r255.L)
    with pytest.raises(ValueError):
        r255.scalar_invert(0)


def test_libsodium_loaded_by_absolute_path():
    """Системная libsodium берётся по абсолютному пути из системных каталогов, а не поиском по имени."""
    from veil.core.crypto import ristretto as r255
    paths = r255._candidates()
    assert paths and (all(p.startswith("/") for p in paths) or len(paths) == 1)
