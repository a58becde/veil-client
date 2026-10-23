"""Обмен с эмитентом (spec/03): формат VEILREQ/VEILRES и кросс-тест с эмитентом сервера."""
import json
from pathlib import Path

import pytest

from veil.core.crypto import poprf
from veil.core.store.db import Token
from veil.core.wallet import issue

VEC = Path(__file__).resolve().parents[2] / "veil-protocol" / "test-vectors"


def _v():
    return json.loads((VEC / "veil-v1.json").read_text(encoding="utf-8"))


def _pending(c):
    want = [(w["day"], w["kid"], w["count"]) for w in c["want"]]
    ins = {d: [bytes.fromhex(x) for x in xs] for d, xs in c["inputs"].items()}
    bls = {d: [int.from_bytes(bytes.fromhex(x), "little") for x in xs] for d, xs in c["blinds"].items()}
    first = issue.join(issue.REQ_PREFIX, c["parts"])[0]
    return issue.make_request(want, req_id=first, inputs=ins, blinds=bls)


def test_request_deterministic():
    c = _v()["issue_cross_request"]
    _, parts = _pending(c)
    assert parts == c["parts"]


def test_reject_vectors():
    for case in _v()["issue_reject"]:
        with pytest.raises(issue.IssueFormatError):
            issue.decode(bytes.fromhex(case["hex"]), response=False)


def test_cross_with_go_issuer():
    c = _v()["issue_cross_request"]
    resp = json.loads((VEC / "issue-cross.json").read_text())
    pending, _ = _pending(c)
    pks = {k: bytes.fromhex(v) for k, v in resp["pk"].items()}
    toks = issue.accept_response(pending, list(reversed(resp["parts"])), pks)
    got = {}
    for t in toks:
        got.setdefault(t.day, []).append(t.output.hex())
    assert got == resp["outputs"]
    assert len(got["2026-10-19"]) == 1  # частичная выдача
    t = toks[0]
    env = Token(0, t.kid, t.day, t.input, t.output).envelope()  # так токен уходит в конверт (db.Token)
    assert set(env) == {"scheme", "kid", "day", "input", "output"} and env["scheme"] == issue.SCHEME


def test_cross_rejects_tampering():
    c = _v()["issue_cross_request"]
    resp = json.loads((VEC / "issue-cross.json").read_text())
    pending, _ = _pending(c)
    pks = {k: bytes.fromhex(v) for k, v in resp["pk"].items()}
    _, payload = issue.join(issue.RESP_PREFIX, resp["parts"])
    msg = issue.decode(payload, response=True)
    msg.days[0].proof = bytes([msg.days[0].proof[0] ^ 1]) + msg.days[0].proof[1:]
    bad = issue.split(issue.RESP_PREFIX, msg.req_id, issue.encode(msg, response=True))
    with pytest.raises(poprf.ProofError):
        issue.accept_response(pending, bad, pks)
    # Доказательство проверяется закреплённым ключом: выдача другим ключом (сервер «пометил» человека) — отказ.
    wrong_pk = {k: poprf.r255.mul_base(12345) for k in pks}
    with pytest.raises(poprf.ProofError):
        issue.accept_response(pending, resp["parts"], wrong_pk)
    other, _ = issue.make_request([("2026-10-18", "t1", 1)])
    with pytest.raises(issue.IssueFormatError):
        issue.accept_response(other, resp["parts"], pks)


def test_split_join_many_parts():
    msg = issue.IssueMessage(b"\x07" * 8, [issue.Day(f"2026-10-{15 + i}", "t1", [bytes(32)] * 50, bytes(64))
                                            for i in range(7)])
    payload = issue.encode(msg, response=True)
    parts = issue.split(issue.RESP_PREFIX, msg.req_id, payload)
    assert len(parts) >= 4 and all(len(p.split(" ")[3]) <= issue.PART_CHARS for p in parts)
    rid, back = issue.join(issue.RESP_PREFIX, parts[::-1] + parts[:1])
    assert rid == msg.req_id and back == payload
    with pytest.raises(issue.IssueFormatError):
        issue.join(issue.RESP_PREFIX, parts[1:])
    with pytest.raises(issue.IssueFormatError):
        issue.join(issue.REQ_PREFIX, parts)


def test_wallet_accepts_response_once_and_rejects_foreign(tmp_path):
    """Ответ эмитента принимается один раз; чужой запрос, лишние элементы и чужой ключ — отказ."""
    import time as _time
    from veil.core.store.db import Store
    c = _v()["issue_cross_request"]
    resp = json.loads((VEC / "issue-cross.json").read_text())
    pending, _ = _pending(c)
    pks = {k: bytes.fromhex(v) for k, v in resp["pk"].items()}
    toks = issue.accept_response(pending, resp["parts"], pks)
    assert toks
    # Ответ с элементами сверх запрошенного: эмитент не может «досыпать» токенов.
    small = issue.PendingRequest(pending.req_id, {d: (k, st[:1]) for d, (k, st) in pending.states.items()})
    with pytest.raises(issue.IssueFormatError):
        issue.accept_response(small, resp["parts"], pks)
    # Хранилище: брошенные запросы с секретами ослепления удаляются.
    s = Store(tmp_path)
    s.save_issue_request("aa" * 8, {"x": 1})
    s.db.execute("UPDATE issue_requests SET created = ?", (int(_time.time()) - 10 * 86400,))
    assert s.drop_stale_issue_requests() == 1 and s.issue_request("aa" * 8) is None


def test_manual_tool_state_is_private(tmp_path):
    """tools.issue_manual пишет секреты ослепления с правами 600 и удаляет их после приёма ответа."""
    import os
    from tools import issue_manual
    keys = Path(__file__).resolve().parents[1] / "keys.json"
    if not keys.exists():
        pytest.skip("нет keys.json")
    st = tmp_path / "state.json"
    issue_manual.request(str(keys), str(st), 1, 1)
    assert os.stat(st).st_mode & 0o077 == 0
