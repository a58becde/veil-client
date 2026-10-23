"""Инструмент разработчика: выдача токенов «вручную», без запущенного бота (проверка эмитента, отладка протокола).

Обычный путь — бот сам: /tokens → «Пополнить» → он присылает VEILREQ, принимает VEILRES и кладёт токены в кошелёк
(veil/core/api.py, те же проверки). Этот скрипт делает то же по шагам:

1. python -m tools.issue_manual request keys.json state.json [дней=2] [токенов=3]
   печатает сообщения VEILREQ: перешлите их эмитенту.
2. Сохраните ответы VEILRES в файл (по одному сообщению в строке) и выполните
   python -m tools.issue_manual accept keys.json state.json replies.txt tokens.json
   скрипт покажет, что принимает (запрос, дни, количество, отпечаток ключа эмитента), проверит DLEQ-доказательства
   закреплённым в keys.json ключом и сохранит токены целиком в tokens.json. Только после записи токенов состояние
   удаляется: принять тот же ответ второй раз нельзя.

state.json содержит секреты ослепления, tokens.json — готовые токены: оба создаются с правами 600 и в репозиторий
не попадают (держите их в data/, он в .gitignore).
"""
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from veil.core.crypto import poprf
from veil.core.protocol import b64, keysdoc
from veil.core.wallet import issue


def _doc(path: str) -> dict:
    return keysdoc.verify(json.load(open(path)))  # подпись server_sig проверяется всегда


def _write_private(path: str, data) -> None:
    """Атомарно, с правами 600 с самого создания. Временный файл — новый, с уникальным именем (mkstemp: O_EXCL),
    поэтому подложенная заранее символическая ссылка не перенаправит запись."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix="." + p.name + ".", suffix=".tmp")  # права 600
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def fingerprint(pk: bytes) -> str:
    return hashlib.sha256(pk).hexdigest()[:16]


def request(keys_path: str, state_path: str, days: int = 2, count: int = 3) -> None:
    doc = _doc(keys_path)
    today = datetime.now(timezone.utc).date()
    kid, _ = keysdoc.issuer_key(doc)  # долгоживущий ключ эмитента (spec/03)
    want = [((today + timedelta(days=i)).isoformat(), kid, count) for i in range(days)]
    pending, parts = issue.make_request(want)
    state = {"req_id": pending.req_id.hex(), "days": {
        d: {"kid": k, "inputs": [s.input.hex() for s in st], "blinds": [s.blind for s in st],
            "blinded": [s.blinded.hex() for s in st]} for d, (k, st) in pending.states.items()}}
    _write_private(state_path, state)
    print("\n\n".join(parts))


def accept(keys_path: str, state_path: str, replies_path: str, out_path: str) -> None:
    doc = _doc(keys_path)
    st = json.load(open(state_path))
    pending = issue.PendingRequest(bytes.fromhex(st["req_id"]), {
        d: (v["kid"], [poprf.BlindState(bytes.fromhex(i), b, bytes.fromhex(bl))
                       for i, b, bl in zip(v["inputs"], v["blinds"], v["blinded"])])
        for d, v in st["days"].items()})
    kid, pk = keysdoc.issuer_key(doc)
    asked = ", ".join(f"{d}: {len(v['inputs'])}" for d, v in sorted(st["days"].items()))
    print(f"запрос {st['req_id']}; просили {asked}; ключ эмитента {kid}, отпечаток {fingerprint(pk)}")
    lines = [ln for ln in open(replies_path, encoding="utf-8").read().splitlines() if ln.startswith("VEILRES ")]
    toks = issue.accept_response(pending, lines, {kid: pk})  # DLEQ — закреплённым ключом
    got: dict[str, int] = {}
    for t in toks:
        got[t.day] = got.get(t.day, 0) + 1
    print("выдано: " + (", ".join(f"{d}: {n}" for d, n in sorted(got.items())) or "ничего"))
    print(f"OK: {len(toks)} tokens, DLEQ proofs verified")
    _write_private(out_path, [{"scheme": "poprf-r255-v1", "kid": t.kid, "day": t.day,
                               "input": b64.enc(t.input), "output": b64.enc(t.output)} for t in toks])
    print(f"токены сохранены: {out_path} (права 600)")
    Path(state_path).unlink()  # только после записи токенов: секреты ослепления больше не нужны


if __name__ == "__main__":
    cmd, *args = sys.argv[1:] or [""]
    if cmd == "request":
        request(args[0], args[1], *(int(a) for a in args[2:]))
    elif cmd == "accept" and len(args) == 4:  # без файла токенов результат пропал бы вместе с состоянием
        accept(*args)
    else:
        sys.exit(__doc__)
