"""Проверка целостности официального движка плагинов: код ↔ релиз ↔ исходники.

    python tools/engine_check.py [--out=<файл>] [--skip-provenance]

Запуск из корня veil-client (Python 3.12, только stdlib; нужны `gh` и `git`, а в CI — история git целиком).
Что проверяется:
  1. ENGINE_SHA256, ENGINE_URL, ENGINE_MAX читаются из veil/plugin_engine.py разбором AST (модуль не импортируется);
  2. файл по ENGINE_URL скачивается (не больше ENGINE_MAX), его SHA-256 равен ENGINE_SHA256;
  3. аттестация происхождения (gh attestation verify): файл собран workflow engine-release.yml этого репозитория
     из тега, указанного в ENGINE_URL; из аттестации берётся коммит исходников;
  4. engine/guest, engine/wit, engine/build.py и engine/requirements-build.lock в HEAD совпадают с этим коммитом.
Выходы: 0 — всё сошлось; 1 — проверка не прошла (в том числе недоступна сеть или аттестация); 2 — неверный вызов,
нет gh/git или не читаются константы. `--skip-provenance` (шаги 3–4 пропускаются) нужен только на машине, где gh не
авторизован; в CI не используется.
"""

from __future__ import annotations

import ast
import hashlib
import http.client
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SOURCE = HERE / "veil" / "plugin_engine.py"
WORKFLOW = ".github/workflows/engine-release.yml"
# Всё, из чего собирается движок: изменение любого из этого без нового релиза — расхождение.
ENGINE_PATHS = ("engine/guest", "engine/wit", "engine/build.py", "engine/requirements-build.lock")
TIMEOUT = 120
# Куда GitHub перенаправляет скачивание ассета релиза (github.com → release-assets.githubusercontent.com).
REDIRECT_HOSTS = frozenset({"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"})
URL_RE = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/download/(engine-[1-9][0-9]*)/veil-engine\.wasm")
SHA_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")


class FailError(Exception):
    """Проверка не прошла (выход 1)."""


class UsageError(Exception):
    """Неверный вызов или окружение (выход 2)."""


def read_constants(path: Path) -> tuple[str, str, int]:
    """ENGINE_SHA256, ENGINE_URL, ENGINE_MAX из исходника: ровно по одному присваиванию, без исполнения кода."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError) as e:
        raise UsageError(f"не читается {path}: {e}") from e
    found: dict[str, list[ast.expr]] = {"ENGINE_SHA256": [], "ENGINE_URL": [], "ENGINE_MAX": []}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        for t in targets:
            if isinstance(t, ast.Name) and t.id in found:
                found[t.id].append(value)
    for name, values in found.items():
        if len(values) != 1:
            raise UsageError(f"{name}: в {path.name} должно быть ровно одно присваивание, найдено {len(values)}")
    sha, url = (_const_str(n, found[n][0]) for n in ("ENGINE_SHA256", "ENGINE_URL"))
    if not SHA_RE.fullmatch(sha):
        raise UsageError("ENGINE_SHA256: нужны 64 шестнадцатеричные цифры в нижнем регистре")
    m = URL_RE.fullmatch(url)
    if m is None or any(set(part) == {"."} for part in m.group(1, 2)):
        raise UsageError("ENGINE_URL: нужен https://github.com/<владелец>/<репозиторий>/releases/download/engine-N/veil-engine.wasm")
    return sha, url, _const_size(found["ENGINE_MAX"][0])


def _const_str(name: str, node: ast.expr) -> str:
    if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        raise UsageError(f"{name}: нужна строковая константа")
    return node.value


def _const_int(node: ast.expr) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _const_size(node: ast.expr) -> int:
    """Целое или `<целое> << <целое>`."""
    value = _const_int(node)
    if value is None and isinstance(node, ast.BinOp) and isinstance(node.op, ast.LShift):
        left, right = _const_int(node.left), _const_int(node.right)
        if left is not None and right is not None and 0 <= right <= 40:
            value = left << right
    if value is None or value <= 0:
        raise UsageError("ENGINE_MAX: нужно положительное целое или `<целое> << <целое>`")
    return value


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Редирект — только на https и только на хосты GitHub, с которых отдаются файлы релизов."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D102  # сигнатура базового класса
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https" or parts.hostname not in REDIRECT_HOSTS:
            raise FailError(f"редирект на недопустимый адрес отклонён: {parts.scheme}://{parts.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, limit: int) -> bytes:
    """Скачать url (HTTPS, редиректы — по SafeRedirect), прочитав не больше limit байт; больше — FailError."""
    urllib.request.install_opener(urllib.request.build_opener(SafeRedirect))
    req = urllib.request.Request(url, headers={"User-Agent": "veil-engine-check"})  # noqa: S310  # схема https проверена по URL_RE
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310  # то же
            data = r.read(limit + 1)
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
        raise FailError(f"не удалось скачать {url}: {e}") from e
    if len(data) > limit:
        raise FailError(f"файл по {url} больше ENGINE_MAX ({limit} байт)")
    return data


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Запуск внешней программы с фиксированными аргументами, без оболочки."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=300)  # noqa: S603  # аргументы фиксированы
    except (OSError, subprocess.TimeoutExpired) as e:
        raise FailError(f"{cmd[0]}: {e}") from e


def provenance(path: Path, owner: str, repo: str, tag: str) -> str:
    """Проверить аттестацию файла; вернуть коммит исходников, из которого собран релиз."""
    res = run(["gh", "attestation", "verify", str(path), "--repo", f"{owner}/{repo}",
               "--signer-workflow", f"{owner}/{repo}/{WORKFLOW}", "--format", "json"])
    if res.returncode != 0:
        tail = res.stderr.strip()[-500:]
        raise FailError(f"аттестация происхождения не подтверждена (gh, код {res.returncode}): {tail}")
    try:
        results = json.loads(res.stdout)
    except ValueError as e:
        raise FailError(f"ответ gh не разобран как JSON: {e}") from e
    if not isinstance(results, list) or not results:
        raise FailError("аттестаций нет")
    commits: set[str] = set()
    for item in results:
        pred = _dig(item, "verificationResult", "statement", "predicate", "buildDefinition")
        ref = _dig(pred, "externalParameters", "workflow", "ref")
        if ref != f"refs/tags/{tag}":
            raise FailError(f"аттестация выдана для {ref!r}, ожидался refs/tags/{tag}")
        deps = _dig(pred, "resolvedDependencies")
        if not isinstance(deps, list):
            raise FailError("в аттестации нет resolvedDependencies")
        for dep in deps:
            commit = _dig(dep, "digest", "gitCommit")
            if commit is not None:
                if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
                    raise FailError("в аттестации коммит исходников записан неверно")
                commits.add(commit)
    if len(commits) != 1:
        raise FailError(f"в аттестации должен быть ровно один коммит исходников, найдено {len(commits)}")
    return commits.pop()


def _dig(obj: object, *keys: str) -> object:
    for k in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(k)
    return obj


def sources_match(commit: str, tag: str) -> None:
    """Исходники движка в HEAD равны исходникам коммита релиза."""
    if run(["git", "cat-file", "-e", f"{commit}^{{commit}}"]).returncode != 0:
        raise FailError(f"коммита {commit} нет в истории git (в CI нужен fetch-depth: 0)")
    res = run(["git", "diff", "--quiet", commit, "HEAD", "--", *ENGINE_PATHS])
    if res.returncode == 1:
        raise FailError(f"движок изменён после {tag}: нужен новый релиз engine-N и новый ENGINE_SHA256")
    if res.returncode != 0:
        raise FailError(f"git diff не выполнился (код {res.returncode}): {res.stderr.strip()[-500:]}")


def check(out: Path | None, skip_provenance: bool) -> str:
    sha, url, limit = read_constants(SOURCE)
    m = URL_RE.fullmatch(url)
    assert m is not None  # URL_RE проверена в read_constants
    owner, repo, tag = m.groups()
    if shutil.which("git") is None or (not skip_provenance and shutil.which("gh") is None):
        raise UsageError("нужны git и gh (https://cli.github.com)")
    data = fetch(url, limit)
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        raise FailError(f"SHA-256 релиза {tag} не совпал: в релизе {got}, в коде ENGINE_SHA256 {sha}")
    with tempfile.TemporaryDirectory() as tmp:
        path = out if out is not None else Path(tmp) / "veil-engine.wasm"
        try:
            path.write_bytes(data)
        except OSError as e:
            raise FailError(f"не удалось записать {path}: {e}") from e
        if skip_provenance:
            return f"engine ok {tag} {sha} (происхождение не проверялось)"
        commit = provenance(path, owner, repo, tag)
    sources_match(commit, tag)
    return f"engine ok {tag} {sha} {commit}"


def main(argv: list[str]) -> int:
    out: Path | None = None
    skip = False
    for a in argv:
        if a == "--skip-provenance":
            skip = True
        elif a.startswith("--out=") and len(a) > len("--out="):
            out = Path(a.split("=", 1)[1])
        else:
            print(f"неизвестный аргумент: {a}", file=sys.stderr)
            print("использование: python tools/engine_check.py [--out=<файл>] [--skip-provenance]", file=sys.stderr)
            return 2
    try:
        print(check(out, skip))
    except UsageError as e:
        print(f"engine_check: {e}", file=sys.stderr)
        return 2
    except FailError as e:
        print(f"engine_check: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
