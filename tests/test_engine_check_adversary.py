"""Проверка происхождения движка: тесты-противник по контракту, без обращения к сети и к настоящему gh.

Сеть подменена заглушкой urlopen (а сокеты запрещены), gh — скрипт в PATH, git — настоящий, во временном репозитории.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import shutil
import socket
import stat
import subprocess
import urllib.error
from pathlib import Path

import pytest

from tools import engine_check as ec  # noqa: E402

OWNER, REPO, TAG = "acme", "widgets", "engine-3"
URL = f"https://github.com/{OWNER}/{REPO}/releases/download/{TAG}/veil-engine.wasm"
BODY = b"\x00asm-fake-engine-bytes" * 10
SHA = hashlib.sha256(BODY).hexdigest()
REAL_GIT = shutil.which("git")


def consts(sha: str = SHA, url: str = URL, mx: str = "64 << 20") -> str:
    return f'ENGINE_SHA256 = "{sha}"\nENGINE_URL = "{url}"\nENGINE_MAX = {mx}\n'


class FakeResp:
    def __init__(
        self, data: bytes, length: str | None = "auto", endless: bool = False, fail_after: Exception | None = None
    ):
        self.data, self.pos, self.endless, self.fail_after = data, 0, endless, fail_after
        self.served = 0
        n = str(len(data)) if length == "auto" else length
        self.headers = {} if n is None else {"Content-Length": n}
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def close(self):
        pass

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def geturl(self):
        return URL

    def read(self, n=-1):
        if self.endless:
            assert n is not None and n >= 0, "чтение без предела из бесконечного потока"
            self.served += n
            assert self.served < 300 * 1024 * 1024, "прочитано слишком много"
            return b"\x01" * n
        if self.fail_after is not None:
            if self.pos > 0:
                raise self.fail_after
            n = min(n if n is not None and n >= 0 else len(self.data), len(self.data) // 2)
        if n is None or n < 0:
            n = len(self.data)
        chunk = self.data[self.pos : self.pos + n]
        self.pos += len(chunk)
        return chunk

    def readinto(self, b):  # pragma: no cover - на случай буферного чтения
        chunk = self.read(len(b))
        b[: len(chunk)] = chunk
        return len(chunk)


class Env:
    def __init__(self, tmp: Path, monkeypatch, capsys):
        self.tmp, self.mp, self.capsys = tmp, monkeypatch, capsys
        self.tree = tmp / "tree"
        self.bin = tmp / "bin"
        self.tmpd = tmp / "tmpd"
        self.log = tmp / "log"
        for d in (self.tree, self.bin, self.tmpd, self.log):
            d.mkdir()
        self.calls: list = []
        self.response: object = FakeResp(BODY)
        self.mp.setattr(ec, "HERE", self.tree)
        self.mp.setattr(ec, "SOURCE", self.tree / "veil" / "plugin_engine.py")
        self.mp.chdir(self.tree)
        self.mp.setattr(__import__("tempfile"), "tempdir", str(self.tmpd))
        self.mp.setattr(urllib_request(), "urlopen", self._urlopen)
        self.mp.setattr(socket, "getaddrinfo", self._nonet)
        self.mp.setenv("PATH", f"{self.bin}{os.pathsep}/usr/bin{os.pathsep}/bin")
        self.write_consts(consts())
        self.git_wrapper()
        self.gh_script(rc=0, stdout="[]")

    # --- сеть
    def _nonet(self, *a, **k):
        raise AssertionError("обращение к настоящей сети")

    def _urlopen(self, req, *a, **k):
        url = getattr(req, "full_url", req)
        self.calls.append((url, k.get("timeout", a[1] if len(a) > 1 else None)))
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response

    # --- дерево
    def write_consts(self, text: str):
        p = self.tree / "veil" / "plugin_engine.py"
        p.parent.mkdir(exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def git(self, *args: str) -> str:
        r = subprocess.run(
            [
                REAL_GIT,
                "-C",
                str(self.tree),
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            capture_output=True,
            text=True,
            check=True,
        )  # noqa: E501
        return r.stdout.strip()

    def init_repo(self) -> str:
        self.git("init", "-q")
        for rel in (
            "engine/guest/a.py",
            "engine/wit/w.wit",
            "engine/build.py",
            "engine/requirements-build.lock",
            "engine/other.txt",
            "veil/x.py",
        ):
            f = self.tree / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("v1\n")
        return self.commit("one")

    def commit(self, msg: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def git_wrapper(self):
        w = self.bin / "git"
        w.write_text(
            f'#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a" >> "{self.log}/git.args"; done\nexec {REAL_GIT} "$@"\n'
        )
        w.chmod(w.stat().st_mode | stat.S_IXUSR)

    def gh_script(self, rc: int, stdout: str, stderr: str = ""):
        (self.tmp / "gh.out").write_text(stdout)
        (self.tmp / "gh.err").write_text(stderr)
        w = self.bin / "gh"
        w.write_text(
            "#!/bin/sh\n"
            f'for a in "$@"; do printf "%s\\n" "$a" >> "{self.log}/gh.args"; done\n'
            f'cp "$3" "{self.log}/gh.seen" 2>/dev/null\n'
            f'cat "{self.tmp}/gh.err" >&2\ncat "{self.tmp}/gh.out"\nexit {rc}\n'
        )
        w.chmod(w.stat().st_mode | stat.S_IXUSR)

    def remove_gh(self):
        (self.bin / "gh").unlink()

    def attest(self, entries: list[dict] | str, rc: int = 0):
        self.gh_script(rc, entries if isinstance(entries, str) else json.dumps(entries))

    def run(self, *args: str) -> tuple[int, str]:
        code = ec.main(list(args))
        c = self.capsys.readouterr()
        self.out, self.err = c.out, c.err
        return code, c.out + c.err

    def gh_args(self) -> list[str]:
        p = self.log / "gh.args"
        return p.read_text().split("\n")[:-1] if p.exists() else []

    def git_args(self) -> list[str]:
        p = self.log / "git.args"
        return p.read_text().split("\n")[:-1] if p.exists() else []

    def tmp_left(self) -> list[str]:
        return os.listdir(self.tmpd)


def urllib_request():
    import urllib.request

    return urllib.request


def entry(commit: str, ref: str = f"refs/tags/{TAG}", extra_deps: list[dict] | None = None) -> dict:
    deps = [{"uri": f"git+https://github.com/{OWNER}/{REPO}@{ref}", "digest": {"gitCommit": commit}}]
    deps += extra_deps or []
    return {
        "verificationResult": {
            "statement": {
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "externalParameters": {
                            "workflow": {
                                "ref": ref,
                                "repository": f"https://github.com/{OWNER}/{REPO}",
                                "path": ".github/workflows/engine-release.yml",
                            }
                        },
                        "resolvedDependencies": deps,
                    }
                },
            }
        }
    }


@pytest.fixture
def env(tmp_path, monkeypatch, capsys):
    return Env(tmp_path, monkeypatch, capsys)


@pytest.fixture
def full(env):
    """Полный успешный сценарий: репозиторий, аттестация на HEAD."""
    commit = env.init_repo()
    env.attest([entry(commit)])
    env.commit_sha = commit
    return env


# ---------------------------------------------------------------- успех и формат строки


def test_success_line_and_exit_zero(full):
    code, out = full.run()
    assert code == 0, out
    assert f"engine ok {TAG} {SHA} {full.commit_sha}" in out
    assert full.calls and full.calls[0][0] == URL


def test_timeout_for_download_is_set_and_bounded(full):
    full.run()
    timeout = full.calls[0][1]
    assert timeout is not None and 0 < timeout <= 120


def test_gh_receives_downloaded_bytes_and_fixed_args(full):
    code, _ = full.run()
    assert code == 0
    assert (full.log / "gh.seen").read_bytes() == BODY
    a = full.gh_args()
    assert a[:2] == ["attestation", "verify"]
    assert a[a.index("--repo") + 1] == f"{OWNER}/{REPO}"
    assert a[a.index("--signer-workflow") + 1] == f"{OWNER}/{REPO}/.github/workflows/engine-release.yml"
    assert a[a.index("--format") + 1] == "json"
    # ничего лишнего: файл + три флага со значениями
    assert len(a) == 2 + 1 + 6


def test_out_writes_file_and_keeps_it(full, tmp_path):
    dst = tmp_path / "keep.wasm"
    code, _ = full.run(f"--out={dst}")
    assert code == 0
    assert dst.read_bytes() == BODY
    assert full.tmp_left() == []


def test_temp_file_removed_on_success(full):
    assert full.run()[0] == 0
    assert full.tmp_left() == []


# ---------------------------------------------------------------- целостность


def test_wrong_hash_exit1_both_hashes_in_message(env):
    other = "ab" * 32
    env.write_consts(consts(sha=other))
    code, out = env.run("--skip-provenance")
    assert code == 1
    assert other in out and SHA in out
    assert env.tmp_left() == []


def test_hash_mismatch_never_reaches_gh(env):
    env.write_consts(consts(sha="cd" * 32))
    assert env.run()[0] == 1
    assert env.gh_args() == []


def test_exactly_max_bytes_ok(env):
    data = b"a" * 1000
    env.write_consts(consts(sha=hashlib.sha256(data).hexdigest(), mx="1000"))
    env.response = FakeResp(data)
    code, out = env.run("--skip-provenance")
    assert code == 0, out


def test_max_plus_one_exit1_even_with_right_hash(env):
    data = b"a" * 1001
    env.write_consts(consts(sha=hashlib.sha256(data).hexdigest(), mx="1000"))
    env.response = FakeResp(data)
    code, out = env.run("--skip-provenance")
    assert code == 1, out
    assert env.tmp_left() == []


def test_max_as_shift_expression_is_honoured(env):
    data = b"a" * 1025
    env.write_consts(consts(sha=hashlib.sha256(data).hexdigest(), mx="1 << 10"))
    env.response = FakeResp(data)
    assert env.run("--skip-provenance")[0] == 1
    env.response = FakeResp(data[:1024])
    env.write_consts(consts(sha=hashlib.sha256(data[:1024]).hexdigest(), mx="1 << 10"))
    assert env.run("--skip-provenance")[0] == 0


def test_server_lies_content_length_small_but_body_over_max(env):
    data = b"a" * 5000
    env.write_consts(consts(sha=hashlib.sha256(data).hexdigest(), mx="1000"))
    env.response = FakeResp(data, length="10")
    code, _ = env.run("--skip-provenance")
    assert code == 1


def test_content_length_over_max_but_body_small_and_right_is_still_judged_by_body(env):
    # заголовок врёт в большую сторону, тело и хеш верны: решает тело
    data = b"a" * 500
    env.write_consts(consts(sha=hashlib.sha256(data).hexdigest(), mx="1000"))
    env.response = FakeResp(data, length="999999")
    assert env.run("--skip-provenance")[0] in (0, 1)  # допустимы оба; главное — без падения


def test_endless_stream_stops_at_limit(env):
    env.write_consts(consts(mx="1000"))
    env.response = FakeResp(b"", endless=True)
    code, _ = env.run("--skip-provenance")
    assert code == 1
    assert env.response.served <= 1000 + 1


def test_no_content_length_header_still_limited(env):
    data = b"a" * 3000
    env.write_consts(consts(sha=hashlib.sha256(data).hexdigest(), mx="1000"))
    env.response = FakeResp(data, length=None)
    assert env.run("--skip-provenance")[0] == 1


def test_empty_body_is_hash_mismatch(env):
    env.response = FakeResp(b"")
    code, out = env.run("--skip-provenance")
    assert code == 1
    assert hashlib.sha256(b"").hexdigest() in out


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError("no route"),
        urllib.error.HTTPError(URL, 404, "Not Found", {}, None),
        urllib.error.HTTPError(URL, 500, "boom", {}, None),
        TimeoutError("timed out"),
        socket.timeout("timed out"),
        ConnectionResetError("reset"),
        OSError("network unreachable"),
        http.client.RemoteDisconnected("gone"),
    ],
    ids=lambda e: type(e).__name__ + str(getattr(e, "code", "")),
)
def test_network_failures_exit1_never_zero(env, exc):
    env.response = exc
    code, out = env.run()
    assert code == 1, out
    assert env.gh_args() == []
    assert env.tmp_left() == []


@pytest.mark.parametrize("exc", [http.client.IncompleteRead(b"abc", 10)])
def test_http_client_errors_reported_as_message_not_traceback(env, exc):
    env.response = exc
    code, out = env.run()
    assert code == 1, out


def test_network_failure_with_skip_provenance_is_still_failure(env):
    env.response = urllib.error.URLError("down")
    assert env.run("--skip-provenance")[0] == 1


def test_truncated_midstream_is_failure(env):
    env.response = FakeResp(BODY, fail_after=http.client.IncompleteRead(b"x", 5))
    assert env.run("--skip-provenance")[0] == 1
    assert env.tmp_left() == []


def test_truncated_midstream_oserror_is_failure(env):
    env.response = FakeResp(BODY, fail_after=ConnectionResetError("reset"))
    assert env.run("--skip-provenance")[0] == 1


# ---------------------------------------------------------------- разбор констант как внешнего ввода

GOOD_SHA = SHA
FURL = URL.replace("engine-3", "engine-{x}")
BAD_CONSTS = {
    "два присваивания sha": consts() + f'ENGINE_SHA256 = "{"1" * 64}"\n',
    "два присваивания url": consts() + f'ENGINE_URL = "{URL}"\n',
    "нет sha": f'ENGINE_URL = "{URL}"\nENGINE_MAX = 64 << 20\n',
    "нет url": f'ENGINE_SHA256 = "{SHA}"\nENGINE_MAX = 64 << 20\n',
    "нет max": f'ENGINE_SHA256 = "{SHA}"\nENGINE_URL = "{URL}"\n',
    "sha не строка": f'ENGINE_SHA256 = 5\nENGINE_URL = "{URL}"\nENGINE_MAX = 64 << 20\n',
    "sha bytes": f'ENGINE_SHA256 = b"{SHA}"\nENGINE_URL = "{URL}"\nENGINE_MAX = 64 << 20\n',
    "url не строка": f'ENGINE_SHA256 = "{SHA}"\nENGINE_URL = None\nENGINE_MAX = 64 << 20\n',
    "sha f-строка": f'x = "a"\nENGINE_SHA256 = f"{SHA[:63]}{{x}}"\nENGINE_URL = "{URL}"\nENGINE_MAX = 64 << 20\n',
    "url f-строка": f'x = "3"\nENGINE_SHA256 = "{SHA}"\nENGINE_URL = f"{FURL}"\nENGINE_MAX = 64 << 20\n',
    "sha склейка": f'ENGINE_SHA256 = "{SHA[:32]}" + "{SHA[32:]}"\nENGINE_URL = "{URL}"\nENGINE_MAX = 64 << 20\n',
    "sha верхний регистр": consts(sha=SHA.upper()),
    "sha 63": consts(sha=SHA[:63]),
    "sha 65": consts(sha=SHA + "0"),
    "sha пустой": consts(sha=""),
    "sha не hex": consts(sha="g" * 64),
    "sha с пробелом": consts(sha=" " + SHA[:63]),
    "sha с переводом строки": consts(sha=SHA + "\\n"),
    "url http": consts(url=URL.replace("https", "http")),
    "url чужой хост": consts(url=URL.replace("github.com", "gitlab.com")),
    "url хост-суффикс": consts(url=URL.replace("https://github.com/", "https://github.com.evil.example/")),
    "url userinfo": consts(url=URL.replace("https://github.com/", "https://github.com@evil.example/")),
    "url порт": consts(url=URL.replace("github.com/", "github.com:8443/")),
    "url лишний сегмент": consts(url=URL.replace("/releases/", "/x/releases/")),
    "url лишний сегмент в конце": consts(url=URL + "/more"),
    "url запрос": consts(url=URL + "?token=1"),
    "url фрагмент": consts(url=URL + "#x"),
    "url engine-0": consts(url=URL.replace("engine-3", "engine-0")),
    "url engine-01": consts(url=URL.replace("engine-3", "engine-01")),
    "url engine-x": consts(url=URL.replace("engine-3", "engine-x")),
    "url engine- без номера": consts(url=URL.replace("engine-3", "engine-")),
    "url другой префикс тега": consts(url=URL.replace("engine-3", "v3")),
    "url latest": consts(url=f"https://github.com/{OWNER}/{REPO}/releases/latest/download/veil-engine.wasm"),
    "url другое имя файла": consts(url=URL.replace("veil-engine.wasm", "veil-engine.wasm.exe")),
    "url другое имя файла 2": consts(url=URL.replace("veil-engine.wasm", "other.wasm")),
    "url без owner": consts(url="https://github.com/releases/download/engine-3/veil-engine.wasm"),
    "url пробел": consts(url=URL + " "),
    "url перевод строки": consts(url=URL + "\\n"),
    "max строкой": consts(mx='"64"'),
    "max умножением": consts(mx="64 * 1024 * 1024"),
    "max степенью": consts(mx="2 ** 26"),
    "max тройной сдвиг": consts(mx="1 << 2 << 3"),
    "max вызов": consts(mx="int('5')"),
    "max имя": consts(mx="SOMETHING"),
    "max float": consts(mx="1.5"),
    "max отрицательный": consts(mx="-1"),
    "max сдвиг отрицательный": consts(mx="1 << -1"),
    "max сдвиг огромный": consts(mx="1 << 100000000"),
    "синтаксическая ошибка": "ENGINE_SHA256 = (\n",
}


BAD_CONSTS["sha аннотированный + обычное"] = (
    f'ENGINE_SHA256: str = "{SHA}"\nENGINE_SHA256 = "{SHA}"\nENGINE_URL = "{URL}"\nENGINE_MAX = 64 << 20\n'
)
BAD_CONSTS["url обычное + аннотированное"] = (
    f'ENGINE_SHA256 = "{SHA}"\nENGINE_URL = "{URL}"\nENGINE_URL: str = "{URL}"\nENGINE_MAX = 64 << 20\n'
)
BAD_CONSTS["max обычное + аннотированное"] = (
    f'ENGINE_SHA256 = "{SHA}"\nENGINE_URL = "{URL}"\nENGINE_MAX = 1\nENGINE_MAX: int = 64 << 20\n'
)


@pytest.mark.parametrize("name", sorted(BAD_CONSTS))
def test_bad_constants_exit2_no_network(env, name):
    env.write_consts(BAD_CONSTS[name])
    code, out = env.run()
    assert code == 2, f"{name}: код {code}: {out}"
    assert env.calls == [], "скачивание не должно начинаться при неверных константах"
    assert out.strip() != ""
    assert env.tmp_left() == []


def test_single_annotated_assignment_is_accepted(tmp_path):
    """Аннотация не делает второго присваивания: `ENGINE_SHA256: str = "…"` — единственное, допустимо."""
    path = tmp_path / "plugin_engine.py"
    path.write_text(
        f'ENGINE_SHA256: str = "{SHA}"\nENGINE_URL: str = "{URL}"\nENGINE_MAX: int = 64 << 20\n', encoding="utf-8"
    )
    assert ec.read_constants(path) == (SHA, URL, 64 << 20)


def test_missing_source_file_exit2_or_1_not_crash(env):
    (env.tree / "veil" / "plugin_engine.py").unlink()
    code, _ = env.run()
    assert code in (1, 2)
    assert env.calls == []


def test_constants_module_is_not_imported(env, tmp_path):
    marker = tmp_path / "executed"
    env.write_consts(f"open({str(marker)!r}, 'w').write('x')\n" + consts())
    env.response = FakeResp(BODY)
    env.run("--skip-provenance")
    assert not marker.exists(), "модуль с константами выполнен — разбор должен идти без импорта"


def test_constants_module_with_side_effect_in_bad_file_not_imported(env, tmp_path):
    marker = tmp_path / "executed2"
    env.write_consts(f"import os\nos.system('touch {marker}')\n" + BAD_CONSTS["sha 63"])
    env.run()
    assert not marker.exists()


def test_other_assignments_and_annotations_are_ignored(env):
    env.write_consts("ENGINE_SHA256_OLD = 'x'\nOTHER: int = 3\n" + consts() + "\ndef f():\n    ENGINE_URL = 'local'\n")
    code, out = env.run("--skip-provenance")
    # присваивание в теле функции — не константа модуля; допустимо и 0, и 2, но не принять чужое значение
    assert code in (0, 2), out
    if code == 0:
        assert env.calls[0][0] == URL


def test_long_but_valid_owner_repo_chars(env):
    url = "https://github.com/a-b_c.d/re-po_1.x/releases/download/engine-12/veil-engine.wasm"
    env.write_consts(consts(url=url))
    code, out = env.run("--skip-provenance")
    assert code == 0, out
    assert "engine-12" in out
    assert env.calls[0][0] == url


@pytest.mark.parametrize("owner", [".", ".."])
def test_dot_owner_or_repo_rejected(env, owner):
    url = f"https://github.com/{owner}/{owner}/releases/download/engine-3/veil-engine.wasm"
    env.write_consts(consts(url=url))
    code, _ = env.run("--skip-provenance")
    assert code == 2


# ---------------------------------------------------------------- аттестация


def test_gh_missing_exit2(full):
    full.remove_gh()
    # без gh в PATH нет и системного: оставляем только git-обёртку
    full.mp.setenv("PATH", f"{full.bin}")
    code, out = full.run()
    assert code == 2, out
    assert "gh" in out
    assert full.tmp_left() == []


def test_gh_missing_with_skip_provenance_is_fine(full):
    full.remove_gh()
    full.mp.setenv("PATH", f"{full.bin}")
    assert full.run("--skip-provenance")[0] == 0


@pytest.mark.parametrize("rc", [1, 2, 4, 127])
def test_gh_nonzero_exit1_even_with_valid_json(full, rc):
    full.attest([entry(full.commit_sha)], rc=rc)
    code, _ = full.run()
    assert code == 1
    assert full.tmp_left() == []


@pytest.mark.parametrize(
    "text",
    ["", "not json", "{", "null", "[]", "{}", "[{}]", "[1,2]", '"str"', "[[]]", '[{"verificationResult": null}]',
     '[{"verificationResult": {"statement": {"predicate": []}}}]'],
)  # fmt: skip
def test_bad_attestation_json_exit1(full, text):
    full.attest(text)
    code, out = full.run()
    assert code == 1, out
    assert out.strip() != ""


def test_attestation_zero_commits_exit1(full):
    e = entry(full.commit_sha)
    e["verificationResult"]["statement"]["predicate"]["buildDefinition"]["resolvedDependencies"] = []
    full.attest([e])
    assert full.run()[0] == 1


def test_attestation_dependency_without_commit_exit1(full):
    e = entry(full.commit_sha)
    e["verificationResult"]["statement"]["predicate"]["buildDefinition"]["resolvedDependencies"] = [
        {"uri": "x", "digest": {}}
    ]
    full.attest([e])
    assert full.run()[0] == 1


def test_two_different_commits_in_one_attestation_exit1(full):
    other = "1" * 40
    full.attest([entry(full.commit_sha, extra_deps=[{"uri": "y", "digest": {"gitCommit": other}}])])
    assert full.run()[0] == 1


def test_two_attestations_same_commit_and_tag_is_ok(full):
    full.attest([entry(full.commit_sha), entry(full.commit_sha)])
    code, out = full.run()
    assert code == 0, out
    assert full.commit_sha in out


def test_two_attestations_different_commits_exit1(full):
    full.attest([entry(full.commit_sha), entry("2" * 40)])
    assert full.run()[0] == 1


def test_attestations_same_commit_but_different_tag_exit1(full):
    full.attest([entry(full.commit_sha), entry(full.commit_sha, ref="refs/tags/engine-4")])
    assert full.run()[0] == 1


@pytest.mark.parametrize(
    "ref",
    [
        "refs/tags/engine-4",
        "refs/tags/engine-30",
        "refs/tags/engine-",
        "refs/tags/engine-3/x",
        "refs/tags/engine-3 ",
        "refs/tags/Engine-3",
        "refs/heads/engine-3",
        "refs/heads/main",
        "refs/pull/1/merge",
        "engine-3",
        "tags/engine-3",
        "refs/tags/",
        "",
        "refs/tags/v1",
    ],
)
def test_wrong_ref_exit1(full, ref):
    full.attest([entry(full.commit_sha, ref=ref)])
    code, out = full.run()
    assert code == 1, f"{ref!r}: {out}"


def test_missing_ref_exit1(full):
    e = entry(full.commit_sha)
    del e["verificationResult"]["statement"]["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["ref"]
    full.attest([e])
    assert full.run()[0] == 1


@pytest.mark.parametrize(
    "commit", ["", "abc", "A" * 40, "g" * 40, "0" * 39, "0" * 41, "HEAD", "--output=/tmp/x", "-p", "HEAD~1"]
)
def test_malformed_commit_exit1_and_not_passed_to_git(full, commit):
    full.attest([entry(commit)])
    code, _ = full.run()
    assert code == 1
    args = full.git_args()
    assert commit not in [a for a in args if commit], "значение из JSON не должно попадать в командную строку git"
    assert not any(a.startswith("--output") for a in args)


def test_commit_is_not_number_exit1(full):
    full.attest([entry(123)])
    assert full.run()[0] == 1


def test_no_value_from_json_reaches_gh_command_line(full):
    full.attest([entry("--evil", ref="--evil-ref")])
    full.run()
    assert not any("evil" in a for a in full.gh_args())


# ---------------------------------------------------------------- исходники


def test_sources_match_exact_git_call_shape(full):
    assert full.run()[0] == 0
    a = full.git_args()
    assert full.commit_sha in a
    assert "HEAD" in a
    assert "--" in a
    for p in ec.ENGINE_PATHS:
        assert p in a


@pytest.mark.parametrize(
    "path", ["engine/guest/a.py", "engine/wit/w.wit", "engine/build.py", "engine/requirements-build.lock"]
)
def test_change_in_each_guarded_path_exit1(full, path):
    (full.tree / path).write_text("v2 — изменено\n")
    full.commit("change")
    code, out = full.run()
    assert code == 1, out
    assert "engine" in out and ("релиз" in out or "release" in out.lower())
    assert TAG in out
    assert full.tmp_left() == []


def test_new_file_in_guest_exit1(full):
    (full.tree / "engine/guest/new.py").write_text("x\n")
    full.commit("add")
    assert full.run()[0] == 1


def test_deleted_file_in_guest_exit1(full):
    (full.tree / "engine/guest/a.py").unlink()
    full.commit("rm")
    assert full.run()[0] == 1


def test_change_in_nested_guest_subdir_exit1(full):
    d = full.tree / "engine/guest/deep/er"
    d.mkdir(parents=True)
    (d / "z.py").write_text("x\n")
    full.commit("deep")
    assert full.run()[0] == 1


def test_change_outside_guarded_paths_is_ok(full):
    (full.tree / "engine/other.txt").write_text("changed\n")
    (full.tree / "veil/x.py").write_text("changed\n")
    (full.tree / "README.md").write_text("new\n")
    full.commit("harmless")
    code, out = full.run()
    assert code == 0, out
    assert full.commit_sha in out


def test_change_in_similarly_named_path_is_ok(full):
    d = full.tree / "engine/guest2"
    d.mkdir()
    (d / "a.py").write_text("x\n")
    (full.tree / "engine/build.py.bak").write_text("x\n")
    full.commit("similar")
    assert full.run()[0] == 0


def test_commit_not_in_history_exit1_not_zero(full):
    full.attest([entry("f" * 40)])
    code, out = full.run()
    assert code == 1, out


def test_not_a_git_repo_exit_nonzero(env):
    env.attest([entry("a" * 40)])
    code, _ = env.run()
    assert code in (1, 2)


def test_skip_provenance_skips_gh_and_git(env):
    # ни репозитория, ни gh: всё равно 0
    env.remove_gh()
    code, out = env.run("--skip-provenance")
    assert code == 0, out
    assert env.gh_args() == [] and env.git_args() == []
    assert "engine ok" in out and TAG in out and SHA in out


def test_skip_provenance_still_checks_hash(env):
    env.response = FakeResp(BODY + b"x")
    assert env.run("--skip-provenance")[0] == 1


# ---------------------------------------------------------------- аргументы


@pytest.mark.parametrize(
    "args",
    [
        ["--bogus"],
        ["extra"],
        ["--skip-provenance", "extra"],
        ["--skip-provenance=1"],
        ["--out"],
        ["--out="],
        ["-x"],
        ["--Skip-Provenance"],
        ["--out", "file"],
        ["--skip-provenance", "--bogus"],
        [""],
    ],
)
def test_bad_arguments_exit2_without_network(env, args):
    code, _ = env.run(*args)
    assert code == 2
    assert env.calls == []


def test_args_order_independent(full, tmp_path):
    dst = tmp_path / "o.wasm"
    assert full.run("--skip-provenance", f"--out={dst}")[0] == 0
    assert dst.read_bytes() == BODY


def test_out_in_missing_directory_does_not_traceback(env, tmp_path):
    code, _ = env.run(f"--out={tmp_path / 'no' / 'dir' / 'f.wasm'}", "--skip-provenance")
    assert code in (1, 2)


@pytest.mark.parametrize("scenario", ["gh_fail", "bad_json", "sources", "wrong_ref"])
def test_temp_file_removed_on_every_failure(full, scenario):
    if scenario == "gh_fail":
        full.attest([entry(full.commit_sha)], rc=1)
    elif scenario == "bad_json":
        full.attest("garbage")
    elif scenario == "sources":
        (full.tree / "engine/guest/a.py").write_text("v9\n")
        full.commit("c")
    else:
        full.attest([entry(full.commit_sha, ref="refs/tags/engine-9")])
    assert full.run()[0] == 1
    assert full.tmp_left() == []
    assert (full.log / "gh.seen").exists()  # файл был передан gh, значит это не пустая проверка


def test_main_constants_exposed_match_contract():
    assert ec.ENGINE_PATHS == ("engine/guest", "engine/wit", "engine/build.py", "engine/requirements-build.lock")
    assert ec.TIMEOUT <= 120


# ---------------------------------------------------------------- сообщения и границы (диагностика читается человеком)

MESSAGES = {
    "два присваивания sha": ("ENGINE_SHA256", "ровно одно присваивание"),
    "нет url": ("ENGINE_URL", "ровно одно присваивание"),
    "нет max": ("ENGINE_MAX", "ровно одно присваивание"),
    "sha не строка": ("ENGINE_SHA256", "нужна строковая константа"),
    "url не строка": ("ENGINE_URL", "нужна строковая константа"),
    "sha 63": ("ENGINE_SHA256", "нужны 64 шестнадцатеричные цифры в нижнем регистре"),
    "sha верхний регистр": ("ENGINE_SHA256", "нужны 64 шестнадцатеричные цифры в нижнем регистре"),
    "url http": (
        "ENGINE_URL",
        "https://github.com/<владелец>/<репозиторий>/releases/download/engine-N/veil-engine.wasm",
    ),
    "url engine-0": ("ENGINE_URL", "engine-N"),
    "max умножением": ("ENGINE_MAX", "нужно положительное целое или `<целое> << <целое>`"),
    "max строкой": ("ENGINE_MAX", "нужно положительное целое или `<целое> << <целое>`"),
    "синтаксическая ошибка": ("plugin_engine.py", "не читается"),
}


@pytest.mark.parametrize("name", sorted(MESSAGES))
def test_bad_constants_message_goes_to_stderr_and_names_the_problem(env, name):
    env.write_consts(BAD_CONSTS[name])
    assert env.run()[0] == 2
    for part in MESSAGES[name]:
        assert part in env.err, (name, env.err)
    assert env.out == ""


def test_max_boundaries_of_constant_forms(env):
    one = b"z"
    base = consts(sha=hashlib.sha256(one).hexdigest())
    for mx in ("1", "5 << 0", "1 << 1", "1 << 40"):
        env.response = FakeResp(one)
        env.write_consts(base.replace("64 << 20", mx))
        code, out = env.run("--skip-provenance")
        assert code == 0, (mx, out)
    for mx in ("0", "0 << 5", "1 << 41", "1 << 1000"):
        env.write_consts(base.replace("64 << 20", mx))
        assert env.run("--skip-provenance")[0] == 2, mx


def test_max_one_byte_limit_is_enforced(env):
    env.write_consts(consts(sha=hashlib.sha256(b"zz").hexdigest(), mx="1"))
    env.response = FakeResp(b"zz")
    code, _ = env.run("--skip-provenance")
    assert code == 1
    assert "ENGINE_MAX" in env.err and "(1 байт)" in env.err and env.out == ""


def test_download_failure_message_has_url_and_goes_to_stderr(env):
    env.response = urllib.error.URLError("no route to host")
    assert env.run()[0] == 1
    assert URL in env.err and "no route to host" in env.err and env.out == ""


def test_download_request_has_user_agent(env):
    seen = []

    def spy(req, *a, **k):
        seen.append(req)
        return FakeResp(BODY)

    env.mp.setattr(urllib_request(), "urlopen", spy)
    assert env.run("--skip-provenance")[0] == 0
    assert seen[0].get_header("User-agent") == "veil-engine-check"


def test_gh_failure_message_has_code_and_text_stderr_tail(env):
    commit = env.init_repo()
    env.gh_script(rc=3, stdout="", stderr="A" * 200 + "B" * 500)
    code, _ = env.run()
    assert code == 1
    assert "код 3" in env.err
    assert "B" * 500 in env.err and "A" not in env.err.replace("аттестация", "").replace("Attest", "")
    assert "b'" not in env.err  # текст, а не repr байтов
    assert commit


def test_gh_failure_message_stderr_tail_is_last_500_not_first(env):
    env.init_repo()
    env.gh_script(rc=1, stdout="", stderr="X" * 300 + "Y" * 400)
    env.run()
    assert "Y" * 400 in env.err and "X" * 100 in env.err and "X" * 101 not in env.err


def test_bad_json_message_mentions_json(full):
    full.attest("{oops")
    assert full.run()[0] == 1
    assert "JSON" in full.err


@pytest.mark.parametrize("text", ["[]", "{}", '{"a": 1}', "null", '"str"', "0", "false"])
def test_non_list_or_empty_attestation_says_no_attestations(full, text):
    full.attest(text)
    assert full.run()[0] == 1
    assert "аттестаций нет" in full.err


def test_wrong_ref_message_names_both_refs(full):
    full.attest([entry(full.commit_sha, ref="refs/tags/engine-9")])
    assert full.run()[0] == 1
    assert "refs/tags/engine-9" in full.err and f"refs/tags/{TAG}" in full.err


def test_bad_commit_message(full):
    full.attest([entry("nothex")])
    assert full.run()[0] == 1
    assert "коммит исходников записан неверно" in full.err


def test_commit_count_message_has_count(full):
    full.attest([entry(full.commit_sha), entry("2" * 40), entry("3" * 40)])
    assert full.run()[0] == 1
    assert "ровно один коммит" in full.err and "найдено 3" in full.err
    full.response = FakeResp(BODY)
    e = entry(full.commit_sha)
    e["verificationResult"]["statement"]["predicate"]["buildDefinition"]["resolvedDependencies"] = []
    full.attest([e])
    assert full.run()[0] == 1
    assert "ровно один коммит" in full.err and "найдено 0" in full.err


def test_commit_missing_from_history_message_names_commit(full):
    full.attest([entry("f" * 40)])
    assert full.run()[0] == 1
    assert "f" * 40 in full.err and "истории" in full.err


def test_source_change_message_names_tag_and_asks_new_release(full):
    (full.tree / "engine/guest/a.py").write_text("changed\n")
    full.commit("c")
    assert full.run()[0] == 1
    assert TAG in full.err and "нужен новый релиз" in full.err and "ENGINE_SHA256" in full.err
    assert full.out == ""


def test_missing_tools_message(full):
    full.remove_gh()
    full.mp.setenv("PATH", f"{full.bin}")
    assert full.run()[0] == 2
    assert "нужны git и gh" in full.err and "https://cli.github.com" in full.err


def test_missing_git_exit2(full):
    (full.bin / "git").unlink()
    full.mp.setenv("PATH", f"{full.bin}")
    assert full.run("--skip-provenance")[0] == 2
    assert "git" in full.err


def test_file_given_to_gh_is_named_veil_engine_wasm(full):
    assert full.run()[0] == 0
    assert Path(full.gh_args()[2]).name == "veil-engine.wasm"


def test_gh_and_git_run_with_timeout_and_without_shell(full):
    calls = []
    real = subprocess.run

    def spy(cmd, *a, **k):
        calls.append((cmd, k))
        return real(cmd, *a, **k)

    full.mp.setattr(subprocess, "run", spy)
    assert full.run()[0] == 0
    assert [c[0][0] for c in calls] == ["gh", "git", "git"]
    for cmd, k in calls:
        assert isinstance(cmd, list) and not k.get("shell")
        assert k.get("timeout") is not None and 0 < k["timeout"] <= 600
        assert k.get("text") or k.get("encoding") or k.get("universal_newlines")


@pytest.mark.parametrize("which", ["gh", "git"])
def test_tool_timeout_is_failure_not_success(full, which):
    real = subprocess.run

    def spy(cmd, *a, **k):
        if cmd[0] == which:
            raise subprocess.TimeoutExpired(cmd, 1)
        return real(cmd, *a, **k)

    full.mp.setattr(subprocess, "run", spy)
    code, _ = full.run()
    assert code == 1
    assert which in full.err
    assert full.out == ""


def test_git_diff_error_code_other_than_1_is_failure(full):
    real = subprocess.run

    def spy(cmd, *a, **k):
        if cmd[:2] == ["git", "diff"]:
            return subprocess.CompletedProcess(cmd, 129, "", "usage: boom")
        return real(cmd, *a, **k)

    full.mp.setattr(subprocess, "run", spy)
    assert full.run()[0] == 1
    assert "129" in full.err and "boom" in full.err


def test_out_path_with_equals_sign_is_kept_whole(full, tmp_path):
    dst = tmp_path / "a=b=c.wasm"
    assert full.run(f"--out={dst}")[0] == 0
    assert dst.read_bytes() == BODY


def test_usage_error_goes_to_stderr_with_argument_and_usage(env):
    assert env.run("--bogus")[0] == 2
    assert "неизвестный аргумент: --bogus" in env.err
    assert "использование: python tools/engine_check.py [--out=<файл>] [--skip-provenance]" in env.err
    assert env.out == ""


def test_failure_message_prefixed_and_on_stderr(full):
    full.attest("garbage")
    assert full.run()[0] == 1
    assert full.err.startswith("engine_check: ") and full.out == ""


def test_success_line_on_stdout_only(full):
    assert full.run()[0] == 0
    assert full.out.strip() == f"engine ok {TAG} {SHA} {full.commit_sha}" and full.err == ""


def test_exact_messages_for_constants(env):
    expect = {
        "sha 63": "engine_check: ENGINE_SHA256: нужны 64 шестнадцатеричные цифры в нижнем регистре\n",
        "url http": "engine_check: ENGINE_URL: нужен https://github.com/<владелец>/<репозиторий>/releases/download/"
        "engine-N/veil-engine.wasm\n",
        "max умножением": "engine_check: ENGINE_MAX: нужно положительное целое или `<целое> << <целое>`\n",
        "sha не строка": "engine_check: ENGINE_SHA256: нужна строковая константа\n",
    }
    for name, text in expect.items():
        env.write_consts(BAD_CONSTS[name])
        assert env.run()[0] == 2
        assert env.err == text, name


def test_exact_message_no_attestations(full):
    full.attest("[]")
    assert full.run()[0] == 1
    assert full.err == "engine_check: аттестаций нет\n"


def test_exact_message_bad_commit(full):
    full.attest([entry("zz")])
    assert full.run()[0] == 1
    assert full.err == "engine_check: в аттестации коммит исходников записан неверно\n"


def test_exact_message_missing_tools(full):
    full.remove_gh()
    full.mp.setenv("PATH", f"{full.bin}")
    assert full.run()[0] == 2
    assert full.err == "engine_check: нужны git и gh (https://cli.github.com)\n"


def test_exact_usage_text(env):
    assert env.run("--bogus")[0] == 2
    assert env.err == (
        "неизвестный аргумент: --bogus\n"
        "использование: python tools/engine_check.py [--out=<файл>] [--skip-provenance]\n"
    )


def test_timeout_message_names_program(full):
    real = subprocess.run

    def spy(cmd, *a, **k):
        if cmd[0] == "gh":
            raise subprocess.TimeoutExpired(cmd, 1)
        return real(cmd, *a, **k)

    full.mp.setattr(subprocess, "run", spy)
    assert full.run()[0] == 1
    assert full.err.startswith("engine_check: gh: ")


def test_git_diff_error_shows_only_last_500_of_stderr(full):
    real = subprocess.run

    def spy(cmd, *a, **k):
        if cmd[:2] == ["git", "diff"]:
            return subprocess.CompletedProcess(cmd, 128, "", "P" * 300 + "Q" * 500)
        return real(cmd, *a, **k)

    full.mp.setattr(subprocess, "run", spy)
    assert full.run()[0] == 1
    assert "Q" * 500 in full.err and "P" not in full.err
