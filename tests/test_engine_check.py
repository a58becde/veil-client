"""tools/engine_check.py: выходы 0/1/2 при подменённых gh, git и сети (настоящие не запускаются)."""

import hashlib
import io
import json
import subprocess
import textwrap
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tools import engine_check as ec

BLOB = b"\0asm-fake-engine"
SHA = hashlib.sha256(BLOB).hexdigest()
TAG = "engine-7"
URL = f"https://github.com/acme/veil-client/releases/download/{TAG}/veil-engine.wasm"
COMMIT = "a" * 40
OTHER = "b" * 40


def source(sha: str = SHA, url: str = URL, size: str = "64 << 20") -> str:
    return textwrap.dedent(f'''
        ENGINE_SHA256 = "{sha}"  # комментарий
        ENGINE_URL = "{url}"
        ENGINE_MAX = {size}
    ''')


def attestation(commits=(COMMIT,), ref: str = f"refs/tags/{TAG}") -> str:
    deps = [{"uri": "git+https://github.com/acme/veil-client", "digest": {"gitCommit": c}} for c in commits]
    pred = {"buildDefinition": {"externalParameters": {"workflow": {"ref": ref}}, "resolvedDependencies": deps}}
    return json.dumps([{"verificationResult": {"statement": {"predicate": pred}}}])


class Env:
    """Подмена внешнего мира: сеть, gh, git; запоминает вызовы."""

    def __init__(self, monkeypatch, tmp_path: Path):
        self.calls: list[list[str]] = []
        self.blob: bytes | Exception = BLOB
        self.gh = subprocess.CompletedProcess([], 0, attestation(), "")
        self.cat = subprocess.CompletedProcess([], 0, "", "")
        self.diff = subprocess.CompletedProcess([], 0, "", "")
        self.have = {"git", "gh"}
        self.src = tmp_path / "plugin_engine.py"
        self.src.write_text(source())
        monkeypatch.setattr(ec, "SOURCE", self.src)
        monkeypatch.setattr(ec, "fetch", self._fetch)
        monkeypatch.setattr(ec, "run", self._run)
        monkeypatch.setattr(ec.shutil, "which", lambda name: f"/usr/bin/{name}" if name in self.have else None)

    def _fetch(self, url: str, limit: int) -> bytes:
        self.calls.append(["fetch", url, str(limit)])
        if isinstance(self.blob, Exception):
            raise self.blob
        return self.blob

    def _run(self, cmd: list[str]):
        self.calls.append(cmd)
        if cmd[0] == "gh":
            return self.gh
        return self.cat if cmd[1] == "cat-file" else self.diff

    def names(self) -> list[str]:
        return [c[0] if c[0] != "git" else f"git {c[1]}" for c in self.calls]


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


def test_all_ok(env, capsys):
    assert ec.main([]) == 0
    assert capsys.readouterr().out.strip() == f"engine ok {TAG} {SHA} {COMMIT}"
    gh = next(c for c in env.calls if c[0] == "gh")
    assert gh[1:3] == ["attestation", "verify"]
    assert gh[gh.index("--repo") + 1] == "acme/veil-client"
    assert gh[gh.index("--signer-workflow") + 1] == "acme/veil-client/.github/workflows/engine-release.yml"
    assert gh[gh.index("--format") + 1] == "json"
    diff = next(c for c in env.calls if c[:2] == ["git", "diff"])
    assert diff[:6] == ["git", "diff", "--quiet", COMMIT, "HEAD", "--"]
    assert diff[6:] == ["engine/guest", "engine/wit", "engine/build.py", "engine/requirements-build.lock"]
    assert ["fetch", URL, str(64 << 20)] in env.calls


def test_out_file_written(env, tmp_path):
    out = tmp_path / "w.wasm"
    assert ec.main([f"--out={out}"]) == 0
    assert out.read_bytes() == BLOB
    gh = next(c for c in env.calls if c[0] == "gh")
    assert gh[3] == str(out)


def test_out_unwritable_exit_1_with_message(env, tmp_path, capsys):
    out = tmp_path / "нет" / "w.wasm"
    assert ec.main([f"--out={out}"]) == 1
    err = capsys.readouterr().err
    assert str(out) in err
    assert "Traceback" not in err


@pytest.mark.parametrize("argv", [["--bogus"], ["x"], ["--out="], ["--skip-provenance=1"], ["--out"]])
def test_bad_args_exit_2(env, argv):
    assert ec.main(argv) == 2
    assert env.calls == []


def test_no_gh_exit_2(env):
    env.have = {"git"}
    assert ec.main([]) == 2
    assert env.calls == []


def test_no_gh_ok_when_skipping(env, capsys):
    env.have = {"git"}
    assert ec.main(["--skip-provenance"]) == 0
    assert "происхождение не проверялось" in capsys.readouterr().out
    assert env.names() == ["fetch"]


def test_no_git_exit_2(env):
    env.have = {"gh"}
    assert ec.main([]) == 2


def test_hash_mismatch_exit_1(env, capsys):
    env.blob = BLOB + b"x"
    assert ec.main([]) == 1
    err = capsys.readouterr().err
    assert SHA in err
    assert hashlib.sha256(BLOB + b"x").hexdigest() in err
    assert "gh" not in env.names()


def test_hash_mismatch_exit_1_even_when_skipping(env):
    env.blob = b"other"
    assert ec.main(["--skip-provenance"]) == 1


def test_network_down_exit_1(env):
    env.blob = ec.FailError("нет сети")
    assert ec.main([]) == 1
    assert ec.main(["--skip-provenance"]) == 1


def test_gh_failure_exit_1(env):
    env.gh = subprocess.CompletedProcess([], 1, "", "verification failed")
    assert ec.main([]) == 1
    assert "git diff" not in " ".join(env.names())


@pytest.mark.parametrize("stdout", ["", "не json", "{}", "[]", "[1]", "[{}]", "null"])
def test_attestation_garbage_exit_1(env, stdout):
    env.gh = subprocess.CompletedProcess([], 0, stdout, "")
    assert ec.main([]) == 1


@pytest.mark.parametrize("ref", ["refs/tags/engine-8", "refs/heads/main", "refs/tags/engine-7x", "", None])
def test_foreign_ref_exit_1(env, ref):
    env.gh = subprocess.CompletedProcess([], 0, attestation(ref=ref), "")
    assert ec.main([]) == 1


@pytest.mark.parametrize("commits", [(), (COMMIT, OTHER), ("a" * 39,), ("A" * 40,), ("zz",)])
def test_wrong_commit_count_or_format_exit_1(env, commits):
    env.gh = subprocess.CompletedProcess([], 0, attestation(commits), "")
    assert ec.main([]) == 1
    assert "git diff" not in " ".join(env.names())


def test_repeated_attestation_same_commit_ok(env):
    env.gh = subprocess.CompletedProcess([], 0, attestation((COMMIT, COMMIT)), "")
    assert ec.main([]) == 0


def test_second_attestation_with_foreign_ref_exit_1(env):
    first, second = json.loads(attestation()), json.loads(attestation(ref="refs/tags/engine-1"))
    env.gh = subprocess.CompletedProcess([], 0, json.dumps(first + second), "")
    assert ec.main([]) == 1


def test_commit_not_in_history_exit_1(env, capsys):
    env.cat = subprocess.CompletedProcess([], 128, "", "bad object")
    assert ec.main([]) == 1
    assert "истории" in capsys.readouterr().err
    assert "git diff" not in " ".join(env.names())


def test_engine_changed_exit_1(env, capsys):
    env.diff = subprocess.CompletedProcess([], 1, "", "")
    assert ec.main([]) == 1
    assert "нужен новый релиз" in capsys.readouterr().err


def test_git_diff_error_exit_1(env):
    env.diff = subprocess.CompletedProcess([], 128, "", "fatal")
    assert ec.main([]) == 1


@pytest.mark.parametrize("text", [
    source(sha="A" * 64), source(sha="a" * 63), source(sha="g" * 64), source(sha=""),
    source(url=URL.replace("https", "http")),
    source(url=URL.replace("engine-7", "engine-0")),
    source(url=URL.replace("engine-7", "engine-07")),
    source(url=URL.replace("engine-7", "engine-x")),
    source(url=URL.replace("veil-engine.wasm", "other.wasm")),
    source(url=URL.replace("acme", "..")),
    source(url=URL.replace("veil-client", "..")),
    source(url=URL.replace("acme", ".").replace("veil-client", "...")),
    source(url=URL + "?x=1"),
    source(url="https://evil.example/acme/veil-client/releases/download/engine-7/veil-engine.wasm"),
    source(size="0"), source(size="-1"), source(size="1.5"), source(size="'64'"), source(size="1 << -1"),
    source(size="64 * 1024"), source(size="a << 20"),
    "ENGINE_URL = 'x'\nENGINE_MAX = 1\n",
    source() + f'ENGINE_SHA256 = "{SHA}"\n',
    source() + "ENGINE_MAX = 2\n",
    "def broken(:\n",
    "ENGINE_SHA256 = SHA\nENGINE_URL = URL\nENGINE_MAX = 1\n",
])
def test_bad_constants_exit_2(env, text):
    env.src.write_text(text)
    assert ec.main([]) == 2
    assert env.calls == []


def test_annotated_assignment_is_read(env):
    env.src.write_text(source().replace("ENGINE_MAX =", "ENGINE_MAX: int ="))
    assert ec.read_constants(env.src) == (SHA, URL, 64 << 20)


@pytest.mark.parametrize(("size", "expected"), [("5", 5), ("1 << 10", 1024), ("64 << 20", 64 << 20)])
def test_size_forms(env, size, expected):
    env.src.write_text(source(size=size))
    assert ec.read_constants(env.src)[2] == expected


def test_missing_source_exit_2(env, monkeypatch, tmp_path):
    monkeypatch.setattr(ec, "SOURCE", tmp_path / "нет.py")
    assert ec.main([]) == 2


def test_constants_are_not_executed(env, tmp_path):
    marker = tmp_path / "ran"
    env.src.write_text(f"open({str(marker)!r}, 'w')\n" + source())
    assert ec.main(["--skip-provenance"]) == 0
    assert not marker.exists()


def test_real_source_constants_parse():
    sha, url, limit = ec.read_constants(Path(__file__).resolve().parent.parent / "veil" / "plugin_engine.py")
    assert len(sha) == 64
    assert url.endswith("/veil-engine.wasm")
    assert limit == 64 << 20


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_limit(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["timeout"], seen["url"] = timeout, req.full_url
        return FakeResponse(b"x" * 11)

    monkeypatch.setattr(ec.urllib.request, "urlopen", fake_urlopen)
    assert ec.fetch(URL, 11) == b"x" * 11
    assert seen == {"timeout": 120, "url": URL}
    with pytest.raises(ec.FailError):
        ec.fetch(URL, 10)


@pytest.mark.parametrize("exc", [urllib.error.URLError("down"), TimeoutError("slow"), ConnectionResetError()])
def test_fetch_network_errors(monkeypatch, exc):
    def fake_urlopen(req, timeout):
        raise exc

    monkeypatch.setattr(ec.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ec.FailError):
        ec.fetch(URL, 10)


def test_run_missing_program_is_failure():
    with pytest.raises(ec.FailError):
        ec.run(["/нет/такой/программы"])


def _redirect(newurl):
    handler = ec.SafeRedirect()
    req = urllib.request.Request(URL)
    return handler.redirect_request(req, io.BytesIO(), 302, "Found", {}, newurl)


@pytest.mark.parametrize("newurl", [
    "http://github.com/x",  # понижение до http
    "https://evil.example/x",  # чужой хост
    "https://github.com.evil.example/x",  # похожий хост
    "ftp://github.com/x",
    "file:///etc/passwd",
])
def test_redirect_rejected(newurl):
    with pytest.raises(ec.FailError):
        _redirect(newurl)


@pytest.mark.parametrize("host", [
    "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
])
def test_redirect_allowed(host):
    new = _redirect(f"https://{host}/a?b=c")
    assert new is not None
    assert new.full_url == f"https://{host}/a?b=c"


def test_fetch_installs_safe_redirect(monkeypatch):
    monkeypatch.setattr(ec.urllib.request, "urlopen", lambda req, timeout: FakeResponse(b"x"))
    opened = {}
    monkeypatch.setattr(ec.urllib.request, "install_opener", lambda o: opened.setdefault("o", o))
    ec.fetch(URL, 10)
    assert any(isinstance(h, ec.SafeRedirect) for h in opened["o"].handlers)


def test_redirect_rejection_names_target():
    with pytest.raises(ec.FailError) as e:
        _redirect("http://evil.example/x")
    assert str(e.value) == "редирект на недопустимый адрес отклонён: http://evil.example"


def test_redirect_passes_arguments_to_base_handler():
    """Для кода, не являющегося редиректом, базовый класс поднимает HTTPError с теми же fp, msg, headers."""
    fp, headers = io.BytesIO(b"body"), {"X": "1"}
    with pytest.raises(urllib.error.HTTPError) as e:
        ec.SafeRedirect().redirect_request(urllib.request.Request(URL), fp, 300, "Multiple", headers,
                                           "https://github.com/x")
    assert e.value.code == 300 and e.value.msg == "Multiple"
    assert e.value.hdrs is headers and e.value.fp is fp
