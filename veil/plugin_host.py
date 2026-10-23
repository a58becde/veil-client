"""Хост движка плагинов: отдельный процесс, в котором работает WASM-движок (docs/PLUGINS.md, «Движок»).

Запускает бот (veil.plugin_engine): один процесс на бота, в пуле — один на группу ботов. В процессе нет ключей, токенов
и данных ботов. До первого события он закрывает себе сеть (seccomp: только UNIX-сокеты) и файлы (Landlock: только
чтение Python и движка); в macOS этой защиты нет — только WASM, бот говорит об этом владельцу. Код плагинов приходит
от бота строкой протокола и исполняется внутри WASM: каждое событие — новый экземпляр движка со своим лимитом памяти и
времени, сеть и файлы в WASM не подключены вовсе. Действия плагина (host.call) хост не выполняет сам — передаёт боту и
ждёт ответа: разрешения и лимиты проверяет бот.

Протокол — JSON по строке на сообщение, stdin/stdout:
  бот → хост   {"t":"hello","cwasm":путь,"workers":N,"memory_mb":M,"read":[пути],"confine":bool}   первым
  хост → бот   {"t":"ready","os_sandbox":bool} или {"t":"fail","error":…}
  бот → хост   {"t":"load","key":…,"pkg":{"id","entry","files"}} / {"t":"unload","key":…}
  бот → хост   {"t":"run","id":N,"op":"describe"|"handle","key":…,"settings":{…},"event":{…},"timeout":с}
  хост → бот   {"t":"call","id":C,"run":N,"fn":…,"args":{…}}
  бот → хост   {"t":"result","id":C,"ok":true,"value":…} или {"t":"result","id":C,"ok":false,"error":…}
  хост → бот   {"t":"done","id":N,"ok":true,"value":{…}} или {"t":"done","id":N,"ok":false,"error":…,"log":[…]}
  бот → хост   {"t":"stop"}

  python -m veil.plugin_host compile <движок.wasm> <каталог или файл.cwasm> [--target=x86_64-unknown-linux-gnu]
скомпилировать движок в машинный код заранее (12–18 с, ~350 МБ памяти) — там, где компилировать при запуске нельзя. В
каталог файл ложится под именем, которое ищет бот; --target — без особых команд процессора этой машины (для другой).
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import resource
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TICK = 0.01             # с: шаг счётчика эпох — точность лимита времени
MAX_LINE = 8 << 20      # байт: строка протокола (ответ http до 4 МиБ в base64 и запас)
CALLS_PER_RUN = 500     # действий плагина за одно событие
# Всё, что выходит из WASM, ограничивает хост, а не код движка: плагин исполняется в том же CPython, что и движок, и
# может переписать его ограничения. Иначе огромный ответ сорвал бы канал с ботом и перезапуск хоста (в пуле — у всей
# группы).
CALL_ARGS_MAX = 2 << 20  # аргументы действия: тело http до 1 МиБ в base64, хранилище до 1 МиБ
RESULT_MAX = 1 << 20     # ответ события или describe
LOG_LINES, LOG_LINE = 100, 500
LIMITS = {resource.RLIMIT_NOFILE: 64, resource.RLIMIT_CORE: 0}



def engine_config(target: str | None = None):
    import wasmtime  # noqa: PLC0415 — wasmtime нужен только процессу хоста и компиляции, не боту
    cfg = wasmtime.Config()
    cfg.epoch_interruption = True  # лимит времени: счётчик эпох, а не подсчёт инструкций — дешевле
    cfg.memory_init_cow = True     # начальная память движка (снимок CPython) — общая, копируется только при записи
    if target:
        cfg.target = target
    return cfg


def cwasm_name(wasm: Path) -> str:
    """Имя машинного кода движка: своё для сборки движка, версии wasmtime и процессора."""
    from importlib import metadata  # noqa: PLC0415
    sha = hashlib.sha256(Path(wasm).read_bytes()).hexdigest()
    return f"veil-engine-{sha[:16]}-wasmtime{metadata.version('wasmtime')}-{platform.machine()}.cwasm"


def compile_engine(wasm: Path, out: Path, target: str | None = None) -> Path:
    if out.is_dir():
        out = out / cwasm_name(wasm)
    import wasmtime  # noqa: PLC0415
    from wasmtime import component as wc  # noqa: PLC0415
    comp = wc.Component.from_file(wasmtime.Engine(engine_config(target)), str(wasm))
    tmp = out.with_name(out.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(comp.serialize())
    os.replace(tmp, out)
    return out


class _Run:
    def __init__(self, rid: int, deadline: float):
        self.id, self.deadline, self.calls = rid, deadline, 0


class Host:
    def __init__(self, out, comp, eng, linker, workers: int, memory: int):
        self.out, self.comp, self.eng, self.linker, self.memory = out, comp, eng, linker, memory
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self.packages: dict[str, dict] = {}
        self.waiting: dict[int, list] = {}
        self.lock = threading.Lock()
        self.n = 0
        self.tls = threading.local()

    def send(self, msg: dict) -> None:
        line = (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        with self.lock:
            self.out.write(line)
            self.out.flush()

    # --- действие плагина: к боту и ждать ответа ---
    def call(self, store, name: str, args: str):
        from wasmtime import component as wc  # noqa: PLC0415
        run: _Run | None = getattr(self.tls, "run", None)
        if run is None:
            return wc.Variant("err", "действие вне события")
        run.calls += 1
        left = run.deadline - time.monotonic()
        if run.calls > CALLS_PER_RUN or left <= 0:
            return wc.Variant("err", "слишком много действий за одно событие" if left > 0 else "время вышло")
        if len(args) > CALL_ARGS_MAX:
            return wc.Variant("err", "аргументы действия больше 2 МиБ")
        try:
            parsed = json.loads(args)
        except ValueError:
            return wc.Variant("err", "аргументы — не JSON")
        with self.lock:
            self.n += 1
            cid = self.n
        box = [threading.Event(), None]
        self.waiting[cid] = box
        try:
            self.send({"t": "call", "id": cid, "run": run.id, "fn": str(name)[:32], "args": parsed})
            if not box[0].wait(left):
                return wc.Variant("err", "время вышло")
        finally:
            self.waiting.pop(cid, None)
        r = box[1]
        if r.get("ok"):
            return wc.Variant("ok", json.dumps(r.get("value"), ensure_ascii=False))
        return wc.Variant("err", str(r.get("error", "отказ"))[:300])

    # --- событие ---
    def run(self, msg: dict) -> None:
        import wasmtime  # noqa: PLC0415
        rid = msg["id"]
        timeout = min(max(float(msg.get("timeout", 30)), 0.1), 300.0)
        started = time.monotonic()
        deadline = msg["_got"] + timeout
        pkg = self.packages.get(msg.get("key"))
        if pkg is None or started >= deadline:
            self.send({"t": "done", "id": rid, "ok": False, "error": "пакет не загружен" if pkg is None else
                       "очередь: время вышло до запуска"})
            return
        op = "describe" if msg.get("op") == "describe" else "handle"
        store = wasmtime.Store(self.eng)
        store.set_wasi(wasmtime.WasiConfig())
        store.set_limits(memory_size=self.memory, instances=50, tables=50, memories=10, table_elements=100_000)
        store.set_epoch_deadline(max(1, int((deadline - started) / TICK)))
        self.tls.run = _Run(rid, deadline)
        try:
            inst = self.linker.instantiate(store, self.comp)
            raw = json.dumps({**pkg, "settings": msg.get("settings") or {}}, ensure_ascii=False)
            args = (raw,) if op == "describe" else (raw, json.dumps(msg.get("event") or {}, ensure_ascii=False))
            res = inst.get_func(store, op)(store, *args)
            body = json.loads(res.payload) if isinstance(res.payload, str) and len(res.payload) <= RESULT_MAX else None
            if not isinstance(body, dict):
                self.send({"t": "done", "id": rid, "ok": False, "error": "ответ плагина больше 1 МиБ или не объект"})
                return
            lines = body.pop("log", None)
            log = [str(x)[:LOG_LINE] for x in lines[:LOG_LINES]] if isinstance(lines, list) else []
            if res.tag == "ok":
                self.send({"t": "done", "id": rid, "ok": True, "value": {**body, "log": log}})
            else:
                self.send({"t": "done", "id": rid, "ok": False, "error": str(body.get("error", "сбой"))[:300],
                           "log": log})
        except (wasmtime.Trap, wasmtime.WasmtimeError) as e:
            why = "время вышло" if time.monotonic() >= deadline - TICK * 5 else f"движок: {str(e).splitlines()[0][:200]}"
            self.send({"t": "done", "id": rid, "ok": False, "error": why})
        except Exception as e:  # noqa: BLE001 — сбой одного события не роняет хост
            self.send({"t": "done", "id": rid, "ok": False, "error": f"хост: {type(e).__name__}"})
        finally:
            self.tls.run = None
            store.close()

    def serve(self, inp) -> None:
        while line := inp.readline(MAX_LINE + 1):
            if len(line) > MAX_LINE:
                raise SystemExit("строка протокола слишком длинная")
            msg = json.loads(line)
            t = msg.get("t")
            if t == "run":
                msg["_got"] = time.monotonic()
                self.pool.submit(self.run, msg)
            elif t == "result":
                box = self.waiting.get(msg.get("id"))
                if box:
                    box[1] = msg
                    box[0].set()
            elif t == "load":
                self.packages[str(msg["key"])] = {k: msg["pkg"][k] for k in ("id", "entry", "files")}
            elif t == "unload":
                self.packages.pop(str(msg.get("key")), None)
            elif t == "stop":
                break


def _linker(eng, host_call):
    from wasmtime import component as wc  # noqa: PLC0415
    linker = wc.Linker(eng)
    # WASI с настройками по умолчанию: ни каталогов, ни переменных окружения, ни аргументов; сокеты WASI есть в
    # интерфейсе движка, но ни один адрес не разрешён и имена не резолвятся. В Linux поверх — seccomp хоста.
    linker.add_wasip2()
    with linker.root() as root:
        with root.add_instance("veil:plugin/host@1.0.0") as h:
            h.add_func("call", host_call)
    return linker


def confine(read: list[Path]) -> bool:
    """Linux: seccomp и Landlock — после этого ни сети, ни записи файлов, ни чтения вне Python и движка. Другие
    системы — False: защищает только WASM."""
    if not sys.platform.startswith("linux"):
        return False
    from veil import sandbox, seccomp  # noqa: PLC0415
    seccomp.apply()
    paths = sandbox.SYSTEM_READ + [Path(sys.prefix), Path(sys.base_prefix), Path(sys.exec_prefix),
                                   Path(__file__).resolve().parent] + read
    files = [Path(p) for p in ("/etc/ld.so.cache", "/etc/localtime", "/dev/urandom", "/dev/null")]
    sandbox.restrict(read=paths, write=[], read_files=files, ports=[])
    return True


def main() -> None:
    out = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)  # всё, что напечатает кто-то кроме протокола, — в журнал бота
    inp = sys.stdin.buffer

    def fail(why: str) -> None:
        out.write((json.dumps({"t": "fail", "error": why[:300]}, ensure_ascii=False) + "\n").encode())
        raise SystemExit(1)

    hello = json.loads(inp.readline(MAX_LINE))
    os.umask(0o077)
    for res, val in LIMITS.items():
        resource.setrlimit(res, (val, val))
    try:
        import ctypes  # noqa: PLC0415 — только для prctl
        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0: память процесса не читает никто
    except (OSError, AttributeError):
        pass
    try:
        import wasmtime  # noqa: PLC0415
        from wasmtime import component as wc  # noqa: PLC0415
        eng = wasmtime.Engine(engine_config())
        comp = wc.Component.deserialize_file(eng, hello["cwasm"])
    except Exception as e:  # noqa: BLE001 — сказать боту словами: движок не загрузился
        fail(f"движок не загрузился: {str(e).splitlines()[0] if str(e) else type(e).__name__}")
    host: Host | None = None
    linker = _linker(eng, lambda store, name, args: host.call(store, name, args))
    host = Host(out, comp, eng, linker, int(hello.get("workers", 4)), int(hello.get("memory_mb", 64)) << 20)
    try:
        os_sandbox = confine([Path(p) for p in hello.get("read") or []]) if hello.get("confine", True) else False
    except Exception as e:  # noqa: BLE001 — без защиты ОС в Linux хост не работает
        fail(f"песочница ОС не включилась: {e}")

    def tick() -> None:
        while True:
            eng.increment_epoch()
            time.sleep(TICK)
    threading.Thread(target=tick, daemon=True).start()
    host.send({"t": "ready", "os_sandbox": os_sandbox})
    try:
        host.serve(inp)
    finally:
        os._exit(0)  # потоки движка не ждём: бот уже не слушает


def cli(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[0] == "compile":
        target = next((a.split("=", 1)[1] for a in argv if a.startswith("--target=")), None)
        t = time.monotonic()
        out = compile_engine(Path(argv[1]), Path(argv[2]), target)
        print(f"{out}: {time.monotonic() - t:.1f} с")
        return 0
    print(__doc__.split("\n\n")[-1].strip())
    return 2


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))
