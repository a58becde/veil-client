"""seccomp-фильтр процесса-хоста движка плагинов (docs/PLUGINS.md, «Как это работает»): из сокетов — только UNIX,
без io_uring.

Landlock ограничивает сеть только по портам TCP: UDP (например, DNS-запрос на свой сервер с данными в имени) и
raw-сокеты он не видит. Фильтр закрывает сеть целиком: socket()/socketpair() с семейством, отличным от AF_UNIX,
и io_uring (через него сокеты создаются в обход socket()) возвращают EPERM; системные вызовы x32 на x86_64
и чужая архитектура — тоже отказ. Действует на процесс и всех его потомков, снять его нельзя.
"""
from __future__ import annotations

import ctypes
import platform
import struct

PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2
RET_ALLOW, RET_ERRNO, RET_KILL_PROCESS = 0x7FFF0000, 0x00050000, 0x80000000
EPERM, AF_UNIX = 1, 1
LD_ABS_W, JEQ_K, JGE_K, RET_K = 0x20, 0x15, 0x35, 0x06
X32_BIT = 0x40000000

# Архитектура → (AUDIT_ARCH, socket, socketpair); io_uring_setup/enter/register — 425–427 на обеих.
ARCHES = {"x86_64": (0xC000003E, 41, 53), "aarch64": (0xC00000B7, 198, 199)}
IO_URING = (425, 426, 427)


class SeccompError(RuntimeError):
    pass


def program(machine: str | None = None) -> list[tuple[int, int, int, int]]:
    """Программа BPF: (code, jt, jf, k). Переходы — смещения от следующей инструкции."""
    machine = machine or platform.machine()
    if machine not in ARCHES:
        raise SeccompError(f"seccomp-фильтр есть для x86_64 и aarch64, а не для {machine}")
    arch, sock, sockpair = ARCHES[machine]
    return [
        (LD_ABS_W, 0, 0, 4),               # 0  arch
        (JEQ_K, 1, 0, arch),               # 1  своя архитектура → 3
        (RET_K, 0, 0, RET_KILL_PROCESS),   # 2  чужая — убить
        (LD_ABS_W, 0, 0, 0),               # 3  номер вызова
        (JGE_K, 9, 0, X32_BIT),            # 4  x32 → 14 (отказ)
        (JEQ_K, 5, 0, sock),               # 5  socket → 11
        (JEQ_K, 4, 0, sockpair),           # 6  socketpair → 11
        (JEQ_K, 6, 0, IO_URING[0]),        # 7  → 14
        (JEQ_K, 5, 0, IO_URING[1]),        # 8  → 14
        (JEQ_K, 4, 0, IO_URING[2]),        # 9  → 14
        (RET_K, 0, 0, RET_ALLOW),          # 10
        (LD_ABS_W, 0, 0, 16),              # 11 семейство (args[0], младшие 32 бита)
        (JEQ_K, 0, 1, AF_UNIX),            # 12 AF_UNIX → 13, иначе → 14
        (RET_K, 0, 0, RET_ALLOW),          # 13
        (RET_K, 0, 0, RET_ERRNO | EPERM),  # 14
    ]


def apply(machine: str | None = None) -> None:
    """Включить фильтр в текущем процессе (навсегда)."""
    prog = program(machine)
    raw = b"".join(struct.pack("=HBBI", *ins) for ins in prog)
    buf = ctypes.create_string_buffer(raw, len(raw))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(prog), ctypes.cast(buf, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SeccompError(f"prctl(NO_NEW_PRIVS): errno {ctypes.get_errno()}")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        raise SeccompError(f"prctl(SECCOMP): errno {ctypes.get_errno()}")
