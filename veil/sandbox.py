"""Песочница процесса группы пула на Landlock (Linux ≥ 5.13; сеть — ABI ≥ 4, Linux ≥ 6.7; ioctl устройств — ABI ≥ 5;
сигналы и абстрактные UNIX-сокеты — ABI ≥ 6, Linux ≥ 6.12).

Процесс сам и навсегда запрещает себе доступ ко всему, кроме перечисленного: чтение кода (Python, приложение),
отдельных файлов (`keys.json`, сертификаты), запись в каталог своей группы, при ABI ≥ 4 — TCP-соединения только
на разрешённые порты (прокси Telegram), при ABI ≥ 6 — сигналы и абстрактные UNIX-сокеты только внутри себя. Так ошибка
с выполнением кода в процессе группы не достаёт главный ключ пула, токен менеджера, индекс и данные других групп
(файлы того же пользователя ОС открыть уже нельзя) и не может остановить менеджер или другие группы сигналом.
Права пользователя ОС Landlock не расширяет — только сужает.
"""
from __future__ import annotations

import ctypes
import os
import struct
import sys
from pathlib import Path

SYS_CREATE, SYS_ADD_RULE, SYS_RESTRICT = 444, 445, 446  # x86_64 и aarch64 — одинаковые номера
RULE_PATH_BENEATH, RULE_NET_PORT = 1, 2
PR_SET_NO_NEW_PRIVS = 38
CREATE_RULESET_VERSION = 1

EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR, MAKE_REG = 1 << 4, 1 << 5, 1 << 6, 1 << 7, 1 << 8
MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM, REFER, TRUNCATE = 1 << 9, 1 << 10, 1 << 11, 1 << 12, 1 << 13, 1 << 14
IOCTL_DEV = 1 << 15  # ABI 5: ioctl на устройствах — не разрешается никому из правил
NET_BIND, NET_CONNECT = 1 << 0, 1 << 1
SCOPE_ABSTRACT_UNIX_SOCKET, SCOPE_SIGNAL = 1 << 0, 1 << 1  # ABI 6: только внутри своего домена Landlock

READ = EXECUTE | READ_FILE | READ_DIR
FILE_READ = READ_FILE
WRITE = READ | WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG | REFER | TRUNCATE


class SandboxError(RuntimeError):
    pass


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def abi() -> int:
    """Версия Landlock ядра; 0 — нет."""
    libc = _libc()
    libc.syscall.restype = ctypes.c_long
    v = libc.syscall(SYS_CREATE, None, ctypes.c_size_t(0), ctypes.c_uint32(CREATE_RULESET_VERSION))
    return max(int(v), 0)


def _fs_handled(version: int) -> int:
    handled = (1 << 13) - 1  # ABI 1: биты 0–12
    if version >= 2:
        handled |= REFER
    if version >= 3:
        handled |= TRUNCATE
    if version >= 5:
        handled |= IOCTL_DEV
    return handled


def _ruleset_attr(version: int, handled_fs: int, handled_net: int) -> bytes:
    """struct landlock_ruleset_attr своей версии: handled_access_fs; с ABI 4 — handled_access_net; с ABI 6 — scoped."""
    if version >= 6:
        return struct.pack("=QQQ", handled_fs, handled_net, SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL)
    if version >= 4:
        return struct.pack("=QQ", handled_fs, handled_net)
    return struct.pack("=Q", handled_fs)


def restrict(read: list[Path], write: list[Path], read_files: list[Path], ports: list[int]) -> int:
    """Применить песочницу к текущему процессу. Возвращает версию ABI. Несуществующие пути пропускаются."""
    version = abi()
    if version < 1:
        raise SandboxError("Landlock недоступен в ядре")
    libc = _libc()
    libc.syscall.restype = ctypes.c_long
    handled_fs = _fs_handled(version)
    handled_net = (NET_BIND | NET_CONNECT) if version >= 4 else 0
    attr = _ruleset_attr(version, handled_fs, handled_net)
    buf = ctypes.create_string_buffer(attr, len(attr))
    fd = libc.syscall(SYS_CREATE, buf, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    if fd < 0:
        raise SandboxError(f"landlock_create_ruleset: errno {ctypes.get_errno()}")
    try:
        def add_path(p: Path, access: int) -> None:
            try:
                pfd = os.open(p, os.O_PATH | os.O_CLOEXEC)
            except FileNotFoundError:
                return
            try:
                if not os.path.isdir(p):
                    access &= READ_FILE | WRITE_FILE | TRUNCATE | EXECUTE  # для файла — только права на файл
                rule = ctypes.create_string_buffer(struct.pack("=Qi", access & handled_fs, pfd), 12)
                if libc.syscall(SYS_ADD_RULE, ctypes.c_int(fd), ctypes.c_int(RULE_PATH_BENEATH), rule,
                                ctypes.c_uint32(0)) < 0:
                    raise SandboxError(f"landlock_add_rule {p}: errno {ctypes.get_errno()}")
            finally:
                os.close(pfd)

        for p in read:
            add_path(Path(p), READ)
        for p in read_files:
            add_path(Path(p), FILE_READ)
        for p in write:
            add_path(Path(p), WRITE)
        if handled_net:
            for port in ports:
                rule = ctypes.create_string_buffer(struct.pack("=QQ", NET_CONNECT, port), 16)
                if libc.syscall(SYS_ADD_RULE, ctypes.c_int(fd), ctypes.c_int(RULE_NET_PORT), rule,
                                ctypes.c_uint32(0)) < 0:
                    raise SandboxError(f"landlock_add_rule port {port}: errno {ctypes.get_errno()}")
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise SandboxError("prctl(NO_NEW_PRIVS)")
        if libc.syscall(SYS_RESTRICT, ctypes.c_int(fd), ctypes.c_uint32(0)) < 0:
            raise SandboxError(f"landlock_restrict_self: errno {ctypes.get_errno()}")
    finally:
        os.close(fd)
    return version


SYSTEM_READ = [Path(p) for p in ("/usr", "/lib", "/lib64", "/etc/ssl", "/etc/ca-certificates", "/etc/pki")]
SYSTEM_FILES = [Path(p) for p in ("/etc/ld.so.cache", "/etc/localtime", "/etc/resolv.conf", "/etc/hosts",
                                  "/etc/nsswitch.conf", "/etc/gai.conf", "/etc/host.conf", "/dev/urandom", "/dev/null")]


def restrict_group(group_root: Path, app_dir: Path, config_files: list[Path], ports: list[int],
                   extra_read: list[Path] = ()) -> int:
    """Песочница процесса группы: код и системные библиотеки — чтение; конфиг группы — отдельные файлы; запись —
    только каталог группы; сеть — только порты Telegram/прокси. extra_read — движок плагинов и локальный каталог
    маркета."""
    read = SYSTEM_READ + [Path(sys.prefix), Path(sys.base_prefix), Path(sys.exec_prefix), app_dir, *extra_read]
    return restrict(read=read, write=[group_root], read_files=SYSTEM_FILES + config_files, ports=ports)
