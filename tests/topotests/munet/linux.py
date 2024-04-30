# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# June 10 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
#
"""A module that gives access to linux unshare system call."""

import ctypes  # pylint: disable=C0415
import ctypes.util  # pylint: disable=C0415
import errno
import functools
import os


libc = None


def raise_oserror(enum):
    s = errno.errorcode[enum] if enum in errno.errorcode else str(enum)
    error = OSError(s)
    error.errno = enum
    error.strerror = s
    raise error


def _load_libc():
    global libc  # pylint: disable=W0601,W0603
    if libc:
        return
    lcpath = ctypes.util.find_library("c")
    libc = ctypes.CDLL(lcpath, use_errno=True)


def pause():
    if not libc:
        _load_libc()
    libc.pause()


MS_RDONLY = 1
MS_NOSUID = 1 << 1
MS_NODEV = 1 << 2
MS_NOEXEC = 1 << 3
MS_SYNCHRONOUS = 1 << 4
MS_REMOUNT = 1 << 5
MS_MANDLOCK = 1 << 6
MS_DIRSYNC = 1 << 7
MS_NOSYMFOLLOW = 1 << 8
MS_NOATIME = 1 << 10
MS_NODIRATIME = 1 << 11
MS_BIND = 1 << 12
MS_MOVE = 1 << 13
MS_REC = 1 << 14
MS_SILENT = 1 << 15
MS_POSIXACL = 1 << 16
MS_UNBINDABLE = 1 << 17
MS_PRIVATE = 1 << 18
MS_SLAVE = 1 << 19
MS_SHARED = 1 << 20
MS_RELATIME = 1 << 21
MS_KERNMOUNT = 1 << 22
MS_I_VERSION = 1 << 23
MS_STRICTATIME = 1 << 24
MS_LAZYTIME = 1 << 25


def mount(source, target, fs, flags=0, options=""):
    if not libc:
        _load_libc()
    libc.mount.argtypes = (
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_char_p,
    )
    fsenc = fs.encode() if fs else None
    optenc = options.encode() if options else None
    ret = libc.mount(source.encode(), target.encode(), fsenc, flags, optenc)
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(
            err,
            f"Error mounting {source} ({fs}) on {target}"
            f" with options '{options}': {os.strerror(err)}",
        )


# unmout options
MNT_FORCE = 0x1
MNT_DETACH = 0x2
MNT_EXPIRE = 0x4
UMOUNT_NOFOLLOW = 0x8


def umount(target, options):
    if not libc:
        _load_libc()
    libc.umount.argtypes = (ctypes.c_char_p, ctypes.c_uint)

    ret = libc.umount(target.encode(), int(options))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(
            err,
            f"Error umounting {target} with options '{options}': {os.strerror(err)}",
        )


def pidfd_open(pid, flags=0):
    if hasattr(os, "pidfd_open") and os.pidfd_open is not pidfd_open:
        return os.pidfd_open(pid, flags)  # pylint: disable=no-member

    if not libc:
        _load_libc()

    try:
        pfof = libc.pidfd_open
    except AttributeError:
        __NR_pidfd_open = 434
        _pidfd_open = libc.syscall
        _pidfd_open.restype = ctypes.c_int
        _pidfd_open.argtypes = ctypes.c_long, ctypes.c_uint, ctypes.c_uint
        pfof = functools.partial(_pidfd_open, __NR_pidfd_open)

    fd = pfof(int(pid), int(flags))
    if fd == -1:
        raise_oserror(ctypes.get_errno())

    return fd


# Runtime patch if kernel supports the call.
if not hasattr(os, "pidfd_open"):
    try:
        import platform

        kversion = [int(x) for x in platform.release().split("-")[0].split(".")]
        kvok = kversion[0] > 5 or (kversion[0] == 5 and kversion[1] >= 4)
    except ValueError:
        kvok = False
    if kvok:
        os.pidfd_open = pidfd_open


def setns(fd, nstype):  # noqa: D402
    """See setns(2) manpage."""
    if not libc:
        _load_libc()

    if libc.setns(int(fd), int(nstype)) == -1:
        raise_oserror(ctypes.get_errno())


def unshare(flags):  # noqa: D402
    """See unshare(2) manpage."""
    if not libc:
        _load_libc()

    if libc.unshare(int(flags)) == -1:
        raise_oserror(ctypes.get_errno())


CLONE_NEWTIME = 0x00000080
CLONE_VM = 0x00000100
CLONE_FS = 0x00000200
CLONE_FILES = 0x00000400
CLONE_SIGHAND = 0x00000800
CLONE_PIDFD = 0x00001000
CLONE_PTRACE = 0x00002000
CLONE_VFORK = 0x00004000
CLONE_PARENT = 0x00008000
CLONE_THREAD = 0x00010000
CLONE_NEWNS = 0x00020000
CLONE_SYSVSEM = 0x00040000
CLONE_SETTLS = 0x00080000
CLONE_PARENT_SETTID = 0x00100000
CLONE_CHILD_CLEARTID = 0x00200000
CLONE_DETACHED = 0x00400000
CLONE_UNTRACED = 0x00800000
CLONE_CHILD_SETTID = 0x01000000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_IO = 0x80000000

clone_flag_names = {
    CLONE_NEWTIME: "CLONE_NEWTIME",
    CLONE_VM: "CLONE_VM",
    CLONE_FS: "CLONE_FS",
    CLONE_FILES: "CLONE_FILES",
    CLONE_SIGHAND: "CLONE_SIGHAND",
    CLONE_PIDFD: "CLONE_PIDFD",
    CLONE_PTRACE: "CLONE_PTRACE",
    CLONE_VFORK: "CLONE_VFORK",
    CLONE_PARENT: "CLONE_PARENT",
    CLONE_THREAD: "CLONE_THREAD",
    CLONE_NEWNS: "CLONE_NEWNS",
    CLONE_SYSVSEM: "CLONE_SYSVSEM",
    CLONE_SETTLS: "CLONE_SETTLS",
    CLONE_PARENT_SETTID: "CLONE_PARENT_SETTID",
    CLONE_CHILD_CLEARTID: "CLONE_CHILD_CLEARTID",
    CLONE_DETACHED: "CLONE_DETACHED",
    CLONE_UNTRACED: "CLONE_UNTRACED",
    CLONE_CHILD_SETTID: "CLONE_CHILD_SETTID",
    CLONE_NEWCGROUP: "CLONE_NEWCGROUP",
    CLONE_NEWUTS: "CLONE_NEWUTS",
    CLONE_NEWIPC: "CLONE_NEWIPC",
    CLONE_NEWUSER: "CLONE_NEWUSER",
    CLONE_NEWPID: "CLONE_NEWPID",
    CLONE_NEWNET: "CLONE_NEWNET",
    CLONE_IO: "CLONE_IO",
}


def clone_flag_string(flags):
    ns = [v for k, v in clone_flag_names.items() if k & flags]
    if ns:
        return "|".join(ns)
    return "None"


namespace_files = {
    CLONE_NEWUSER: "ns/user",
    CLONE_NEWCGROUP: "ns/cgroup",
    CLONE_NEWIPC: "ns/ipc",
    CLONE_NEWUTS: "ns/uts",
    CLONE_NEWNET: "ns/net",
    CLONE_NEWPID: "ns/pid_for_children",
    CLONE_NEWNS: "ns/mnt",
    CLONE_NEWTIME: "ns/time_for_children",
}

PR_SET_PDEATHSIG = 1
PR_GET_PDEATHSIG = 2
PR_SET_NAME = 15
PR_GET_NAME = 16


def set_process_name(name):
    if not libc:
        _load_libc()

    # Why does uncommenting this cause failure?
    # libc.prctl.argtypes = (
    #     ctypes.c_int,
    #     ctypes.c_ulong,
    #     ctypes.c_ulong,
    #     ctypes.c_ulong,
    #     ctypes.c_ulong,
    # )

    s = ctypes.create_string_buffer(bytes(name, encoding="ascii"))
    sr = ctypes.byref(s)
    libc.prctl(PR_SET_NAME, sr, 0, 0, 0)


def set_parent_death_signal(signum):
    if not libc:
        _load_libc()

    # Why does uncommenting this cause failure?
    libc.prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )

    libc.prctl(PR_SET_PDEATHSIG, signum, 0, 0, 0)
