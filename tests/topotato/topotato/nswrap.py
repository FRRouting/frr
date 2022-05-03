# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Base wrapper around Linux network namespaces
"""

import os
import subprocess
import time
import ctypes

from typing import List

_setns = ctypes.cdll.LoadLibrary("libc.so.6").setns


def setns(nsfd: int, nstype: int = 0):
    ret = _setns(nsfd, nstype)
    if ret != 0:
        raise OSError(ctypes.get_errno())


_orig_ns = {}
for _nstype in ["net", "mnt"]:
    _orig_ns[_nstype] = os.open("/proc/self/ns/" + _nstype, os.O_RDONLY)
del _nstype


def find_child(parent: int) -> int:
    """
    trawl /proc to find (a|the) child process of something

    since PID namespaces need an extra fork(), we occasionally need to
    find the child of something we started to send signals to
    """

    for piddir in os.listdir("/proc"):
        if not piddir.isnumeric():
            continue
        pid = int(piddir)

        try:
            with open("/proc/%d/status" % pid, "r", encoding="ascii") as fd:
                status = fd.read().splitlines()
        except FileNotFoundError:
            continue

        ppids = [l for l in status if l.startswith("PPid:")]
        assert len(ppids) == 1
        ppid = int(ppids[0].split("\t")[1])

        if ppid == parent:
            return pid

    raise ValueError("cannot find child process of PID %d" % parent)


class LinuxNamespace:
    """
    wrapper around a network namespace for testing

    sets hostname and spawns a waiter process in the namespace
    """

    name: str
    pid: int

    _exec = {
        "unshare": None,
        "nsenter": None,
        "tini": None,
    }

    def __init__(self, name):
        self.name = name
        self.process = None

    def start(self):
        # pylint: disable=consider-using-with
        self.process = subprocess.Popen(
            [
                self._exec.get("unshare", "unshare"),
                "-u",
                "-m",
                "-n",
                "-p",
                "-f",
                "--mount-proc",
                self._exec.get("tini", "tini"),
                "-g",
                "/bin/sh",
                "--",
                "-c",
                "hostname %s; [ -d /var/tmp/frr ] || mkdir /var/tmp/frr; mount -t tmpfs none /var/tmp/frr; echo IGN; read IGN"
                % (self.name),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            shell=False,
        )
        self.process.stdout.read(1)

        self.pid = find_child(self.process.pid)

        # import logging
        # import shlex
        # logger = logging.getLogger('topotato')
        # with open('/proc/%d/cmdline' % self.pid, 'rb') as fd:
        #    cmdline = [i.decode('UTF-8') for i in fd.read().rstrip(b'\0').split(b'\0')]
        # logger.debug("child pid: %d  cmdline: %s" % (self.pid, shlex.join(cmdline)))

    def end(self):
        """
        stop namespace (and kill everything within)

        since this is a PID namespace and the "read IGN" process above is
        PID 1, killing that process will zap the entire namespace
        """

        self.process.stdin.write(b"\n")
        self.process.stdin.close()
        self.process.wait()
        del self.process

    def prefix(self, kwargs) -> List[str]:
        ret = [
            str(self._exec.get("nsenter", "nsenter")),
            "-t",
            str(self.pid),
            "-m",
            "-u",
            "-n",
            "-p",
        ]
        if "cwd" in kwargs:
            cwd = kwargs.pop("cwd")
            ret.extend(["--wd=%s" % cwd])
        return ret

    def popen(self, cmdline: List[str], *args, **kwargs):
        # pylint: disable=consider-using-with
        return subprocess.Popen(self.prefix(kwargs) + cmdline, *args, **kwargs)

    def check_call(self, cmdline: List[str], *args, **kwargs):
        return subprocess.check_call(self.prefix(kwargs) + cmdline, *args, **kwargs)

    def check_output(self, cmdline: List[str], *args, **kwargs):
        return subprocess.check_output(self.prefix(kwargs) + cmdline, *args, **kwargs)

    def __enter__(self):
        if self.process is None:
            raise ValueError("cannot enter non-running namespace")

        for nstype in _orig_ns:
            nsfd = os.open("/proc/%d/ns/%s" % (self.pid, nstype), os.O_RDONLY)
            try:
                setns(nsfd)
            finally:
                os.close(nsfd)
        return self

    def __exit__(self, type_, value, traceback):
        for nsfd in _orig_ns.values():
            setns(nsfd)


def test():
    ns = LinuxNamespace("test")
    ns.start()
    ns.check_call(["ip", "addr", "list"])
    with ns:
        subprocess.check_call(["ip", "addr", "list"])
    ns.check_call(["/bin/sh", "-c", "sleep 3"])
    time.sleep(3)
    ns.end()
    print("ended")
    time.sleep(3)


if __name__ == "__main__":
    test()
