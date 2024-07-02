# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Base wrapper around Linux network namespaces
"""

import sys
import os
import time
import ctypes
import ctypes.util
import errno

from typing import List, ClassVar

from .defer import subprocess
from .utils import LockedFile

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

_setns = _libc.setns
_setns.argtypes = [ctypes.c_int, ctypes.c_int]
_setns.restype = ctypes.c_int

_unshare = _libc.unshare
_unshare.argtypes = [ctypes.c_int]
_unshare.restype = ctypes.c_int

CLONE_NEWNS = 0x00020000
CLONE_NEWNET = 0x40000000


def setns(nsfd: int, nstype: int = 0):
    ret = _setns(nsfd, nstype)
    if ret != 0:
        _errno = ctypes.get_errno()
        raise OSError(_errno, os.strerror(_errno))


def unshare(nstype: int = 0):
    ret = _unshare(nstype)
    if ret != 0:
        _errno = ctypes.get_errno()
        raise OSError(_errno, os.strerror(_errno))


class LinuxNamespaceJoinFailed(SystemError):
    pass


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

    taskdir: ClassVar[str] = "/tmp/topotato"

    def __init__(self, name):
        self.name = name
        self.process = None

    def start(self):
        # pylint: disable=consider-using-with

        env = dict(os.environ)
        env.update(
            {
                "TOPOTATO_TASKDIR": self.taskdir,
                "TOPOTATO_NSNAME": self.name,
                "TOPOTATO_INNER": "1",
                "PYTHONPATH": ":".join(
                    [os.path.abspath(os.path.dirname(os.path.dirname(__file__)))]
                    + sys.path
                ),
            }
        )

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
                sys.executable,
                "--",
                "-m",
                "topotato.nswrap",
                self.name,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            shell=False,
            env=env,
        )
        # wait for child to tell us it's ready...
        # (match sys.stdout.write("\n") below)
        self.process.stdout.read(1)

        self.pid = find_child(self.process.pid)

        # import logging
        # import shlex
        # logger = logging.getLogger('topotato')
        # with open('/proc/%d/cmdline' % self.pid, 'rb') as fd:
        #    cmdline = [i.decode('UTF-8') for i in fd.read().rstrip(b'\0').split(b'\0')]
        # logger.debug("child pid: %d  cmdline: %s" % (self.pid, shlex.join(cmdline)))

    @staticmethod
    def inner():
        """
        Set up inner namespace details and synchronize with parent.
        """
        nsname = sys.argv[1]
        frrtmp = "/var/tmp/frr"

        subprocess.check_call(["hostname", nsname.replace("_", "-")])
        try:
            os.mkdir(frrtmp)
        except FileExistsError:
            pass
        subprocess.check_call(["mount", "-t", "tmpfs", "none", frrtmp])

        taskfilename = os.path.join(os.environ["TOPOTATO_TASKDIR"], "ns-" + nsname)

        with LockedFile(taskfilename):
            # tell parent we're ready...
            sys.stdout.write("\n")
            sys.stdout.flush()

            # ... and wait for parent to tell us to exit
            sys.stdin.read()

    def end(self):
        """
        stop namespace (and kill everything within)

        since this is a PID namespace and the "read IGN" process above is
        PID 1, killing that process will zap the entire namespace
        """

        if self.process is None:
            return

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
            except OSError as e:
                if nstype == "mnt" and e.errno == errno.EINVAL:
                    try:
                        # KERNEL BUG: 5.18-ish needs the current mntns to have
                        # no other users before switching, so switch to an
                        # empty one as a workaround.  Note this empty one only
                        # exists for the time between unshare() and setns(),
                        # and __exit__ will switch back to the "proper"
                        # original one.

                        unshare(CLONE_NEWNS)
                        setns(nsfd)
                        return self
                    except OSError:
                        # original exception below is more useful
                        pass

                raise LinuxNamespaceJoinFailed(
                    "Failed to enter %s namespace of PID %d" % (nstype, self.pid)
                ) from e

            finally:
                os.close(nsfd)
        return self

    def __exit__(self, type_, value, traceback):
        for nsfd in _orig_ns.values():
            setns(nsfd)


# pylint: disable=duplicate-code
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
    if "TOPOTATO_INNER" in os.environ:
        LinuxNamespace.inner()
        sys.exit(0)

    test()
