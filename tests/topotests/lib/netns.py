# SPDX-License-Identifier: GPL-3.0-only
# Author: Lars Kellogg-Stedman
# https://pypi.org/project/netns/#description
# https://github.com/larsks/python-netns/commits/master/netns.py

import os
import socket as socket_module

# Python doesn't expose the `setns()` function manually, so
# we'll use the `ctypes` module to make it available.
import ctypes
import ctypes.util

CLONE_NEWIPC = 0x08000000
CLONE_NEWNET = 0x40000000
CLONE_NEWUTS = 0x04000000

NETNS_RUN_DIR = "/var/run/netns"


def errcheck(ret, func, args):
    if ret == -1:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.setns.errcheck = errcheck


def setns(fd, nstype):
    """Change the network namespace of the calling thread.

    Given a file descriptor referring to a namespace, reassociate the
    calling thread with that namespace.  The fd argument may be either a
    numeric file  descriptor or a Python object with a fileno() method.
    """

    if hasattr(fd, "fileno"):
        fd = fd.fileno()

    return libc.setns(fd, nstype)


def socket(nspath, *args):
    """Return a socket from a network namespace.

    This is a wrapper for socket.socket() that will return a socket
    inside the namespace specified by the nspath argument, which should be
    a filesystem path to an appropriate namespace file.  You can use the
    get_ns_path() function to generate an appropriate filesystem path if
    you know a namespace name or pid.
    """

    with NetNS(nspath=nspath):
        return socket_module.socket(*args)


def get_ns_path(nspath=None, nsname=None, nspid=None):
    """Generate a filesystem path from a namespace name or pid.

    Generate a filesystem path from a namespace name or pid, and return
    a filesystem path to the appropriate file.  Returns the nspath argument
    if both nsname and nspid are None.
    """

    if nsname:
        nspath = f"{NETNS_RUN_DIR}/{nsname}"
    elif nspid:
        nspath = f"/proc/{nspid}/ns/net"

    if not os.path.exists(nspath):
        raise ValueError(f"namespace path {nspath} does not exist")

    return nspath


class NetNS(object):
    """A context manager for running code inside a network namespace.

    This is a context manager that on enter assigns the current process
    to an alternate network namespace (specified by name, filesystem path,
    or pid) and then re-assigns the process to its original network
    namespace on exit.
    """

    def __init__(self, nsname=None, nspath=None, nspid=None):
        self.mypath = get_ns_path(nspid=os.getpid())
        self.targetpath = get_ns_path(nspath, nsname=nsname, nspid=nspid)

        if not self.targetpath:
            raise ValueError("invalid namespace")

    def __enter__(self):
        # before entering a new namespace, we open a file descriptor
        # in the current namespace that we will use to restore
        # our namespace on exit.
        self.myns = open(self.mypath)
        with open(self.targetpath) as fd:
            setns(fd, CLONE_NEWNET)

    def __exit__(self, *args):
        setns(self.myns, CLONE_NEWNET)
        self.myns.close()
