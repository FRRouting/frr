#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
Auxiliary watcher module to externally attach to topotato test runs.

This module is NOT used from within topotato runs, it is for tools that are
started independently.
"""

import os
import logging
from pathlib import Path
import subprocess
import shlex
import json
import signal
from os import tcgetpgrp, tcsetpgrp
from termios import tcgetattr, tcsetattr, TCSAFLUSH

from typing import (
    Any,
    ClassVar,
    Dict,
    Optional,
    Union,
)

try:
    from pyinotify import WatchManager, IN_CREATE, IN_MOVED_TO, IN_DELETE  # type: ignore
    from pyinotify import Event as InoEvent  # type: ignore
except ImportError:

    class WatchManager:  # type: ignore
        def add_watch(self, dirname, mask, proc_fun):
            pass

    class InoEvent:  # type: ignore
        name: str
        mask: int

    IN_CREATE = 0
    IN_MOVED_TO = 0
    IN_DELETE = 0

from . import interactive
from .utils import Forked
from .nswrap import unshare, setns, CLONE_NEWNS

_logger = logging.getLogger(__name__)

_PathLike = Union[os.PathLike, str, bytes]
_selfpath = Path(os.path.abspath(__file__)).parent
_taskbasedir = Path(interactive.taskbasedir)

_wm_mask = IN_CREATE | IN_DELETE | IN_MOVED_TO


def _getlockpid(filename: _PathLike) -> Optional[int]:
    """
    Call fcntl(F_GETLK) via external helper.

    Sadly this is not currently provided in python's fcntl module.
    """
    try:
        # pylint: disable=consider-using-with
        pid = subprocess.check_output(
            [os.fspath(_selfpath.parent / "getlockpid"), os.fspath(filename)],
            shell=False,
            stderr=open("/dev/null", "wb"),
        )
        return int(pid)
    except subprocess.CalledProcessError as e:
        if e.returncode == 2:
            # not locked
            return None
        raise


class WatchedSession:
    """
    Enumerate and access topotato / pytest sessions.

    This has functionality on the class (enumeration) and instance (access)
    level.  The class itself tracks which pytest sessions are running;
    instances are created for specific sessions.

    Optionally uses pyinotify to automatically track changes.
    """

    # class

    instances: ClassVar[Dict[str, "WatchedSession"]] = {}
    """All pytest sessions that were found.  Some may be dead."""
    running: ClassVar[Dict[str, "WatchedSession"]] = {}
    """Currently running pytest sessions."""
    _wm: ClassVar[Optional[WatchManager]] = None
    """pyinotify WatchManager used for change tracking"""

    # instance

    name: str
    _dirname: Path
    pid: Optional[int]
    state: Dict[Any, Any]
    """state dictionary as published by :py:class:`interactive.Interactive`."""
    routers: Dict[str, "WatchedSession.Router"]
    """currently running virtual routers/namespaces in this session"""

    # pylint: disable=unused-argument
    def __new__(cls, name, *args, **kwargs):
        """
        Singleton-ize WatchedSession by name of the run
        """
        if name not in cls.instances:
            if not (_taskbasedir / name).is_dir():
                raise RuntimeError(
                    "%s must be a directory for WatchedSession" % _taskbasedir / name
                )

            cls.instances[name] = super().__new__(cls)

        return cls.instances[name]

    def __init__(self, name: str, *, wm: Optional[WatchManager]):
        self.name = name
        self._dirname = _taskbasedir / name
        self.pid = None
        self.state = {}
        self.routers = {}

        if wm is not None:
            wm.add_watch(os.fspath(self._dirname), _wm_mask, proc_fun=self._ino_process)

        for filename in os.listdir(self._dirname):
            if filename.endswith(".tmp") or filename.startswith("."):
                continue
            if filename.startswith("ns-"):
                self._router_setup(filename)

        self.update()

    def __repr__(self):
        return f"<{self.__class__.__name__} name={self.name!r} pid={self.pid!r}>"

    def _update(self):
        self.state = {}

        lockfilename = self._dirname / "lock"
        if not lockfilename.is_file():
            self.pid = None
            return
        self.pid = _getlockpid(lockfilename)
        if self.pid is None:
            return

        statefilename = self._dirname / "state"
        try:
            with open(statefilename, "rb") as fd:
                self.state = json.load(fd)
        except FileNotFoundError:
            _logger.info(
                "state file %s not found, hung/crashed topotato run?", statefilename
            )
        except json.decoder.JSONDecodeError:
            _logger.info(
                "state file %s failed to decode, hung/crashed topotato run?",
                statefilename,
            )

    @classmethod
    def session_started(cls, inst):
        """
        Instance transitioned to running.

        Extended in potatool for selection tracking.
        """
        cls.running[inst.name] = inst

    @classmethod
    def session_stopped(cls, inst):
        """
        Instance transitioned to stopped.

        Extended in potatool for selection tracking.
        """
        del cls.running[inst.name]

    def update(self):
        """
        Refresh state of this instance from ``/tmp``.
        """

        keys = ["status", "when", "nodeid", "outcome"]

        _oldpid = self.pid
        _oldstate = (self.state.get(k) for k in keys)
        self._update()
        _newstate = (self.state.get(k) for k in keys)

        if self.pid is None:
            if _oldpid:
                _logger.debug("topotato[%s](%r) has exited", self.name, _oldpid)
                self.session_stopped(self)
            return

        if _oldpid is None:
            self.session_started(self)

        if _oldstate != _newstate or _oldpid is None:
            if self.state.get("when") in {"call", None}:
                _logger.debug(
                    "topotato[%s](%r): %s %s",
                    self.name,
                    self.pid,
                    self.state.get("status"),
                    self.state.get("nodeid"),
                )

    def _router_setup(self, filename):
        rtrname = filename[3:]
        if rtrname in self.routers:
            return

        self.routers[rtrname] = self.Router(self, rtrname)

    def _router_teardown(self, filename):
        rtrname = filename[3:]
        if rtrname not in self.routers:
            return

        del self.routers[rtrname]

    def _ino_process(self, event: InoEvent):
        """
        Event handler for pyinotify change notifications inside a session dir.

        Not to be confused with :py:meth:`_ino_process_root`, this is called
        for changes inside a topotato session's temporary directory.  The
        ``state`` and ``lock`` files we're interested in are created with
        atomic create-write-rename, so the relevant event here isn't *CREATE*,
        *WRITE* or *CLOSE* but rather *MOVED_TO*.  This way we shouldn't ever
        end up seeing incomplete/unfinished data.
        """
        if event.name.startswith(".") or event.name.endswith(".tmp"):
            return
        if event.name in ["state", "lock"]:
            self.update()
        if event.name.startswith("ns-"):
            if event.mask & (IN_CREATE | IN_MOVED_TO):
                self._router_setup(event.name)
            if event.mask & IN_DELETE:
                self._router_teardown(event.name)

    @classmethod
    def start_watch(cls, wm: WatchManager):
        """
        Enumerate and begin monitoring topotato sessions.

        Calls :py:meth:`load` after registering the pyinotify watch.
        """
        cls._wm = wm
        wm.add_watch(os.fspath(_taskbasedir), _wm_mask, proc_fun=cls._ino_process_root)
        cls.load()

    @classmethod
    def load(cls):
        """One-shot scan for currently running topotato sessions."""
        try:
            os.mkdir(_taskbasedir)
        except FileExistsError:
            pass

        for filename in os.listdir(_taskbasedir):
            if filename.startswith(".") or filename.endswith(".tmp"):
                continue
            cls(filename, wm=cls._wm)

    @classmethod
    def _ino_process_root(cls, event: InoEvent):
        """
        Event handler for pyinotify change notifications on session directory.

        Subdirectories of the session directory correspond 1:1 to topotato
        sessions.  Not to be confused with :py:meth:`_ino_process`.
        """
        if event.name.startswith(".") or event.name.endswith(".tmp"):
            return
        if not (_taskbasedir / event.name).is_dir():
            return

        run = cls(event.name, wm=cls._wm)
        run.update()

    class Router:
        """
        Represent a virtual router/namespace inside a topotato session.

        This is under :py:class:`WatchedSession` to aid subclassing both
        classes in a compound manner.
        """

        session: "WatchedSession"
        name: str
        pid: Optional[int]

        def __init__(self, running: "WatchedSession", name: str):
            self.running = running
            self.name = name

            self.pid = _getlockpid(os.path.join(self.running._dirname, "ns-" + name))

        def __repr__(self):
            return f"<{self.__class__.__name__} name={self.name!r} pid={self.pid!r}>"

        # pylint: disable=too-many-locals
        def run(self, cmd):
            """
            Execute command inside this router.

            .. todo::

               This is really specific to :py:mod:`topotato.nswrap` and should
               be moved there/integrated with that.
            """
            with Forked(shlex.join(cmd)) as is_child:
                if not is_child:
                    return

                # FD leaks beyond this point are luckily irrelevant since
                # we're in the forked child.

                def ns_open(nstype):
                    return os.open(
                        f"/proc/{ self.pid }/ns/{ nstype }", os.O_RDONLY | os.O_CLOEXEC
                    )

                # become root inside userns first
                nsfd = ns_open("user")
                setns(nsfd)
                os.close(nsfd)

                nsfds = []

                # open everything first, won't work after joining mnt/pid namespace
                for nstype in ["net", "uts", "mnt", "pid_for_children"]:
                    nsfds.append((nstype, ns_open(nstype)))

                for nstype, nsfd in nsfds:
                    if nstype == "mnt":
                        # kernel bug workaround, cf. nswrap.py
                        unshare(CLONE_NEWNS)

                    setns(nsfd)
                    os.close(nsfd)

                # pseudo-shell job control, let's get started...
                orig_pgrp = tcgetpgrp(0)
                orig_term = tcgetattr(0)
                # tcsetpgrp will send SIGTTOU
                signal.signal(signal.SIGTTOU, signal.SIG_IGN)

                # synchronize with child setting up its pgrp
                rdfd, wrfd = os.pipe2(os.O_CLOEXEC)

                pid = os.fork()
                if pid == 0:
                    os.close(rdfd)
                    pid = os.getpid()
                    # create pgrp and take ownership of terminal
                    os.setpgid(pid, pid)
                    tcsetpgrp(0, pid)

                    # reset signals to sane behavior
                    for sig in [
                        signal.SIGHUP,
                        signal.SIGINT,
                        signal.SIGTERM,
                        signal.SIGTSTP,
                        signal.SIGTTIN,
                        signal.SIGTTOU,
                    ]:
                        signal.signal(sig, signal.SIG_DFL)

                    # pipe closed as side effect (CLOEXEC)
                    os.execlp(cmd[0], *cmd)

                os.close(wrfd)
                # just wait for pipe to get closed
                os.read(rdfd, 1)
                os.close(rdfd)

                rc = None
                while rc is None:
                    _, status = os.waitpid(pid, os.WUNTRACED)
                    if os.WIFSTOPPED(status):
                        # potatool doesn't implement job control - so just
                        # stop ourselves along with the child.  but first,
                        # claim back terminal & settings
                        tcsetpgrp(0, orig_pgrp)
                        child_term = tcgetattr(0)
                        tcsetattr(0, TCSAFLUSH, orig_term)

                        # ...and then stop the entire pgrp
                        os.killpg(orig_pgrp, os.WSTOPSIG(status))
                        # ... zZzZzZ ...

                        # give terminal back to child and resume it
                        tcsetattr(0, TCSAFLUSH, child_term)
                        tcsetpgrp(0, pid)
                        os.killpg(pid, signal.SIGCONT)
                    else:
                        rc = os.waitstatus_to_exitcode(status)

                tcsetpgrp(0, orig_pgrp)
                tcsetattr(0, TCSAFLUSH, orig_term)
                # pylint: disable=protected-access
                os._exit(rc)
