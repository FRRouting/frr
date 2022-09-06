#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Extensions for interactive topotato runs (pausing & potatool)
"""
# pylint: disable=unused-argument,no-self-use

import os
import code
import json

import typing
from typing import Any, Callable, Dict

import pytest
from .utils import LockedFile, AtomicPublishFile

if typing.TYPE_CHECKING:
    from .base import TopotatoItem


taskbasedir = "/tmp/topotato-%s" % os.uname().nodename


class Interactive:
    taskid: str
    taskdir: str
    taskfile: LockedFile
    statefile: AtomicPublishFile
    session: pytest.Session

    pause_on_fail: bool = False

    def __init__(self):
        if not os.path.isdir(taskbasedir):
            os.mkdir(taskbasedir)
            os.chmod(taskbasedir, 0o1777)

    def _post(self, content: Dict[str, Any]):
        with self.statefile as fd:
            fd.write(json.dumps(content))

    @pytest.hookimpl()
    def pytest_addoption(self, parser, pluginmanager):
        parser.addoption(
            "--pause-on-fail",
            action="store_const",
            const=True,
            default=None,
            help="pause test execution on failure",
        )
        parser.addoption(
            "--id",
            type=str,
            default=None,
            help="set identifier for this topotato run (for potatool)",
        )

    @pytest.hookimpl()
    def pytest_sessionstart(self, session):
        session.interactive = self
        self.session = session

        self.pause_on_fail = bool(session.config.getoption("--pause-on-fail"))

        taskid_opt = session.config.getoption("--id")
        if taskid_opt:
            taskids = [taskid_opt]
        else:
            taskids = [str(i) for i in range(0, 99999)]

        last_exc = None
        for taskid in taskids:
            try:
                # this is atomic; if we succeed in creating a directory we can be
                # sure it didn't already exist, so it's entirely ours.
                taskdir = os.path.join(taskbasedir, taskid)
                os.mkdir(taskdir)
                break
            except FileExistsError as e:
                last_exc = e
                continue
        else:
            raise EnvironmentError(
                "failed to set up topotato run directory"
            ) from last_exc

        self.taskdir = taskdir
        self.taskid = taskid

        self.taskfile = LockedFile(os.path.join(taskdir, "lock"))
        self.statefile = AtomicPublishFile(os.path.join(taskdir, "state"), "w")

        self.taskfile.lock()
        self._post(
            {
                "status": "starting",
            }
        )

        # FIXME
        from .nswrap import LinuxNamespace

        LinuxNamespace.taskdir = taskdir

    @pytest.hookimpl()
    def pytest_topotato_run(self, item: "TopotatoItem", testfunc: Callable):
        self._post(
            {
                "status": "running",
                "nodeid": item.nodeid,
            }
        )

    @pytest.hookimpl()
    def pytest_topotato_failure(self, item, excinfo, excrepr, codeloc):
        if not self.pause_on_fail:
            return

        tw = item.session.config.get_terminal_writer()
        tw.line("")
        tw.sep("=", "paused on failure", bold=True, purple=True)
        excrepr.toterminal(tw)
        tw.line("")
        tw.sep("^", "paused on failure", bold=True, purple=True)

        code.interact(local=codeloc.frame.f_locals)
