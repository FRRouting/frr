#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Extensions for interactive topotato runs (pausing & potatool)
"""
# pylint: disable=unused-argument,no-self-use

import sys
import os
import code
import json
import pickle
import binascii

import typing
from typing import Any, Callable, Dict

import pytest
from . import toponom
from .base import TopotatoItem, TopotatoFunction
from .utils import LockedFile, AtomicPublishFile, deindent

if typing.TYPE_CHECKING:
    from _pytest import nodes
    from .network import TopotatoNetwork


taskbasedir = "/tmp/topotato-%s" % os.uname().nodename
# _interactive_session = pytest.StashKey["Interactive"]()


class Interactive:
    taskid: str
    taskdir: str
    taskfile: LockedFile
    statefile: AtomicPublishFile
    session: pytest.Session

    pause_on_fail: bool = False

    def __init__(self):
        try:
            os.mkdir(taskbasedir)
            os.chmod(taskbasedir, 0o1777)
        except FileExistsError:
            pass

    def _post(self, content: Dict[str, Any]):
        with self.statefile as fd:
            fd.write(json.dumps(content))

    @pytest.hookimpl()
    @staticmethod
    def pytest_addoption(parser, pluginmanager):
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
        parser.addoption(
            "--run-topology",
            action="store_const",
            const=True,
            default=None,
            help="run a test topology",
        )

    @staticmethod
    @pytest.hookimpl(hookwrapper=True, trylast=True)
    def pytest_collection(session):
        _ = yield

        if session.config.getoption("--run-topology"):
            sys.stdout.write("\navailable topologies:\n")

            allitems = session.items
            session.items = []
            for item in allitems:
                if isinstance(item, TopotatoItem) and item.name == "startup":
                    sys.stdout.write(f"    {item.parent.nodeid}\n")
                    session.items.append(item)

            sys.stdout.write("\n")
            if len(session.items) != 1:
                sys.stdout.write(
                    "  More than one topology selected.  Please choose one.\n"
                )
                session.items = []

    @pytest.hookimpl()
    @classmethod
    def pytest_sessionstart(cls, session):
        # self = session.stash[_interactive_session] = cls()
        self = session.interactive_session = cls()
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
        # pylint: disable=import-outside-toplevel
        from .nswrap import LinuxNamespace

        LinuxNamespace.taskdir = taskdir

    @staticmethod
    @pytest.hookimpl()
    def pytest_topotato_run(item: "TopotatoItem", testfunc: Callable):
        # self = item.session.stash[_interactive_session]
        self = item.session.interactive_session  # type: ignore
        # pylint: disable=protected-access
        self._topotato_run(item, testfunc)

    def _topotato_run(self, item: "TopotatoItem", testfunc: Callable):
        state: Dict[str, Any] = {
            "status": "running",
            "nodeid": item.nodeid,
        }
        instance = getattr(item, "instance", None)
        if instance:
            nom = pickle.dumps(instance.network)
            state["nom"] = binascii.b2a_base64(nom, newline=False).decode("ASCII")

            state["routers"] = {}

            for name, rtr in instance.routers.items():
                state["routers"][name] = rtr.interactive_state()

        self._post(state)

    @staticmethod
    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_runtest_call(item):
        # self = item.session.stash[_interactive_session]
        self = item.session.interactive_session

        _ = yield
        if item.session.config.getoption("--run-topology"):
            tw = item.session.config.get_terminal_writer()
            tw.line("")
            tw.sep("═", "paused (--run-topology)", bold=True, purple=True)

            # pylint: disable=protected-access
            self._topotato_stop(item)

    @staticmethod
    def show_diagram(net: toponom.Network, out):
        if not net.diagram:
            return

        text = deindent(net.diagram).strip()
        out.write(
            "\033[37;40;1m%s\033[m\n" % (("━━━━━ topology definition ").ljust(72, "━"))
        )
        out.write("\n")
        for line in text.split("\n"):
            out.write(f"\t{line}\n")
        out.write("\n")

    @staticmethod
    def show_network(net: toponom.Network, out):
        for rtrname, rtr in net.routers.items():
            out.write(
                "\033[32;1m%s\033[m\n" % (("━━━━━ " + rtrname + " ").ljust(72, "━"))
            )
            out.write(
                "\033[36;1m  %16s   %s\033[m\n"
                % ("lo", ", ".join([str(i) for i in rtr.lo_ip4 + rtr.lo_ip6]))
            )
            for iface in rtr.ifaces:
                if isinstance(iface.other.endpoint, toponom.LAN):
                    other = "\033[35;1m→ %-10s\033[34;1m" % iface.other.endpoint.name
                else:
                    other = "\033[32;1m→ %-10s\033[34;1m" % iface.other.endpoint.name
                out.write(
                    "\033[34;1m  %16s   %s %s\033[m\n"
                    % (
                        iface.ifname,
                        other,
                        ", ".join([str(i) for i in iface.ip4 + iface.ip6]),
                    )
                )

        for lanname, lan in net.lans.items():
            out.write(
                "\033[35;1m%s\033[m\n"
                % (("━━━━━ " + lanname + " (LAN) ").ljust(72, "━"))
            )
            for iface in lan.ifaces:
                other = "\033[32;1m%16s\033[34;1m" % iface.other.endpoint.name
                out.write(
                    "\033[34;1m  %s   %s\033[m\n"
                    % (
                        other,
                        ", ".join([str(i) for i in iface.other.ip4 + iface.other.ip6]),
                    )
                )

    def show_banner(self, out):
        out.write(
            "\033[37;40;1m%s\033[m\n" % (("━━━━━ topotato session ").ljust(72, "━"))
        )
        out.write(
            f"""this topotato session is named \033[30;107m { self.taskid } \033[m

to attach to a router in this session, use:
\t\033[37;40;1mpotatool -s { self.taskid } -r \033[32;1mROUTER\033[37;1m shell\033[m

Dropping into python interactive shell.  Use \033[37;40;1mdir()\033[m to see state
available for inspection.  Press \033[37;40;1mCtrl+D\033[m to continue test run.
To modify & run a test item, replace "yield from X.make(...)" with
\033[37;40;1m_yield_from(X.make(...))\033[m.
"""
        )

    def show_instance_for_stop(self, instance: "TopotatoNetwork"):
        network: toponom.Network = instance.network

        self.show_diagram(network, sys.stdout)
        self.show_network(network, sys.stdout)
        sys.stdout.write("\n")
        self.show_banner(sys.stdout)

    @staticmethod
    @pytest.hookimpl()
    def pytest_topotato_failure(item, excinfo, excrepr, codeloc):
        # self = item.session.stash[_interactive_session]
        self = item.session.interactive_session
        # pylint: disable=protected-access
        self._topotato_failure(item, excinfo, excrepr, codeloc)

    def _topotato_failure(self, item, excinfo, excrepr, codeloc):
        if not self.pause_on_fail:
            return

        tw = item.session.config.get_terminal_writer()
        tw.line("")
        tw.sep("═", "paused on failure", bold=True, purple=True)
        excrepr.toterminal(tw)
        tw.line("")
        tw.sep("^", "paused on failure", bold=True, purple=True)

        context = {}
        if codeloc is not None:
            context.update(codeloc.frame.f_globals)
            context.update(codeloc.frame.f_locals)
            context = {
                k: v
                for k, v in context.items()
                if not k.startswith("__") and not k.startswith("@")
            }

        context.update(
            {
                "__excinfo__": excinfo,
            }
        )
        self._topotato_stop(item, context)

    def _topotato_stop(self, item: "nodes.Item", context=None):
        capman = item.config.pluginmanager.getplugin("capturemanager")
        if capman:
            capwhat = capman.is_capturing()
            if capwhat:
                capman.suspend(in_=True)

        context = context or {}
        context["__item__"] = item

        if hasattr(item, "instance"):
            context["_instance"] = item.instance
            self.show_instance_for_stop(item.instance)

        def _yield_from(iterator):
            tests = item.getparent(TopotatoFunction).collect_iter(iter(iterator))

            for value in tests:
                value.instance = item.instance
                value.timeline = item.timeline
                print("_yield_from(): executing test: %r" % (value,))
                value()

        context["_yield_from"] = _yield_from
        try:
            code.interact(local=context, banner="")
        finally:
            if capman:
                capman.resume()
