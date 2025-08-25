#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
topotato pytest integration / hook module, plumbs everything into pytest.

This is a dumping ground that is slowly getting cleaned up and reduced piece
by piece.
"""

import sys
import os
import time
import logging
import signal

import pytest

from . import hooks
from .utils import EnvcheckResult
from .base import TopotatoItem
from .frr import FRRSetup
from .toponom import LAN
from .interactive import Interactive
from .pretty import PrettySession
from .osdep import NetworkInstance

logger = logging.getLogger("topotato")

# pidns (or tini?) sets these to IGN by default, which isn't quite what we want
signal.signal(signal.SIGINT, signal.default_int_handler)
signal.signal(signal.SIGTERM, signal.SIG_DFL)


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_report_teststatus(report):
    outcome = yield
    res = outcome.get_result()
    if res[2] == "PASSED":
        res = (res[0], res[1], "%s (%.2f)" % (res[2], report.duration))
    outcome.force_result(res)


def pytest_addhooks(pluginmanager):
    pluginmanager.add_hookspecs(hooks)
    pluginmanager.register(NetworkInstance)
    pluginmanager.register(TopotatoItem)
    pluginmanager.register(FRRSetup)
    pluginmanager.register(PrettySession)
    pluginmanager.register(Interactive)


def pytest_addoption(parser):
    parser.addoption(
        "--show-configs",
        action="store_const",
        const=True,
        default=None,
        help="show configurations",
    )
    parser.addoption(
        "--show-config", type=str, default=None, help="show specific configuration"
    )
    parser.addoption(
        "--show-topology", type=str, default=None, help="show specific topology"
    )


# @pytest.hookimpl()
# def pytest_configure(config):
#    pass


@pytest.hookimpl()
def pytest_sessionstart(session):
    tw = session.config.get_terminal_writer()
    session.terminal_writer = tw

    if session.config.getoption("--collect-only"):
        return

    tw.sep("=", "topotato initialization", bold=True)

    envstate = EnvcheckResult()

    session.config.hook.pytest_topotato_envcheck(session=session, result=envstate)

    if os.getuid() != 0:
        envstate.errors.append("topotato must be run as root.")

    for err in envstate.errors:
        if isinstance(err, Exception):
            while err is not None:
                tw.line("ERROR:   %r" % err, red=True, bold=True)
                err = getattr(err, "__cause__", None)
        else:
            tw.line("ERROR:   %s" % err, red=True, bold=True)

    for warn in envstate.warnings:
        tw.line("Warning: %s" % warn, yellow=True, bold=True)

    if not envstate:
        tw.sep("=", "topotato aborting", bold=True)
        raise EnvironmentError("\n".join([str(e) for e in envstate.errors]))


# pylint: disable=unused-argument
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if not isinstance(item, TopotatoItem):
        return

    if getattr(item, "instance", None) is None:
        return

    if not hasattr(item.instance, "reports"):
        item.instance.reports = []

    if report.when == "call":
        report.timestamp = time.time()
        item.instance.reports.append(report)


# pylint: disable=too-many-locals,too-many-branches,too-many-statements,protected-access
@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_collection(session):
    _ = yield

    def topologies():
        for item in session.items:
            if not isinstance(item, TopotatoItem):
                continue
            if item.name != "startup":
                continue
            yield item

    if session.config.getoption("--show-configs"):
        sys.stdout.write("\navailable configs:\n")

        # TODO: refactor for FRRNetworkInstance removal / FRRConfigs rework
        for item in topologies():
            name = item.parent.nodeid

            cfgsetup = item._obj.instancefn.configs
            cfgs = cfgsetup.cfgclass(cfgsetup.net)
            routers = cfgs.generate()

            for rtr, configs in routers.items():
                for cfg, content in configs.items():
                    sys.stdout.write("    %s/%s/%s\n" % (name, rtr, cfg))
            sys.stdout.write("\n")

        session.items = []
        return

    if session.config.getoption("--show-config"):
        which = session.config.getoption("--show-config")
        path = which.split("/")

        # TODO: refactor for FRRNetworkInstance removal / FRRConfigs rework
        for item in topologies():
            name = item.parent.nodeid
            if path[0] != name:
                continue

            cfgsetup = item._obj.instancefn.configs
            cfgs = cfgsetup.cfgclass(cfgsetup.net)
            routers = cfgs.generate()

            for rtr, configs in routers.items():
                if len(path) > 1 and path[1] != rtr:
                    continue
                for cfg, content in configs.items():
                    if len(path) > 2 and path[2] != cfg:
                        continue

                    sys.stdout.write(
                        "\033[33;1m--- %s/%s/%s ---\033[m\n%s\n"
                        % (name, rtr, cfg, content)
                    )
            sys.stdout.write("\n")

        session.items = []
        return

    if session.config.getoption("--show-topology"):
        which = session.config.getoption("--show-topology")

        for item in topologies():
            name = item.parent.nodeid
            if name != which:
                continue

            net = item._obj.instancefn.net

            for rtrname, rtr in net.routers.items():
                sys.stdout.write(
                    "\033[32;1m%s\033[m\n" % (("----- " + rtrname + " ").ljust(60, "-"))
                )
                sys.stdout.write(
                    "\033[36;1m  %16s   %s\033[m\n"
                    % ("lo", ", ".join([str(i) for i in rtr.lo_ip4 + rtr.lo_ip6]))
                )
                for iface in rtr.ifaces:
                    if isinstance(iface.other.endpoint, LAN):
                        other = "\033[35;1m%-10s\033[34;1m" % iface.other.endpoint.name
                    else:
                        other = "\033[32;1m%-10s\033[34;1m" % iface.other.endpoint.name
                    sys.stdout.write(
                        "\033[34;1m  %16s   %s %s\033[m\n"
                        % (
                            iface.ifname,
                            other,
                            ", ".join([str(i) for i in iface.ip4 + iface.ip6]),
                        )
                    )

                sys.stdout.write("\n")

            for lanname, lan in net.lans.items():
                sys.stdout.write(
                    "\033[35;1m%s\033[m\n" % (("----- " + lanname + " ").ljust(60, "-"))
                )
                for iface in lan.ifaces:
                    other = "\033[32;1m%16s\033[34;1m" % iface.other.endpoint.name
                    sys.stdout.write(
                        "\033[34;1m  %s   %s\033[m\n"
                        % (
                            other,
                            ", ".join(
                                [str(i) for i in iface.other.ip4 + iface.other.ip6]
                            ),
                        )
                    )

                sys.stdout.write("\n")

        session.items = []
        return
