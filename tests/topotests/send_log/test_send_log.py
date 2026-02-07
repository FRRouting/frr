# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# June 14 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""
Test Logging Config
"""
import re

import pytest
from lib.topogen import Topogen
from munet.testing.util import retry
from munet.watchlog import WatchLog

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()
    tgen.routers()["r1"].load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@retry(retry_timeout=30)
def scan_log(log, regex):
    log.update_content()
    new_content = log.from_mark(log.last_snap_mark)
    assert re.search(regex, new_content)


def test_log(tgen):
    r1 = tgen.net.hosts["r1"]
    log = WatchLog(r1.rundir / "frr.log")

    s = "Foo  Bar  Baz"
    assert s not in log.snapshot()
    r1.cmd_raises(f"vtysh -c 'send log {s}'")
    scan_log(log, re.escape(s))

    s = "Notice Me!"
    assert s not in log.snapshot()
    r1.cmd_raises(f"vtysh -c 'send log level warning {s}'")
    scan_log(log, f"warnings:.*{re.escape(s)}")
