# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# December 31 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""
Test static route functionality
"""
import datetime
import logging
import os
import re
import time

import pytest
from lib.common_config import step
from lib.topogen import Topogen
from munet.base import Timeout
from munet.watchlog import WatchLog

pytestmark = [pytest.mark.staticd]


@pytest.fixture(scope="function")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def scan_for_match(wl, regex, timeout=30):
    regex = re.compile(regex)
    to = Timeout(timeout)
    logging.debug("scanning %s for %s", wl.path, regex)
    while to:
        content = wl.snapshot_refresh()
        if m := regex.search(content):
            logging.debug("found '%s' in %s", m.group(0), wl.path)
            return m
        time.sleep(0.5)
    raise TimeoutError(f"timeout waiting for {regex} in {wl.path}")

def test_quit_during_config(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1g = tgen.gears["r1"]
    r1 = r1g.net
    wl = WatchLog(r1.rundir / "mgmtd.log")

    # Get a config file with `count` static IPv4 routes
    count = 10 * 1024
    config_file = os.path.join(r1.logdir, "bigconfig.conf")
    with open(config_file, "w") as cfile:
        for i in range((1 << 24), (1 << 24) + count * 4, 4):
            dq0 = (i >> 24) & 0xff
            dq1 = (i >> 16) & 0xff
            dq2 = (i >> 8) & 0xff
            dq3 = i & 0xff
            cfile.write(f"ip route {dq0}.{dq1}.{dq2}.{dq3}/30 101.0.0.2\n")

    step(f"add {count} static routes", reset=True)
    load_command = 'vtysh -f "{}"'.format(config_file)

    wl.snapshot()
    config_proc = r1.popen(load_command)
    try:

        # Wait for part of the configuration to start being applied
        scan_for_match(wl, re.escape(r"ip route 1.0.1.0/30 101.0.0.2"))
        logging.info("partial config applied, waiting for completion")

        # Now stop the router to see if we get any core files
        r1.stopRouter(False)
    finally:
        if config_proc:
            config_proc.kill()
