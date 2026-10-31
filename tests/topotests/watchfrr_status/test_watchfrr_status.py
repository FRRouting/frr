#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Verify watchfrr's JSON and text status with healthy monitored daemons."""

import os
import subprocess
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    mod.watchfrr = None
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_frr_config()
    tgen.start_router()

    # Topogen starts daemons directly. Monitor them without managing restarts.
    with open(os.path.join(r1.gearlogdir, "watchfrr.log"), "w") as logfile:
        mod.watchfrr = r1.popen(
            [
                os.path.join(r1.net.daemondir, "watchfrr"),
                "--dry",
                "-p",
                os.path.join(r1.gearlogdir, "watchfrr.pid"),
                "zebra",
                "bgpd",
            ],
            stdout=logfile,
            stderr=subprocess.STDOUT,
        )


def teardown_module(mod):
    try:
        if mod.watchfrr is not None:
            mod.watchfrr.terminate()
            try:
                mod.watchfrr.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mod.watchfrr.kill()
                mod.watchfrr.wait()
    finally:
        get_topogen().stop_topology()


def test_watchfrr_status():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check_status():
        output = r1.vtysh_cmd("show watchfrr json", isjson=True, daemon="watchfrr")
        expected = {
            "allUp": True,
            "daemons": [
                {"name": "zebra", "state": "Up", "ignoreTimeout": False},
                {"name": "bgpd", "state": "Up", "ignoreTimeout": False},
            ],
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(check_status, None, count=30, wait=1)
    assert result is None, "Unexpected watchfrr JSON status: {}".format(result)

    output = r1.vtysh_cmd("show watchfrr", daemon="watchfrr")
    assert "All daemons up: yes" in output, "Unexpected watchfrr text status"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
