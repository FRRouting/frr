#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check that re-applying `bgp graceful-restart restart-time` with the value it
already has does not reset the BGP sessions.

`show running-config` hides the restart-time when it matches the default, so
frr-reload.py sees the line in the config file but not in the running config
and replays it on every single reload. The CLI handler used to unconditionally
re-advertise the Graceful Restart capability, which for peers without dynamic
capability support means tearing the session down.
"""

import os
import sys
import json
import functools
import pytest

from time import sleep

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_gr_restart_time_reload():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "connectionsEstablished": 1,
                "neighborCapabilities": {
                    # Without dynamic capability the peer can only be told
                    # about a capability change by resetting the session,
                    # which is the path this test cares about.
                    "dynamic": None,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    step("Wait for the BGP session to be established")

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Can't converge"

    step("Check that the peer really is in graceful-restart mode")

    output = json.loads(
        r1.vtysh_cmd("show bgp neighbor 192.168.1.2 graceful-restart json")
    )
    expected = {
        "192.168.1.2": {
            "neighborCapabilities": {"gracefulRestart": "advertisedAndReceived"},
            "gracefulRestartInfo": {"localGrMode": "Restart*"},
        }
    }
    assert (
        topotest.json_cmp(output, expected) is None
    ), "Peer is not in graceful-restart mode, the test would be a no-op"

    step("Build a config file that spells out the default restart-time")

    # `write terminal` never emits the restart-time when it's the default one,
    # so add it by hand - this is exactly what a hand-written config looks like.
    config = r1.cmd_raises("vtysh -c 'write terminal no-header'")
    assert (
        "bgp graceful-restart restart-time" not in config
    ), "Default restart-time is unexpectedly shown in the running configuration"

    config = config.replace(
        "router bgp 65001\n",
        "router bgp 65001\n bgp graceful-restart restart-time 120\n",
    )

    reload_conf = os.path.join(str(r1.net.rundir), "reload.conf")
    with open(reload_conf, "w") as fd:
        fd.write(config)

    step("Reload the very same configuration twice")

    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    for _ in range(2):
        r1.cmd_raises("{}/frr-reload.py --reload {}".format(frrdir, reload_conf))

    step("Check that the session was not reset")

    def _bgp_check_session_not_reset():
        output = json.loads(r1.vtysh_cmd("show bgp neighbor 192.168.1.2 json"))
        expected = {
            "192.168.1.2": {
                "bgpState": "Established",
                "connectionsEstablished": 1,
                "messageStats": {
                    "notificationsSent": 0,
                },
            }
        }
        return topotest.json_cmp(output, expected)

    # This is a "nothing happened" assertion, so keep checking for a while
    # instead of stopping at the first success.
    for _ in range(10):
        result = _bgp_check_session_not_reset()
        assert (
            result is None
        ), "Session was reset after reloading the same restart-time: {}".format(result)
        sleep(1)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
