#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_static_spurious_route_install.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_static_spurious_route_install.py: test that static routes don't
get reinstalled when interface information changes.
"""

import os
import re
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topolog import logger

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    topodef = {
        "s1": ("r1")
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(f"{CWD}/{router.name}/frr.conf")

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def parse_uptime(uptime):
    "Parse the format 00:00:00 into seconds"
    match = re.match(r"(\d+):(\d+):(\d+)", uptime)
    assert match is not None
    return (int(match[1]) * 60 * 60) + (int(match[2]) * 60) + int(match[3])


def test_static_route_no_flap():
    "Test that static route doesn't flap when interface update is received"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(60, "introduce some route uptime")

    # Get initial uptime
    route_output = tgen.gears["r1"].vtysh_cmd("show ip route json", isjson=True)
    uptime_before = parse_uptime(route_output["192.168.1.0/24"][0]["uptime"])

    # Change the interface MTU
    tgen.gears["r1"].run("ip link set r1-eth0 mtu 1490")

    # Wait for zebra to actually process the interface notification before
    # looking at route uptime, otherwise we might read a stale value that
    # predates a delayed (and asynchronous) route reinstall.
    def interface_mtu_updated():
        iface_output = tgen.gears["r1"].vtysh_cmd("show interface r1-eth0 json", isjson=True)
        return iface_output["r1-eth0"]["mtu"] == 1490

    _, result = topotest.run_and_expect(interface_mtu_updated, True, count=15, wait=1)
    assert result, "zebra did not process the interface MTU update"

    # Now that the interface update was processed, keep sampling uptime for
    # a while to make sure it keeps increasing (i.e. the route never gets
    # reinstalled), instead of stopping at the first sample that happens to
    # look fine.
    uptime_after = uptime_before
    for _ in range(5):
        topotest.sleep(3, "waiting uptime to change")
        route_output = tgen.gears["r1"].vtysh_cmd("show ip route json", isjson=True)
        uptime_after = parse_uptime(route_output["192.168.1.0/24"][0]["uptime"])
        logger.info(f"Checking current route uptime: before {uptime_before} now {uptime_after}")
        assert uptime_before < uptime_after, (
            f"static route flapped: uptime in seconds before {uptime_before} after {uptime_after}"
        )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
