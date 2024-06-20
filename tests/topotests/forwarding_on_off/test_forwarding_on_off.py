#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_forwarding_on_off.py
#
# Copyright (c) 2024 by Nvidia Corporation
# Donald Sharp
#

"""
test_forwarding_on_off.py: Test that forwarding is turned off then back on

"""

import ipaddress
import json
import pytest
import sys
import time

from functools import partial
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.checkping import check_ping

pytestmark = [
    pytest.mark.staticd,
]


def build_topo(tgen):
    """Build the topology used by all tests below."""

    # Create 3 routers
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    # Add a link between r1 <-> r2 and r2 <-> r3
    tgen.add_link(r1, r2, ifname1="eth0", ifname2="eth0")
    tgen.add_link(r2, r3, ifname1="eth1", ifname2="eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_no_forwarding():
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    def _no_forwarding(family, status):
        logger.info("Testing for: {} {}".format(family, status))
        rc, o, e = r2.net.cmd_status(
            'vtysh -c "show zebra" | grep "{}" | grep "{}"'.format(family, status)
        )

        logger.info("Output: {}".format(o))
        return rc

    test_func = partial(_no_forwarding, "v4 Forwarding", "Off")
    _, result = topotest.run_and_expect(test_func, 0, count=15, wait=1)
    assert result == 0

    test_func = partial(_no_forwarding, "v6 Forwarding", "Off")
    _, result = topotest.run_and_expect(test_func, 0, count=15, wait=1)
    assert result == 0

    logger.info("Sending pings that should fail")
    check_ping("r1", "10.1.1.3", False, 10, 1)
    check_ping("r1", "10:1::1:3", False, 10, 1)

    logger.info("Turning on Forwarding")
    r2.vtysh_cmd("conf\nip forwarding\nipv6 forwarding")

    test_func = partial(_no_forwarding, "v4 Forwarding", "On")
    _, result = topotest.run_and_expect(test_func, 0, count=15, wait=1)
    assert result == 0

    test_func = partial(_no_forwarding, "v6 Forwarding", "On")
    _, result = topotest.run_and_expect(test_func, 0, count=15, wait=1)
    assert result == 0

    check_ping("r1", "10.1.1.3", True, 10, 1)
    check_ping("r1", "10:1::1:3", True, 10, 1)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
