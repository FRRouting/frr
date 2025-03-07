#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_msdp_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2024 by
# Adriano Marto Reis <adrianomarto@gmail.com>
#

"""
test_msdp_topo2.py: Test the FRR PIM MSDP peer.

          ────────────────────►
              shortest path
                   ┌──┐
           ┌───────┤r2├───────┐
sender     │  s1   └──┘   s2  │   receiver
 ┌──┐    ┌─┴┐               ┌─┴┐    ┌──┐
 │h1├────┤r1│               │r5├────┤h2│
 └──┘ s6 └─┬┘               └─┬┘ s7 └──┘
           │   ┌──┐    ┌──┐   │
           └───┤r3├────┤r4├───┘
           s3  └──┘ s4 └──┘  s5
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

app_helper = McastTesterHelper()

MCAST_ADDR = "229.1.2.3"

def build_topo(tgen):
    "Build function"

    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s6")
    tgen.add_host("h1", "192.168.6.100/24", "via 192.168.6.1")
    switch.add_link(tgen.gears["h1"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s7")
    tgen.add_host("h2", "192.168.7.100/24", "via 192.168.7.5")
    switch.add_link(tgen.gears["h2"])
    switch.add_link(tgen.gears["r5"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():

        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

        daemon_file = "{}/{}/bgpd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_BGP, daemon_file)

        daemon_file = "{}/{}/pimd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_PIM, daemon_file)

    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def test_bgp_convergence():
    """
    Wait for BGP protocol convergence
    All the loopback addresses (10.254.254.x) must be reachable from all
    routers.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    routes = {
        "r1": "10.254.254.1/32",
        "r2": "10.254.254.2/32",
        "r3": "10.254.254.3/32",
        "r4": "10.254.254.4/32",
        "r5": "10.254.254.5/32",
    }

    for router1 in routes.keys():
        for router2, route in routes.items():
            if router1 != router2:
                logger.info("waiting route {} in {}".format(route, router1))
                test_func = partial(
                    topotest.router_json_cmp,
                    tgen.gears[router1],
                    "show ip route json",
                    {route: [{"protocol": "bgp"}]},
                )
                _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
                assertmsg = '"{}" convergence failure'.format(router1)
                assert result is None, assertmsg


def test_msdp_peers():
    """
    Waits for the MSPD peer connections to be established.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected_msdp_peers = {
        "r1": {
            "192.168.1.2": {
                "peer": "192.168.1.2",
                "local": "192.168.1.1",
                "state": "established",
            },
            "192.168.3.3": {
                "peer": "192.168.3.3",
                "local": "192.168.3.1",
                "state": "established",
            },
        },
        "r2": {
            "192.168.1.1": {
                "peer": "192.168.1.1",
                "local": "192.168.1.2",
                "state": "established",
            },
            "192.168.2.5": {
                "peer": "192.168.2.5",
                "local": "192.168.2.2",
                "state": "established",
            },
        },
        "r3": {
            "192.168.3.1": {
                "peer": "192.168.3.1",
                "local": "192.168.3.3",
                "state": "established",
            },
            "192.168.4.4": {
                "peer": "192.168.4.4",
                "local": "192.168.4.3",
                "state": "established",
            },
        },
        "r4": {
            "192.168.4.3": {
                "peer": "192.168.4.3",
                "local": "192.168.4.4",
                "state": "established",
            },
            "192.168.5.5": {
                "peer": "192.168.5.5",
                "local": "192.168.5.4",
                "state": "established",
            },
        },
        "r5": {
            "192.168.2.2": {
                "peer": "192.168.2.2",
                "local": "192.168.2.5",
                "state": "established",
            },
            "192.168.5.4": {
                "peer": "192.168.5.4",
                "local": "192.168.5.5",
                "state": "established",
            },
        },
    }

    for router, peers in expected_msdp_peers.items():
        logger.info("Waiting for {} msdp peer data".format(router))
        test_function = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip msdp peer json",
            peers,
        )
        _, val = topotest.run_and_expect(test_function, None, count=30, wait=1)
        assert val is None, "multicast route convergence failure"


def test_msdp_sa():
    """
    Waits for the MSDP SA to be propagated.
    The MSDP SA must be present on all routers. The MSDP SA must indicate
    the original RP.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run("h1", ["--send=0.7", MCAST_ADDR, "h1-eth0"])
    app_helper.run("h2", [MCAST_ADDR, "h2-eth0"])

    expected_sa_r1 = {
        MCAST_ADDR: {
            "192.168.6.100": {
                "source": "192.168.6.100",
                "group": MCAST_ADDR,
                "rp": "-",
                "local": "yes",
            }
        }
    }

    expected_sa_r2_r3_r4_r5 = {
        MCAST_ADDR: {
            "192.168.6.100": {
                "source": "192.168.6.100",
                "group": MCAST_ADDR,
                "rp": "10.254.254.1",
                "local": "no",
            }
        }
    }

    expected_sa = {
        "r1": expected_sa_r1,
        "r2": expected_sa_r2_r3_r4_r5,
        "r3": expected_sa_r2_r3_r4_r5,
        "r4": expected_sa_r2_r3_r4_r5,
        "r5": expected_sa_r2_r3_r4_r5,
    }

    for router, sa in expected_sa.items():
        logger.info("Waiting for {} msdp peer data".format(router))
        test_function = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip msdp sa json",
            sa,
        )
        _, val = topotest.run_and_expect(test_function, None, count=30, wait=1)
        assert val is None, "multicast route convergence failure"


def test_mroute():
    """
    Wait for the multicast routes.
    The multicast routes must connect the shortest path between h1 and h2:
    h1 ─► r1 ─► r2 ─► r5 ─► h2

    The routers r3 and r4 must have no multicast routes, as they are not
    included in the shortest path between h1 and h2.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run("h1", ["--send=0.7", MCAST_ADDR, "h1-eth0"])
    app_helper.run("h2", [MCAST_ADDR, "h2-eth0"])

    expected_mroutes = {
        "r1": {
            MCAST_ADDR: {
                "192.168.6.100": {
                    "iif": "r1-eth2",
                    "oil": {
                        "r1-eth0": {"source": "192.168.6.100", "group": MCAST_ADDR},
                        "r1-eth1": None,
                    },
                },
            },
        },
        "r2": {
            MCAST_ADDR: {
                "192.168.6.100": {
                    "iif": "r2-eth0",
                    "oil": {
                        "r2-eth1": {"source": "192.168.6.100", "group": MCAST_ADDR},
                    },
                },
            },
        },
        "r3": {
        },
        "r4": {
        },
        "r5": {
            MCAST_ADDR: {
                "192.168.6.100": {
                    "iif": "r5-eth0",
                    "oil": {
                        "r5-eth1": None,
                        "r5-eth2": {"source": "192.168.6.100", "group": MCAST_ADDR},
                    },
                },
            },
        },
    }

    for router, mroute in expected_mroutes.items():
        logger.info("Waiting for {} mroute data".format(router))
        test_function = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip mroute json",
            mroute,
        )
        _, val = topotest.run_and_expect(test_function, None, count=30, wait=1)
        assert val is None, "mroute convergence failure"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
