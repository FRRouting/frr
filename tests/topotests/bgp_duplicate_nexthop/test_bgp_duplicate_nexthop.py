#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_duplicate_nexthop.py
#
# Copyright 2024 6WIND S.A.
#

r"""
 test_bgp_nhg_duplicate_nexthop.py:
 Check that the FRR BGP daemon on r1 selects updates with same nexthops


+---+----+          +---+----+          +--------+
|        |          |        +          |        |
|  r1    +----------+  r3    +----------+  r5    +
|        |          |  rr    +    +-----+        |
+++-+----+          +--------+\  /      +--------+
    |                          \/
    |                          /\
    |               +--------+/  \      +--------+
    |               |        +    +-----+        +
    +---------------+  r4    +----------+  r6    +
                    |        |          |        |
                    +--------+          +--------+
"""

import os
import sys
import json
from functools import partial
import pytest
import functools

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.common_check import ip_check_path_selection, iproute2_check_path_selection
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 7 PE routers.
    tgen.add_router("r1")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    tgen.add_router("r6")

    # switch
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s12")
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s13")
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s14")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        if rname in ("r1", "r3", "r5", "r6"):
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def check_ipv4_prefix_with_multiple_nexthops(prefix, multipath=True):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        f"Check that {prefix} unicast entry is installed with paths for r5 and r6"
    )

    r5_nh = [
        {
            "ip": "192.0.2.5",
            "active": True,
            "recursive": True,
        },
        {
            "ip": "172.31.0.3",
            "interfaceName": "r1-eth1",
            "active": True,
            "labels": [
                16055,
            ],
        },
        {
            "ip": "172.31.2.4",
            "interfaceName": "r1-eth2",
            "active": True,
            "labels": [
                16055,
            ],
        },
    ]

    r6_nh = [
        {
            "ip": "192.0.2.6",
            "active": True,
            "recursive": True,
        },
        {
            "ip": "172.31.0.3",
            "interfaceName": "r1-eth1",
            "active": True,
            "labels": [
                16006,
            ],
        },
        {
            "ip": "172.31.2.4",
            "interfaceName": "r1-eth2",
            "active": True,
            "labels": [
                16006,
            ],
        },
    ]

    expected = {
        prefix: [
            {
                "prefix": prefix,
                "protocol": "bgp",
                "metric": 0,
                "table": 254,
                "nexthops": [],
            }
        ]
    }
    for nh in r5_nh:
        expected[prefix][0]["nexthops"].append(nh)
    if multipath:
        for nh in r6_nh:
            expected[prefix][0]["nexthops"].append(nh)

    test_func = functools.partial(
        ip_check_path_selection, tgen.gears["r1"], prefix, expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assert (
        result is None
    ), f"Failed to check that {prefix} uses the IGP label 16055 and 16006"


def get_nh_formatted(nexthop, fib=True, duplicate=False):
    nh = dict(nexthop)
    if duplicate:
        nh.update({"duplicate": True})
    if fib:
        nh.update({"fib": True})
    return nh


def check_ipv4_prefix_recursive_with_multiple_nexthops(
    prefix, recursive_nexthop, multipath=True
):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info(
        f"Check that {prefix} unicast entry is correctly recursive via {recursive_nexthop} with paths for r5 and r6"
    )

    r5_nh = [
        {
            "ip": "172.31.0.3",
            "interfaceName": "r1-eth1",
            "active": True,
            "labels": [
                16055,
            ],
        },
        {
            "ip": "172.31.2.4",
            "interfaceName": "r1-eth2",
            "active": True,
            "labels": [
                16055,
            ],
        },
    ]

    r6_nh = [
        {
            "ip": "172.31.0.3",
            "interfaceName": "r1-eth1",
            "active": True,
            "labels": [
                16006,
            ],
        },
        {
            "ip": "172.31.2.4",
            "interfaceName": "r1-eth2",
            "active": True,
            "labels": [
                16006,
            ],
        },
    ]

    expected = {
        prefix: [
            {
                "prefix": prefix,
                "protocol": "bgp",
                "metric": 0,
                "table": 254,
                "nexthops": [],
            }
        ]
    }

    recursive_nh = [
        {
            "ip": recursive_nexthop,
            "active": True,
            "recursive": True,
        },
    ]
    for nh in recursive_nh:
        expected[prefix][0]["nexthops"].append(get_nh_formatted(nh, fib=False))

    for nh in r5_nh:
        expected[prefix][0]["nexthops"].append(get_nh_formatted(nh))

    if multipath:
        for nh in r6_nh:
            expected[prefix][0]["nexthops"].append(get_nh_formatted(nh))

        for nh in recursive_nh:
            expected[prefix][0]["nexthops"].append(
                get_nh_formatted(nh, fib=False, duplicate=True)
            )

        for nh in r5_nh:
            expected[prefix][0]["nexthops"].append(
                get_nh_formatted(nh, fib=False, duplicate=True)
            )

        for nh in r6_nh:
            expected[prefix][0]["nexthops"].append(
                get_nh_formatted(nh, fib=False, duplicate=True)
            )

    test_func = functools.partial(
        ip_check_path_selection, tgen.gears["r1"], prefix, expected, check_fib=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), f"Failed to check that {prefix} is correctly recursive via {recursive_nexthop}"


def check_ipv4_prefix_with_multiple_nexthops_linux(prefix):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        f"Check that {prefix} unicast entry is installed with paths for r5 and r6 on Linux"
    )

    r5_nh = [
        {
            "encap": "mpls",
            "dst": "16055",
            "gateway": "172.31.0.3",
            "dev": "r1-eth1",
        },
        {
            "encap": "mpls",
            "dst": "16055",
            "gateway": "172.31.2.4",
            "dev": "r1-eth2",
        },
    ]

    r6_nh = [
        {
            "encap": "mpls",
            "dst": "16006",
            "gateway": "172.31.0.3",
            "dev": "r1-eth1",
        },
        {
            "encap": "mpls",
            "dst": "16006",
            "gateway": "172.31.2.4",
            "dev": "r1-eth2",
        },
    ]

    expected = [
        {
            "dst": prefix,
            "protocol": "bgp",
            "metric": 20,
            "nexthops": [],
        }
    ]

    # only one path
    for nh in r5_nh:
        expected[0]["nexthops"].append(nh)
    for nh in r6_nh:
        expected[0]["nexthops"].append(nh)

    test_func = functools.partial(
        iproute2_check_path_selection, tgen.routers()["r1"], prefix, expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), f"Failed to check that {prefix} unicast entry is installed with paths for r5 and r6 on Linux"


def test_bgp_ipv4_convergence():
    """
    Check that R1 has received the 192.0.2.9/32 prefix from R5, and R6
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Ensure that the 192.0.2.9/32 route is available")
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32")

    check_ipv4_prefix_with_multiple_nexthops_linux("192.0.2.9")


def test_bgp_ipv4_recursive_routes():
    """
    Check that R1 has received the recursive routes, and duplicate nexthops are in zebra, but are not installed
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ipv4_prefix_recursive_with_multiple_nexthops("192.0.2.8/32", "192.0.2.9")

    check_ipv4_prefix_with_multiple_nexthops_linux("192.0.2.8")


def test_bgp_ipv4_recursive_routes_when_no_mpath():
    """
    Unconfigure multipath ibgp
    Check that duplicate nexthops are not in zebra
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        router bgp
        address family ipv4 unicast
        maximum-paths ibgp 1
        """,
        isjson=False,
    )
    tgen.gears["r1"].vtysh_cmd("clear bgp ipv4 *")
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32", multipath=False)

    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "192.0.2.8/32", "192.0.2.9", multipath=False
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
