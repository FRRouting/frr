#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_backup_route.py
#
# Copyright 2023 6WIND S.A.
#

"""
 test_bgp_backup_route.py: Test the FRR BGP daemon with backup routes

                                        +--------+          +--------+
                                        |        |          |        |
                        +---------------+  r10   +----------+  r11   +-------+
                        |               |        +    +-----+        |       |
                        |               +---+----+\  /      +---+----+       |
                        |                   |      \/           |            |
                        |                   |      /\           |            |
+--------+          +---+----+          +---+----+/  \      +---+----+       |
|        |          |        |          |        +    +-----+        +-----+ |
|  ce7   +----------+  r1    +----------+  r3    +----------+  r5    |     | |
|        |          |        |          |  rr    +    +-----+        |  +--+-+--+
+--------+          +---+----+          +--------+\  /      +--------+  |       |
                        |                          \/                   |  ce9  |
                        |                          /\                   |       |
                        |               +--------+/  \      +--------+  +---+---+
                        |               |        +    +-----+        |      |
                        +---------------+  r4    +----------+  r6    +------+
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 2 routers.
    tgen.add_router("ce7")
    tgen.add_router("ce9")
    # Create 7 PE routers.
    tgen.add_router("r1")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    tgen.add_router("r6")
    tgen.add_router("r10")
    tgen.add_router("r11")

    # switch
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["ce7"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["ce9"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["ce9"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s12")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r6"])

    switch = tgen.add_switch("s13")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s14")
    switch.add_link(tgen.gears["r10"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s15")
    switch.add_link(tgen.gears["r10"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s16")
    switch.add_link(tgen.gears["r10"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s17")
    switch.add_link(tgen.gears["r11"])
    switch.add_link(tgen.gears["r10"])

    switch = tgen.add_switch("s18")
    switch.add_link(tgen.gears["r11"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s19")
    switch.add_link(tgen.gears["r11"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s20")
    switch.add_link(tgen.gears["r11"])
    switch.add_link(tgen.gears["ce9"])


def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "ip link add loop2 type dummy",
        "ip link set dev loop2 up",
    ]

    for name in ("ce7", "ce9"):
        for cmd in cmds_list:
            logger.info("input: " + cmd)
            output = tgen.net[name].cmd(cmd)
            logger.info("output: " + output)

    cmds_list = [
        "modprobe mpls_router",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
    ]

    for name in ("r1", "r3", "r4", "r5", "r6", "r10", "r11"):
        for cmd in cmds_list:
            logger.info("input: " + cmd)
            output = tgen.net[name].cmd(cmd)
            logger.info("output: " + output)


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if rname in ("r1", "r3", "r4", "r5", "r6", "r10", "r11"):
            router.load_config(
                TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
            )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def bgp_check_path_selection_ecmp_backup(router, expected):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast 192.0.2.9/32 json"))
    return topotest.json_cmp(output, expected)


def bgp_check_path_selection_not_ecmp_backup(router, expected):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast 192.0.2.9/32 json"))
    ret = topotest.json_cmp(output, expected)
    if ret is None:
        return "not good"
    return None


def bgp_ipv4_route_advertised_all_paths_to_ce7():
    """
    Check that all addpath routes are advertised to ce7
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "bestpath": {"overall": True},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["ce7"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "ce7, failed to check that 192.0.2.9/32 has 1 best path, and 2 other routes"


def bgp_check_route_primary_and_backup_advertised_to_ce7():
    """
    Check that only the primary and backup path routes are advertised to ce7
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("ce7, check that 192.0.2.9/32 has not 1 path and 2 other routes")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "bestpath": {"overall": True},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_not_ecmp_backup, tgen.gears["ce7"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "ce7, failed to check that 192.0.2.9/32 has not 1 best path, and 2 other routes"

    logger.info("ce7, check that 192.0.2.9/32 has 1 best path and 1 other routes")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "bestpath": {"overall": True},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["ce7"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "ce7, failed to check that 192.0.2.9/32 has 1 best path and 1 other route"


def test_ipv4_route_presence():
    """
    Assert that the 192.0.2.9/32 prefix is present
    Check the presence of backup and primary routes when addpath-backup is configured.
    The IGP is modified:
    - by default, IGP metric for r6 is longer to reach than for r11 and r5
    - IGP metric for r6 is equal to the IGP metric for r11 and r5
    - IGP metric for r6 is equal to the IGP metric for r11 and r5
    - IGP metric for r5 and r11 is longer than for r6
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check that 192.0.2.9/32 has 2 ECMP paths and 1 backup path")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "multipath": True,
                "bestpath": {
                    "overall": True,
                },
                "originatorId": "192.0.2.5",
                "nexthops": [{"ip": "192.0.2.5", "metric": 30}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "multipath": True,
                "originatorId": "192.0.2.11",
                "nexthops": [{"ip": "192.0.2.11", "metric": 30}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "backup-bestpath": {"second": True},
                "originatorId": "192.0.2.6",
                "nexthops": [{"ip": "192.0.2.6", "metric": 40}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has 2 ECMP paths and 1 backup path"

    logger.info("Changing IGP metric on r6 from 20 to 10")
    tgen.gears["r6"].vtysh_cmd(
        "configure terminal\ninterface lo\nisis metric 10\n",
        isjson=False,
    )

    logger.info("Check that 192.0.2.9/32 has 3 ECMP paths")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "bestpath": {"overall": True},
                "multipath": True,
                "originatorId": "192.0.2.5",
                "nexthops": [{"ip": "192.0.2.5", "metric": 30}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "multipath": True,
                "originatorId": "192.0.2.11",
                "nexthops": [{"ip": "192.0.2.11", "metric": 30}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "multipath": True,
                "originatorId": "192.0.2.6",
                "nexthops": [{"ip": "192.0.2.6", "metric": 30}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 has 3 ECMP paths"

    logger.info("Changing IGP metric on r5 from 10 to 20")
    tgen.gears["r5"].vtysh_cmd(
        "configure terminal\ninterface lo\nisis metric 20\n",
        isjson=False,
    )
    logger.info("Changing IGP metric on r11 from 10 to 20")
    tgen.gears["r11"].vtysh_cmd(
        "configure terminal\ninterface lo\nisis metric 20\n",
        isjson=False,
    )

    logger.info("Check that 192.0.2.9/32 has 1 best path and 2 ECMP backup paths")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "backup-multipath": True,
                "backup-bestpath": {"second": True},
                "originatorId": "192.0.2.5",
                "nexthops": [{"ip": "192.0.2.5", "metric": 40}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "backup-multipath": True,
                "originatorId": "192.0.2.11",
                "nexthops": [{"ip": "192.0.2.11", "metric": 40}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "bestpath": {"overall": True},
                "originatorId": "192.0.2.6",
                "nexthops": [{"ip": "192.0.2.6", "metric": 30}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has 1 best path and 2 ECMP backup paths"

    logger.info("Changing IGP metric on r11 from 20 to 30")
    tgen.gears["r11"].vtysh_cmd(
        "configure terminal\ninterface lo\nisis metric 30\n",
        isjson=False,
    )
    logger.info(
        "Check that 192.0.2.9/32 has 1 best path, 1 backup path, and an other route"
    )
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "backup-bestpath": {"second": True},
                "originatorId": "192.0.2.5",
                "nexthops": [{"ip": "192.0.2.5", "metric": 40}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "originatorId": "192.0.2.11",
                "nexthops": [{"ip": "192.0.2.11", "metric": 50}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "bestpath": {"overall": True},
                "originatorId": "192.0.2.6",
                "nexthops": [{"ip": "192.0.2.6", "metric": 30}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has 1 best path, 1 backup path, and an other route"
    bgp_ipv4_route_advertised_all_paths_to_ce7()


def test_configure_tx_backup_route_ce7():
    """
    Configure r1 to send only backup paths to ce7
    Check that only the primary and backup path routes are advertised to ce7
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring 'neighbor 172.31.10.7 addpath-tx-backup-paths")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nneighbor 172.31.10.7 addpath-tx-backup-paths\n",
        isjson=False,
    )
    bgp_check_route_primary_and_backup_advertised_to_ce7()


def test_ipv4_route_presence_when_unconfigured():
    """
    Check that there are no backup and backup-multipath routes when addpath-backup is unconfigured.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Unconfiguring 'addpath path-selection backup' on r1")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nno addpath path-selection backup\n",
        isjson=False,
    )

    logger.info("Check that 192.0.2.9/32 has 1 best path")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "originatorId": "192.0.2.5",
                "nexthops": [{"ip": "192.0.2.5", "metric": 40}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "originatorId": "192.0.2.11",
                "nexthops": [{"ip": "192.0.2.11", "metric": 50}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "bestpath": {"overall": True},
                "originatorId": "192.0.2.6",
                "nexthops": [{"ip": "192.0.2.6", "metric": 30}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 has 1 best path"

    logger.info("Check that 192.0.2.9/32 has no backup-bestpath")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "backup-bestpath": {"second": True},
                "originatorId": "192.0.2.5",
                "nexthops": [{"ip": "192.0.2.5", "metric": 40}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "originatorId": "192.0.2.11",
                "nexthops": [{"ip": "192.0.2.11", "metric": 50}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "bestpath": {"overall": True},
                "originatorId": "192.0.2.6",
                "nexthops": [{"ip": "192.0.2.6", "metric": 30}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_not_ecmp_backup, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 has no backup-bestpath"


def test_ipv4_route_advertised_primary_only_to_ce7():
    """
    Check that only the primary routes is advertised to ce7
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("ce7, check that 192.0.2.9/32 has not 1 path and not 1 backup routes")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "bestpath": {"overall": True},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_not_ecmp_backup, tgen.gears["ce7"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "ce7, failed to check that 192.0.2.9/32 has not 1 best path, and not 1 backup route"

    logger.info("ce7, check that 192.0.2.9/32 has 1 best path only")
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64500 64511"},
                "bestpath": {"overall": True},
                "nexthops": [{"ip": "172.31.10.1"}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["ce7"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "ce7, failed to check that 192.0.2.9/32 has 1 best path only"


def test_ipv4_route_presence_when_reconfigured():
    """
    Check that there are backup and backup-multipath routes when addpath-backup is configured.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring 'addpath path-selection backup' on r1")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\naddpath path-selection backup\n",
        isjson=False,
    )

    logger.info(
        "Check that 192.0.2.9/32 has 1 best path, 1 backup path, and 1 other route"
    )
    expected = {
        "paths": [
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "backup-bestpath": {"second": True},
                "originatorId": "192.0.2.5",
                "nexthops": [{"ip": "192.0.2.5", "metric": 40}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "originatorId": "192.0.2.11",
                "nexthops": [{"ip": "192.0.2.11", "metric": 50}],
            },
            {
                "valid": True,
                "aspath": {"string": "64511"},
                "bestpath": {"overall": True},
                "originatorId": "192.0.2.6",
                "nexthops": [{"ip": "192.0.2.6", "metric": 30}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_ecmp_backup, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has 1 best path, 1 backup path, and 1 other route"

    bgp_check_route_primary_and_backup_advertised_to_ce7()


def test_ipv4_route_advertised_all_paths_to_ce7():
    """
    Configure r1 to send all paths to ce7
    Check that the three paths are advertised to ce7
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Configuring 'neighbor 172.31.10.7 addpath-tx-all-paths")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nneighbor 172.31.10.7 addpath-tx-all-paths\n",
        isjson=False,
    )
    bgp_ipv4_route_advertised_all_paths_to_ce7()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
