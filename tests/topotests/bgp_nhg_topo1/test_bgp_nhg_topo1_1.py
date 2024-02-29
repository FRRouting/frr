#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_nhg_topo1.py
#
# Copyright 2024 6WIND S.A.
#

"""
 test_bgp_nhg_topo1.py: Test the FRR BGP daemon with bgp nexthop groups
            Check BGP nexthop groups with MPLSVPN and unicast paths.


+--------+          +---+----+          +---+----+          +--------+
|        |          |        |          |        +          |        |
|  ce7   +----------+  r1    +----------+  r3    +----------+  r5    +----------------+
|        |          |        |          |  rr    +    +-----+        |  +--+-+--+ +--+++--+
+--------+          ++--+----+          +--------+\  /      +--------+  |       | |       |
                     |  |                          \/                   |  ce9  | |  ce10 |
                     |  |                          /\                   |unicast| |  vpn  |
+--------+           |  |               +--------+/  \      +--------+  +---+---+ +---+---+
|        |           |  |               |        +    +-----+        +----------------+
|  ce8   +-----------+  +---------------+  r4    +----------+  r6    +------+
|        |                              |        |          |        |
+--------+                              +--------+          +--------+
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
from lib.nexthopgroup import route_check_nhg_id_is_protocol
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]

nhg_id_1 = 0
nhg_id_2 = 0


def build_topo(tgen):
    "Build function"

    # Create 2 routers.
    tgen.add_router("ce7")
    tgen.add_router("ce8")
    tgen.add_router("ce9")
    tgen.add_router("ce10")
    # Create 7 PE routers.
    tgen.add_router("r1")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    tgen.add_router("r6")

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
    switch.add_link(tgen.gears["ce10"])

    switch = tgen.add_switch("s13")
    switch.add_link(tgen.gears["r6"])
    switch.add_link(tgen.gears["ce10"])

    switch = tgen.add_switch("s14")
    switch.add_link(tgen.gears["ce8"])
    switch.add_link(tgen.gears["r1"])


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
        "ip link add loop2 type dummy",
        "ip link set dev loop2 up",
    ]

    output = tgen.net["r1"].cmd("ip link add vrf1 type vrf table 101")
    output = tgen.net["r1"].cmd("ip link set dev vrf1 up")
    output = tgen.net["r1"].cmd("ip link set dev r1-eth0 master vrf1")
    output = tgen.net["r1"].cmd("ip link add vrf2 type vrf table 102")
    output = tgen.net["r1"].cmd("ip link set dev vrf2 up")
    output = tgen.net["r1"].cmd("ip link set dev r1-eth3 master vrf2")
    output = tgen.net["r5"].cmd("ip link add vrf1 type vrf table 101")
    output = tgen.net["r5"].cmd("ip link set dev vrf1 up")
    output = tgen.net["r5"].cmd("ip link set dev r5-eth3 master vrf1")
    output = tgen.net["r6"].cmd("ip link add vrf1 type vrf table 101")
    output = tgen.net["r6"].cmd("ip link set dev vrf1 up")
    output = tgen.net["r6"].cmd("ip link set dev r6-eth3 master vrf1")

    cmds_list = [
        "modprobe mpls_router",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
    ]

    for name in ("r1", "r3", "r4", "r5", "r6"):
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
        if rname in ("r1", "r3", "r4", "r5", "r6"):
            router.load_config(
                TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
            )
        if rname in ("r1", "r3", "r5", "r6", "r8", "ce7", "ce8", "ce9", "ce10"):
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def bgp_check_path_selection_unicast(router, expected):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast 192.0.2.9/32 json"))
    return topotest.json_cmp(output, expected)


def bgp_check_path_selection_vpn(router, prefix, expected, vrf_name="vrf1"):
    output = json.loads(router.vtysh_cmd(f"show bgp vrf {vrf_name} ipv4 {prefix} json"))
    return topotest.json_cmp(output, expected)


def ip_check_path_not_present(router, ipaddr_str):
    output = json.loads(router.vtysh_cmd(f"show ip route {ipaddr_str} json"))
    if ipaddr_str in output.keys():
        return "Not Good"
    return None


def iproute2_check_path_not_present(router, ipaddr_str):
    if not topotest.iproute2_is_json_capable():
        return None

    output = json.loads(router.run(f"ip -json route show {ipaddr_str}"))
    for entry in output:
        for nhid_entry in entry:
            return f"The following entry is found: {nhid_entry['dst']}."

    return None


def test_bgp_ipv4_route_presence():
    """
    Assert that the 192.0.2.9/32 prefix is present in unicast and vpn RIB
    Check the presence of routes with r6 as nexthop for 192.0.2.9/32
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info(
        "Check that 192.0.2.9/32 unicast entry has 1 entry with 192.0.2.6 nexthop"
    )
    expected = {
        "paths": [
            {
                "origin": "IGP",
                "metric": 0,
                "valid": True,
                "bestpath": {
                    "overall": True,
                },
                "originatorId": "192.0.2.6",
                "nexthops": [{"ip": "192.0.2.6", "metric": 25}],
                "peer": {
                    "peerId": "192.0.2.3",
                },
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_unicast, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 unicast entry has one next-hop to 192.0.2.6"

    logger.info(
        "Check that 192.0.2.9/32 mpls vpn entry has 1 selected entry with 192.0.2.6 nexthop"
    )
    expected = {
        "paths": [
            {
                "valid": True,
                "bestpath": {
                    "overall": True,
                },
                "origin": "IGP",
                "metric": 0,
                "originatorId": "192.0.2.6",
                "remoteLabel": 6000,
                "nexthops": [{"ip": "192.0.2.6", "metric": 25}],
            },
            {
                "valid": True,
                "origin": "IGP",
                "metric": 0,
                "originatorId": "192.0.2.5",
                "remoteLabel": 500,
                "nexthops": [{"ip": "192.0.2.5", "metric": 30}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_vpn, tgen.gears["r1"], "192.0.2.9/32", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has one next-hop to 192.0.2.6"
    # debug
    tgen.gears["r1"].vtysh_cmd(f"show bgp nexthop-group detail")


def test_bgp_vrf_ipv4_route_presence():
    """
    Assert that the 192.0.2.7/32 prefix is present in two VRFs
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Check that 192.0.2.7/32 entry has 1 selected entry with 172.31.10.7 nexthop in vrf1"
    )
    expected = {
        "paths": [
            {
                "valid": True,
                "bestpath": {
                    "overall": True,
                },
                "origin": "IGP",
                "metric": 0,
                "nexthops": [{"ip": "172.31.10.7", "metric": 0, "used": True}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_vpn,
        tgen.gears["r1"],
        "192.0.2.7/32",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.7/32 has one next-hop to 172.31.10.7 in vrf1"

    step(
        "Check that 192.0.2.7/32 entry has 1 selected entry with 172.31.11.8 nexthop in vrf2"
    )
    expected = {
        "paths": [
            {
                "valid": True,
                "bestpath": {
                    "overall": True,
                },
                "origin": "IGP",
                "metric": 0,
                "nexthops": [{"ip": "172.31.11.8", "metric": 0, "used": True}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_vpn,
        tgen.gears["r1"],
        "192.0.2.7/32",
        expected,
        vrf_name="vrf2",
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.7/32 has one next-hop to 172.31.11.8 in vrf2"
    # debug
    tgen.gears["r1"].vtysh_cmd(f"show bgp nexthop-group detail")


def test_bgp_vrf_ipv4_route_uses_vrf_nexthop_group():
    """
    Check that the installed 192.0.2.7/32 route uses two distinct BGP NHG
    Which respectively uses the vrf1 and vrf2 nexthop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check that 192.0.2.7/32 has 1 path in vrf1")
    expected = {
        "192.0.2.7/32": [
            {
                "prefix": "192.0.2.7/32",
                "protocol": "bgp",
                "vrfName": "vrf1",
                "metric": 0,
                "table": 101,
                "nexthops": [
                    {
                        "ip": "172.31.10.7",
                        "interfaceName": "r1-eth0",
                        "active": True,
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection,
        tgen.gears["r1"],
        "192.0.2.7/32",
        expected,
        vrf_name="vrf1",
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.7/32 has 1 path in vrf1."

    local_nhg_id_1 = route_check_nhg_id_is_protocol(
        "192.0.2.7/32", "r1", vrf_name="vrf1"
    )

    step("Check that 192.0.2.7/32 has 1 path in vrf1 in Linux")
    expected = [
        {
            "dst": "192.0.2.7",
            "gateway": "172.31.10.7",
            "dev": "r1-eth0",
            "protocol": "bgp",
            "metric": 20,
        }
    ]

    test_func = functools.partial(
        iproute2_check_path_selection,
        tgen.routers()["r1"],
        "192.0.2.7/32",
        expected,
        vrf_name="vrf1",
        nhg_id=local_nhg_id_1,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that Linux has 192.0.2.7/32 route in vrf1 with BGP ID."

    step("Check that 192.0.2.7/32 has 1 path in vrf2")
    expected = {
        "192.0.2.7/32": [
            {
                "prefix": "192.0.2.7/32",
                "protocol": "bgp",
                "vrfName": "vrf2",
                "metric": 0,
                "table": 102,
                "nexthops": [
                    {
                        "ip": "172.31.11.8",
                        "interfaceName": "r1-eth3",
                        "active": True,
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection,
        tgen.gears["r1"],
        "192.0.2.7/32",
        expected,
        vrf_name="vrf2",
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.7/32 has 1 path in vrf2."

    local_nhg_id_2 = route_check_nhg_id_is_protocol(
        "192.0.2.7/32", "r1", vrf_name="vrf2"
    )

    step("Check that 192.0.2.7/32 has 1 path in vrf2 in Linux")
    expected = [
        {
            "dst": "192.0.2.7",
            "gateway": "172.31.11.8",
            "dev": "r1-eth3",
            "protocol": "bgp",
            "metric": 20,
        }
    ]

    test_func = functools.partial(
        iproute2_check_path_selection,
        tgen.routers()["r1"],
        "192.0.2.7/32",
        expected,
        vrf_name="vrf2",
        nhg_id=local_nhg_id_2,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that Linux has 192.0.2.7/32 route in vrf2 with BGP ID."

    step("Check that both routes do not share the same NHG")

    assert local_nhg_id_1 != local_nhg_id_2, (
        "The same NHG %d is used for both vrfs" % local_nhg_id_1
    )


def test_bgp_ipv4_route_uses_nexthop_group():
    """
    Check that the installed route uses a BGP NHG
    Check that the MPLS VPN route uses a different NHG
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step("Check that 192.0.2.9/32 unicast entry has 1 BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1", vrf_name="vrf1")
    assert nhg_id_1 != nhg_id_2, (
        "The same NHG %d is used for both MPLS and unicast routes" % nhg_id_1
    )


def test_bgp_ipv4_route_presence_after_igp_change():
    """
    The IGP is modified on r6 so that r5 will be selected
    Check that routes to r5 are best.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Changing IGP metric on r6 from 5 to 40")
    tgen.gears["r6"].vtysh_cmd(
        """
        configure terminal\n
        interface lo
        isis metric 40\n
        """,
        isjson=False,
    )

    step("Check that 192.0.2.9/32 unicast entry has 1 entry with 192.0.2.5 nexthop")
    expected = {
        "paths": [
            {
                "origin": "IGP",
                "metric": 0,
                "valid": True,
                "bestpath": {
                    "overall": True,
                },
                "originatorId": "192.0.2.5",
                "nexthops": [{"ip": "192.0.2.5", "metric": 30}],
                "peer": {
                    "peerId": "192.0.2.3",
                },
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_unicast, tgen.gears["r1"], expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 unicast entry has one next-hop to 192.0.2.5"

    step(
        "Check that 192.0.2.9/32 mpls vpn entry has 1 selected entry with 192.0.2.5 nexthop"
    )
    expected = {
        "paths": [
            {
                "valid": True,
                "origin": "IGP",
                "metric": 0,
                "originatorId": "192.0.2.6",
                "remoteLabel": 6000,
                "nexthops": [{"ip": "192.0.2.6", "metric": 60}],
            },
            {
                "valid": True,
                "bestpath": {
                    "overall": True,
                },
                "origin": "IGP",
                "metric": 0,
                "originatorId": "192.0.2.5",
                "remoteLabel": 500,
                "nexthops": [{"ip": "192.0.2.5", "metric": 30}],
            },
        ]
    }
    test_func = functools.partial(
        bgp_check_path_selection_vpn, tgen.gears["r1"], "192.0.2.9/32", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has one next-hop to 192.0.2.5"

    # debug
    tgen.gears["r1"].vtysh_cmd(f"show bgp nexthop-group detail")


def test_bgp_ipv4_new_route_uses_nexthop_group():
    """
    Check that the installed route uses a BGP NHG
    Check that the MPLS VPN route uses a different NHG
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step("Check that 192.0.2.9/32 unicast entry has 1 BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1", vrf_name="vrf1")
    assert nhg_id_1 != nhg_id_2, (
        "The same NHG %d is used for both MPLS and unicast routes" % nhg_id_1
    )


def test_bgp_ipv4_unconfigure_r6_network():
    """
    Only r5 will advertise the prefixes
    Check that a change in the IGP is automatically modified
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    tgen.gears["r6"].vtysh_cmd(
        """
        conf t\n
        router bgp 64500 vrf vrf1\n
        no neighbor 172.31.22.9 remote-as 64500\n
        """,
        isjson=False,
    )
    tgen.gears["r6"].vtysh_cmd(
        """
        conf t\n
        router bgp 64500 vrf vrf1\n
        address-family ipv4 unicast\n
        no network 192.0.2.9/32\n
        """,
        isjson=False,
    )


def test_isis_ipv4_unshutdown_r4_eth0():
    """
    Unconfigure r4 to un-shutdown the r4-eth0
    Check that the 192.0.2.5/32 route is now multi path in the IGP
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    tgen.gears["r4"].vtysh_cmd(
        """
        configure terminal\n
        interface r4-eth0\n
        no shutdown\n
        """,
        isjson=False,
    )

    step("Check that 192.0.2.5/32 has 2 paths now")
    expected = {
        "192.0.2.5/32": [
            {
                "prefix": "192.0.2.5/32",
                "protocol": "isis",
                "metric": 30,
                "table": 254,
                "nexthops": [
                    {
                        "ip": "172.31.0.3",
                        "interfaceName": "r1-eth1",
                        "active": True,
                        "labels": [
                            16005,
                        ],
                    },
                    {
                        "ip": "172.31.2.4",
                        "interfaceName": "r1-eth2",
                        "active": True,
                        "labels": [
                            16005,
                        ],
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection, tgen.gears["r1"], "192.0.2.5/32", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.5/32 has 2 paths now"


def test_bgp_ipv4_convergence_igp():
    """
    Check that the BGP route to 192.0.2.9/32 route is now multi path
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check that 192.0.2.9/32 unicast entry has 2 paths now")
    expected = {
        "192.0.2.9/32": [
            {
                "prefix": "192.0.2.9/32",
                "protocol": "bgp",
                "metric": 0,
                "table": 254,
                "nexthopGroupId": nhg_id_1,
                "installedNexthopGroupId": nhg_id_1,
                "nexthops": [
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
                            16005,
                        ],
                    },
                    {
                        "ip": "172.31.2.4",
                        "interfaceName": "r1-eth2",
                        "active": True,
                        "labels": [
                            16005,
                        ],
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection, tgen.gears["r1"], "192.0.2.9/32", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 has 2 paths now"

    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    step("Check that 192.0.2.9/32 has 2 paths in Linux")
    expected = [
        {
            "dst": "192.0.2.9",
            "protocol": "bgp",
            "metric": 20,
            "nexthops": [
                {
                    "encap": "mpls",
                    "dst": "16005",
                    "gateway": "172.31.0.3",
                    "dev": "r1-eth1",
                },
                {
                    "encap": "mpls",
                    "dst": "16005",
                    "gateway": "172.31.2.4",
                    "dev": "r1-eth2",
                },
            ],
        }
    ]

    test_func = functools.partial(
        iproute2_check_path_selection,
        tgen.routers()["r1"],
        "192.0.2.9/32",
        expected,
        nhg_id=local_nhg_id_1,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has 2 paths now in Linux with BGP ID"

    step("Check that 192.0.2.9/32 mpls vpn entry has 2 paths now")
    expected = {
        "192.0.2.9/32": [
            {
                "prefix": "192.0.2.9/32",
                "protocol": "bgp",
                "metric": 0,
                "table": 101,
                "nexthops": [
                    {
                        "ip": "192.0.2.5",
                        "active": True,
                        "recursive": True,
                        "labels": [500],
                    },
                    {
                        "ip": "172.31.0.3",
                        "interfaceName": "r1-eth1",
                        "active": True,
                        "labels": [16005, 500],
                    },
                    {
                        "ip": "172.31.2.4",
                        "interfaceName": "r1-eth2",
                        "active": True,
                        "labels": [16005, 500],
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection,
        tgen.gears["r1"],
        "192.0.2.9/32",
        expected,
        vrf_name="vrf1",
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 mpls vpn entry has 2 paths now"

    local_nhg_id_1 = route_check_nhg_id_is_protocol(
        "192.0.2.9/32", "r1", vrf_name="vrf1"
    )

    step("Check that 192.0.2.9/32 mpls vpn entry has 2 paths now in Linux")
    expected = [
        {
            "dst": "192.0.2.9",
            "protocol": "bgp",
            "metric": 20,
            "nexthops": [
                {
                    "encap": "mpls",
                    "dst": "16005/500",
                    "gateway": "172.31.0.3",
                    "dev": "r1-eth1",
                },
                {
                    "encap": "mpls",
                    "dst": "16005/500",
                    "gateway": "172.31.2.4",
                    "dev": "r1-eth2",
                },
            ],
        }
    ]

    test_func = functools.partial(
        iproute2_check_path_selection,
        tgen.routers()["r1"],
        "192.0.2.9/32",
        expected,
        vrf_name="vrf1",
        nhg_id=local_nhg_id_1,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 mpls vpn entry has 2 paths now in Linux with BGP ID"

    # debug
    tgen.gears["r1"].vtysh_cmd(f"show bgp nexthop-group detail")


def test_bgp_ipv4_convergence_igp_label_changed():
    """
    Change the r5 label value
    Check that the BGP route to 192.0.2.9/32 route uses the new label value
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("On r5, change the index IS-IS SID to 55")
    tgen.gears["r5"].vtysh_cmd(
        """
        configure terminal\n
        router isis 1\n
        segment-routing prefix 192.0.2.5/32 index 55\n
        """,
        isjson=False,
    )

    step("Check that 192.0.2.9/32 unicast entry uses the IGP label 16055")
    expected = {
        "192.0.2.9/32": [
            {
                "prefix": "192.0.2.9/32",
                "protocol": "bgp",
                "metric": 0,
                "table": 254,
                "nexthops": [
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
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection, tgen.gears["r1"], "192.0.2.9/32", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 uses the IGP label 16055"

    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    step("Check that 192.0.2.9/32 has 2 paths in Linux")
    expected = [
        {
            "dst": "192.0.2.9",
            "protocol": "bgp",
            "metric": 20,
            "nexthops": [
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
            ],
        }
    ]

    test_func = functools.partial(
        iproute2_check_path_selection,
        tgen.routers()["r1"],
        "192.0.2.9/32",
        expected,
        nhg_id=local_nhg_id_1,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has 2 paths now in Linux with BGP ID"

    step("Check that 192.0.2.9/32 mpls vpn entry uses the IGP label 16055")
    expected = {
        "192.0.2.9/32": [
            {
                "prefix": "192.0.2.9/32",
                "protocol": "bgp",
                "metric": 0,
                "table": 101,
                "nexthops": [
                    {
                        "ip": "192.0.2.5",
                        "active": True,
                        "recursive": True,
                        "labels": [500],
                    },
                    {
                        "ip": "172.31.0.3",
                        "interfaceName": "r1-eth1",
                        "active": True,
                        "labels": [16055, 500],
                    },
                    {
                        "ip": "172.31.2.4",
                        "interfaceName": "r1-eth2",
                        "active": True,
                        "labels": [16055, 500],
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection,
        tgen.gears["r1"],
        "192.0.2.9/32",
        expected,
        vrf_name="vrf1",
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 mpls vpn entry uses the IGP label 16055"

    local_nhg_id_1 = route_check_nhg_id_is_protocol(
        "192.0.2.9/32", "r1", vrf_name="vrf1"
    )

    step("Check that 192.0.2.9/32 mpls vpn entry uses the IGP label 16055 in Linux")
    expected = [
        {
            "dst": "192.0.2.9",
            "protocol": "bgp",
            "metric": 20,
            "nexthops": [
                {
                    "encap": "mpls",
                    "dst": "16055/500",
                    "gateway": "172.31.0.3",
                    "dev": "r1-eth1",
                },
                {
                    "encap": "mpls",
                    "dst": "16055/500",
                    "gateway": "172.31.2.4",
                    "dev": "r1-eth2",
                },
            ],
        }
    ]

    test_func = functools.partial(
        iproute2_check_path_selection,
        tgen.routers()["r1"],
        "192.0.2.9/32",
        expected,
        vrf_name="vrf1",
        nhg_id=local_nhg_id_1,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 mpls vpn entry uses the IGP label 16055 in Linux with BGP ID"

    # debug
    tgen.gears["r1"].vtysh_cmd(f"show bgp nexthop-group detail")


def test_bgp_ipv4_r5_router_removed():
    """
    Remove the R5 router from the IGP
    Remove the 192.0.2.9/32 network address on R6
    Check that the BGP route to 192.0.2.9/32 route is removed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("On r5, remove the lo interface from the IGP")
    tgen.gears["r5"].vtysh_cmd(
        """
        configure terminal\n
        interface lo\n
        no ip router isis 1\n
        """,
        isjson=False,
    )

    step("On r6, remove the 192.0.2.9/32 network")
    tgen.gears["r6"].vtysh_cmd(
        """
        configure terminal\n
        router bgp 64500\n
        address-family ipv4 unicast\n
        no network 192.0.2.9/32\n
        """,
        isjson=False,
    )

    step("Check that 192.0.2.9/32 is removed from the 'show ip route' table")
    test_func = functools.partial(
        ip_check_path_not_present, tgen.gears["r1"], "192.0.2.9/32"
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 is not present."

    step("Check that 192.0.2.9/32 is removed from the 'iproute2' command on Linux")
    test_func = functools.partial(
        iproute2_check_path_not_present, tgen.gears["r1"], "192.0.2.9"
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 is not present on Linux."

    # debug
    tgen.gears["r1"].vtysh_cmd(f"show bgp nexthop-group detail")


def test_bgp_ipv4_r5_router_restored():
    """
    Restore the R5 router in the IGP
    Restore the 192.0.2.9/32 network address on R6
    Check that the BGP route to 192.0.2.9/32 route is readded.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("On r5, restore the lo interface in the IGP")
    tgen.gears["r5"].vtysh_cmd(
        """
        configure terminal\n
        interface lo\n
        ip router isis 1\n
        """,
        isjson=False,
    )

    step("On r6, restore the 192.0.2.9/32 network")
    tgen.gears["r6"].vtysh_cmd(
        """
        configure terminal\n
        router bgp 64500\n
        address-family ipv4 unicast\n
        network 192.0.2.9/32\n
        """,
        isjson=False,
    )

    step("Check that 192.0.2.9/32 unicast entry uses the IGP label 16055")
    expected = {
        "192.0.2.9/32": [
            {
                "prefix": "192.0.2.9/32",
                "protocol": "bgp",
                "metric": 0,
                "table": 254,
                "nexthops": [
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
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection, tgen.gears["r1"], "192.0.2.9/32", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 uses the IGP label 16055"

    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    step("Check that 192.0.2.9/32 has 2 paths in Linux")
    expected = [
        {
            "dst": "192.0.2.9",
            "protocol": "bgp",
            "metric": 20,
            "nexthops": [
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
            ],
        }
    ]

    test_func = functools.partial(
        iproute2_check_path_selection,
        tgen.routers()["r1"],
        "192.0.2.9/32",
        expected,
        nhg_id=local_nhg_id_1,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to check that 192.0.2.9/32 has 2 paths now in Linux with BGP ID"

    # debug
    tgen.gears["r1"].vtysh_cmd(f"show bgp nexthop-group detail")


def test_bgp_ipv4_addpath_configured():
    """
    R6 lo metric is set to default
    R1 addpath is configured
    Change the r6 metric value
    Check that the BGP route to 192.0.2.9/32 route uses zebra nexthops
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("On r3, configure addpath")
    tgen.gears["r3"].vtysh_cmd(
        """
        configure terminal\n
        router bgp 64500\n
        address-family ipv4 unicast\n
        neighbor rr addpath-tx-all-paths\n
        """,
        isjson=False,
    )

    step("On r6, change the IS-IS metric to default for lo interface")
    tgen.gears["r6"].vtysh_cmd(
        """
        configure terminal\n
        interface lo\n
        no isis metric\n
        """,
        isjson=False,
    )

    step("Check that 192.0.2.9/32 unicast entry is installed with both endpoints")
    expected = {
        "192.0.2.9/32": [
            {
                "prefix": "192.0.2.9/32",
                "protocol": "bgp",
                "metric": 0,
                "table": 254,
                "nexthops": [
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
                ],
            }
        ]
    }

    test_func = functools.partial(
        ip_check_path_selection, tgen.gears["r1"], "192.0.2.9/32", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to check that 192.0.2.9/32 uses the IGP label 16055"

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    route_check_nhg_id_is_protocol("192.0.2.9/32", "r1", protocol="bgp")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
