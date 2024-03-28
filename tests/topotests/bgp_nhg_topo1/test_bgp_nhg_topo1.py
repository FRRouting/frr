#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_nhg_topo1.py
#
# Copyright 2024 6WIND S.A.
#

"""
 test_bgp_nhg_topo1.py: Test the FRR BGP daemon with backup routes


+--------+          +---+----+          +---+----+          +--------+
|        |          |        |          |        +          |        |
|  ce7   +----------+  r1    +----------+  r3    +----------+  r5    +----------------+
|        |          |        |          |  rr    +    +-----+        |  +--+-+--+ +--+++--+
+--------+          +++-+----+          +--------+\  /      +--------+  |       | |       |
                     || |                          \/                   |  ce9  | |  ce10 |
                     || |                          /\                   |unicast| |  vpn  |
+--------+           || |               +--------+/  \      +--------+  +---+-+-+ +---+-+-+
|        |           || |               |        +    +-----+        +----------------+ |
|  ce8   +-----------+| +---------------+  r4    +----------+  r6    +------+ |         |
|        |            |                 |        |          |        |        |         |
+--------+            |                 +--------+          +--------+        |         |
                      |                                                       |         |
                      |                 +--------+          +--------+        |         |
                      |                 |        |          |        +--------+         |
                      +-----------------+   r7   +----------+  r8    +------------------+
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
    tgen.add_router("r7")
    tgen.add_router("r8")

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

    switch = tgen.add_switch("s15")
    switch.add_link(tgen.gears["r7"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s16")
    switch.add_link(tgen.gears["r7"])
    switch.add_link(tgen.gears["r8"])

    switch = tgen.add_switch("s17")
    switch.add_link(tgen.gears["r8"])
    switch.add_link(tgen.gears["ce9"])

    switch = tgen.add_switch("s18")
    switch.add_link(tgen.gears["r8"])
    switch.add_link(tgen.gears["ce10"])


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
    output = tgen.net["r8"].cmd("ip link add vrf1 type vrf table 101")
    output = tgen.net["r8"].cmd("ip link set dev vrf1 up")
    output = tgen.net["r8"].cmd("ip link set dev r8-eth2 master vrf1")

    cmds_list = [
        "modprobe mpls_router",
        "echo 100000 > /proc/sys/net/mpls/platform_labels",
    ]

    for name in ("r1", "r3", "r4", "r5", "r6", "r7", "r8"):
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
        if rname in ("r1", "r3", "r4", "r5", "r6", "r7", "r8"):
            router.load_config(
                TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
            )
        if rname in ("r1", "r3", "r5", "r6", "r8", "ce7", "ce8", "ce9", "ce10"):
            router.load_config(
                TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
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
        "configure terminal\ninterface lo\nisis metric 40\n",
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
        "conf t\nrouter bgp 64500 vrf vrf1\nno neighbor 172.31.22.9 remote-as 64500\n",
        isjson=False,
    )
    tgen.gears["r6"].vtysh_cmd(
        "conf t\nrouter bgp 64500 vrf vrf1\naddress-family ipv4 unicast\nno network 192.0.2.9/32\n",
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
        "configure terminal\ninterface r4-eth0\nno shutdown\n",
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
        "configure terminal\nrouter isis 1\nsegment-routing prefix 192.0.2.5/32 index 55\n",
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
        "configure terminal\ninterface lo\nno ip router isis 1\n",
        isjson=False,
    )

    step("On r6, remove the 192.0.2.9/32 network")
    tgen.gears["r6"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nno network 192.0.2.9/32\n",
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
        "configure terminal\ninterface lo\nip router isis 1\n",
        isjson=False,
    )

    step("On r6, restore the 192.0.2.9/32 network")
    tgen.gears["r6"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nnetwork 192.0.2.9/32\n",
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


def check_ipv4_prefix_with_multiple_nexthops(
    prefix, r5_path=True, r6_path=True, r8_path=False
):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        f"Check that {prefix} unicast entry is installed with paths for r5 {r5_path}, r6 {r6_path}, r8 {r8_path}"
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

    r8_nh = [
        {
            "ip": "192.0.2.8",
            "active": True,
            "recursive": True,
        },
        {
            "ip": "172.31.8.7",
            "interfaceName": "r1-eth4",
            "active": True,
            "labels": [
                16008,
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
    if r5_path:
        for nh in r5_nh:
            expected[prefix][0]["nexthops"].append(nh)
    if r6_path:
        for nh in r6_nh:
            expected[prefix][0]["nexthops"].append(nh)
    if r8_path:
        for nh in r8_nh:
            expected[prefix][0]["nexthops"].append(nh)

    test_func = functools.partial(
        ip_check_path_selection, tgen.gears["r1"], prefix, expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), f"Failed to check that {prefix} unicast entry is installed with paths for r5 {r5_path}, r6 {r6_path}, r8 {r8_path}"


def check_ipv4_prefix_with_multiple_nexthops_linux(
    prefix, nhg_id, r5_path=True, r6_path=True, r8_path=False
):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        f"Check that {prefix} unicast entry is installed with paths for r5 {r5_path}, r6 {r6_path}, r8 {r8_path} with NHID {nhg_id} on Linux"
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

    r8_nh = [
        {
            "encap": "mpls",
            "dst": "16008",
            "gateway": "172.31.8.7",
            "dev": "r1-eth4",
        }
    ]

    expected_r8_nh_only = [
        {
            "dst": prefix,
            "protocol": "bgp",
            "metric": 20,
            "encap": "mpls",
            "dst": "16008",
            "gateway": "172.31.8.7",
            "dev": "r1-eth4",
        }
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
    if r8_path and not r5_path and not r6_path:
        expected = expected_r8_nh_only
    else:
        if r5_path:
            for nh in r5_nh:
                expected[0]["nexthops"].append(nh)
        if r6_path:
            for nh in r6_nh:
                expected[0]["nexthops"].append(nh)
        if r8_path:
            for nh in r8_nh:
                expected[0]["nexthops"].append(nh)

    test_func = functools.partial(
        iproute2_check_path_selection,
        tgen.routers()["r1"],
        prefix,
        expected,
        nhg_id=nhg_id,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), f"Failed to check that {prefix} unicast entry is installed with paths for r5 {r5_path}, r6 {r6_path}, r8 {r8_path} on Linux with BGP ID"


def test_bgp_ipv4_addpath_configured():
    """
    R6 lo metric is set to default
    R1 addpath is configured
    Change the r6 metric value
    Check that the BGP route to 192.0.2.9/32 route uses BGP nexthops
    Check that the BGP nexthop groups used are same in BGP and in ZEBRA
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("On r3, configure addpath")
    tgen.gears["r3"].vtysh_cmd(
        "configure terminal\n"
        "router bgp 64500\n"
        "address-family ipv4 unicast\n"
        "neighbor rr addpath-tx-all-paths\n",
        isjson=False,
    )

    step("On r6, change the IS-IS metric to default for lo interface")
    tgen.gears["r6"].vtysh_cmd(
        "configure terminal\ninterface lo\nno isis metric\n",
        isjson=False,
    )

    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32")

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux("192.0.2.9", nhg_id=local_nhg_id)


def test_bgp_ipv4_three_ecmp_paths_configured():
    """
    R7 interface is unshutdown
    Check that the BGP route to 192.0.2.9/32 route uses 3 BGP nexthops
    Check that the 3 BGP nexthop groups are used.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r7"].vtysh_cmd(
        "configure terminal\ninterface r7-eth0\nno shutdown\n",
        isjson=False,
    )

    step("Check that 192.0.2.9/32 unicast entry is installed with three endpoints")
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32", r8_path=True)

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=local_nhg_id, r8_path=True
    )

    step(f"Get 192.0.2.9/32 dependent groups for ID {local_nhg_id}")
    output = json.loads(
        tgen.gears["r1"].vtysh_cmd(f"show bgp nexthop-group {local_nhg_id} json")
    )
    assert (
        "nhgDepends" in output.keys()
    ), f"ID {local_nhg_id}, BGP nexthop group with no dependent groups."
    assert (
        "dependsCount" in output.keys() and output["dependsCount"] == 3
    ), f"ID {local_nhg_id}, expected 2 dependent nexthops."


def test_bgp_ipv4_one_additional_network_configured():
    """
    R5, R6, and R8 have a new network to declare: 192.0.2.20/32
    Check that 192.0.2.9/32 and 192.0.2.20/32 use the same NHG
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check that 192.0.2.20/32 unicast entry is installed with three endpoints")
    for rname in ("r5", "r6", "r8"):
        tgen.gears[rname].vtysh_cmd(
            "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nnetwork 192.0.2.20/32",
            isjson=False,
        )
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.20/32", r8_path=True)

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=nhg_id_2, r8_path=True
    )

    step(
        "Check that same NHG is used by both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
    )
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")
    assert nhg_id_1 == nhg_id_2, (
        "The same NHG %d is not used for both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
        % nhg_id_1
    )


def test_bgp_ipv4_additional_network_has_only_two_paths_configured():
    """
    On R6, we remove the update to 192.0.2.9/32
    Check that the same NHG is used by 192.0.2.9/32 unicast routes
    Check that 192.0.2.9/32 and 192.0.2.20/32 do not use the same NHG
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Unconfigure 192.0.2.9/32 unicast entry on r6")
    tgen.gears["r6"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nno network 192.0.2.9/32",
        isjson=False,
    )

    step("Check that 192.0.2.9/32 unicast entry is installed with two endpoints")
    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=nhg_id_1, r6_path=False, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops("192.0.2.20/32", r8_path=True)

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=local_nhg_id_2, r8_path=True
    )

    step("Check that the same NHG is used by 192.0.2.20/32 unicast routes")
    assert (
        local_nhg_id_2 == nhg_id_2
    ), "The same NHG %d is not used by 192.0.2.20/32 unicast routes: %d" % (
        nhg_id_2,
        local_nhg_id_2,
    )

    step(
        "Check that different NHG is used by both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
    )
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")
    assert nhg_id_1 != nhg_id_2, (
        "The same NHG %d is used for both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
        % nhg_id_1
    )


def test_bgp_ipv4_additional_network_has_again_three_paths_configured():
    """
    On R6, we add back the update to 192.0.2.9/32
    Check that the same NHG is used by 192.0.2.20/32 unicast routes
    Check that the same NHG is used by both 192.0.2.20/32 and 192.0.2.9/32 unicast routes
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Reconfigure 192.0.2.9/32 unicast entry on r6")
    tgen.gears["r6"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nnetwork 192.0.2.9/32",
        isjson=False,
    )

    step("Check that 192.0.2.20/32 unicast entry is installed with three endpoints")
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32", r8_path=True)

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=nhg_id_1, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops("192.0.2.20/32", r8_path=True)

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=local_nhg_id_2, r8_path=True
    )

    step("Check that the same NHG is used by 192.0.2.20/32 unicast routes")
    assert (
        local_nhg_id_2 == nhg_id_2
    ), "The same NHG %d is not used by 192.0.2.20/32 unicast routes: %d" % (
        nhg_id_2,
        local_nhg_id_2,
    )

    step(
        "Check that same NHG is used by both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
    )
    assert nhg_id_1 == nhg_id_2, (
        "The same NHG %d is not used for both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
        % nhg_id_1
    )


def test_bgp_ipv4_lower_preference_value_on_r5_and_r8_configured():
    """
    On R5, and R8, we add a route-map to lower local-preference
    Check that only R6 is selected
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Reconfigure R5 and R8 to lower the preference value of advertised unicast networks"
    )
    for rname in ("r5", "r8"):
        tgen.gears[rname].vtysh_cmd(
            "configure terminal\nroute-map rmap permit 1\nset local-preference 50\n",
            isjson=False,
        )
        for prefix in ("192.0.2.9/32", "192.0.2.20/32"):
            tgen.gears[rname].vtysh_cmd(
                f"configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nnetwork {prefix} route-map rmap",
                isjson=False,
            )
    step("Check that 192.0.2.20/32 unicast entry is installed with one endpoints")
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32", r5_path=False)

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=nhg_id_1, r5_path=False
    )

    check_ipv4_prefix_with_multiple_nexthops("192.0.2.20/32", r5_path=False)

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=nhg_id_2, r5_path=False
    )

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {nhg_id_1}, and 192.0.2.20/32: {nhg_id_2}"
    )


def test_bgp_ipv4_increase_preference_value_on_r5_and_r8_configured():
    """
    On R5, and R8, we change the local-preference to a bigger value
    Check that R5, and R8 are selected
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Reconfigure R5 and R8 to increase the preference value of advertised unicast networks"
    )
    for rname in ("r5", "r8"):
        tgen.gears[rname].vtysh_cmd(
            "configure terminal\nroute-map rmap permit 1\nset local-preference 220\n",
            isjson=False,
        )
    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=nhg_id_1, r6_path=False, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=nhg_id_2, r6_path=False, r8_path=True
    )

    step(
        f"Get the nhg_id used for 192.0.2.9/32: {nhg_id_1}, and 192.0.2.20/32: {nhg_id_2}"
    )


def test_bgp_ipv4_simulate_r5_machine_going_down():
    """
    On R5, we shutdown the interface
    Check that R8 is selected
    Check that R5 failure did not change the NHG (EDGE implementation needed)
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nshutdown\n",
            isjson=False,
        )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r5_path=False, r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=local_nhg_id_1, r5_path=False, r6_path=False, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r5_path=False, r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=local_nhg_id_2, r5_path=False, r6_path=False, r8_path=True
    )

    step(
        f"Get the nhg_id used for 192.0.2.9/32: {nhg_id_1}, and 192.0.2.20/32: {local_nhg_id_2}"
    )
    step("Check that other NHG is used by 192.0.2.9/32 unicast routes")
    assert local_nhg_id_1 == nhg_id_1, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id_1
    )


def test_bgp_ipv4_simulate_r5_machine_going_up():
    """
    On R5, we unshutdown the interface
    Check that R8 is selected
    Check that the same NHG is used by both unicast routes
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Unshutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nno shutdown\n",
            isjson=False,
        )

    logger.info("Check that routes from R5 are back again")

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=nhg_id_1, r6_path=False, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=nhg_id_2, r6_path=False, r8_path=True
    )

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {nhg_id_1}, and 192.0.2.20/32: {nhg_id_2}"
    )
    step(
        "Check that the same NHG is used by both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
    )
    assert nhg_id_1 == nhg_id_2, (
        "A different NHG %d is used after R5 unshutdown between 192.0.2.9 and 192.0.2.20"
        % nhg_id_1
    )


def test_bgp_ipv4_unpeering_with_r5():
    """
    On R5, we unconfigure R3 peering
    Check that, on R1, routes from R5 are removed
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("R5, unpeer with R3")
    tgen.gears["r5"].vtysh_cmd(
        f"configure terminal\nrouter bgp 64500\nno neighbor 192.0.2.3 peer-group rrserver\n",
        isjson=False,
    )

    logger.info("Check that routes from R5 are removed")

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r5_path=False, r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=local_nhg_id_1, r5_path=False, r6_path=False, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r5_path=False, r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=local_nhg_id_2, r5_path=False, r6_path=False, r8_path=True
    )


def test_bgp_ipv4_direct_peering_with_r5():
    """
    On R5, we configure a peering with R1
    On R1, we configure a peering with R5
    Check that routes from R5 are removed
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("R5, peer with R1")
    tgen.gears["r5"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\nneighbor rrserver bfd\nneighbor rrserver bfd check-control-plane-failure",
        isjson=False,
    )
    tgen.gears["r5"].vtysh_cmd(
        f"configure terminal\nrouter bgp 64500\nneighbor 192.0.2.1 peer-group rrserver\n",
        isjson=False,
    )
    step("R1, peer with R5")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\nneighbor rrserver bfd\nneighbor rrserver bfd check-control-plane-failure",
        isjson=False,
    )
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\nneighbor 192.0.2.5 peer-group rrserver\n",
        isjson=False,
    )

    logger.info("Check that routes from R5 are readded")

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=nhg_id_1, r6_path=False, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=nhg_id_2, r6_path=False, r8_path=True
    )

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {nhg_id_1}, and 192.0.2.20/32: {nhg_id_2}"
    )
    step(
        "Check that the same NHG is used by both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
    )
    assert nhg_id_1 == nhg_id_2, (
        "A different NHG %d is used after R5 unshutdown between 192.0.2.9 and 192.0.2.20"
        % nhg_id_1
    )


def test_bgp_ipv4_simulate_r5_direct_peering_going_down():
    """
    On R5, we shutdown the interface
    Check that R8 is selected
    Check that R5 failure did not change the NHG (EDGE implementation needed)
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nshutdown\n",
            isjson=False,
        )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r5_path=False, r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=local_nhg_id_1, r5_path=False, r6_path=False, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r5_path=False, r6_path=False, r8_path=True
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=local_nhg_id_2, r5_path=False, r6_path=False, r8_path=True
    )

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {local_nhg_id_1}, and 192.0.2.20/32: {local_nhg_id_2}"
    )
    step("Check that previous NHG used by 192.0.2.9/32 unicast routes is same as now")
    assert local_nhg_id_1 == nhg_id_1, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id_1
    )


def test_bgp_ipv4_simulate_r5_direct_peering_up_again_with_three_paths():
    """
    On R5 and R8, we remove the route-map
    On R5, we unshutdown the interface
    Check that R8 and R5 are selected again
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove route-map from R5 and R8")
    for rname in ("r5", "r8"):
        for prefix in ("192.0.2.9/32", "192.0.2.20/32"):
            tgen.gears[rname].vtysh_cmd(
                f"configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nnetwork {prefix}",
                isjson=False,
            )

    step("UnShutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nno shutdown\n",
            isjson=False,
        )
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32", r8_path=True)

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=nhg_id_1, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops("192.0.2.20/32", r8_path=True)

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=nhg_id_2, r8_path=True
    )

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {nhg_id_1}, and 192.0.2.20/32: {nhg_id_2}"
    )
    step(
        "Check that the same NHG is used by both 192.0.2.9/32 and 192.0.2.20/32 unicast routes"
    )
    assert nhg_id_1 == nhg_id_2, (
        "A different NHG %d is used after R5 unshutdown between 192.0.2.9 and 192.0.2.20"
        % nhg_id_1
    )


def test_bgp_ipv4_simulate_r5_direct_peering_going_down_two_path_remain():
    """
    On R5, we shutdown the interface
    Check that R8 and R6 are selected
    Check that R5 failure did not change the NHG (EDGE implementation needed)
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nshutdown\n",
            isjson=False,
        )
    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r5_path=False, r6_path=True, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=local_nhg_id_1, r5_path=False, r6_path=True, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r5_path=False, r6_path=True, r8_path=True
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=local_nhg_id_2, r5_path=False, r6_path=True, r8_path=True
    )

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {local_nhg_id_1}, and 192.0.2.20/32: {local_nhg_id_2}"
    )
    step("Check that previous NHG used by 192.0.2.9/32 unicast routes is same as now")
    assert local_nhg_id_1 == nhg_id_1, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id_1
    )


def test_bgp_ipv4_simulate_r5_direct_peering_going_down_one_path_remain():
    """
    On R8, we shutdown the r8-eth0 interface
    Check that R6 only is selected
    Check that the NHG change did not change the NHG (EDGE implementation needed)
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown r8-eth0 interface")
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\ninterface r8-eth0\nshutdown\n",
        isjson=False,
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r5_path=False, r6_path=True, r8_path=False
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=local_nhg_id_1, r5_path=False, r6_path=True, r8_path=False
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r5_path=False, r6_path=True, r8_path=False
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=local_nhg_id_2, r5_path=False, r6_path=True, r8_path=False
    )

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {local_nhg_id_1}, and 192.0.2.20/32: {local_nhg_id_2}"
    )
    step("Check that previous NHG used by 192.0.2.9/32 unicast routes is same as now")
    assert local_nhg_id_1 == nhg_id_1, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id_1
    )
    step("UnShutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nno shutdown\n",
            isjson=False,
        )


def test_bgp_ipv4_three_paths_again():
    """
    On R8, we remove the route-map
    On R5, we unshutdown the interface
    Check that R6, R8 and R5 are selected again
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("UnShutdown r8-eth0 interface")
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\ninterface r8-eth0\nno shutdown\n",
        isjson=False,
    )

    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32", r8_path=True)

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=local_nhg_id_1, r8_path=True
    )

    check_ipv4_prefix_with_multiple_nexthops("192.0.2.20/32", r8_path=True)

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20", nhg_id=local_nhg_id_2, r8_path=True
    )


def test_bgp_ipv4_r8_uses_nh_from_r5():
    """
    On R8, we use a route-map to change NH of 192.0.2.20 to RT5
    On R5, we unshutdown the interface
    Check that R6, R8 and R5 are selected again
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global nhg_id_1
    global nhg_id_2

    step("Reconfigure R8 to advertise nexthops with R5 nexthop")
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\nip prefix-list plist1 seq 10 permit 192.0.2.20/32",
        isjson=False,
    )
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\nip prefix-list plist2 seq 10 permit 192.0.2.9/32",
        isjson=False,
    )
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\nroute-map rmap_nh permit 1\nmatch ip address prefix-list plist1\nset ip next-hop 192.0.2.5",
        isjson=False,
    )
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\nroute-map rmap_nh permit 2\nmatch ip address prefix-list plist2",
        isjson=False,
    )
    tgen.gears["r8"].vtysh_cmd(
        f"configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nneighbor rrserver route-map rmap_nh out\n",
        isjson=False,
    )

    # R5, R6 and R8 are selected
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32", r8_path=True)

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=nhg_id_1, r8_path=True
    )

    # R5, R6 are selected
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.20/32")

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux("192.0.2.20", nhg_id=nhg_id_2)

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {nhg_id_1}, and 192.0.2.20/32: {nhg_id_2}"
    )


def test_bgp_ipv4_simulate_r5_direct_peering_going_down_and_r8_announce_r5_two_path_remain():
    """
    On R5, we shutdown the interface
    Check that R8 and R6 are selected for 192.0.2.9
    Check that R8 and R6 are selected for 192.0.2.20
    Check that R5 failure did not change the NHG (EDGE implementation needed)
    """
    global nhg_id_1
    global nhg_id_2

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nshutdown\n",
            isjson=False,
        )
    # R6 and R8 are selected
    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.9/32", r5_path=False, r6_path=True, r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id_1 = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.9", nhg_id=local_nhg_id_1, r5_path=False, r6_path=True, r8_path=True
    )

    # R6 are selected
    check_ipv4_prefix_with_multiple_nexthops(
        "192.0.2.20/32", r5_path=False, r6_path=True, r8_path=False
    )

    step("Check that 192.0.2.20/32 unicast entry uses a BGP NHG")
    local_nhg_id_2 = route_check_nhg_id_is_protocol("192.0.2.20/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "192.0.2.20",
        nhg_id=local_nhg_id_2,
        r5_path=False,
        r6_path=True,
        r8_path=False,
    )

    logger.info(
        f"Get the nhg_id used for 192.0.2.9/32: {local_nhg_id_1}, and 192.0.2.20/32: {local_nhg_id_2}"
    )
    step("Check that previous NHG used by 192.0.2.9/32 unicast routes is same as now")
    assert local_nhg_id_1 == nhg_id_1, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id_1
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
