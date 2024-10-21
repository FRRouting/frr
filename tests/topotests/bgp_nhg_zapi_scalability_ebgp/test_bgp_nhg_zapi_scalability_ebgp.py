#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_nhg_zapi_scalability_ebgp.py
#
# Copyright 2024 6WIND S.A.
#

"""
 test_bgp_nhg_zapi_scalability_ebgp.py:
 Check that the FRR BGP daemon reduces the number of route_add messages
 by using bgp nexthop group facility.


+---+----+          +---+----+          +--------+
|        |          |        +          |        |
|  r1    +----------+  r3    +----------+  r5    +
|        |          |  rs    +    +-----+        |
+++-+----+          +--------+\  /      +--------+
  | |                          \/
  | |                          /\
  | |               +--------+/  \      +--------+
  | |               |        +    +-----+        +
  | +---------------+  r4    +----------+  r6    +
  |                 |        |          |        |
  |                 +--------+          +--------+
  |
  |                 +--------+          +--------+
  |                 |        |          |        +
  +-----------------+   r7   +----------+  r8    +
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

nhg_id = 0
nhg_id_18 = 0
nhg_id_22 = 0
route_count = 0
route_exact_number = 7


def build_topo(tgen):
    "Build function"

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

    switch = tgen.add_switch("s15")
    switch.add_link(tgen.gears["r7"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s16")
    switch.add_link(tgen.gears["r7"])
    switch.add_link(tgen.gears["r8"])

    switch = tgen.add_switch("s17")
    switch.add_link(tgen.gears["r8"])

    switch = tgen.add_switch("s18")
    switch.add_link(tgen.gears["r8"])


def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        "ip link add loop2 type dummy",
        "ip link set dev loop2 up",
    ]

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
        if rname in ("r1", "r3", "r5", "r6", "r7", "r8"):
            router.load_config(
                TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
            )
        if rname in ("r1", "r3", "r5", "r6", "r8"):
            router.load_config(
                TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
            )
        if rname in ("r5", "r6", "r8"):
            router.load_config(
                TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
            )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def ip_check_ibgp_prefix_count_in_rib(router, count):
    output = json.loads(router.vtysh_cmd(f"show ip route summary json"))
    for entry in output["routes"]:
        if entry["type"] == "ebgp":
            if count == int(entry["rib"]):
                return None
            return f'ibgp ipv4 route count differs from expected: {entry["rib"]}, expected {count}'
    return f"ibgp ipv4 route count not found"


def check_ipv4_prefix_with_multiple_nexthops(
    prefix, r5_path=True, r6_path=True, r8_path=False
):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
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
    assert result is None, f"Failed to check that {prefix} uses the IGP label 16055"


def check_ipv4_prefix_recursive_with_multiple_nexthops(
    prefix, recursive_nexthop, r5_path=True, r6_path=True, r8_path=False
):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info(
        f"Check that {prefix} unicast entry is correctly recursive via {recursive_nexthop} with paths for r5 {r5_path}, r6 {r6_path}, r8 {r8_path}"
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

    r8_nh = [
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

    recursive_nh = [
        {
            "ip": recursive_nexthop,
            "active": True,
            "recursive": True,
        },
    ]
    for nh in recursive_nh:
        expected[prefix][0]["nexthops"].append(nh)

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
        ip_check_path_selection,
        tgen.gears["r1"],
        prefix,
        expected,
        ignore_duplicate_nh=True,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), f"Failed to check that {prefix} is correctly recursive via {recursive_nexthop}"


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


def _get_bgp_route_count(router, add_routes=True):
    """
    Dump 'show zebra client' for BGP and extract the number of ipv4 route add messages
    if add_routes is not True, then it returns the number of ipv4 route_delete messages
    """
    if add_routes:
        return int(
            router.cmd(
                "vtysh -c 'show zebra client' | grep -e 'Client: bgp$' -A 40 | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 6'"
            )
        )
    # IS-IS may have counter to update, lets filter only on BGP clients
    return int(
        router.cmd(
            "vtysh -c 'show zebra client' | grep -e 'Client: bgp$' -A 40 | grep IPv4 | awk -F ' ' '{print $4}' | uniq"
        )
    )


def test_bgp_ipv4_convergence():
    """
    Check that R1 has received the 192.0.2.9/32 prefix from R5, and R8
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Ensure that the 192.0.2.9/32 route is available")
    check_ipv4_prefix_with_multiple_nexthops("192.0.2.9/32", r8_path=True)

    step("Check that 192.0.2.9/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("192.0.2.9/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux("192.0.2.9", nhg_id=local_nhg_id)


def test_bgp_ipv4_multiple_routes():
    """
    Configure 2000 routes on R5, R6, and R8, and redistribute routes in BGP.
    Check that R1 has received 2 of those routesprefix from R5, and R8
    Check that the number of RIB routes in ZEBRA is 2001
    """
    global nhg_id, nhg_id_18, nhg_id_22
    global route_count, route_exact_number

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r5"].vtysh_cmd(
        "sharp install routes 172.16.0.100 nexthop 192.0.2.5 2\n"
    )
    tgen.gears["r6"].vtysh_cmd(
        "sharp install routes 172.16.0.100 nexthop 192.0.2.6 2\n"
    )
    tgen.gears["r8"].vtysh_cmd(
        "sharp install routes 172.16.0.100 nexthop 192.0.2.8 2\n"
    )
    tgen.gears["r5"].vtysh_cmd(
        "sharp install routes 172.18.1.100 nexthop 172.16.0.100 2\n"
    )
    tgen.gears["r6"].vtysh_cmd(
        "sharp install routes 172.18.1.100 nexthop 172.16.0.100 2\n"
    )
    tgen.gears["r8"].vtysh_cmd(
        "sharp install routes 172.18.1.100 nexthop 172.16.0.100 2\n"
    )
    tgen.gears["r5"].vtysh_cmd(
        "sharp install routes 172.22.1.100 nexthop 172.18.1.100 2\n"
    )
    tgen.gears["r6"].vtysh_cmd(
        "sharp install routes 172.22.1.100 nexthop 172.18.1.100 2\n"
    )
    tgen.gears["r8"].vtysh_cmd(
        "sharp install routes 172.22.1.100 nexthop 172.18.1.100 2\n"
    )

    check_ipv4_prefix_with_multiple_nexthops("172.16.0.101/32", r8_path=True)

    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.18.1.100/32", "172.16.0.100", r8_path=True
    )
    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.22.1.100/32", "172.18.1.100", r8_path=True
    )

    step("Check that 192.0.2.9/32 unicast entry has 1 BGP NHG")
    nhg_id = route_check_nhg_id_is_protocol("172.16.0.101/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux("172.16.0.101", nhg_id=nhg_id)

    step("Check that 172.18.1.100/32 unicast entry has 1 BGP NHG")
    nhg_id_18 = route_check_nhg_id_is_protocol("172.18.1.100/32", "r1")
    check_ipv4_prefix_with_multiple_nexthops_linux("172.18.1.100/32", nhg_id=nhg_id_18)

    step("Check that 172.22.1.100/32 unicast entry has 1 BGP NHG")
    nhg_id_22 = route_check_nhg_id_is_protocol("172.22.1.100/32", "r1")
    check_ipv4_prefix_with_multiple_nexthops_linux("172.22.1.100/32", nhg_id=nhg_id_22)

    step(f"Check that the ipv4 zebra RIB count reaches {route_exact_number}")
    test_func = functools.partial(
        ip_check_ibgp_prefix_count_in_rib, tgen.gears["r1"], route_exact_number
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), f"Failed to check that the ipv4 zebra RIB count reaches {route_exact_number} :{result}"


def test_bgp_ipv4_simulate_r5_machine_going_down():
    """
    On R5, we shutdown the interface
    Check that only R8 is selected
    Check that R5 failure did not change the NHG (EDGE implementation needed)
    Check that the number of zclient messages did not move
    """
    global nhg_id, nhg_id_18, nhg_id_22
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # debug
    tgen.gears["r1"].vtysh_cmd("show zebra client")
    tgen.gears["r1"].vtysh_cmd("show bgp nexthop-group")
    tgen.gears["r1"].vtysh_cmd("show bgp nexthop")

    # take the reference number of zebra route add/update messages
    local_route_count_add = _get_bgp_route_count(tgen.net["r1"])
    logger.info(
        f"Number of route messages between BGP and ZEBRA, before shutdown: {local_route_count_add}"
    )

    step("Shutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nshutdown\n",
            isjson=False,
        )
    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.0.101/32", r5_path=False, r8_path=True
    )
    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.18.1.100/32", "172.16.0.100", r5_path=False, r8_path=True
    )
    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.22.1.100/32", "172.18.1.100", r5_path=False, r8_path=True
    )

    step("Check that 172.16.0.101/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.0.101/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.0.101", nhg_id=local_nhg_id, r5_path=False, r8_path=True
    )

    step("Check that other NHG is used by 172.16.0.101/32 unicast routes")
    assert local_nhg_id == nhg_id, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id
    )

    step("Check that 172.18.1.100/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.18.1.100/32", "r1")
    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.18.1.100", nhg_id=local_nhg_id, r5_path=False, r8_path=True
    )
    step("Check that other NHG is used by 172.18.1.100/32 unicast routes")
    assert local_nhg_id == nhg_id_18, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id_18
    )

    step("Check that 172.22.1.100/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.22.1.100/32", "r1")
    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.22.1.100", nhg_id=local_nhg_id, r5_path=False, r8_path=True
    )
    step("Check that other NHG is used by 172.22.1.150/32 unicast routes")
    assert local_nhg_id == nhg_id_22, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id_22
    )

    step(
        "Check that the number of route ADD messages between BGP and ZEBRA did not move"
    )
    route_count = _get_bgp_route_count(tgen.net["r1"])

    logger.info(f"Number of route messages ADD: {route_count}")
    assert route_count == local_route_count_add, (
        "The number of route messages increased when r5 machine goes down : %d, expected %d"
        % (route_count, local_route_count_add)
    )

    step("Check that the number of route DEL messages between BGP and ZEBRA is zero")
    local_route_count_del = _get_bgp_route_count(tgen.net["r1"], add_routes=False)

    logger.info(f"Get the route count messages between BGP and ZEBRA: {route_count}")
    assert local_route_count_del == 0, (
        "The number of route messages delete increased when r5 machine goes down : %d, expected 0"
        % local_route_count_del
    )
    # debug
    tgen.gears["r1"].vtysh_cmd("show zebra client")
    tgen.gears["r1"].vtysh_cmd("show bgp nexthop-group")
    tgen.gears["r1"].vtysh_cmd("show bgp nexthop")


def test_bgp_ipv4_simulate_r5_machine_going_up():
    """
    On R5, we unshutdown the interface
    Check that R5 is re-selected
    Check that the number of zclient messages has not been multiplied per 2
    """
    global nhg_id
    global route_count

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
    check_ipv4_prefix_with_multiple_nexthops("172.16.0.101/32", r8_path=True)

    step("Check that 172.16.0.101/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.0.101/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.0.101", nhg_id=local_nhg_id, r8_path=True
    )

    step("Check that other NHG is used by 172.16.0.101/32 unicast routes")
    assert (
        local_nhg_id != nhg_id
    ), "The same NHG %d is used after R5 recovers. The NHG_ID should be different" % (
        local_nhg_id
    )

    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.22.1.100/32", "172.18.1.100", r8_path=True
    )
    step("Check that 172.22.1.100/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.22.1.100/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.22.1.100", nhg_id=local_nhg_id, r8_path=True
    )

    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.18.1.100/32", "172.16.0.100", r8_path=True
    )
    step("Check that 172.18.1.100/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.18.1.100/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.18.1.100", nhg_id=local_nhg_id, r8_path=True
    )

    step("Check that the number of route ADD messages between BGP and ZEBRA did move")
    local_route_count_add = _get_bgp_route_count(tgen.net["r1"])
    logger.info(
        f"Get the route count messages between BGP and ZEBRA: {local_route_count_add}"
    )
    assert route_count != local_route_count_add, (
        "The number of route messages should have increased after r5 machine goes up : %d"
        % (local_route_count_add)
    )
    route_count = local_route_count_add


def test_bgp_ipv4_change_igp_on_r8_removed():
    """
    On R8, we remove the lo interface from the IGP
    Consequently, BGP NHT will tell the path to R8 lo interface is invalid
    Check that only R5, and R6 are selected, and use the same NHG_ID
    """
    global nhg_id, nhg_id_18, nhg_id_22
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Reconfigure R3 to remove BGP BFD with R8")
    tgen.gears["r3"].vtysh_cmd(
        """
        configure terminal\n
        router bgp 64501 view one\n
        no neighbor 192.0.2.8 bfd check-control-plane-failure\n
        no neighbor 192.0.2.8 bfd\n
        """,
        isjson=False,
    )
    step("Reconfigure R8 to remove BGP BFD with R3")
    tgen.gears["r8"].vtysh_cmd(
        """
        configure terminal\n
        router bgp 64500\n
        no neighbor rrserver bfd\n
        """,
        isjson=False,
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.0.101/32", r5_path=True, r6_path=True, r8_path=True
    )
    nhg_id = route_check_nhg_id_is_protocol("172.16.0.101/32", "r1")
    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.18.1.100/32", "172.16.0.100", r5_path=True, r6_path=True, r8_path=True
    )
    nhg_id_18 = route_check_nhg_id_is_protocol("172.18.1.100/32", "r1")
    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.22.1.100/32", "172.18.1.100", r5_path=True, r6_path=True, r8_path=True
    )
    nhg_id_22 = route_check_nhg_id_is_protocol("172.22.1.100/32", "r1")

    step("Get the number of route ADD messages between BGP and ZEBRA")
    route_count = _get_bgp_route_count(tgen.net["r1"])

    step("Reconfigure R8 to remove the lo interface from the IGP")
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\nno router isis 1\n",
        isjson=False,
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.0.101/32", r5_path=True, r6_path=True, r8_path=False
    )

    step("Check that 172.16.0.101/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.0.101/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.0.101", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=False
    )

    step("Check that same NHG is used by 172.16.0.101/32 unicast routes")
    assert local_nhg_id == nhg_id, (
        "A different NHG %d is used after IGP on R7 changed. The NHG_ID should be same (expected %d)"
        % (local_nhg_id, nhg_id)
    )

    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.18.1.100/32", "172.16.0.100", r5_path=True, r6_path=True, r8_path=False
    )

    step("Check that 172.18.1.100/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.18.1.100/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.18.1.100", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=False
    )

    step("Check that same NHG is used by 172.18.1.100/32 unicast routes")
    assert local_nhg_id == nhg_id_18, (
        "A different NHG %d is used after IGP on R7 changed. The NHG_ID should be same (expected %d)"
        % (local_nhg_id, nhg_id_18)
    )

    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.22.1.100/32", "172.18.1.100", r5_path=True, r6_path=True, r8_path=False
    )

    step("Check that 172.22.1.100/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.22.1.100/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.22.1.100", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=False
    )

    step("Check that same NHG is used by 172.22.1.100/32 unicast routes")
    assert local_nhg_id == nhg_id_22, (
        "A different NHG %d is used after IGP on R7 changed. The NHG_ID should be same (expected %d)"
        % (local_nhg_id, nhg_id_22)
    )

    step(
        "Check that the number of route ADD messages between BGP and ZEBRA did not move"
    )
    local_route_count_add = _get_bgp_route_count(tgen.net["r1"])
    logger.info(
        f"Get the route count messages between BGP and ZEBRA: {local_route_count_add}"
    )
    assert route_count == local_route_count_add, (
        "The number of route messages should have not moved after r8 IGP metric changed: expected %d"
        % (route_count)
    )
    route_count = local_route_count_add


def test_bgp_ipv4_change_igp_on_r8_readded():
    """
    On R8, we restore the lo interface in the IGP
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Readd the IGP to loopback interface of R8")
    conf_file = os.path.join(CWD, "r8/isisd.conf")
    tgen.net["r8"].cmd("vtysh -f {}".format(conf_file))

    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.0.101/32", r5_path=True, r6_path=True, r8_path=True
    )

    step("Check that 172.16.0.101/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.0.101/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.0.101", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=True
    )

    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.18.1.100/32", "172.16.0.100", r5_path=True, r6_path=True, r8_path=True
    )
    step("Check that 172.18.1.100/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.18.1.100/32", "r1")
    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.18.1.100", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=False
    )

    check_ipv4_prefix_recursive_with_multiple_nexthops(
        "172.22.1.100/32", "172.18.1.100", r5_path=True, r6_path=True, r8_path=True
    )
    step("Check that 172.22.1.100/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.22.1.100/32", "r1")
    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.18.1.100", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=False
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
