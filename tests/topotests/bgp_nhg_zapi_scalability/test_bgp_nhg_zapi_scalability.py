#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_nhg_zapi_scalability.py
#
# Copyright 2024 6WIND S.A.
#

"""
 test_bgp_nhg_zapi_scalability.py:
 Check that the FRR BGP daemon reduces the number of route_add messages
 by using bgp nexthop group facility.


+---+----+          +---+----+          +--------+
|        |          |        +          |        |
|  r1    +----------+  r3    +----------+  r5    +
|        |          |  rr    +    +-----+        |
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
route_count = 0


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
        if rname in ("r1", "r3", "r5", "r6", "r8"):
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
        if entry["type"] == "ibgp":
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
    global nhg_id
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r5"].vtysh_cmd(
        "sharp install routes 172.16.0.100 nexthop 192.0.2.5 2000\n"
    )
    tgen.gears["r6"].vtysh_cmd(
        "sharp install routes 172.16.0.100 nexthop 192.0.2.6 2000\n"
    )
    tgen.gears["r8"].vtysh_cmd(
        "sharp install routes 172.16.0.100 nexthop 192.0.2.8 2000\n"
    )

    check_ipv4_prefix_with_multiple_nexthops("172.16.5.150/32", r8_path=True)

    step("Check that 192.0.2.9/32 unicast entry has 1 BGP NHG")
    nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux("172.16.5.150", nhg_id=nhg_id)

    step("Check that the ipv4 zebra RIB count reaches 2001")
    test_func = functools.partial(
        ip_check_ibgp_prefix_count_in_rib, tgen.gears["r1"], 2001
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), f"Failed to check that the ipv4 zebra RIB count reaches 2001 :{result}"


def test_bgp_ipv4_simulate_r5_machine_going_down():
    """
    On R5, we shutdown the interface
    Check that only R8 is selected
    Check that R5 failure did not change the NHG (EDGE implementation needed)
    Check that the number of zclient messages did not move
    """
    global nhg_id
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # take the reference number of zebra route add/update messages
    local_route_count_add = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
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
        "172.16.5.150/32", r5_path=False, r8_path=True
    )

    step("Check that 172.16.5.150/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=local_nhg_id, r5_path=False, r8_path=True
    )

    step("Check that other NHG is used by 172.16.5.150/32 unicast routes")
    assert local_nhg_id == nhg_id, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id
    )

    step(
        "Check that the number of route ADD messages between BGP and ZEBRA did not move"
    )
    route_count = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
    logger.info(f"Number of route messages ADD: {route_count}")
    assert route_count == local_route_count_add, (
        "The number of route messages increased when r5 machine goes down : %d, expected %d"
        % (route_count, local_route_count_add)
    )

    step("Check that the number of route DEL messages between BGP and ZEBRA is zero")
    local_route_count_del = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $4}' | uniq"
        )
    )
    logger.info(f"Get the route count messages between BGP and ZEBRA: {route_count}")
    assert local_route_count_del == 0, (
        "The number of route messages delete increased when r5 machine goes down : %d, expected 0"
        % local_route_count_del
    )
    # debug: show zebra client
    tgen.gears["r1"].vtysh_cmd(f"show zebra client")


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
    check_ipv4_prefix_with_multiple_nexthops("172.16.5.150/32", r8_path=True)

    step("Check that 172.16.5.150/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=local_nhg_id, r8_path=True
    )

    step("Check that other NHG is used by 172.16.5.150/32 unicast routes")
    assert (
        local_nhg_id != nhg_id
    ), "The same NHG %d is used after R5 recovers. The NHG_ID should be different" % (
        local_nhg_id
    )

    step(
        "Check that the number of route ADD messages between BGP and ZEBRA did not move"
    )
    local_route_count_add = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
    logger.info(
        f"Get the route count messages between BGP and ZEBRA: {local_route_count_add}"
    )
    assert route_count != local_route_count_add, (
        "The number of route messages should have increased after r5 machine goes up : %d"
        % (local_route_count_add)
    )
    route_count = local_route_count_add


def test_bgp_ipv4_unpeering_with_r5():
    """
    On R5, we unconfigure R3 peering
    Check that, on R1, routes from R5 are removed
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("R5, unpeer with R3")
    tgen.gears["r5"].vtysh_cmd(
        f"configure terminal\nrouter bgp 64500\nno neighbor 192.0.2.3 peer-group rrserver\n",
        isjson=False,
    )

    logger.info("Check that routes from R5 are removed")
    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.5.150/32", r5_path=False, r6_path=True, r8_path=True
    )

    step("Check that 172.16.5.150/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=local_nhg_id, r5_path=False, r6_path=True, r8_path=True
    )

    # debug: show zebra client
    tgen.gears["r1"].vtysh_cmd(f"show zebra client")


def test_bgp_ipv4_direct_peering_with_r5():
    """
    On R5, we configure a peering with R1
    On R1, we configure a peering with R5
    Check that routes from R5 are re-added
    """
    global nhg_id
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("R5, peer with R1")
    tgen.gears["r5"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\nneighbor rrserver bfd\nneighbor rrserver bfd check-control-plane-failure",
        isjson=False,
    )
    tgen.gears["r5"].vtysh_cmd(
        f"configure terminal\nrouter bgp 64500\nneighbor 192.0.2.1 peer-group rrserver\n",
        isjson=False,
    )
    logger.info("R1, peer with R5")
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\nneighbor rrserver bfd\nneighbor rrserver bfd check-control-plane-failure",
        isjson=False,
    )
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp 64500\nneighbor 192.0.2.5 peer-group rrserver\n",
        isjson=False,
    )

    logger.info("Check that routes from R5 are readded")
    check_ipv4_prefix_with_multiple_nexthops("172.16.5.150/32", r8_path=True)

    step("Check that 172.16.5.150/32 unicast entry has 1 BGP NHG")
    nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=nhg_id, r8_path=True
    )

    route_count = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
    logger.info(f"Get the route count messages between BGP and ZEBRA: {route_count}")


def test_bgp_ipv4_simulate_r5_peering_going_down():
    """
    On R5, we shutdown the interface
    Check that R8 is selected
    Check that R5 failure did not change the NHG (EDGE implementation needed)
    """
    global nhg_id
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Shutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nshutdown\n",
            isjson=False,
        )
    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.5.150/32", r5_path=False, r6_path=True, r8_path=True
    )

    step("Check that 172.16.5.150/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=local_nhg_id, r5_path=False, r6_path=True, r8_path=True
    )

    step("Check that same NHG is used by 172.16.5.150/32 unicast routes")
    assert local_nhg_id == nhg_id, (
        "The same NHG %d is not used after R5 shutdown, EDGE implementation missing"
        % nhg_id
    )

    step(
        "Check that the number of route ADD messages between BGP and ZEBRA did not move"
    )
    local_route_count_add = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
    logger.info(f"Number of route messages ADD: {local_route_count_add}")
    assert route_count == local_route_count_add, (
        "The number of route messages increased when r5 machine goes down : %d, expected %d"
        % (local_route_count_add, route_count)
    )

    step("Check that the number of route DEL messages between BGP and ZEBRA is zero")
    local_route_count_del = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $4}' | uniq"
        )
    )
    logger.info(
        f"Get the route DELETE count messages between BGP and ZEBRA: {local_route_count_del}"
    )
    assert local_route_count_del == 0, (
        "The number of route messages delete increased when r5 machine goes down : %d, expected 0"
        % local_route_count_del
    )

    # debug: show zebra client
    tgen.gears["r1"].vtysh_cmd(f"show zebra client")


def test_bgp_ipv4_simulate_r5_peering_going_up_again():
    """
    On R5, we un-shutdown the interface
    Check that R5 routes are re-added
    """
    global nhg_id
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Un-Shutdown R5 interface")
    for ifname in ("r5-eth1", "r5-eth2"):
        tgen.gears["r5"].vtysh_cmd(
            f"configure terminal\ninterface {ifname}\nno shutdown\n",
            isjson=False,
        )
    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.5.150/32", r5_path=True, r6_path=True, r8_path=True
    )

    step("Check that 172.16.5.150/32 unicast entry has 1 BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=True
    )

    step("Check that the number of route ADD messages between BGP and ZEBRA did move")
    local_route_count_add = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
    logger.info(f"Number of route messages ADD: {local_route_count_add}")
    assert (
        route_count != local_route_count_add
    ), "The number of route messages did not increas since r5 machine went up : %d" % (
        route_count
    )
    route_count = local_route_count_add


def test_bgp_ipv4_lower_preference_value_on_r5_and_r8_configured():
    """
    On R5, and R8, we add a route-map to lower local-preference
    Check that only R6 is selected
    """
    global nhg_id
    global route_count

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
        tgen.gears[rname].vtysh_cmd(
            f"configure terminal\nrouter bgp 64500\naddress-family ipv4 unicast\nredistribute sharp route-map rmap",
            isjson=False,
        )

    step("Check that 172.16.5.150/32 unicast entry is installed with one endpoints")
    check_ipv4_prefix_with_multiple_nexthops("172.16.5.150/32", r5_path=False)

    step("Check that 172.16.5.150/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=local_nhg_id, r5_path=False
    )

    step("Check that other NHG is used by 172.16.5.150/32 unicast routes")
    assert local_nhg_id != nhg_id, (
        "The same NHG %d is used after R5 and R8 updates use a different preference value. The NHG_ID should be different"
        % (local_nhg_id)
    )

    step(
        "Check that the number of route ADD messages between BGP and ZEBRA did not move"
    )
    local_route_count_add = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
    logger.info(
        f"Get the route count messages between BGP and ZEBRA: {local_route_count_add}"
    )
    assert route_count != local_route_count_add, (
        "The number of route messages should have increased after r5 machine goes up : %d"
        % (local_route_count_add)
    )
    route_count = local_route_count_add


def test_bgp_ipv4_reset_preference_value():
    """
    On R5 and R8, we reset the route-map preference value
    Check that R5 routes are re-added
    """
    global nhg_id
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Reconfigure R5 and R8 to reset the preference value of advertised unicast networks"
    )
    for rname in ("r5", "r8"):
        tgen.gears[rname].vtysh_cmd(
            "configure terminal\nroute-map rmap permit 1\nno set local-preference 50\n",
            isjson=False,
        )

    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.5.150/32", r5_path=True, r6_path=True, r8_path=True
    )

    step("Check that 172.16.5.150/32 unicast entry has 1 BGP NHG")
    nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=nhg_id, r5_path=True, r6_path=True, r8_path=True
    )

    step("Check that the number of route ADD messages between BGP and ZEBRA did move")
    local_route_count_add = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
    logger.info(f"Number of route messages ADD: {local_route_count_add}")
    assert (
        route_count != local_route_count_add
    ), "The number of route messages did not increas since r5 machine went up : %d" % (
        route_count
    )
    route_count = local_route_count_add


def test_bgp_ipv4_change_igp_on_r8_removed():
    """
    On R8, we remove the lo interface from the IGP
    Consequently, BGP NHT will tell the path to R8 lo interface is invalid
    Check that only R5, and R6 are selected, and use the same NHG_ID
    """
    global nhg_id
    global route_count

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Reconfigure R8 to remove the lo interface from the IGP")
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\ninterface lo\nno ip router isis 1\n",
        isjson=False,
    )

    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.5.150/32", r5_path=True, r6_path=True, r8_path=False
    )

    step("Check that 172.16.5.150/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=False
    )

    step("Check that same NHG is used by 172.16.5.150/32 unicast routes")
    assert local_nhg_id == nhg_id, (
        "A different NHG %d is used after IGP on R7 changed. The NHG_ID should be same (expected %d)"
        % (local_nhg_id, nhg_id)
    )

    step(
        "Check that the number of route ADD messages between BGP and ZEBRA did not move"
    )
    local_route_count_add = int(
        tgen.net["r1"].cmd(
            "vtysh -c 'show zebra client' | grep IPv4 | awk -F ' ' '{print $2}' | awk -F\, '$1 > 2000'"
        )
    )
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
    tgen.gears["r8"].vtysh_cmd(
        "configure terminal\ninterface lo\nip router isis 1\n",
        isjson=False,
    )
    check_ipv4_prefix_with_multiple_nexthops(
        "172.16.5.150/32", r5_path=True, r6_path=True, r8_path=True
    )

    step("Check that 172.16.5.150/32 unicast entry uses a BGP NHG")
    local_nhg_id = route_check_nhg_id_is_protocol("172.16.5.150/32", "r1")

    check_ipv4_prefix_with_multiple_nexthops_linux(
        "172.16.5.150", nhg_id=local_nhg_id, r5_path=True, r6_path=True, r8_path=True
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
