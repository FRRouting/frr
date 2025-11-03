#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2026 6WIND S.A.

"""
test_bgp_evpn_vxlan.py: Test EVPN VPWS VXLAN port-based single-homed.

      +-----+   +-----+   +----+   +-----+   +-----+
      |     |   |     |   |    |   |     |   |     |
      |HOST1+---+ PE1 +---+ P1 +---+ PE2 +---+HOST2|
      |     |   |     |   |    |   |     |   |     |
      +-----+   +-----+   +----+   +-----+   +-----+
"""

import os
import sys
import json
from functools import partial
import pytest
import re

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.common_config import retry
from lib.checkping import check_ping
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]
EVI = 100
ESI = "00:00:00:00:00:00:00:00:00:00"
AC_PE1 = 111
AC_PE2 = 222


def build_topo(tgen):
    "Build function"

    tgen.add_router("P1")
    tgen.add_router("PE1")
    tgen.add_router("PE2")
    tgen.add_router("host1")
    tgen.add_router("host2")

    # Host1-PE1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["host1"])
    switch.add_link(tgen.gears["PE1"])

    # PE1-P1
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["PE1"])
    switch.add_link(tgen.gears["P1"])

    # P1-PE2
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["P1"])
    switch.add_link(tgen.gears["PE2"])

    # PE2-host2
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["PE2"])
    switch.add_link(tgen.gears["host2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    p1 = tgen.gears["P1"]
    host1 = tgen.gears["host1"]
    host2 = tgen.gears["host2"]

    pe1.run("ip link add vrf1 type vrf table 10")
    pe1.run("ip link set up dev vrf1")
    pe1.run("ip link add name br101 type bridge stp_state 0")
    pe1.run("ip addr add 10.10.1.1/24 dev br101")
    pe1.run("ip link set dev br101 up")
    pe1.run("ip link set dev br101 master vrf1")
    pe1.run(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.10.10.10 nolearning"
    )
    pe1.run("ip link set dev vxlan101 master br101")
    pe1.run("ip link set dev vxlan101 type bridge_slave neigh_suppress on learning off")
    pe1.run("ip link set up dev vxlan101")
    pe1.run("ip link set dev PE1-eth0 master br101")
    pe1.run("ip link set dev PE1-eth0 type bridge_slave neigh_suppress on learning off")

    pe2.run("ip link add name br101 type bridge stp_state 0")
    pe2.run("ip addr add 10.10.1.3/24 dev br101")
    pe2.run("ip link set dev br101 up")
    pe2.run(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.30.30.30 nolearning"
    )
    pe2.run("ip link set dev vxlan101 master br101 addrgenmode none")
    pe2.run("ip link set dev vxlan101 type bridge_slave neigh_suppress on learning off")
    pe2.run("ip link set up dev vxlan101")
    pe2.run("ip link set dev PE2-eth1 master br101")
    pe2.run("ip link set dev PE2-eth1 type bridge_slave neigh_suppress on learning off")
    p1.run("sysctl -w net.ipv4.ip_forward=1")

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, None),
             (TopoRouter.RD_OSPF, None)],
        )

    tgen.start_router()

    host1.run("ip link add vlan10 link host1-eth0 type vlan id 10")
    host1.run("ip link set up dev vlan10")
    host2.run("ip link add vlan10 link host2-eth0 type vlan id 10")
    host2.run("ip link set up dev vlan10")


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


@retry(retry_timeout=60)
def check_es_evi_route(router, rd, evi, esi, iplen, vtep, nexthop, fragid=0):
    "Check EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]"
    #fragid in global table is always 0
    #vtep is null in global table
    #local es evi route iplen is 128 in global table
    res = json.loads(router.vtysh_cmd("show bgp l2vpn evpn json"))
    res = res.get(rd)
    if not res:
        return f"{router.name}: can not find RD {rd}"

    route = f"[1]:[{evi}]:[{esi}]:[{iplen}]:[{vtep}]:[{fragid}]"
    res = res.get(route)
    if not res:
        return f"{router.name}: can not find route {route}"

    found = False
    paths = res["paths"]

    for path in paths:
        for n in path["nexthops"]:
            if n["ip"] == nexthop:
                found = True
                break;

    if not found:
        return f"{router.name}: can not find nexthop {nexthop} for route {route}"

    return True

@retry(retry_timeout=10)
def check_show_l2vpn_vpws(router, name, evi, acs, pw_iface, proto):
    """
    Check show l2vpn <name> vpws
    EVI    local/remote AC    PW    Status    PROTO
    100    10/20              eth0  Up        BGP
    """

    res = router.vtysh_cmd(f"show l2vpn {name} vpws")
    if re.search(rf"{evi}\s+{acs}\s+{pw_iface}\s+Up\s+{proto}", res):
        return True

    return f"{router.name}: VPWS EVI {evi} is not up"


def test_converge_evpn_vpws():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    # local es evi route
    logger.info("Checking local es-evi route")
    res = check_es_evi_route(
        pe1, "10.10.10.10:1", EVI, ESI, 128, "::", "0.0.0.0")
    assert res is True, res
    res = check_es_evi_route(
        pe2, "10.30.30.30:1", EVI, ESI, 128, "::", "0.0.0.0")
    assert res is True, res

    # remote es evi route
    logger.info("Checking remote es-evi route")
    res = check_es_evi_route(pe1, "10.30.30.30:1", EVI, ESI, 32, "0.0.0.0",
                             "10.30.30.30")
    assert res is True, res
    res = check_es_evi_route(pe2, "10.10.10.10:1", EVI, ESI, 32, "0.0.0.0",
                             "10.10.10.10")
    assert res is True, res

    # check EVPN VPWS state is up
    logger.info("Checking EVPN VPWS status")
    res = check_show_l2vpn_vpws(pe1, "test", EVI, f"{AC_PE1}/{AC_PE2}", "vxlan101",
                                "BGP")
    assert res is True, res
    res = check_show_l2vpn_vpws(pe2, "test", EVI, f"{AC_PE2}/{AC_PE1}", "vxlan101",
                                "BGP")
    assert res is True, res


def test_ping():
    "Ping host1 <-> host2 on vlan10"

    logger.info("Checking EVPN VPWS dataplane")
    check_ping("host1", "10.10.1.56", True, 10, 3)
    check_ping("host2", "10.10.1.55", True, 10, 3)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
