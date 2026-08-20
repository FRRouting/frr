#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2026 6WIND S.A.

"""
test_bgp_evpn_vxlan.py: Test EVPN VPWS VXLAN port-based single-homed.
     +-----+
     |     |                        +-----+   +-----+
     |HOST1|                        |     |   |     |
     |     |                    +---+ PE2 +---+HOST2|
     +--+--+                    |   |     |   |     |
        |                       |   +-----+   +-----+
        |    +-----+   +----+   |
        +----+     |   |    +---+
             | PE1 +---+ P1 |
        +----+     |   |    +---+
        |    +--+--+   +----+   |
        |                       |   +-----+   +-----+
     +--+--+                    |   |     |   |     |
     |     |                    +---+ PE3 +---+HOST4|
     |HOST3|                        |     |   |     |
     |     |                        +-----+   +-----+
     +-----+

EVPN VPWS PE1 <----> PE2
Standard EVPN multipoint PE1 <----> PE3
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
PE1_SVI = 1
PE2_SVI = 2
ESI = "00:00:00:00:00:00:00:00:00:00"
AC_PE1 = 111
AC_PE2 = 222


def build_topo(tgen):
    "Build function"

    tgen.add_router("P1")
    tgen.add_router("PE1")
    tgen.add_router("PE2")
    tgen.add_router("PE3")
    tgen.add_router("host1")
    tgen.add_router("host2")
    tgen.add_router("host3")
    tgen.add_router("host4")

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

    # P1-PE3
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["P1"])
    switch.add_link(tgen.gears["PE3"])

    # PE2-host2
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["PE2"])
    switch.add_link(tgen.gears["host2"])

    # Host3-PE1
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["host3"])
    switch.add_link(tgen.gears["PE1"])

     #Host4-PE3
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["host4"])
    switch.add_link(tgen.gears["PE3"])

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    pe3 = tgen.gears["PE3"]
    p1 = tgen.gears["P1"]
    host1 = tgen.gears["host1"]
    host2 = tgen.gears["host2"]
    host3 = tgen.gears["host3"]
    host4 = tgen.gears["host4"]

    pe1.run("ip link add vrf1 type vrf table 10")
    pe1.run("ip link set up dev vrf1")
    pe1.run("ip link add link PE1-eth0 name vlanTest type vlan id 777")
    pe1.run("ip link set up dev vlanTest")
    p1.run("sysctl -w net.ipv4.ip_forward=1")
    # setup EVPN VPWS VXLAN VNI 101
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

    # setup EVPN VXLAN VNI 102
    pe1.run("ip link add name br102 type bridge stp_state 0")
    pe1.run("ip addr add 10.10.2.1/24 dev br102")
    pe1.run("ip link set dev br102 up")
    pe1.run(
        "ip link add vxlan102 type vxlan id 102 dstport 4789 local 10.10.10.11 nolearning"
    )
    pe1.run("ip link set dev vxlan102 master br102")
    pe1.run("ip link set dev PE1-eth2 master br102")
    pe1.run("ip link set dev PE1-eth2")

    pe3.run("ip link add name br102 type bridge stp_state 0")
    pe3.run("ip addr add 10.10.2.2/24 dev br102")
    pe3.run("ip link set dev br102 up")
    pe3.run(
        "ip link add vxlan102 type vxlan id 102 dstport 4789 local 10.30.30.31 nolearning"
    )
    pe3.run("ip link set dev vxlan102 master br102")
    pe3.run("ip link set dev PE3-eth1 master br102")
    pe3.run("ip link set dev PE3-eth1")

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
    host3.run("ip addr add 10.10.2.3/24 dev host3-eth0")
    host4.run("ip addr add 10.10.2.4/24 dev host4-eth0")


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


@retry(retry_timeout=60)
def check_es_evi_route(router, rd, tag, esi, iplen, vtep, nexthop, ecomm=None, fragid=0):
    "Check EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]"
    #fragid in global table is always 0
    #vtep is null in global table
    #local es evi route iplen is 128 in global table
    res = json.loads(router.vtysh_cmd("show bgp l2vpn evpn json"))
    res = res.get(rd)
    if not res:
        return f"{router.name}: can not find RD {rd}"

    route = f"[1]:[{tag}]:[{esi}]:[{iplen}]:[{vtep}]:[{fragid}]"
    res = res.get(route)
    if not res:
        return f"{router.name}: can not find route {route}"

    found = False
    paths = res["paths"]

    for path in paths:
        ecomm_str = path.get("extendedCommunity", {}).get("string", "")
        for n in path["nexthops"]:
            if n["ip"] == nexthop:
                found = True
                break;

    if not found:
        return f"{router.name}: can not find nexthop {nexthop} for route {route}"

    if ecomm:
        if ecomm not in ecomm_str:
            return f"{router.name}: can not find {ecomm} in {ecomm_str}"

    return True


@retry(retry_timeout=10)
def check_show_l2vpn_vpws(router, name, vsi, rvsi, iface, state):
    res = json.loads(router.vtysh_cmd(f"show l2vpn {name} vpws json"))

    if not res:
        return f"Can not find L2VPN {name}"

    match = None
    for vpws in res["instances"]:
        if vpws["localVsi"] != vsi:
            continue

        if vpws["remoteVsi"] != rvsi:
            continue

        if vpws["memberEVPN"] != iface:
            continue

        if vpws["state"] != state:
            continue

        match = vpws
        break

    if match is None:
        return f"""
        Can not match VPWS(memberEVPN={iface}, localVsi={vsi},
        remoteVsi={rvsi}, state={state})
        """

    return True

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
        pe1, "10.10.10.10:1", PE1_SVI, ESI, 128, "::", "0.0.0.0")
    assert res is True, res
    res = check_es_evi_route(
        pe2, "10.30.30.30:1", PE2_SVI, ESI, 128, "::", "0.0.0.0")
    assert res is True, res

    # remote es evi route
    logger.info("Checking remote es-evi route")
    res = check_es_evi_route(pe1, "10.30.30.30:1", PE2_SVI, ESI, 32, "0.0.0.0",
                             "10.30.30.30")
    assert res is True, res
    res = check_es_evi_route(pe2, "10.10.10.10:1", PE1_SVI, ESI, 32, "0.0.0.0",
                             "10.10.10.10")
    assert res is True, res

    # check EVPN VPWS state is up
    logger.info("Checking EVPN VPWS state")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Up")
    assert res is True, res
    res = check_show_l2vpn_vpws(pe2, "test", PE2_SVI, PE1_SVI, "vxlan101", "Up")
    assert res is True, res


def test_ping():
    "Ping host1 <-> host2 on vlan10"

    logger.info("Checking EVPN VPWS dataplane")
    check_ping("host1", "10.10.1.56", True, 10, 3)
    check_ping("host2", "10.10.1.55", True, 10, 3)


def test_rd():
    "Change RD/RT configs and check EVPN VPWS state"

    tgen = get_topogen()
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    logger.info("PE1: change RD to 10.10.10.10:111 and RT to 65000:111")
    pe1.vtysh_multicmd(
        """
        configure terminal
        router bgp 65000
         address-family l2vpn evpn
          vni 101
           rd 10.10.10.10:111
           no route-target both 65000:1
           route-target both 65000:100
        """)

    logger.info("PE1: checking local es-evi route")
    res = check_es_evi_route(
        pe1, "10.10.10.10:111", PE1_SVI, ESI, 128, "::", "0.0.0.0")
    assert res is True, res

    logger.info("Checking EVPN VPWS state is Down")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Down")
    assert res is True, res

    logger.info("PE2: change RD to 10.30.30.30:222 and RT to 65000:100")
    pe2.vtysh_multicmd(
        """
        configure terminal
        router bgp 65000
         address-family l2vpn evpn
          vni 101
           rd 10.30.30.30:222
           no route-target both 65000:1
           route-target both 65000:100
        """)

    logger.info("PE2: checking local es-evi route")
    res = check_es_evi_route(
        pe2, "10.30.30.30:222", PE2_SVI, ESI, 128, "::", "0.0.0.0")
    assert res is True, res

    logger.info("Checking EVPN VPWS state is Up")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Up")
    assert res is True, res


def test_mtu():
    "Check dataplane MTU and ignore-mtu-mismatch config changes"

    tgen = get_topogen()
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    logger.info("PE1: change PE1-eth0 MTU to 1200 to trigger to trigger new EVI"
                " per A-D route")
    pe1.run("ip link set mtu 1200 PE1-eth0")
    res = check_es_evi_route(
        pe1, "10.10.10.10:111", PE1_SVI, ESI, 128, "::", "0.0.0.0", ecomm="MTU 0")
    assert res is True, res

    logger.info("PE2: check new es-evi route from PE1")
    res = check_es_evi_route(
        pe2, "10.10.10.10:111", PE1_SVI, ESI, 32, "0.0.0.0", "10.10.10.10",
        ecomm="MTU 0")
    assert res is True, res

    logger.info("Checking EVPN VPWS state is Up")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Up")
    assert res is True, res

    logger.info("PE2: Disable ignore-mtu-mismatch")
    pe2.vtysh_multicmd(
        """
        configure terminal
        l2vpn test type vpws
         member evpn vxlan101
          ignore-mtu-mismatch disable
        """)

    logger.info("PE1: check new es-evi route from PE2 MTU 1500")
    res = check_es_evi_route(
        pe1, "10.30.30.30:222", PE2_SVI, ESI, 32, "0.0.0.0", "10.30.30.30",
        ecomm="MTU 1500")
    assert res is True, res

    logger.info("Checking EVPN VPWS state is Down")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Down")
    assert res is True, res

    logger.info("PE1: restore PE1-eth0 mtu to 1500")
    pe1.run("ip link set mtu 1500 PE1-eth0")

    logger.info("Checking EVPN VPWS state is Up")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Up")
    assert res is True, res


def test_setup_changes():
    "Check zebra is enable to detect EVPN VPWS VXLAN setup changes"

    tgen = get_topogen()
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    logger.info("PE1: deattach AC interface (PE1-eth0) from the SVI")
    pe1.run("ip link set nomaster PE1-eth0")
    logger.info("Checking EVPN VPWS state is Down")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Down")
    assert res is True, res
    res = check_show_l2vpn_vpws(pe2, "test", PE2_SVI, PE1_SVI, "vxlan101", "Down")
    assert res is True, res

    logger.info("PE1: attach AC interface (PE1-eth0) to the SVI")
    pe1.run("ip link set master br101 PE1-eth0")
    logger.info("Checking EVPN VPWS state is Up")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Up")
    assert res is True, res
    res = check_show_l2vpn_vpws(pe2, "test", PE2_SVI, PE1_SVI, "vxlan101", "Up")
    assert res is True, res

    logger.info("PE1: attach vlanTest interface to the SVI")
    pe1.run("ip link set master br101 dev vlanTest")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Down")
    assert res is True, res
    logger.info("Checking EVPN VPWS state is Down")
    res = check_show_l2vpn_vpws(pe2, "test", PE2_SVI, PE1_SVI, "vxlan101", "Down")
    assert res is True, res

    logger.info("PE1: deattach vlanTest interface from the SVI")
    pe1.run("ip link set nomaster dev vlanTest")
    logger.info("Checking EVPN VPWS state is Up")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Up")
    assert res is True, res
    res = check_show_l2vpn_vpws(pe2, "test", PE2_SVI, PE1_SVI, "vxlan101", "Up")
    assert res is True, res

    logger.info("Checking EVPN VPWS dataplane")
    check_ping("host1", "10.10.1.56", True, 10, 3)
    check_ping("host2", "10.10.1.55", True, 10, 3)


@retry(retry_timeout=30)
def check_macip(router, bridge, mac):
    output = router.cmd(f"bridge fdb show br {bridge} | grep '{mac}'")

    if mac not in output:
        return f"{mac} is not present in {bridge} table"

    return True


def test_evpn_mix_mode():
    "Check EVPN VPWS and standard EVPN multipoint mixed mode"

    tgen = get_topogen()
    pe1 = tgen.gears["PE1"]
    pe3 = tgen.gears["PE3"]
    host4 = tgen.gears["host4"]

    logger.info("Waing EVPN connection PE1 <-> PE3")
    pe1.run("ip link set up dev vxlan102")
    pe3.run("ip link set up dev vxlan102")
    output = host4.cmd("ip link show host4-eth0")
    match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", output)
    res = check_macip(pe1, "br102", match.group(1))
    assert res is True, res


    logger.info("Check ping host3 <-> host4")
    check_ping("host3", "10.10.2.4", True, 10, 3)

    logger.info("Checking EVPN VPWS state is Up")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101", "Up")
    assert res is True, res

    logger.info("Check ping host1 <-> host2")
    check_ping("host1", "10.10.1.56", True, 10, 3)


def test_vni_changes():
    "Check EVPN VPWS VNI changes"

    tgen = get_topogen()
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    logger.info("Removing Vxlan101 interface")
    pe1.run("ip link del vxlan101")
    pe2.run("ip link del vxlan101")
    logger.info("Checking EVPN VPWS state is Down")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101",
                                "Down")
    assert res is True, res

    logger.info("Adding Vxlan101 VNI 200 interface")
    pe1.run("ip link add vxlan101 type vxlan id 200 dstport 4789")
    pe1.run("ip link set master br101 dev vxlan101")
    pe1.run("ip link set up dev vxlan101")
    pe2.run("ip link add vxlan101 type vxlan id 200 dstport 4789")
    pe2.run("ip link set master br101 dev vxlan101")
    pe2.run("ip link set up dev vxlan101")

    logger.info("Checking EVPN VPWS VNI 200 state is Up")
    res = check_show_l2vpn_vpws(pe1, "test", PE1_SVI, PE2_SVI, "vxlan101",
                                "Up")
    assert res is True, res


    logger.info("Check ping host1 <-> host2")
    check_ping("host1", "10.10.1.56", True, 10, 3)


def _memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
