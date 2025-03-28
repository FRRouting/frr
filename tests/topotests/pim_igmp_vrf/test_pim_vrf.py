#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_vrf.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
# Copyright (c) 2025 by Martin Buck
#

"""
test_pim_vrf.py: Test PIM with VRFs, both IPv4 and IPv6.
"""

# XXX clean up in later commit to avoid conflict on rebase
# pylint: disable=C0413

# Tests PIM with VRF
#
# R1 is split into 2 VRF: Blue and Red, the others are normal
# routers and Hosts
# There are 2 similar topologies with overlapping IPs in each
# section.
#
# Test steps:
# - setup_module()
#     Create topology. Hosts are only using zebra/staticd,
#     no PIM, no OSPF (using IGMPv2/MLDv1 for multicast)
# - test_ospf_convergence()
#     Wait for OSPFv2 convergence in each VRF. OSPF is run on
#     R1, R11 and R12.
# - test_ospf6_convergence()
#     Wait for OSPFv3 convergence in each VRF.
# - test_pim_convergence()
#     Wait for PIM (IPv4) convergence in each VRF. PIM is run on
#     R1, R11 and R12. R11 is the RP for vrf blue, R12 is RP
#     for vrf red.
# - test_pim6_convergence()
#     Wait for PIM (IPv6) convergence in each VRF.
# - test_vrf_pimreg_interfaces()
#     Adding PIM RP in VRF information and verify pimreg
#     interfaces in VRF blue and red
# - test_vrf_pim6reg_interfaces()
#     Adding PIM (IPv6) RP in VRF information and verify pim6reg
#     interfaces in VRF blue and red
# - test_mcast_vrf_blue()
#     Join MC group 239.100.0.1 from Host H1 on vrf blue
#     Start MC stream from Host H2
#     Verify PIM JOIN status on R1 and R11
#     Stop multicast after verification
#     Check (interface statistics) whether PIM Register messages were
#     generated towards RP and answered by Register-Stop
# - test_mcast_vrf_red()
#     Join MC group 239.100.0.1 from Host H4 on vrf red
#     Start MC stream from Host H4
#     Verify PIM JOIN status on R1 and R12
#     Stop multicast after verification
#     Check (interface statistics) whether PIM Register messages were
#     generated towards RP and answered by Register-Stop
# - test_ipv6_mcast_vrf_blue()
#     Join MC group ff18:100::1 from Host H1 on vrf blue
#     Start MC stream from Host H2
#     Verify PIM JOIN status on R1 and R11
#     Stop multicast after verification
#     Check (interface statistics) whether PIM Register messages were
#     generated towards RP and answered by Register-Stop
# - test_ipv6_mcast_vrf_red()
#     Join MC group ff18:100::1 from Host H4 on vrf red
#     Start MC stream from Host H4
#     Verify PIM JOIN status on R1 and R12
#     Stop multicast after verification
#     Check (interface statistics) whether PIM Register messages were
#     generated towards RP and answered by Register-Stop
# - teardown_module(module)
#     shutdown topology
#

TOPOLOGY = """
                                                +----------+
                                                |  Host H2 |
                                                |  Source  |
                                                +----------+
                                                  .2 |
+---------+ 192.168.100.0/24  +------------+         |         +---------+
| Host H1 | 2001:db8:100::/64 |            | .1      |     .11 | R11     |
| receive |-------------------|  VRF Blue  |---------+---------| PIM RP  |
|IGMP JOIN| .10            .1 |            | 192.168.101.0/24  |         |
+---------+                   |            | 2001:db8:101::/64 +---------+
                             =| = = R1 = = |=
+---------+ 192.168.100.0/24  |            | 192.168.101.0/24  +---------+
| Host H3 | 2001:db8:100::/64 |            | 2001:db8:101::/64 | R12     |
| receive |-------------------|  VRF Red   |---------+---------| PIM RP  |
|IGMP JOIN| .20            .1 |            | .1      |     .12 |         |
+---------+                   +------------+         |         +---------+
                                                  .4 |
                                                +----------+
                                                |  Host H4 |
                                                |  Source  |
                                                +----------+
"""

import json
import functools
import os
import re
import sys
import pytest
import logging

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.topotest import iproute2_is_vrf_capable
from lib.common_config import required_linux_kernel_version
from lib.pim import McastTesterHelper


pytestmark = [
    pytest.mark.ospfd,
    pytest.mark.pimd,
    pytest.mark.ospf6d,
    pytest.mark.pim6d,
]


def build_topo(tgen):
    for hostNum in range(1, 5):
        tgen.add_router("h{}".format(hostNum))

    # Create the main router
    tgen.add_router("r1")

    # Create the PIM RP routers
    for rtrNum in range(11, 13):
        tgen.add_router("r{}".format(rtrNum))

    # Setup Switches and connections
    for swNum in range(1, 5):
        tgen.add_switch("sw{}".format(swNum))

    ################
    # 1st set of connections to routers for VRF red
    ################

    # Add connections H1 to R1 switch sw1
    tgen.gears["h1"].add_link(tgen.gears["sw1"])
    tgen.gears["r1"].add_link(tgen.gears["sw1"])

    # Add connections R1 to R1x switch sw2
    tgen.gears["r1"].add_link(tgen.gears["sw2"])
    tgen.gears["h2"].add_link(tgen.gears["sw2"])
    tgen.gears["r11"].add_link(tgen.gears["sw2"])

    ################
    # 2nd set of connections to routers for vrf blue
    ################

    # Add connections H1 to R1 switch sw1
    tgen.gears["h3"].add_link(tgen.gears["sw3"])
    tgen.gears["r1"].add_link(tgen.gears["sw3"])

    # Add connections R1 to R1x switch sw2
    tgen.gears["r1"].add_link(tgen.gears["sw4"])
    tgen.gears["h4"].add_link(tgen.gears["sw4"])
    tgen.gears["r12"].add_link(tgen.gears["sw4"])


#####################################################
#
#   Tests starting
#
#####################################################


def setup_module(module):
    logger.info("PIM IGMP VRF Topology: \n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    vrf_setup_cmds = [
        "ip link add name blue type vrf table 11",
        "ip link add name red type vrf table 12",
        "ip link set dev blue up",
        "ip link set dev red up",
        "ip link set dev r1-eth0 vrf blue up",
        "ip link set dev r1-eth1 vrf blue up",
        "ip link set dev r1-eth2 vrf red up",
        "ip link set dev r1-eth3 vrf red up",
    ]

    # Starting Routers
    router_list = tgen.routers()

    # Create VRF on r2 first and add it's interfaces
    for cmd in vrf_setup_cmds:
        tgen.net["r1"].cmd(cmd)

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    # iproute2 needs to support VRFs for this suite to run.
    if not iproute2_is_vrf_capable():
        pytest.skip(
            "Installed iproute2 version does not support VRFs", allow_module_level=True
        )

    if os.getenv("MROUTE_VRF_MISSING"):
        pytest.skip(
            "Kernel does not support vrf mroute tables.", allow_module_level=True
        )


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def _test_ospf23_convergence(protoname, ipname, confname, vrf):
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Checking {} convergence on router r1 for VRF {}".format(protoname, vrf)
    )

    # Check for VRF neighbor
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/{}_{}_neighbor.json".format(confname, vrf))
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show {} {} vrf {} neighbor json".format(ipname, confname, vrf),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "{} router R1 did not converge on VRF {} (nbr)".format(protoname, vrf)
    assert res is None, assertmsg

    # Check for VRF loopback route
    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/{}_{}_route.json".format(confname, vrf))
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show {} {} vrf {} route json".format(ipname, confname, vrf),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
    assertmsg = "{} router R1 did not converge on VRF {} (route)".format(protoname, vrf)
    assert res is None, assertmsg


def test_ospf2_convergence():
    "Test for OSPFv2 convergence"
    _test_ospf23_convergence("OSPFv2", "ip", "ospf", "blue")
    _test_ospf23_convergence("OSPFv2", "ip", "ospf", "red")


def test_ospf3_convergence():
    "Test for OSPFv3 convergence"
    _test_ospf23_convergence("OSPFv3", "ipv6", "ospf6", "blue")
    _test_ospf23_convergence("OSPFv3", "ipv6", "ospf6", "red")


def canonicalize_linklocals(obj):
    for k in list(obj.keys()):
        v = obj[k]
        if isinstance(v, dict):
            canonicalize_linklocals(v)
        elif isinstance(v, str) and re.match(r"fe80::[0-9a-f:]+", v):
            obj[k] = "fe80::XXXX:XXXX:XXXX:XXXX"
        if isinstance(k, str) and re.match(r"fe80::[0-9a-f:]+", k):
            obj["fe80::XXXX:XXXX:XXXX:XXXX"] = obj.pop(k)


def router_json_cmp_canonical_linklocals(router, cmd, data):
    o = router.vtysh_cmd(cmd, isjson=True)
    canonicalize_linklocals(o)
    return topotest.json_cmp(o, data)


def _test_pim46_convergence(protoname, ipname, confname, vrf):
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Checking {} convergence on router r1 for VRF {}".format(protoname, vrf)
    )

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/{}_{}_neighbor.json".format(confname, vrf))
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        router_json_cmp_canonical_linklocals,
        router,
        "show {} pim vrf {} neighbor json".format(ipname, vrf),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=2)
    assertmsg = "{} router R1 did not converge for VRF {}".format(protoname, vrf)
    assert res is None, assertmsg


def test_pim4_convergence():
    "Test for PIM IPv4 convergence"
    _test_pim46_convergence("PIM IPv4", "ip", "pim", "red")
    _test_pim46_convergence("PIM IPv4", "ip", "pim", "blue")


def test_pim6_convergence():
    "Test for PIM IPv6 convergence"
    _test_pim46_convergence("PIM IPv6", "ipv6", "pim6", "red")
    _test_pim46_convergence("PIM IPv6", "ipv6", "pim6", "blue")


def _test_vrf_pim46reg_interfaces(
    protoname, ipname, confname, vrf, pimregiface, rpaddr, mcprefix
):
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        conf
        interface {}
          {} pim passive
        router {} vrf {}
          rp {} {}
        """.format(
            vrf, ipname, confname, vrf, rpaddr, mcprefix
        )
    )

    # Check pim*reg* interface on R1 in VRF
    reffile = os.path.join(CWD, "r1/{}_{}_{}.json".format(confname, vrf, pimregiface))
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show {} pim vrf {} inter {} json".format(ipname, vrf, pimregiface),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=15, wait=2)
    assertmsg = "{} router R1, VRF {} {} interface missing or incorrect status".format(
        protoname, vrf, pimregiface
    )
    assert res is None, assertmsg


def test_vrf_pimreg_interfaces():
    "Adding PIM IPv4 RP in VRF information and verify pimreg interfaces"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    try:
        _test_vrf_pim46reg_interfaces(
            "PIM IPv4",
            "ip",
            "pim",
            "blue",
            "pimreg11",
            "192.168.0.11",
            "239.100.0.1/32",
        )
        _test_vrf_pim46reg_interfaces(
            "PIM IPv4", "ip", "pim", "red", "pimreg12", "192.168.0.12", "239.100.0.1/32"
        )
    except Exception:
        # get some debug info.
        output = r1.net.cmd_nostatus("ip -o link")
        logging.error("ip link info after failure: %s", output)
        raise


def test_vrf_pim6reg_interfaces():
    "Adding PIM IPv& RP in VRF information and verify pim6reg interfaces"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    try:
        _test_vrf_pim46reg_interfaces(
            "PIM IPv6",
            "ipv6",
            "pim6",
            "blue",
            "pim6reg11",
            "2001:db8:0::11",
            "ff18:100::1/128",
        )
        _test_vrf_pim46reg_interfaces(
            "PIM IPv6",
            "ipv6",
            "pim6",
            "red",
            "pim6reg12",
            "2001:db8:0::12",
            "ff18:100::1/128",
        )
    except Exception:
        # get some debug info.
        output = r1.net.cmd_nostatus("ip -o link")
        logging.error("ip link info after failure: %s", output)
        raise


##################################
###  Test PIM / IGMP with VRF
##################################


def router_json_check(router, cmd, checkfn):
    return checkfn(router.vtysh_cmd(cmd, isjson=True))


def check_mcast46_entry(
    protoname, ipname, confname, vrf, r1iface, mcastaddr, pimrp, receiver, sender
):
    "Helper function to check IPv4/6 RP"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Testing {} for VRF {} entry using {}".format(protoname, vrf, mcastaddr)
    )

    with McastTesterHelper(tgen) as helper:
        helper.run(receiver, [mcastaddr, str(receiver) + "-eth0"])
        topotest.sleep(1)
        helper.run(sender, ["--send=0.7", mcastaddr, str(sender) + "-eth0"])

        logger.info("mcast join and source for {} started".format(mcastaddr))

        router = tgen.gears["r1"]
        reffile = os.path.join(CWD, "r1/{}_{}_join.json".format(confname, vrf))
        expected = json.loads(open(reffile).read())

        logger.info("verifying pim join on r1 for {} on VRF {}".format(mcastaddr, vrf))
        test_func = functools.partial(
            router_json_cmp_canonical_linklocals,
            router,
            "show {} pim vrf {} join json".format(ipname, vrf),
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=2)
        assertmsg = "{} router r1 did not show join status on VRF {}".format(
            protoname, vrf
        )
        assert res is None, assertmsg

        logger.info("verifying pim join on PIM RP {} for {}".format(pimrp, mcastaddr))
        router = tgen.gears[pimrp]
        reffile = os.path.join(CWD, "{}/{}_{}_join.json".format(pimrp, confname, vrf))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            router_json_cmp_canonical_linklocals,
            router,
            "show {} pim join json".format(ipname),
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=2)
        assertmsg = "{} router {} did not get selected as the PIM RP for VRF {}".format(
            protoname, pimrp, vrf
        )
        assert res is None, assertmsg

        logger.info("verifying pim register/register stop on r1 on VRF {}".format(vrf))
        router = tgen.gears["r1"]

        test_func = functools.partial(
            router_json_check,
            router,
            "show {} pim vrf {} interface traffic json".format(ipname, vrf),
            lambda stats: stats[r1iface]["registerTx"] > 0,
        )
        _, res = topotest.run_and_expect(test_func, True, count=10, wait=2)
        assertmsg = "{} R1 VRF {}: No PIM Register sent towards RP".format(
            protoname, vrf
        )
        assert res is True, assertmsg

        test_func = functools.partial(
            router_json_check,
            router,
            "show {} pim vrf {} interface traffic json".format(ipname, vrf),
            lambda stats: stats[r1iface]["registerStopRx"] > 0,
        )
        _, res = topotest.run_and_expect(test_func, True, count=10, wait=2)
        assertmsg = "{} R1 VRF {}: No PIM Register-Stop received from RP".format(
            protoname, vrf
        )
        assert res is True, assertmsg


def test_mcast_vrf_blue():
    "Test vrf blue with 239.100.0.1"
    check_mcast46_entry(
        "PIM IPv4", "ip", "pim", "blue", "r1-eth1", "239.100.0.1", "r11", "h1", "h2"
    )


def test_mcast_vrf_red():
    "Test vrf red with 239.100.0.1"
    check_mcast46_entry(
        "PIM IPv4", "ip", "pim", "red", "r1-eth3", "239.100.0.1", "r12", "h3", "h4"
    )


def test_ipv6_mcast_vrf_blue():
    "Test vrf blue with ff18:100::1"
    check_mcast46_entry(
        "PIM IPv6", "ipv6", "pim6", "blue", "r1-eth1", "ff18:100::1", "r11", "h1", "h2"
    )


def test_ipv6_mcast_vrf_red():
    "Test vrf red with ff18:100::1"
    check_mcast46_entry(
        "PIM IPv6", "ipv6", "pim6", "red", "r1-eth3", "ff18:100::1", "r12", "h3", "h4"
    )


def _test_pim46_interface_removal(protoname, ipname, gmname, ifnames, vrf):
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Testing {} VRF {} interface removal for interfaces {}".format(
            protoname, vrf, " ".join(ifnames)
        )
    )

    r1 = tgen.gears["r1"]
    for ifname in ifnames:
        r1.vtysh_cmd(
            """
            conf
            interface {} vrf {}
              no {} pim
              no {} {}
            """.format(
                ifname, vrf, ipname, ipname, gmname
            )
        )

    ifstatus = r1.vtysh_cmd(
        "show {} pim vrf {} interface json".format(ipname, vrf), isjson=True
    )
    excess_ifnames = set(ifstatus.keys()) & set(ifnames)
    assertmsg = "{} R1 VRF {}: Failed to remove all interfaces, remaining: {}".format(
        protoname, vrf, list(excess_ifnames)
    )
    assert len(excess_ifnames) == 0, assertmsg


def test_pim4_interface_removal():
    "Test removing interfaces from VRF PIM IPv4 router"
    _test_pim46_interface_removal(
        "PIM IPv4", "ip", "igmp", ["blue", "r1-eth0", "r1-eth1"], "blue"
    )
    _test_pim46_interface_removal(
        "PIM IPv4", "ip", "igmp", ["red", "r1-eth2", "r1-eth3"], "red"
    )


def test_pim6_interface_removal():
    "Test removing interfaces from VRF PIM IPv6 router"
    _test_pim46_interface_removal(
        "PIM IPv6", "ipv6", "mld", ["blue", "r1-eth0", "r1-eth1"], "blue"
    )
    _test_pim46_interface_removal(
        "PIM IPv6", "ipv6", "mld", ["red", "r1-eth2", "r1-eth3"], "red"
    )


def _test_pim46_router_removal(protoname, ipname, confname, vrf):
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing {} VRF {} router removal".format(protoname, vrf))

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        conf
        no router {} vrf {}
        """.format(
            confname, vrf
        )
    )

    # Interfaces should be gone completely now, including pimg*reg*
    ifstatus = r1.vtysh_cmd(
        "show {} pim vrf {} interface json".format(ipname, vrf), isjson=True
    )
    assertmsg = (
        "{} R1 VRF {}: Failed to remove router, remaining interfaces: {}".format(
            protoname, vrf, list(ifstatus.keys())
        )
    )
    assert len(ifstatus) == 0, assertmsg


def test_pim4_router_removal():
    "Test removing PIM IPv4 router"
    _test_pim46_router_removal("PIM IPv4", "ip", "pim", "blue")
    _test_pim46_router_removal("PIM IPv4", "ip", "pim", "red")


def test_pim6_router_removal():
    "Test removing PIM IPv6 router"
    _test_pim46_router_removal("PIM IPv6", "ipv6", "pim6", "blue")
    _test_pim46_router_removal("PIM IPv6", "ipv6", "pim6", "red")


def _test_pim46_config_cleanup(protoname, ipname, confname):
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing {} config cleanup after router removal".format(protoname))

    # Both interfaces and routers should be gone completely from config after preceding removals
    r1 = tgen.gears["r1"]
    runconf = r1.vtysh_cmd("show running-config")
    leftover = re.findall(
        r"^( *{} pim|router {} vrf [^ ]+)$".format(ipname, confname),
        runconf,
        re.MULTILINE,
    )
    assertmsg = (
        "{} R1: Unclean config after router/interface removal, remaining:\n{}".format(
            protoname, "\n".join(leftover)
        )
    )
    assert len(leftover) == 0, assertmsg


def test_pim4_config_cleanup():
    "Test whether config is clean after PIM IPv4 router/interface removal"
    _test_pim46_config_cleanup("PIM IPv4", "ip", "pim")


def test_pim6_config_cleanup():
    "Test whether config is clean after PIM IPv4 router/interface removal"
    _test_pim46_config_cleanup("PIM IPv6", "ipv6", "pimv6")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
