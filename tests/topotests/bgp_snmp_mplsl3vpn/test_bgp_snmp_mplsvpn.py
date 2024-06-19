#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_snmp_mplsl3vpn.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_bgp_snmp_mplsl3vpn.py: Test mplsL3Vpn MIB [RFC4382].
"""

import os
import sys
from time import sleep
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.snmptest import SnmpTester
from lib import topotest

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd, pytest.mark.isisd, pytest.mark.snmp]


def build_topo(tgen):
    "Build function"

    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.
    #
    #
    # Create routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")

    # r1-r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-r3
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # r1-r4
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    # r1-ce1
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["ce1"])

    # r1-ce3
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["ce3"])

    # r1-ce4
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["ce4"])

    # r1-dangling
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r1"])

    # r2-r3
    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # r3-r4
    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    # r4-ce2
    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["ce2"])


def setup_module(mod):
    "Sets up the pytest environment"

    # skip tests is SNMP not installed
    snmpd = os.system("which snmpd")
    if snmpd:
        error_msg = "SNMP not installed - skipping"
        pytest.skip(error_msg)

    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    # setup VRF-a in r1
    r1.run("ip link add VRF-a type vrf table 1001")
    r1.run("ip link set up dev VRF-a")
    r1.run("ip link add VRF-b type vrf table 1002")
    r1.run("ip link set up dev VRF-b")
    r4.run("ip link add VRF-a type vrf table 1001")
    r4.run("ip link set up dev VRF-a")

    # enslave vrf interfaces
    r1.run("ip link set r1-eth3 master VRF-a")
    r1.run("ip link set r1-eth4 master VRF-a")
    r1.run("ip link set r1-eth5 master VRF-b")
    r4.run("ip link set r4-eth1 master VRF-a")

    r1.run("sysctl -w net.ipv4.ip_forward=1")
    r2.run("sysctl -w net.ipv4.ip_forward=1")
    r3.run("sysctl -w net.ipv4.ip_forward=1")
    r4.run("sysctl -w net.ipv4.ip_forward=1")
    r1.run("sysctl -w net.mpls.conf.r1-eth0.input=1")
    r1.run("sysctl -w net.mpls.conf.r1-eth1.input=1")
    r1.run("sysctl -w net.mpls.conf.r1-eth2.input=1")

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            "-M snmp",
        )
        router.load_config(
            TopoRouter.RD_SNMP,
            os.path.join(CWD, "{}/snmpd.conf".format(rname)),
            "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX,trap",
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


# SNMP utilities - maybe move to lib
def snmp_uint32_to_oid(val):
    oid1 = int(val / 16777216) % 256
    oid2 = int(val / 65536) % 256
    oid3 = int(val / 256) % 256
    oid4 = int(val) % 256
    return "%(oid1)s.%(oid2)s.%(oid3)s.%(oid4)s" % locals()


def snmp_oid_to_uint32(oid):
    values = oid.split(".")
    return (
        (int(values[0]) * 16777216)
        + (int(values[1]) * 65536)
        + (int(values[2]) * 256)
        + int(values[3])
    )


def snmp_str_to_oid(str):
    out_oid = ""
    for char in str:
        out_oid += "{}.".format(ord(char))
    return out_oid.rstrip(".")


def snmp_oid_to_str(oid):
    out_str = ""
    oids = oid.split(".")
    for char in oids:
        out_str += "{}".format(chr(int(char)))
    return out_str


def snmp_rte_oid(vrf, dtype, dest, plen, policy, ntype, nhop=0):
    oid_1 = snmp_str_to_oid(vrf)
    oid_2 = dtype
    oid_3 = dest
    oid_4 = plen
    oid_5 = "0.{}".format(policy)
    oid_6 = ntype
    if ntype == 0:
        oid_7 = ""
    else:
        oid_7 = ".{}".format(nhop)

    return "{}.{}.{}.{}.{}.{}{}".format(oid_1, oid_2, oid_3, oid_4, oid_5, oid_6, oid_7)


def test_pe1_converge_evpn():
    "Wait for protocol convergence"
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    def _convergence():
        r1 = tgen.gears["r1"]
        r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")

        return r1_snmp.test_oid("bgpVersion", "10")

    _, result = topotest.run_and_expect(_convergence, True, count=20, wait=1)
    assertmsg = "BGP SNMP does not seem to be running"
    assert result, assertmsg

    r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")
    count = 0
    passed = False
    while count < 125:
        if r1_snmp.test_oid_walk("bgpPeerLocalAddr.10.4.4.4", ["10.1.1.1"]):
            passed = True
            break
        count += 1
        sleep(1)
    # tgen.mininet_cli()
    assertmsg = "BGP Peer 10.4.4.4 did not connect"
    assert passed, assertmsg


interfaces_up_test = {
    "mplsL3VpnConfiguredVrfs": "2",
    "mplsL3VpnActiveVrfs": "2",
    "mplsL3VpnConnectedInterfaces": "3",
    "mplsL3VpnNotificationEnable": "true(1)",
    "mplsL3VpnVrfConfMaxPossRts": "0",
    "mplsL3VpnVrfConfRteMxThrshTime": "0 seconds",
    "mplsL3VpnIlllblRcvThrsh": "0",
}

interfaces_down_test = {
    "mplsL3VpnConfiguredVrfs": "2",
    "mplsL3VpnActiveVrfs": "1",
    "mplsL3VpnConnectedInterfaces": "3",
    "mplsL3VpnNotificationEnable": "true(1)",
    "mplsL3VpnVrfConfMaxPossRts": "0",
    "mplsL3VpnVrfConfRteMxThrshTime": "0 seconds",
    "mplsL3VpnIlllblRcvThrsh": "0",
}


def test_r1_mplsvpn_scalars():
    "check scalar values"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")

    for item in interfaces_up_test.keys():
        assertmsg = "{} should be {}: value {}".format(
            item, interfaces_up_test[item], r1_snmp.get_next(item)
        )
        assert r1_snmp.test_oid(item, interfaces_up_test[item]), assertmsg


def test_r1_mplsvpn_scalars_interface():
    "check scalar interface changing values"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")

    r1.vtysh_cmd("conf t\ninterface r1-eth3\nshutdown")
    r1.vtysh_cmd("conf t\ninterface r1-eth4\nshutdown")

    for item in interfaces_up_test.keys():
        assertmsg = "{} should be {}: value {}".format(
            item, interfaces_down_test[item], r1_snmp.get_next(item)
        )
        assert r1_snmp.test_oid(item, interfaces_down_test[item]), assertmsg

    r1.vtysh_cmd("conf t\ninterface r1-eth3\nno shutdown")
    r1.vtysh_cmd("conf t\ninterface r1-eth4\nno shutdown")

    for item in interfaces_up_test.keys():
        assertmsg = "{} should be {}: value {}".format(
            item, interfaces_up_test[item], r1_snmp.get_next(item)
        )
        assert r1_snmp.test_oid(item, interfaces_up_test[item]), assertmsg


def router_interface_get_ifindex(router, interface):
    ifindex = 0
    r_int_output = router.vtysh_cmd(
        "show interface {}-{}".format(router.name, interface)
    )
    int_lines = r_int_output.splitlines()
    for line in int_lines:
        line_items = line.lstrip().split(" ")
        if "index" in line_items[0]:
            ifindex = line_items[1]
    return ifindex


def generate_vrf_ifindex_oid(vrf, ifindex):
    intoid = snmp_uint32_to_oid(int(ifindex))
    vrfoid = snmp_str_to_oid(vrf)
    oid = "{}.{}".format(vrfoid, intoid)

    return oid


def generate_vrf_index_type_oid(vrf, index, type):
    vrfoid = snmp_str_to_oid(vrf)
    intoid = snmp_uint32_to_oid(int(index))
    oid = "{}.{}.{}".format(vrfoid, intoid, type)

    return oid


iftable_up_test = {
    "mplsL3VpnIfVpnClassification": ["enterprise(2)", "enterprise(2)", "enterprise(2)"],
    "mplsL3VpnIfConfStorageType": ["volatile(2)", "volatile(2)", "volatile(2)"],
    "mplsL3VpnIfConfRowStatus": ["active(1)", "active(1)", "active(1)"],
}


def get_timetick_val(time):
    return int(time.split(" ")[0].lstrip("(").rstrip(")"))


def test_r1_mplsvpn_IfTable():
    "mplsL3VpnIf table values"

    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")

    # tgen.mininet_cli()
    eth3_ifindex = router_interface_get_ifindex(r1, "eth3")
    eth4_ifindex = router_interface_get_ifindex(r1, "eth4")
    eth5_ifindex = router_interface_get_ifindex(r1, "eth5")

    # get ifindex and make sure the oid is correct

    oids = []
    # generate oid
    oids.append(generate_vrf_ifindex_oid("VRF-a", eth3_ifindex))
    oids.append(generate_vrf_ifindex_oid("VRF-a", eth4_ifindex))
    oids.append(generate_vrf_ifindex_oid("VRF-b", eth5_ifindex))

    for item in iftable_up_test.keys():
        assertmsg = "{} should be {} oids {} full dict {}:".format(
            item, iftable_up_test[item], oids, r1_snmp.walk(item)
        )
        assert r1_snmp.test_oid_walk(item, iftable_up_test[item], oids), assertmsg

    # an inactive vrf should not affect these values
    r1.cmd("ip link set r1-eth5 down")

    for item in iftable_up_test.keys():
        assertmsg = "{} should be {} oids {} full dict {}:".format(
            item, iftable_up_test[item], oids, r1_snmp.walk(item)
        )
        assert r1_snmp.test_oid_walk(item, iftable_up_test[item], oids), assertmsg

    r1.cmd("ip link set r1-eth5 up")


vrftable_test = {
    "mplsL3VpnVrfDescription": ["VRF-a", "VRF-b"],
    "mplsL3VpnVrfRD": ['"10:1"', '"10:2"'],
    "mplsL3VpnVrfOperStatus": ["up(1)", "up(1)"],
    "mplsL3VpnVrfActiveInterfaces": ["2", "1"],
    "mplsL3VpnVrfAssociatedInterfaces": ["2", "1"],
    "mplsL3VpnVrfConfMidRteThresh": ["0", "0"],
    "mplsL3VpnVrfConfHighRteThresh": ["0", "0"],
    "mplsL3VpnVrfConfMaxRoutes": ["0", "0"],
    "mplsL3VpnVrfConfRowStatus": ["active(1)", "active(1)"],
    "mplsL3VpnVrfConfAdminStatus": ["up(1)", "up(1)"],
    "mplsL3VpnVrfConfStorageType": ["volatile(2)", "volatile(2)"],
}


def test_r1_mplsvpn_VrfTable():
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")

    # tgen.mininet_cli()

    oids = []

    oids.append(snmp_str_to_oid("VRF-a"))
    oids.append(snmp_str_to_oid("VRF-b"))

    # check items
    for item in vrftable_test.keys():
        assertmsg = "{} should be {} oids {} full dict {}:".format(
            item, vrftable_test[item], oids, r1_snmp.walk(item)
        )
        assert r1_snmp.test_oid_walk(item, vrftable_test[item], oids), assertmsg

    # check timetick set and stable
    ts_a = r1_snmp.get("mplsL3VpnVrfCreationTime.{}".format(snmp_str_to_oid("VRF-a")))
    ts_b = r1_snmp.get("mplsL3VpnVrfCreationTime.{}".format(snmp_str_to_oid("VRF-b")))
    ts_val_a1 = get_timetick_val(ts_a)
    ts_val_b1 = get_timetick_val(ts_b)
    ts_a = r1_snmp.get("mplsL3VpnVrfCreationTime.{}".format(snmp_str_to_oid("VRF-a")))
    ts_b = r1_snmp.get("mplsL3VpnVrfCreationTime.{}".format(snmp_str_to_oid("VRF-b")))
    ts_val_a2 = get_timetick_val(ts_a)
    ts_val_b2 = get_timetick_val(ts_b)

    assertmsg = "timestamp values for VRF-a do not match {} {}".format(
        ts_val_a1, ts_val_a2
    )
    assert ts_val_a1 == ts_val_a2, assertmsg
    assertmsg = "timestamp values for VRF-b do not match {} {}".format(
        ts_val_b1, ts_val_b2
    )
    assert ts_val_b1 == ts_val_b2, assertmsg

    # take Last changed time, fiddle with active interfaces, ensure
    # time changes and active interfaces change
    ts_last = r1_snmp.get(
        "mplsL3VpnVrfConfLastChanged.{}".format(snmp_str_to_oid("VRF-a"))
    )
    ts_val_last_1 = get_timetick_val(ts_last)
    r1.vtysh_cmd("conf t\ninterface r1-eth3\nshutdown")
    active_int = r1_snmp.get(
        "mplsL3VpnVrfActiveInterfaces.{}".format(snmp_str_to_oid("VRF-a"))
    )
    assertmsg = "mplsL3VpnVrfActiveInterfaces incorrect should be 1 value {}".format(
        active_int
    )
    assert active_int == "1", assertmsg

    ts_last = r1_snmp.get(
        "mplsL3VpnVrfConfLastChanged.{}".format(snmp_str_to_oid("VRF-a"))
    )
    ts_val_last_2 = get_timetick_val(ts_last)
    assertmsg = "mplsL3VpnVrfConfLastChanged does not update on interface change"
    assert ts_val_last_2 > ts_val_last_1, assertmsg
    r1.vtysh_cmd("conf t\ninterface r1-eth3\nno shutdown")

    # take Last changed time, fiddle with associated interfaces, ensure
    # time changes and active interfaces change
    ts_last = r1_snmp.get(
        "mplsL3VpnVrfConfLastChanged.{}".format(snmp_str_to_oid("VRF-a"))
    )
    ts_val_last_1 = get_timetick_val(ts_last)
    r1.cmd("ip link set r1-eth6 master VRF-a")
    r1.cmd("ip link set r1-eth6 up")

    associated_int = r1_snmp.get(
        "mplsL3VpnVrfAssociatedInterfaces.{}".format(snmp_str_to_oid("VRF-a"))
    )
    assertmsg = (
        "mplsL3VpnVrfAssociatedInterfaces incorrect should be 3 value {}".format(
            associated_int
        )
    )

    assert associated_int == "3", assertmsg
    ts_last = r1_snmp.get(
        "mplsL3VpnVrfConfLastChanged.{}".format(snmp_str_to_oid("VRF-a"))
    )
    ts_val_last_2 = get_timetick_val(ts_last)
    assertmsg = "mplsL3VpnVrfConfLastChanged does not update on interface change"
    assert ts_val_last_2 > ts_val_last_1, assertmsg
    r1.cmd("ip link del r1-eth6 master VRF-a")
    r1.cmd("ip link set r1-eth6 down")


rt_table_test = {
    "mplsL3VpnVrfRT": ['"1:1"', '"1:2"'],
    "mplsL3VpnVrfRTDescr": ["RT both for VRF VRF-a", "RT both for VRF VRF-b"],
    "mplsL3VpnVrfRTRowStatus": ["active(1)", "active(1)"],
    "mplsL3VpnVrfRTStorageType": ["volatile(2)", "volatile(2)"],
}


def test_r1_mplsvpn_VrfRT_table():
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")

    oids = []
    oids.append(generate_vrf_index_type_oid("VRF-a", 1, 3))
    oids.append(generate_vrf_index_type_oid("VRF-b", 1, 3))

    # check items
    for item in rt_table_test.keys():
        print(item)
        assertmsg = "{} should be {} oids {} full dict {}:".format(
            item, rt_table_test[item], oids, r1_snmp.walk(item)
        )
        assert r1_snmp.test_oid_walk(item, rt_table_test[item], oids), assertmsg


def test_r1_mplsvpn_perf_table():
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")

    # tgen.mininet_cli()
    oid_a = snmp_str_to_oid("VRF-a")
    oid_b = snmp_str_to_oid("VRF-b")

    # poll for 10 seconds for routes to appear
    count = 0
    passed = False
    while count < 60:
        if r1_snmp.test_oid_walk(
            "mplsL3VpnVrfPerfCurrNumRoutes.{}".format(oid_a), ["7"]
        ):
            passed = True
            break
        count += 1
        sleep(1)
    # tgen.mininet_cli()
    assertmsg = "mplsL3VpnVrfPerfCurrNumRoutes shouold be 7 got {}".format(
        r1_snmp.get("mplsL3VpnVrfPerfCurrNumRoutes.{}".format(oid_a))
    )
    assert passed, assertmsg
    curr_a = int(r1_snmp.get("mplsL3VpnVrfPerfCurrNumRoutes.{}".format(oid_a)))
    del_a = int(r1_snmp.get("mplsL3VpnVrfPerfRoutesDeleted.{}".format(oid_a)))
    add_a = int(r1_snmp.get("mplsL3VpnVrfPerfRoutesAdded.{}".format(oid_a)))

    assertmsg = "FAIL curr{} does not equal added{} - deleted {}".format(
        curr_a, add_a, del_a
    )
    assert curr_a == (add_a - del_a), assertmsg
    curr_b = int(r1_snmp.get("mplsL3VpnVrfPerfCurrNumRoutes.{}".format(oid_b)))
    del_b = int(r1_snmp.get("mplsL3VpnVrfPerfRoutesDeleted.{}".format(oid_b)))
    add_b = int(r1_snmp.get("mplsL3VpnVrfPerfRoutesAdded.{}".format(oid_b)))
    assertmsg = "FAIL curr{} does not equal added{} - deleted {}".format(
        curr_b, add_b, del_b
    )
    assert curr_b == (add_b - del_b), assertmsg


rte_table_test = {
    "mplsL3VpnVrfRteInetCidrDestType": [
        "ipv4(1)",
        "ipv4(1)",
        "ipv4(1)",
        "ipv4(1)",
        "ipv4(1)",
        "ipv4(1)",
        "ipv4(1)",
    ],
    "mplsL3VpnVrfRteInetCidrDest": [
        "0A 05 05 05",
        "0A 07 07 07",
        "C0 A8 22 00",
        "C0 A8 64 00",
        "C0 A8 64 00",
        "C0 A8 C8 00",
        "C0 A8 C8 00",
    ],
    "mplsL3VpnVrfRteInetCidrPfxLen": ["32", "32", "24", "24", "24", "24", "24"],
    "mplsL3VpnVrfRteInetCidrNHopType": [
        "ipv4(1)",
        "ipv4(1)",
        "ipv4(1)",
        "ipv4(1)",
        "unknown(0)",
        "ipv4(1)",
        "unknown(0)",
    ],
    "mplsL3VpnVrfRteInetCidrNextHop": [
        "C0 A8 64 0A",
        "C0 A8 C8 0A",
        "0A 04 04 04",
        "C0 A8 64 0A",
        '""',
        "C0 A8 C8 0A",
        '""',
    ],
    "mplsL3VpnVrfRteInetCidrType": [
        "local(3)",
        "local(3)",
        "remote(4)",
        "local(3)",
        "other(1)",
        "local(3)",
        "other(1)",
    ],
    "mplsL3VpnVrfRteInetCidrProto": [
        "bgp(14)",
        "bgp(14)",
        "bgp(14)",
        "bgp(14)",
        "local(2)",
        "bgp(14)",
        "local(2)",
    ],
    "mplsL3VpnVrfRteInetCidrNextHopAS": [
        "65001",
        "65001",
        "0",
        "65001",
        "0",
        "65001",
        "0",
    ],
    "mplsL3VpnVrfRteInetCidrMetric1": ["0", "0", "20", "0", "0", "0", "0"],
    "mplsL3VpnVrfRteInetCidrMetric2": ["-1", "-1", "-1", "-1", "-1", "-1", "-1"],
    "mplsL3VpnVrfRteInetCidrMetric3": ["-1", "-1", "-1", "-1", "-1", "-1", "-1"],
    "mplsL3VpnVrfRteInetCidrMetric4": ["-1", "-1", "-1", "-1", "-1", "-1", "-1"],
    "mplsL3VpnVrfRteInetCidrMetric5": ["-1", "-1", "-1", "-1", "-1", "-1", "-1"],
    "mplsL3VpnVrfRteXCPointer": ["00", "00", "00", "00", "00", "00", "00"],
    "mplsL3VpnVrfRteInetCidrStatus": [
        "active(1)",
        "active(1)",
        "active(1)",
        "active(1)",
        "active(1)",
        "active(1)",
        "active(1)",
    ],
}


def test_r1_mplsvpn_rte_table():
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    r1_snmp = SnmpTester(r1, "10.1.1.1", "public", "2c")

    # tgen.mininet_cli()
    oid_1 = snmp_rte_oid("VRF-a", 1, "10.5.5.5", 32, 0, 1, "192.168.100.10")
    oid_2 = snmp_rte_oid("VRF-a", 1, "10.7.7.7", 32, 0, 1, "192.168.200.10")
    oid_3 = snmp_rte_oid("VRF-a", 1, "192.168.34.0", 24, 0, 1, "10.4.4.4")
    oid_4 = snmp_rte_oid("VRF-a", 1, "192.168.100.0", 24, 1, 1, "192.168.100.10")
    oid_4_a = snmp_rte_oid("VRF-a", 1, "192.168.100.0", 24, 0, 1, "192.168.100.10")
    oid_5 = snmp_rte_oid("VRF-a", 1, "192.168.100.0", 24, 0, 0)
    oid_5_a = snmp_rte_oid("VRF-a", 1, "192.168.100.0", 24, 1, 0)
    oid_6 = snmp_rte_oid("VRF-a", 1, "192.168.200.0", 24, 1, 1, "192.168.200.10")
    oid_6_a = snmp_rte_oid("VRF-a", 1, "192.168.200.0", 24, 0, 1, "192.168.200.10")
    oid_7 = snmp_rte_oid("VRF-a", 1, "192.168.200.0", 24, 0, 0)
    oid_7_a = snmp_rte_oid("VRF-a", 1, "192.168.200.0", 24, 1, 0)

    oid_lists = [
        [oid_1, oid_2, oid_3, oid_4, oid_5, oid_6, oid_7],
        [oid_1, oid_2, oid_3, oid_4_a, oid_5_a, oid_6, oid_7],
        [oid_1, oid_2, oid_3, oid_4, oid_5, oid_6_a, oid_7_a],
        [oid_1, oid_2, oid_3, oid_4_a, oid_5_a, oid_6_a, oid_7_a],
        [oid_1, oid_2, oid_3, oid_4, oid_5, oid_6, oid_7],
        [oid_1, oid_2, oid_3, oid_4_a, oid_5_a, oid_6, oid_7],
        [oid_1, oid_2, oid_3, oid_4, oid_5, oid_6_a, oid_7_a],
        [oid_1, oid_2, oid_3, oid_4_a, oid_5_a, oid_6_a, oid_7_a],
    ]

    # check items

    passed = False
    for oid_list in oid_lists:
        passed = True
        for item in rte_table_test.keys():
            print(item)
            assertmsg = "{} should be {} oids {} full dict {}:".format(
                item, rte_table_test[item], oid_list, r1_snmp.walk(item)
            )
            if not r1_snmp.test_oid_walk(item, rte_table_test[item], oid_list):
                passed = False
                break
            print(
                "{} should be {} oids {} full dict {}:".format(
                    item, rte_table_test[item], oid_list, r1_snmp.walk(item)
                )
            )
        if passed:
            break
    # generate ifindex row grabbing ifindices from vtysh
    if passed:
        ifindex_row = [
            router_interface_get_ifindex(r1, "eth3"),
            router_interface_get_ifindex(r1, "eth4"),
            router_interface_get_ifindex(r1, "eth2"),
            router_interface_get_ifindex(r1, "eth3"),
            "0",
            router_interface_get_ifindex(r1, "eth4"),
            "0",
        ]
        if not r1_snmp.test_oid_walk(
            "mplsL3VpnVrfRteInetCidrIfIndex", ifindex_row, oid_list
        ):
            passed = False

    print("passed {}".format(passed))
    assert passed, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
