#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ldp_isis_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_ldp_vpls_topo1.py:

                   +---------+                +---------+
                   |         |                |         |
                   |   CE1   |                |   CE2   |
                   |         |                |         |
                   +---------+                +---------+
ce1-eth0 (172.16.1.1/24)|                          |ce2-eth0 (172.16.1.2/24)
                        |                          |
                        |                          |
                rt1-eth0|                          |rt2-eth0
                   +---------+  10.0.1.0/24   +---------+
                   |         |rt1-eth1        |         |
                   |   RT1   +----------------+   RT2   |
                   | 1.1.1.1 |        rt2-eth1| 2.2.2.2 |
                   |         |                |         |
                   +---------+                +---------+
                rt1-eth2|                          |rt2-eth2
                        |                          |
                        |                          |
             10.0.2.0/24|        +---------+       |10.0.3.0/24
                        |        |         |       |
                        |        |   RT3   |       |
                        +--------+ 3.3.3.3 +-------+
                         rt3-eth2|         |rt3-eth1
                                 +---------+
                                      |rt3-eth0
                                      |
                                      |
              ce3-eth0 (172.16.1.3/24)|
                                 +---------+
                                 |         |
                                 |   CE3   |
                                 |         |
                                 +---------+
"""

import os
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.snmptest import SnmpTester

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ldpd, pytest.mark.isisd, pytest.mark.snmp]


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for router in ["ce1", "ce2", "ce3", "r1", "r2", "r3"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["ce1"])
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["ce2"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["ce3"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        # Don't start isisd and ldpd in the CE nodes
        if router.name[0] == "r":
            router.load_config(
                TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
            )
            router.load_config(
                TopoRouter.RD_LDP,
                os.path.join(CWD, "{}/ldpd.conf".format(rname)),
                "-M snmp",
            )
            router.load_config(
                TopoRouter.RD_SNMP,
                os.path.join(CWD, "{}/snmpd.conf".format(rname)),
                "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX,trap",
            )

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def router_compare_json_output(rname, command, reference):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=320, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def test_isis_convergence():
    logger.info("Test: check ISIS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_rib():
    logger.info("Test: verify RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    # TODO: disabling this check to avoid 'snmpd not running' errors
    # if tgen.routers_have_failure():
    #    pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(rname, "show ip route json", "show_ip_route.ref")


def test_ldp_adjacencies():
    logger.info("Test: verify LDP adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    # TODO: disabling this check to avoid 'snmpd not running' errors
    # if tgen.routers_have_failure():
    #    pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp discovery json", "show_ldp_discovery.ref"
        )


def test_ldp_neighbors():
    logger.info("Test: verify LDP neighbors")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    # if tgen.routers_have_failure():
    #    pytest.skip(tgen.errors)

    for rname in ["r1", "r2", "r3"]:
        router_compare_json_output(
            rname, "show mpls ldp neighbor json", "show_ldp_neighbor.ref"
        )


def test_r1_ldp_lsr_objects():
    "Test mplsLdpLsrObjects objects"
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid("mplsLdpLsrId", "01 01 01 01")
    assert r1_snmp.test_oid("mplsLdpLsrLoopDetectionCapable", "none(1)")


def test_r1_ldp_entity_table():
    "Test mplsLdpEntityTable"
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid_walk("mplsLdpEntityLdpId", ["1.1.1.1:0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityIndex", ["1"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityProtocolVersion", ["1"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityAdminStatus", ["enable(1)"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityOperStatus", ["enabled(2)"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityTcpPort", ["646"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityUdpDscPort", ["646"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityMaxPduLength", ["4096 octets"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityKeepAliveHoldTimer", ["180 seconds"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityHelloHoldTimer", ["0 seconds"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityInitSessionThreshold", ["0"])
    assert r1_snmp.test_oid_walk(
        "mplsLdpEntityLabelDistMethod", ["downstreamUnsolicited(2)"]
    )
    assert r1_snmp.test_oid_walk("mplsLdpEntityLabelRetentionMode", ["liberal(2)"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityPathVectorLimit", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityHopCountLimit", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityTransportAddrKind", ["loopback(2)"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityTargetPeer", ["true(1)"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityTargetPeerAddrType", ["ipv4(1)"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityTargetPeerAddr", ["01 01 01 01"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityLabelType", ["generic(1)"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityDiscontinuityTime", ["(0) 0:00:00.00"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStorageType", ["nonVolatile(3)"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityRowStatus", ["createAndGo(4)"])


def test_r1_ldp_entity_stats_table():
    "Test mplsLdpEntityStatsTable"
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsSessionAttempts", ["0"])
    assert r1_snmp.test_oid_walk(
        "mplsLdpEntityStatsSessionRejectedNoHelloErrors", ["0"]
    )
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsSessionRejectedAdErrors", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsSessionRejectedMaxPduErrors", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsSessionRejectedLRErrors", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsBadLdpIdentifierErrors", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsBadPduLengthErrors", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsBadMessageLengthErrors", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsBadTlvLengthErrors", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsMalformedTlvValueErrors", ["0"])
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsKeepAliveTimerExpErrors", ["0"])
    assert r1_snmp.test_oid_walk(
        "mplsLdpEntityStatsShutdownReceivedNotifications", ["0"]
    )
    assert r1_snmp.test_oid_walk("mplsLdpEntityStatsShutdownSentNotifications", ["0"])


def test_r1_ldp_peer_table():
    "Test mplsLdpPeerTable"
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid_walk("mplsLdpPeerLdpId", ["2.2.2.2:0", "3.3.3.3:0"])
    assert r1_snmp.test_oid_walk(
        "mplsLdpPeerLabelDistMethod",
        ["downstreamUnsolicited(2)", "downstreamUnsolicited(2)"],
    )
    assert r1_snmp.test_oid_walk("mplsLdpPeerPathVectorLimit", ["0", "0"])
    assert r1_snmp.test_oid_walk("mplsLdpPeerTransportAddrType", ["ipv4(1)", "ipv4(1)"])
    assert r1_snmp.test_oid_walk(
        "mplsLdpPeerTransportAddr", ["02 02 02 02", "03 03 03 03"]
    )


def test_r1_ldp_session_table():
    "Test mplsLdpSessionTable"
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid_walk(
        "mplsLdpSessionState", ["operational(5)", "operational(5)"]
    )
    assert r1_snmp.test_oid_walk("mplsLdpSessionRole", ["passive(3)", "passive(3)"])
    assert r1_snmp.test_oid_walk("mplsLdpSessionProtocolVersion", ["1", "1"])
    assert r1_snmp.test_oid_walk(
        "mplsLdpSessionKeepAliveTime", ["180 seconds", "180 seconds"]
    )
    assert r1_snmp.test_oid_walk(
        "mplsLdpSessionMaxPduLength", ["4096 octets", "4096 octets"]
    )
    assert r1_snmp.test_oid_walk(
        "mplsLdpSessionDiscontinuityTime", ["(0) 0:00:00.00", "(0) 0:00:00.00"]
    )


def test_r1_ldp_session_stats_table():
    "Test mplsLdpSessionStatsTable"
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid_walk("mplsLdpSessionStatsUnknownMesTypeErrors", ["0", "0"])
    assert r1_snmp.test_oid_walk("mplsLdpSessionStatsUnknownTlvErrors", ["0", "0"])


def test_r1_ldp_hello_adjacency_table():
    "Test mplsLdpHelloAdjacencyTable"
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid_walk("mplsLdpHelloAdjacencyIndex", ["1", "2", "1"])
    assert r1_snmp.test_oid_walk("mplsLdpHelloAdjacencyHoldTime", ["15", "45", "15"])
    assert r1_snmp.test_oid_walk(
        "mplsLdpHelloAdjacencyType", ["link(1)", "targeted(2)", "link(1)"]
    )


# Memory leak test template
# disabling memory leak
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
