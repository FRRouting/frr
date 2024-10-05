#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_snmp.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_isis_snmp.py:

                   +---------+  45.0.0.0/24   +---------+
                   |         | rt4-eth1       |         |
                   |   RT4   +----------------+   RT5   |
                   |         |        rt5-eth1|         |
                   +---------+                +---------+
                rt4-eth0|                          |rt5-eth0
                        |                          | 
             14.0.0.0/24|                          |25.0.0.0/24
                        |                          |
                rt1-eth0|                          |rt2-eth0
                   +---------+                +---------+
                   |         |                |         |
                   |   RT1   |                |   RT2   |
                   | 1.1.1.1 |                | 2.2.2.2 |
                   |         |                |         |
                   +---------+                +---------+
                rt1-eth1|                          |rt2-eth1
                        |                          |
                        |                          |
             13.0.0.0/24|        +---------+       |23.0.0.0/24
                        |        |         |       |
                        |        |   RT3   |       |
                        +--------+ 3.3.3.3 +-------+
                         rt3-eth1|         |rt3-eth2
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

pytestmark = [pytest.mark.isisd, pytest.mark.ldpd, pytest.mark.snmp]


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for router in ["ce3", "r1", "r2", "r3", "r4", "r5"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["ce3"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"

    # skip tests is SNMP not installed
    if not os.path.isfile("/usr/sbin/snmpd"):
        error_msg = "SNMP not installed - skipping"
        pytest.skip(error_msg)

    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        # Don't start the following in the CE nodes
        if router.name[0] == "r":
            router.load_config(
                TopoRouter.RD_ISIS,
                os.path.join(CWD, "{}/isisd.conf".format(rname)),
                "-M snmp",
            )
            router.load_config(
                TopoRouter.RD_LDP,
                os.path.join(CWD, "{}/ldpd.conf".format(rname)),
            )
            router.load_config(
                TopoRouter.RD_SNMP,
                os.path.join(CWD, "{}/snmpd.conf".format(rname)),
                "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX,trap",
            )

    # After loading the configurations, this function loads configured daemons.
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

    # Run test function until we get an result. Wait at most 80 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=160, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def generate_oid(numoids, index1, index2):
    if numoids == 1:
        oid = "{}".format(index1)
    else:
        oid = "{}.{}".format(index1, index2)
    return oid


def test_isis_convergence():
    logger.info("Test: check ISIS adjacencies")
    tgen = get_topogen()

    for rname in ["r1", "r2", "r3", "r4", "r5"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_r1_scalar_snmp():
    "Wait for protocol convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    assert r1_snmp.test_oid("isisSysVersion", "one(1)")
    assert r1_snmp.test_oid("isisSysLevelType", "level1and2(3)")
    assert r1_snmp.test_oid("isisSysID", "00 00 00 00 00 01")
    assert r1_snmp.test_oid("isisSysMaxPathSplits", "32")
    assert r1_snmp.test_oid("isisSysMaxLSPGenInt", "900 seconds")
    assert r1_snmp.test_oid("isisSysAdminState", "on(1)")
    assert r1_snmp.test_oid("isisSysMaxAge", "1200 seconds")
    assert r1_snmp.test_oid("isisSysProtSupported", "07 5 6 7")

    r2 = tgen.gears["r2"]
    r2_snmp = SnmpTester(r2, "2.2.2.2", "public", "2c")

    assert r2_snmp.test_oid("isisSysVersion", "one(1)")
    assert r2_snmp.test_oid("isisSysLevelType", "level1and2(3)")
    assert r2_snmp.test_oid("isisSysID", "00 00 00 00 00 02")
    assert r2_snmp.test_oid("isisSysMaxPathSplits", "32")
    assert r2_snmp.test_oid("isisSysMaxLSPGenInt", "900 seconds")
    assert r2_snmp.test_oid("isisSysAdminState", "on(1)")
    assert r2_snmp.test_oid("isisSysMaxAge", "1200 seconds")
    assert r2_snmp.test_oid("isisSysProtSupported", "07 5 6 7")


circtable_test = {
    "isisCircAdminState": ["on(1)", "on(1)"],
    "isisCircExistState": ["active(1)", "active(1)"],
    "isisCircType": ["broadcast(1)", "ptToPt(2)"],
    "isisCircExtDomain": ["false(2)", "false(2)"],
    "isisCircLevelType": ["level1(1)", "level1(1)"],
    "isisCircPassiveCircuit": ["false(2)", "false(2)"],
    "isisCircMeshGroupEnabled": ["inactive(1)", "inactive(1)"],
    "isisCircSmallHellos": ["false(2)", "false(2)"],
    "isisCirc3WayEnabled": ["false(2)", "false(2)"],
}


def test_r1_isisCircTable():
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    oids = []
    oids.append(generate_oid(1, 1, 0))
    oids.append(generate_oid(1, 2, 0))

    # check items
    for item in circtable_test.keys():
        assertmsg = "{} should be {} oids {} full dict {}:".format(
            item, circtable_test[item], oids, r1_snmp.walk(item)
        )
        assert r1_snmp.test_oid_walk(item, circtable_test[item], oids), assertmsg


circleveltable_test = {
    "isisCircLevelMetric": ["10", "10"],
    "isisCircLevelWideMetric": ["10", "10"],
    "isisCircLevelISPriority": ["64", "64"],
    "isisCircLevelHelloMultiplier": ["10", "10"],
    "isisCircLevelHelloTimer": [
        "3000 milliseconds",
        "3000 milliseconds",
    ],
    "isisCircLevelMinLSPRetransInt": [
        "1 seconds",
        "1 seconds",
    ],
}


def test_r1_isislevelCircTable():
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    oids = []
    oids.append(generate_oid(2, 1, "area"))
    oids.append(generate_oid(2, 2, "area"))

    # check items
    for item in circleveltable_test.keys():
        assertmsg = "{} should be {} oids {} full dict {}:".format(
            item, circleveltable_test[item], oids, r1_snmp.walk(item)
        )
        assert r1_snmp.test_oid_walk(item, circleveltable_test[item], oids), assertmsg


adjtable_test = {
    "isisISAdjState": ["up(3)", "up(3)"],
    "isisISAdj3WayState": ["down(2)", "up(0)"],
    "isisISAdjNeighSysType": ["l1IntermediateSystem(1)", "l1IntermediateSystem(1)"],
    "isisISAdjNeighSysID": ["00 00 00 00 00 04", "00 00 00 00 00 03"],
    "isisISAdjUsage": ["0", "level1(1)"],
    "isisISAdjNeighPriority": ["64", "0"],
}

adjtable_down_test = {
    "isisISAdjState": ["up(3)"],
    "isisISAdj3WayState": ["down(2)"],
    "isisISAdjNeighSysType": ["l1IntermediateSystem(1)"],
    "isisISAdjNeighSysID": ["00 00 00 00 00 04"],
    "isisISAdjUsage": ["0"],
    "isisISAdjNeighPriority": ["64"],
}


def test_r1_isisAdjTable():
    "check ISIS Adjacency Table"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    oids = []
    oids.append(generate_oid(2, 1, 1))
    oids.append(generate_oid(2, 2, 1))

    oids_down = []
    oids_down.append(generate_oid(2, 1, 1))

    # check items
    for item in adjtable_test.keys():
        assertmsg = "{} should be {} oids {} full dict {}:".format(
            item, adjtable_test[item], oids, r1_snmp.walk(item)
        )
        assert r1_snmp.test_oid_walk(item, adjtable_test[item], oids), assertmsg

    # shutdown interface and one adjacency should be removed
    "check ISIS adjacency is removed when interface is shutdown"
    r1.vtysh_cmd("conf t\ninterface r1-eth1\nshutdown")
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")

    for item in adjtable_down_test.keys():
        assertmsg = "{} should be {} oids {} full dict {}:".format(
            item, adjtable_down_test[item], oids_down, r1_snmp.walk(item)
        )
        assert r1_snmp.test_oid_walk(
            item, adjtable_down_test[item], oids_down
        ), assertmsg

    # no shutdown interface and adjacency should be restored
    r1.vtysh_cmd("conf t\ninterface r1-eth1\nno shutdown")


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
