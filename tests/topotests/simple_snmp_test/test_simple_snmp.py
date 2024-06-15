#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_simple_snmp.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_bgp_simple snmp.py: Test snmp infrastructure.
"""

import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.snmptest import SnmpTester


pytestmark = [pytest.mark.bgpd, pytest.mark.isisd, pytest.mark.snmp]


def setup_module(mod):
    "Sets up the pytest environment"

    # skip tests is SNMP not installed
    if not os.path.isfile("/usr/sbin/snmpd"):
        error_msg = "SNMP not installed - skipping"
        pytest.skip(error_msg)
    # This function initiates the topology build with Topogen...
    topodef = {"s1": "r1", "s2": "r1", "s3": "r1"}
    tgen = Topogen(topodef, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    r1 = tgen.gears["r1"]

    r1.run("ip addr add 192.168.12.12/24 dev r1-eth0")
    r1.run("ip -6 addr add 2000:1:1:12::12/64 dev r1-eth0")
    r1.run("ip addr add 192.168.13.13/24 dev r1-eth1")
    r1.run("ip -6 addr add 2000:1:1:13::13/64 dev r1-eth1")
    r1.run("ip addr add 192.168.14.14/24 dev r1-eth2")
    r1.run("ip -6 addr add 2000:1:1:14::14/64 dev r1-eth2")
    r1.run("ip addr add 1.1.1.1/32 dev lo")
    r1.run("ip -6 addr add 2000:1:1:1::1/128 dev lo")
    r1.run("ip addr show")

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


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_r1_bgp_version():
    "Wait for protocol convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli()
    r1 = tgen.gears["r1"]
    r1_snmp = SnmpTester(r1, "1.1.1.1", "public", "2c")
    assert r1_snmp.test_oid("bgpVersin", None)
    assert r1_snmp.test_oid("bgpVersion", "10")
    assert r1_snmp.test_oid_walk("bgpVersion", ["10"])
    assert r1_snmp.test_oid_walk("bgpVersion", ["10"], ["0"])


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
