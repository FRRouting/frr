#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_rip_snmp_peer_null.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Bing Shui
#

"""
test_rip_snmp_peer_null.py:

    +---------+ 10.0.12.0/24 +---------+
    |   r1    +--------------+   r2    |
    | ripd    |              | ripd    |
    | snmpd   |              |         |
    +---------+              +---------+
    r1-eth1|
           | 10.0.13.0/24
        +---------+
        |   h1    | SNMP manager
        +---------+

Regression test for a ripd NULL pointer dereference in the RIPv2-MIB
rip2PeerTable handler: an exact SNMP GET with a full-length index
(rip2PeerAddress + rip2PeerDomain) for a peer that does not exist made
rip2PeerLookup() dereference the rip_peer_lookup() result without a
NULL check (ripd/rip_snmp.c).  One management-plane GET then killed
ripd.  The fixed daemon must answer noSuchInstance and keep serving
legal queries (exact GET on an existing peer, GETNEXT traversal and
walk of the table).
"""

import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.snmptest import SnmpTester

pytestmark = [pytest.mark.ripd, pytest.mark.snmp]

R1_ETH0 = "10.0.12.1"
R2_ETH0 = "10.0.12.2"
R1_ETH1 = "10.0.13.1"
R2_LO = "203.0.113.1"
NO_PEER = "10.0.99.99"

# RIPv2-MIB::rip2PeerTable = 1.3.6.1.2.1.23.4.1
OID_PEER_ADDRESS = ".1.3.6.1.2.1.23.4.1.1"
OID_PEER_VERSION = ".1.3.6.1.2.1.23.4.1.4"

VALID_ADDR_OID = "{}.{}.0".format(OID_PEER_ADDRESS, R2_ETH0)
VALID_VERSION_OID = "{}.{}.0".format(OID_PEER_VERSION, R2_ETH0)
WRONG_DOMAIN_OID = "{}.{}.5".format(OID_PEER_ADDRESS, R2_ETH0)
NO_PEER_OID = "{}.{}.0".format(OID_PEER_ADDRESS, NO_PEER)


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for router in ["r1", "r2"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    tgen.add_host("h1", "10.0.13.3/24", "via {}".format(R1_ETH1))
    switch.add_link(tgen.gears["h1"])


def setup_module(mod):
    "Sets up the pytest environment"

    # skip tests if SNMP not installed
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
        router.load_frr_config(
            daemons=[
                ("zebra", ""),
                ("ripd", "-M ripd_snmp"),
            ],
        )
        if rname == "r1":
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


def snmpget(oid):
    "Run one snmpget from the SNMP manager h1 against r1's snmpd."
    tgen = get_topogen()
    h1 = tgen.gears["h1"]
    return h1.cmd(
        "snmpget -v2c -c public -t 3 -r 2 {} {} 2>&1".format(R1_ETH1, oid)
    )


def snmpgetnext(oid):
    "Run one snmpgetnext from h1 against r1's snmpd."
    tgen = get_topogen()
    h1 = tgen.gears["h1"]
    return h1.cmd(
        "snmpgetnext -v2c -c public -t 3 -r 2 {} {} 2>&1".format(R1_ETH1, oid)
    )


def ripd_pid():
    "Return r1's ripd pid as recorded in its pid file."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    return r1.run("cat /var/run/frr/ripd.pid").strip()


def test_convergence():
    "Wait for protocol convergence and a RIP peer on r1"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _rip_converged():
        out = r1.vtysh_cmd("show ip rip")
        return R2_LO in out

    _, result = topotest.run_and_expect(_rip_converged, True, count=30, wait=3)
    assert result is True, "r1 did not learn r2's loopback route via RIP"

    # The RIP peer entry for r2 must exist (this is what the valid
    # SNMP queries below read).
    def _peer_present():
        out = r1.vtysh_cmd("show ip rip status")
        return R2_ETH0 in out

    _, result = topotest.run_and_expect(_peer_present, True, count=10, wait=3)
    assert result is True, "r1 has no RIP peer entry for r2"


def test_snmp_ready():
    "A valid exact GET proves the AgentX path into this very ripd works"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _snmp_ready():
        out = snmpget(VALID_ADDR_OID)
        return "IpAddress: {}".format(R2_ETH0) in out

    _, ready = topotest.run_and_expect(_snmp_ready, True, count=40, wait=1)
    assert ready is True, "SNMP path to ripd did not become ready in time"

    out = snmpget(VALID_VERSION_OID)
    assert "INTEGER: 2" in out, out


def test_legal_traversal():
    "GETNEXT and walk of rip2PeerTable keep working (legal traffic)"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    h1 = tgen.gears["h1"]
    r1_snmp = SnmpTester(h1, R1_ETH1, "public", "2c")

    # GETNEXT from the column root must return the existing peer.
    out = snmpgetnext(OID_PEER_ADDRESS)
    assert "IpAddress: {}".format(R2_ETH0) in out, out

    # GETNEXT with a not-yet-existing index is legal and must not crash
    # the daemon; the non-exact lookup branch checks for NULL.
    out = snmpgetnext("{}.{}.0".format(OID_PEER_ADDRESS, NO_PEER))
    assert "Timeout" not in out, out

    # A full walk of the table must show the existing peer.
    assert r1_snmp.test_oid_walk(OID_PEER_ADDRESS, [R2_ETH0])


def test_wrong_domain_exact_get():
    "Exact GET for an existing peer with a wrong domain answers cleanly"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pid_before = ripd_pid()
    out = snmpget(WRONG_DOMAIN_OID)
    assert "No Such Instance" in out, out
    assert ripd_pid() == pid_before, "ripd pid changed on wrong-domain GET"
    assert "IpAddress: {}".format(R2_ETH0) in snmpget(VALID_ADDR_OID)


def test_no_peer_exact_get():
    "Exact GET for a nonexistent peer must not kill ripd"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pid_before = ripd_pid()
    out = snmpget(NO_PEER_OID)
    logger.info("no-peer exact GET answered: {}".format(out))

    # On the unfixed daemon ripd died here: the GET times out and the
    # process is gone (see the ripd.asan.* file in the test logs).
    assert "No Such Instance" in out, out
    assert ripd_pid() == pid_before, "ripd pid changed on no-peer exact GET"


def test_post_trigger_service():
    "ripd keeps answering valid queries and RIP stays up afterwards"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    out = snmpget(VALID_ADDR_OID)
    assert "IpAddress: {}".format(R2_ETH0) in out, out

    r1 = tgen.gears["r1"]
    assert R2_LO in r1.vtysh_cmd("show ip rip"), "RIP route lost after GET"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
