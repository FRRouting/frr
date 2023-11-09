#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test some of the BGP4V2-MIB entries.
"""

import os
import sys
import json
from time import sleep
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.snmptest import SnmpTester
from lib import topotest

pytestmark = [pytest.mark.bgpd, pytest.mark.snmp]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    snmpd = os.system("which snmpd")
    if snmpd:
        error_msg = "SNMP not installed - skipping"
        pytest.skip(error_msg)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            "-M snmp",
        )
        router.load_config(
            TopoRouter.RD_SNMP,
            os.path.join(CWD, "{}/snmpd.conf".format(rname)),
            "-Le -Ivacm_conf,usmConf,iquery -V -DAgentX",
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_snmp_bgp4v2():
    tgen = get_topogen()

    r2 = tgen.gears["r2"]

    def _bgp_converge_summary():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.12.1": {
                        "state": "Established",
                        "pfxRcd": 2,
                    }
                }
            },
            "ipv6Unicast": {
                "peers": {
                    "2001:db8::12:1": {
                        "state": "Established",
                        "pfxRcd": 2,
                    }
                }
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_summary)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see connections established"

    def _bgp_converge_prefixes():
        output = json.loads(r2.vtysh_cmd("show bgp all json"))
        expected = {
            "ipv4Unicast": {
                "routes": {
                    "10.0.0.0/31": [
                        {
                            "metric": 1,
                            "origin": "IGP",
                        }
                    ],
                    "10.0.0.2/32": [
                        {
                            "metric": 2,
                            "origin": "incomplete",
                        }
                    ],
                }
            },
            "ipv6Unicast": {
                "routes": {
                    "2001:db8::1/128": [
                        {
                            "metric": 1,
                            "origin": "IGP",
                        }
                    ],
                    "2001:db8:1::/56": [
                        {
                            "metric": 2,
                            "origin": "incomplete",
                        }
                    ],
                }
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_prefixes)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see prefixes from R1"

    snmp = SnmpTester(r2, "localhost", "public", "2c", "-Ln -On")

    def _snmpwalk_remote_addr():
        expected = {
            "1.3.6.1.3.5.1.1.2.1.5.1.1.192.168.12.1": "C0 A8 0C 01",
            "1.3.6.1.3.5.1.1.2.1.5.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1": "20 01 0D B8 00 00 00 00 00 00 00 00 00 12 00 01",
        }

        # bgp4V2PeerRemoteAddr
        output, _ = snmp.walk(".1.3.6.1.3.5.1.1.2.1.5")
        return output == expected

    _, result = topotest.run_and_expect(_snmpwalk_remote_addr, True, count=10, wait=1)
    assertmsg = "Can't fetch SNMP for bgp4V2PeerRemoteAddr"
    assert result, assertmsg

    def _snmpwalk_peer_state():
        expected = {
            "1.3.6.1.3.5.1.1.2.1.13.1.1.192.168.12.1": "6",
            "1.3.6.1.3.5.1.1.2.1.13.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1": "6",
        }

        # bgp4V2PeerState
        output, _ = snmp.walk(".1.3.6.1.3.5.1.1.2.1.13")
        return output == expected

    _, result = topotest.run_and_expect(_snmpwalk_peer_state, True, count=10, wait=1)
    assertmsg = "Can't fetch SNMP for bgp4V2PeerState"
    assert result, assertmsg

    def _snmpwalk_peer_last_error_code_received():
        expected = {
            "1.3.6.1.3.5.1.1.3.1.1.1.1.192.168.12.1": "0",
            "1.3.6.1.3.5.1.1.3.1.1.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1": "0",
        }

        # bgp4V2PeerLastErrorCodeReceived
        output, _ = snmp.walk(".1.3.6.1.3.5.1.1.3.1.1")
        return output == expected

    _, result = topotest.run_and_expect(
        _snmpwalk_peer_last_error_code_received, True, count=10, wait=1
    )
    assertmsg = "Can't fetch SNMP for bgp4V2PeerLastErrorCodeReceived"
    assert result, assertmsg

    def _snmpwalk_origin():
        expected = {
            "1.3.6.1.3.5.1.1.9.1.9.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1": "1",
            "1.3.6.1.3.5.1.1.9.1.9.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1": "3",
            "1.3.6.1.3.5.1.1.9.1.9.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1": "1",
            "1.3.6.1.3.5.1.1.9.1.9.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1": "3",
        }

        # bgp4V2NlriOrigin
        output, _ = snmp.walk(".1.3.6.1.3.5.1.1.9.1.9")
        return output == expected

    _, result = topotest.run_and_expect(_snmpwalk_origin, True, count=10, wait=1)
    assertmsg = "Can't fetch SNMP for bgp4V2NlriOrigin"
    assert result, assertmsg

    def _snmpwalk_med():
        expected = {
            "1.3.6.1.3.5.1.1.9.1.17.1.1.1.1.10.0.0.0.31.1.192.168.12.1.1": "1",
            "1.3.6.1.3.5.1.1.9.1.17.1.1.1.1.10.0.0.2.32.1.192.168.12.1.1": "2",
            "1.3.6.1.3.5.1.1.9.1.17.1.2.1.2.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1.128.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1": "1",
            "1.3.6.1.3.5.1.1.9.1.17.1.2.1.2.32.1.13.184.0.1.0.0.0.0.0.0.0.0.0.0.56.2.32.1.13.184.0.0.0.0.0.0.0.0.0.18.0.1.1": "2",
        }

        # bgp4V2NlriMed
        output, _ = snmp.walk(".1.3.6.1.3.5.1.1.9.1.17")
        # tgen.mininet_cli()
        return output == expected

    _, result = topotest.run_and_expect(_snmpwalk_med, True, count=10, wait=1)
    assertmsg = "Can't fetch SNMP for bgp4V2NlriMed"
    assert result, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
