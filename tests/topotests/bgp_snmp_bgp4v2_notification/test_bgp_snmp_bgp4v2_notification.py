#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright 2024 6WIND S.A.
#


"""
Test BGP OPEN NOTIFY (Configuration mismatch) followed by snmpwalk.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib import topotest

pytestmark = [pytest.mark.bgpd, pytest.mark.snmp]


def build_topo(tgen):
    """Build function"""

    tgen.add_router("r2")
    tgen.add_router("rr")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["rr"])


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


def test_bgp_open_notification_change_configuration():
    tgen = get_topogen()

    tgen.gears["rr"].vtysh_multicmd(
        """
configure terminal
router bgp 65004
neighbor 192.168.12.2  password 8888"
"""
    )
    tgen.net["r2"].cmd("snmpwalk -v 2c -c public 127.0.0.1 .1.3.6.1.4.1.7336.4.2.1")
    tgen.gears["rr"].vtysh_multicmd(
        """
configure terminal
router bgp 65004
no neighbor 192.168.12.2  password 8888"
"""
    )

    def _check_bgp_session():
        r2 = tgen.gears["r2"]

        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {"peers": {"192.168.12.4": {"state": "Established"}}}
        }

        return topotest.json_cmp(output, expected)

    test_func1 = functools.partial(_check_bgp_session)
    _, result1 = topotest.run_and_expect(test_func1, None, count=120, wait=0.5)

    assert result1 is None, "Failed to verify the bgp session"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
