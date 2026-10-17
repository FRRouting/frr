#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2026 by 6WIND S.A.
#

"""
test_bgp_bmp_initiation.py: BMP Initiation message information.

    +----------+
    | bmp1init |---+
    +----------+   |     +----------+
                   +-----|  r1init  |
    +----------+   |     +----------+
    | bmp2init |---+
    +----------+

r1init has two bmp targets: bmp1 sets the sysDescr and sysName of the
Initiation message and is connected to bmp1init; bmp2 uses the default
values and is connected to bmp2init.
"""

import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from .bgpbmp import get_bmp_messages
from lib.common_config import retry
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1init")

    tgen.add_bmp_server("bmp1init", ip="192.0.2.10", defaultRoute="via 192.0.2.1")
    tgen.add_bmp_server(
        "bmp2init", ip="192.0.2.20", defaultRoute="via 192.0.2.1", port=1790
    )

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1init"])
    switch.add_link(tgen.gears["bmp1init"])
    switch.add_link(tgen.gears["bmp2init"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.gears["r1init"].load_frr_config(
        daemons=["zebra", ("bgpd", "-M bmp")],
    )

    tgen.start_router()

    for bmp_name, server in tgen.get_bmp_servers().items():
        server.start(log_file=os.path.join(tgen.logdir, bmp_name, "bmp.log"))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bmp_initiation():
    """
    Check the sysDescr and sysName received by each BMP collector.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=30)
    def check_bmp_initiation(bmp_name, sysdescr, sysname, sysdescr_prefix=False):
        bmp_log_file = os.path.join(tgen.logdir, bmp_name, "bmp.log")
        for message in get_bmp_messages(tgen.gears[bmp_name], bmp_log_file):
            if "system_description" not in message:
                continue
            received_sysdescr = message["system_description"]
            if sysdescr_prefix:
                sysdescr_ok = received_sysdescr.startswith(sysdescr)
            else:
                sysdescr_ok = received_sysdescr == sysdescr
            if not sysdescr_ok:
                return "{}: unexpected sysDescr {}".format(bmp_name, received_sysdescr)
            if message.get("system_name") != sysname:
                return "{}: unexpected sysName {}".format(
                    bmp_name, message.get("system_name")
                )
            return True
        return "{}: no initiation message received".format(bmp_name)

    result = check_bmp_initiation("bmp1init", "BMP test router", "router1")
    assert result is True, result

    result = check_bmp_initiation(
        "bmp2init", "FRRouting ", "r1init", sysdescr_prefix=True
    )
    assert result is True, result


def test_bmp_initiation_running_config():
    """
    Check the bmp initiation commands in the running-config.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1init"]

    def check_running_config(expected, unexpected):
        output = router.vtysh_cmd("show running-config bgpd")
        for line in expected:
            if line not in output:
                return "missing '{}' in running-config".format(line)
        for line in unexpected:
            if line in output:
                return "unexpected '{}' in running-config".format(line)
        return True

    result = check_running_config(
        [
            "bmp initiation sysDescr BMP test router",
            "bmp initiation sysName router1",
        ],
        [],
    )
    assert result is True, result

    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65501
          bmp targets bmp1
           no bmp initiation sysDescr
           no bmp initiation sysName router1
        """
    )
    result = check_running_config(
        [], ["bmp initiation sysDescr", "bmp initiation sysName"]
    )
    assert result is True, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
