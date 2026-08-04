#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_eigrp_interface_config.py
#
# Copyright (c) 2026 by
# Lee Clements
#

"""
test_eigrp_interface_config.py: Test that EIGRP interface configuration can be
applied before EIGRP is running on the interface.

Regression test for issue #11301: interface parameters used to be rejected with
NB_ERR_INCONSISTENCY unless a `network` statement had already instantiated the
interface, because configuration and running state shared one prefix-derived
object.
"""

import os
import sys
import pytest

pytestmark = [pytest.mark.eigrpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def build_topo(tgen):
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for router in router_list.values():
        # eigrpd is named explicitly because it cannot be inferred: the
        # configuration deliberately carries no "router eigrp" stanza, which is
        # the state this test needs to start from.
        router.load_frr_config(daemons=["zebra", "eigrpd"])

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_eigrp_not_running_initially():
    "There must be no EIGRP instance, so the interface has no running state."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = tgen.gears["r1"].vtysh_cmd("show running-config")
    assert "router eigrp" not in output, "EIGRP is running; test premise is invalid"


def test_interface_config_accepted_before_network():
    "Interface parameters must be accepted while EIGRP is not running (#11301)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
         delay 50
         eigrp bandwidth 5000
        """
    )

    output = r1.vtysh_cmd("show running-config")
    assert "delay 50" in output, "delay was rejected while EIGRP was not running"
    assert (
        "eigrp bandwidth 5000" in output
    ), "eigrp bandwidth was rejected while EIGRP was not running"


def test_config_applied_when_eigrp_starts():
    "Starting EIGRP must adopt the existing configuration, not reset it."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        configure terminal
        router eigrp 1
         network 10.0.1.0/24
        """
    )

    def _check_interface():
        output = r1.vtysh_cmd("show ip eigrp interfaces")
        if "r1-eth0" not in output:
            return "r1-eth0 was not activated by the network statement"
        # Columns are: Interface Bandwidth Delay ...
        for line in output.splitlines():
            if line.startswith("r1-eth0"):
                fields = line.split()
                if len(fields) < 3:
                    return "unexpected output: {}".format(line)
                if fields[1] != "5000":
                    return "bandwidth is {}, expected 5000".format(fields[1])
                if fields[2] != "50":
                    return "delay is {}, expected 50".format(fields[2])
                return None
        return "no line for r1-eth0"

    _, result = topotest.run_and_expect(_check_interface, None, count=30, wait=1)
    assert result is None, result


def test_config_survives_network_removal():
    "Removing the network statement must not discard interface configuration."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
        configure terminal
        router eigrp 1
         no network 10.0.1.0/24
        """
    )

    output = r1.vtysh_cmd("show running-config")
    assert "delay 50" in output, "delay was lost when EIGRP stopped using the interface"
    assert (
        "eigrp bandwidth 5000" in output
    ), "eigrp bandwidth was lost when EIGRP stopped using the interface"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
