#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_linkdown_nhg.py
#
# Copyright (c) 2026 by Manoharan Sundaramoorthy
#

"""
Verify that zebra keeps NEXTHOP_FLAG_LINKDOWN in sync with the carrier state
of a kernel route's interface.

When a link has no carrier but is admin-up, the kernel keeps routes through
it and flags them RTNH_F_LINKDOWN. When carrier changes the kernel sends only
RTM_NEWLINK; it does not re-send the routes. Zebra must therefore update the
flag itself when the interface state changes.

Two bonds drive carrier changes by enslaving or releasing a veth:

  bond0: route added without carrier, then carrier is gained.
         Expect linkDown, then not linkDown.
  bond1: route added with carrier, then carrier is lost and regained.
         Expect not linkDown, linkDown, then not linkDown again.
         The route must stay in the RIB while the carrier is down.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = pytest.mark.random_order(disabled=True)

BOND0, SLAVE0, PEER0 = "bond0", "veth0", "veth1"
PREFIX0 = "fdbd:dc00:46:14::/127"

BOND1, SLAVE1, PEER1 = "bond1", "veth2", "veth3"
PREFIX1 = "fdbd:dc00:46:15::/127"


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))

    tgen.start_router()

    r1.run("ip link add {} type bond".format(BOND0))
    r1.run("ip link set {} up".format(BOND0))
    r1.run("ip link add {} type veth peer name {}".format(SLAVE0, PEER0))
    r1.run("ip link set {} up".format(PEER0))
    r1.run("ip link set {} up".format(SLAVE0))
    r1.run("ip -6 route add {} dev {}".format(PREFIX0, BOND0))

    r1.run("ip link add {} type bond".format(BOND1))
    r1.run("ip link set {} up".format(BOND1))
    r1.run("ip link add {} type veth peer name {}".format(SLAVE1, PEER1))
    r1.run("ip link set {} up".format(PEER1))
    r1.run("ip link set {} down".format(SLAVE1))
    r1.run("ip link set {} master {}".format(SLAVE1, BOND1))
    r1.run("ip link set {} up".format(SLAVE1))
    r1.run("ip -6 route add {} dev {}".format(PREFIX1, BOND1))


def teardown_module(_mod):
    get_topogen().stop_topology()


def check_linkdown(prefix, bond, linkdown):
    r1 = get_topogen().gears["r1"]
    expected = {
        prefix: [
            {
                "protocol": "kernel",
                "nexthops": [
                    {"interfaceName": bond, "linkDown": True if linkdown else None}
                ],
            }
        ]
    }
    test_func = lambda: topotest.router_json_cmp(
        r1, "show ipv6 route {} json".format(prefix), expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "{} on {} should have linkDown={}:\n{}".format(
        prefix, bond, linkdown, result
    )


def test_bond0_route_added_without_carrier():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_linkdown(PREFIX0, BOND0, True)


def test_bond0_carrier_gained():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Enslave {} into {}".format(SLAVE0, BOND0))
    r1.run("ip link set {} down".format(SLAVE0))
    r1.run("ip link set {} master {}".format(SLAVE0, BOND0))
    r1.run("ip link set {} up".format(SLAVE0))

    check_linkdown(PREFIX0, BOND0, False)


def test_bond1_route_added_with_carrier():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_linkdown(PREFIX1, BOND1, False)


def test_bond1_carrier_lost():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Release {} from {}".format(SLAVE1, BOND1))
    r1.run("ip link set {} nomaster".format(SLAVE1))

    check_linkdown(PREFIX1, BOND1, True)


def test_bond1_carrier_regained():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Enslave {} into {} again".format(SLAVE1, BOND1))
    r1.run("ip link set {} down".format(SLAVE1))
    r1.run("ip link set {} master {}".format(SLAVE1, BOND1))
    r1.run("ip link set {} up".format(SLAVE1))

    check_linkdown(PREFIX1, BOND1, False)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
