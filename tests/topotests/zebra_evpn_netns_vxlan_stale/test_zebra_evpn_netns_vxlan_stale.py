#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

#
# test_zebra_evpn_netns_vxlan_stale.py
#
# Copyright (c) 2026 Alphalink
#

"""
test_zebra_evpn_netns_vxlan_stale.py: a vxlan is commonly created next to
zebra and moved into the netns of its VRF, so for a while zebra sees two
interfaces with the same VNI, and the events of the two netns come in any
order. The down and the delete of the old interface, handled after the add of
the new one, must be ignored: zebra used to abort on
assert(zevpn->vxlan_if == ifp).

Many VRFs are created at once to make the two orders happen.
"""

import json
import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import create_interface_in_kernel
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

VRFS = 120
VNI0 = 1000
ROUNDS = 3


def build_topo(tgen):
    "One router, no link: each VRF only holds a bridge and a vxlan."
    tgen.add_router("r1")


def setup_module(mod):
    "Start FRR with EVPN enabled, no VRF yet."
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]

    if r1.check_capability(TopoRouter.RD_ZEBRA, "--vrfwnetns") is False:
        pytest.skip("VRF NETNS backend not available on FRR")
    if os.system("ip netns list") != 0:
        pytest.skip("NETNS not available on system")

    create_interface_in_kernel(tgen, "r1", "vtep0", "192.0.2.65/32")

    r1.use_netns_vrf()
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def create_vrfs(r1, first):
    "Create the netns, bridge and vxlan of each VRF at once, vxlan moved last"
    r1.cmd(
        """
        for i in $(seq {first} {last}); do
            ip netns add vrf$i
            (
                ip -n vrf$i link set lo up
                ip -n vrf$i link add br$i type bridge
                ip -n vrf$i link set br$i addrgenmode none
                ip link add vx$i type vxlan id $i local 192.0.2.65 \
                    dstport 4789 nolearning
                ip link set vx$i netns vrf$i
                ip -n vrf$i link set vx$i master br$i
                ip -n vrf$i link set vx$i type bridge_slave \
                    neigh_suppress on learning off
                ip -n vrf$i link set br$i up
                ip -n vrf$i link set vx$i up
            ) &
        done
        wait
        """.format(
            first=first, last=first + VRFS - 1
        )
    )
    cmds = ["configure terminal"]
    for i in range(first, first + VRFS):
        cmds += ["vrf vrf{}".format(i), "vni {}".format(i), "exit-vrf"]
    r1.vtysh_multicmd("\n".join(cmds))


def l3vnis_unbound(r1, first):
    "L3-VNIs of a round that are not bound to a vxlan interface"
    out = json.loads(r1.vtysh_cmd("show evpn vni detail json"))
    vnis = out.values() if isinstance(out, dict) else out
    bound = {
        v.get("vni")
        for v in vnis
        if v.get("type") == "L3" and v.get("vxlanIntf") not in (None, "None")
    }
    return [i for i in range(first, first + VRFS) if i not in bound]


def check_round(r1, first):
    "None once no daemon died and every L3-VNI of the round has its vxlan"
    died = r1.check_router_running()
    if died:
        return "a daemon crashed: {}".format(died)
    unbound = l3vnis_unbound(r1, first)
    if unbound:
        return "L3-VNIs without vxlan: {}".format(unbound)
    return None


def test_vxlan_moved_to_vrf_netns():
    "Zebra survives VRFs created with a vxlan moved into their netns"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    for n in range(ROUNDS):
        first = VNI0 + n * VRFS
        logger.info("round %d: VRFs %d..%d", n, first, first + VRFS - 1)
        create_vrfs(r1, first)

        # The delete of the old vxlan must not unbind the VNI from the new one.
        test_func = partial(check_round, r1, first)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "round {}: {}".format(n, result)

    assert not r1.check_router_running(), "a daemon crashed"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
