#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

#
# test_zebra_evpn_netns_vrf_deleted.py
#
# Copyright (c) 2026 Alphalink
#

"""
test_zebra_evpn_netns_vrf_deleted.py: with the netns VRF backend, deleting
the netns of a VRF that has an L3-VNI frees its zebra_ns while zvrf->zns still
points to it. Removing the VNI afterwards moves the L3-VNI back to an L2-VNI,
which must not walk the interfaces of the freed netns.
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]

VRFS = 30
VNI0 = 100


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

    r1.cmd("ip link add vtep0 type dummy")
    r1.cmd("ip address add 192.0.2.65/32 dev vtep0")
    r1.cmd("ip link set vtep0 up")

    r1.use_netns_vrf()
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def create_vrfs(r1):
    "Create the netns, bridge and vxlan of each VRF, then its L3-VNI"
    for i in range(VNI0, VNI0 + VRFS):
        r1.cmd(
            """
            ip netns add vrf{i}
            ip -n vrf{i} link set lo up
            ip -n vrf{i} link add br{i} type bridge
            ip -n vrf{i} link set br{i} addrgenmode none
            ip link add vx{i} type vxlan id {i} local 192.0.2.65 \
                dstport 4789 nolearning
            ip link set vx{i} netns vrf{i}
            ip -n vrf{i} link set vx{i} master br{i}
            ip -n vrf{i} link set vx{i} type bridge_slave \
                neigh_suppress on learning off
            ip -n vrf{i} link set br{i} up
            ip -n vrf{i} link set vx{i} up
            """.format(
                i=i
            )
        )
    cmds = ["configure terminal"]
    for i in range(VNI0, VNI0 + VRFS):
        cmds += ["vrf vrf{}".format(i), "vni {}".format(i), "exit-vrf"]
    r1.vtysh_multicmd("\n".join(cmds))


def l3vnis_up(r1):
    "Number of L3-VNIs up with their SVI"
    out = json.loads(r1.vtysh_cmd("show evpn vni detail json"))
    vnis = out.values() if isinstance(out, dict) else out
    return len(
        [
            v
            for v in vnis
            if v.get("type") == "L3"
            and v.get("state") == "Up"
            and v.get("sviIntf") not in (None, "None")
        ]
    )


def vrfs_inactive(r1):
    "Number of our VRFs that zebra shows inactive"
    out = r1.vtysh_cmd("show vrf")
    return len(
        [
            line
            for line in out.splitlines()
            if line.startswith("vrf vrf") and " inactive" in line
        ]
    )


def test_l3vnis_up():
    "The L3-VNIs of the netns VRFs are up with their SVI"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    create_vrfs(r1)

    for _ in range(60):
        if l3vnis_up(r1) == VRFS:
            return
        time.sleep(1)
    assert l3vnis_up(r1) == VRFS, "not all L3-VNIs are up"


def test_remove_vni_after_netns_deleted():
    "Removing the VNI of a VRF whose netns is gone leaves zebra running"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    for i in range(VNI0, VNI0 + VRFS):
        r1.cmd("ip netns del vrf{}".format(i))

    # The freed zebra_ns is only walked once zebra has disabled the VRFs.
    for _ in range(60):
        if vrfs_inactive(r1) == VRFS:
            break
        time.sleep(1)
    assert vrfs_inactive(r1) == VRFS, "not all VRFs are inactive"

    cmds = ["configure terminal"]
    for i in range(VNI0, VNI0 + VRFS):
        cmds += ["vrf vrf{}".format(i), "no vni {}".format(i), "exit-vrf"]
    r1.vtysh_multicmd("\n".join(cmds))
    assert not r1.check_router_running(), "a daemon crashed after no vni"

    cmds = ["configure terminal"]
    for i in range(VNI0, VNI0 + VRFS):
        cmds += ["no vrf vrf{}".format(i)]
    r1.vtysh_multicmd("\n".join(cmds))
    assert not r1.check_router_running(), "a daemon crashed after no vrf"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
