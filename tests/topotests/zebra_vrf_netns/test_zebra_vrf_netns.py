#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_vrf_netns.py
#
# Multiple namespaced VRFs with overlapping interface names and IP addresses.
# Uses integrated FRR config (single frr.conf).
#

"""
test_zebra_vrf_netns.py: Test zebra with multiple netns-based VRFs.
Each VRF has an interface with the same IP (10.0.0.1/24) and logically
the same role (first data interface), demonstrating overlapping addresses
and interface naming across VRFs.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from functools import partial

# VRFs (netns names) and overlapping IP used in each
VRF_NAMES = ["vrf-red", "vrf-blue", "vrf-green"]
OVERLAP_IP = "10.0.0.1"
OVERLAP_PREFIX = "10.0.0.1/24"

# Neighbor table entry per VRF: (ip, mac) on the VRF's interface (r1-eth0, r1-eth1, r1-eth2)
# Same IP 10.0.0.2 in each VRF (overlapping), different MACs to identify
NEIGH_PER_VRF = [
    {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02", "ifname": "r1-eth0"},
    {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:03", "ifname": "r1-eth1"},
    {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:04", "ifname": "r1-eth2"},
]

# New neighbors added at test time to verify runtime receipt (10.0.0.3 in each VRF)
NEIGH_NEW_PER_VRF = [
    {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:12", "ifname": "r1-eth0"},
    {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:13", "ifname": "r1-eth1"},
    {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:14", "ifname": "r1-eth2"},
]


def build_topo(tgen):
    "One router, one link per VRF to a switch."
    tgen.add_router("r1")
    for i in range(len(VRF_NAMES)):
        sw = tgen.add_switch("s{}".format(i + 1))
        sw.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Create netns VRFs, move interfaces, then start FRR with integrated config."
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]

    if r1.check_capability(TopoRouter.RD_ZEBRA, "--vrfwnetns") is False:
        pytest.skip("VRF NETNS backend not available on FRR")
    if os.system("ip netns list") != 0:
        pytest.skip("NETNS not available on system")

    logger.info("Testing with VRF Namespace support (overlapping IPs per VRF)")

    # Create one netns per VRF and move one interface into each
    for i, vrf in enumerate(VRF_NAMES):
        r1.net.add_netns(vrf)
        ifname = "r1-eth{}".format(i)
        r1.net.set_intf_netns(ifname, vrf, up=True)

    r1.use_netns_vrf()
    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        [(TopoRouter.RD_ZEBRA, None)],
    )
    tgen.start_router()

    # Add neighbor table entries in each VRF (same IP per VRF, different MACs)
    for vrf, neigh in zip(VRF_NAMES, NEIGH_PER_VRF):
        r1.run(
            "ip netns exec {} ip neigh add {} lladdr {} dev {} nud reachable".format(
                vrf, neigh["ip"], neigh["mac"], neigh["ifname"]
            )
        )


def teardown_module(_mod):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    for i in range(len(VRF_NAMES)):
        r1.net.reset_intf_netns("r1-eth{}".format(i))
    for vrf in VRF_NAMES:
        r1.net.delete_netns(vrf)
    tgen.stop_topology()


def test_vrf_list():
    "All three VRFs should appear in show vrf."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    out = r1.vtysh_cmd("show vrf", isjson=False)
    for vrf in VRF_NAMES:
        assert vrf in out, "VRF {} missing from show vrf: {}".format(vrf, out)


def test_same_ip_per_vrf():
    "Each VRF should have 10.0.0.1/24 on its interface (overlapping IPs)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    for vrf in VRF_NAMES:
        out = r1.vtysh_cmd("show interface vrf {} json".format(vrf), isjson=True)
        found = False
        for ifname, data in out.items():
            if ifname.startswith("r1-eth"):
                addrs = data.get("ipAddresses", []) or []
                for a in addrs:
                    if isinstance(a, dict) and a.get("address") == OVERLAP_PREFIX:
                        found = True
                        break
                    if isinstance(a, str) and a == OVERLAP_PREFIX:
                        found = True
                        break
            if found:
                break
        assert found, "VRF {} should have {} on an interface".format(
            vrf, OVERLAP_PREFIX
        )


def test_interface_names_overlap():
    "Each VRF has one data interface; show interface shows correct VRF per if."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    out = r1.vtysh_cmd("show interface vrf all json", isjson=True)
    by_vrf = {}
    for ifname, data in out.items():
        vrf = data.get("vrfName") or "default"
        if vrf not in by_vrf:
            by_vrf[vrf] = []
        by_vrf[vrf].append(ifname)
    for vrf in VRF_NAMES:
        assert vrf in by_vrf, "No interfaces in VRF {}: {}".format(
            vrf, list(by_vrf.keys())
        )
        assert len(by_vrf[vrf]) >= 1, "VRF {} has no interfaces".format(vrf)


def test_neighbor_entries_per_vrf():
    "Neighbor entries added via ip netns exec in each VRF show up in show ip neighbor."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    expected = {
        "neighbors": [
            {
                "interface": n["ifname"],
                "neighbor": n["ip"],
                "mac": n["mac"],
                "ruleCount": 0,
                "state": "REACHABLE",
            }
            for n in NEIGH_PER_VRF
        ]
    }
    test_func = partial(topotest.router_json_cmp, r1, "show ip neighbor json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert (
        result is None
    ), "Neighbor entries per VRF missing from show ip neighbor: {}".format(result)


def test_new_neighbor_entries_received():
    "Add new neighbor entries in each VRF at test time and ensure they are received."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Add new neighbors in each VRF via ip netns exec
    for vrf, neigh in zip(VRF_NAMES, NEIGH_NEW_PER_VRF):
        r1.run(
            "ip netns exec {} ip neigh add {} lladdr {} dev {} nud reachable".format(
                vrf, neigh["ip"], neigh["mac"], neigh["ifname"]
            )
        )

    # Expect these new entries to show up in show ip neighbor
    expected = {
        "neighbors": [
            {
                "interface": n["ifname"],
                "neighbor": n["ip"],
                "mac": n["mac"],
                "ruleCount": 0,
                "state": "REACHABLE",
            }
            for n in NEIGH_NEW_PER_VRF
        ]
    }
    test_func = partial(topotest.router_json_cmp, r1, "show ip neighbor json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert (
        result is None
    ), "New neighbor entries per VRF not received in show ip neighbor: {}".format(
        result
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
