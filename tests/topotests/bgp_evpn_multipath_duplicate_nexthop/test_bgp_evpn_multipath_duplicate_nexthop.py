#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nvidia Corporation
#                       Rajasekar Raja
#

"""
EVPN form of the duplicate-nexthop multipath check.

vtep1, vtep2 and vtep3 each originate the same tenant prefix as an EVPN
type-5 route in vrf1 (L3VNI 104001). Both leaves reflect every path, so tor1
imports six paths into vrf1 covering only three distinct VTEP nexthops:

    10.0.0.4, 10.0.0.4, 10.0.0.5,
    10.0.0.5, 10.0.0.6, 10.0.0.6

This is the shape reported in the field: duplicates that are copies of each
other rather than of the bestpath. If a duplicate is allowed to occupy a
maximum-paths slot, one distinct VTEP is left uninstalled.

                         +-- leaf1 --+
    tor1 (vrf1) ---------|           |--------- vtep1, vtep2, vtep3
                         +-- leaf2 --+
                                        each originating 203.0.113.0/24
"""

import os
import sys
import json
import functools
import platform
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

PREFIX = "203.0.113.0/24"
VNI = 104001
VTEPS = ["10.0.0.4", "10.0.0.5", "10.0.0.6"]
L3VNI_ROUTERS = ["tor1", "vtep1", "vtep2", "vtep3"]
VTEP_LOCAL_IP = {
    "tor1": "10.0.0.1",
    "vtep1": "10.0.0.4",
    "vtep2": "10.0.0.5",
    "vtep3": "10.0.0.6",
}


def build_topo(tgen):
    "Every router shares one broadcast segment for the underlay."

    switch = tgen.add_switch("s1")
    for rname in ["tor1", "leaf1", "leaf2", "vtep1", "vtep2", "vtep3"]:
        switch.add_link(tgen.add_router(rname))


def _setup_l3vni(router, rname):
    """Classic L3VNI plumbing: a bridge inside the VRF with a vxlan member."""
    local_ip = VTEP_LOCAL_IP[rname]

    router.run("ip link add vrf1 type vrf table 1001")
    router.run("ip link set dev vrf1 up")
    router.run("ip link add br4001 type bridge stp_state 0")
    router.run("ip link set dev br4001 master vrf1")
    router.run("ip link set dev br4001 up")
    router.run(
        "ip link add vni4001 type vxlan id {} dstport 4789 local {} nolearning".format(
            VNI, local_ip
        )
    )
    router.run("ip link set dev vni4001 master br4001")
    router.run("ip link set dev vni4001 up")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info("EVPN tests require kernel 4.18 or newer, have {}".format(krel))
        pytest.skip("Kernel too old for EVPN")

    for rname in L3VNI_ROUTERS:
        _setup_l3vni(tgen.gears[rname], rname)

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()

    for rname in L3VNI_ROUTERS:
        router = tgen.gears[rname]
        router.run("ip link del vni4001 2>/dev/null || true")
        router.run("ip link del br4001 2>/dev/null || true")
        router.run("ip link del vrf1 2>/dev/null || true")

    tgen.stop_topology()


def _vrf_paths(router):
    "Paths tor1 holds for the prefix inside vrf1."
    output = json.loads(
        router.vtysh_cmd("show bgp vrf vrf1 ipv4 unicast {} json".format(PREFIX))
    )

    return output.get("paths", [])


def _installed_nexthops(router):
    "Distinct nexthops zebra installed in vrf1, ignoring any it flagged duplicate."
    output = json.loads(
        router.vtysh_cmd("show ip route vrf vrf1 {} json".format(PREFIX))
    )
    entries = output.get(PREFIX, [])
    if not entries:
        return []

    nexthops = set()
    for nexthop in entries[0].get("nexthops", []):
        if nexthop.get("duplicate"):
            continue
        if not nexthop.get("active"):
            continue
        if "ip" in nexthop:
            nexthops.add(nexthop["ip"])

    return sorted(nexthops)


def _check_installed_nexthop_count(router, expected):
    got = _installed_nexthops(router)
    if len(got) != expected:
        return "expected {} installed nexthops, got {}: {}".format(
            expected, len(got), got
        )

    for nexthop in got:
        if nexthop not in VTEPS:
            return "unexpected nexthop {}, want a subset of {}".format(nexthop, VTEPS)

    return None


def _set_maximum_paths(router, maxpaths):
    router.vtysh_cmd(
        """
        configure terminal
        router bgp 65000 vrf vrf1
         address-family ipv4 unicast
          maximum-paths ibgp {}
        """.format(
            maxpaths
        )
    )


def test_evpn_type5_paths_converge():
    "tor1 must import all six type-5 paths before the maximum-paths cases mean anything."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    def _converged():
        paths = _vrf_paths(tor1)
        if len(paths) != 6:
            return "expected 6 imported paths for {}, got {}".format(PREFIX, len(paths))

        seen = set()
        for path in paths:
            for nexthop in path.get("nexthops", []):
                if "ip" in nexthop:
                    seen.add(nexthop["ip"])

        if sorted(seen) != VTEPS:
            return "expected nexthops {}, got {}".format(VTEPS, sorted(seen))

        return None

    _, result = topotest.run_and_expect(_converged, None, count=60, wait=1)
    assert result is None, result


@pytest.mark.parametrize("maxpaths,expected", [(6, 3), (5, 3), (4, 3), (3, 3), (2, 2)])
def test_evpn_maximum_paths(maxpaths, expected):
    """
    Walk the budget down across the three distinct VTEP nexthops.

    Only three distinct VTEPs exist, so the installed count should be
    min(maxpaths, 3) throughout. A duplicate permitted to occupy a slot shows
    up as a shortfall once the budget stops exceeding the candidate count.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    step(
        "maximum-paths ibgp {}, expecting {} installed nexthops".format(
            maxpaths, expected
        )
    )
    _set_maximum_paths(tor1, maxpaths)

    test_func = functools.partial(_check_installed_nexthop_count, tor1, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_evpn_no_duplicate_nexthops_installed():
    "Whatever the budget, zebra must never be handed the same VTEP twice."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    _set_maximum_paths(tor1, 6)

    def _no_duplicates():
        output = json.loads(
            tor1.vtysh_cmd("show ip route vrf vrf1 {} json".format(PREFIX))
        )
        entries = output.get(PREFIX, [])
        if not entries:
            return "no route for {} in vrf1".format(PREFIX)

        duplicates = [
            nexthop
            for nexthop in entries[0].get("nexthops", [])
            if nexthop.get("duplicate")
        ]
        if duplicates:
            return "zebra was sent {} duplicate nexthops: {}".format(
                len(duplicates), duplicates
            )

        return None

    _, result = topotest.run_and_expect(_no_duplicates, None, count=60, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
