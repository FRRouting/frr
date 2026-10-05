#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Ming Han Chan <s10159021@gmail.com>
#

"""
test_bgp_evpn_type5_bestpath_change.py

Check that a local EVPN type-5 route follows the VRF best path.

With "advertise ipv4 unicast" (no gateway-ip), a VRF prefix is exported to
EVPN from its best path only. Local type-5 paths are keyed by the VRF path
they were exported from, so when the best path moved from one exportable path
to another, the new best path got its own local type-5 path and the one
exported from the old best path was never withdrawn. It stayed in the EVPN
table, and kept being advertised, even after the prefix left the VRF.

r1 has two exportable paths for 192.0.2.10/32 in vrf-a: a "network" path
(origin IGP, best) and a "redistribute static" path (origin incomplete).
The test moves the best path between them and removes them one by one,
checking after every step that EVPN holds exactly one local type-5 path for
the prefix, exported from the current best path, and none once the VRF has
no path left.

Topology:

    +----+  s1
    | r1 |------
    +----+
"""

import json
import os
import platform
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

VRF = "vrf-a"
PREFIX = "192.0.2.10/32"
EVPN_PREFIX = "[5]:[0]:[32]:[192.0.2.10]"


def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip('EVPN type-5 test requires kernel >= 4.18, found "{}"'.format(krel))

    r1 = tgen.gears["r1"]
    for command in [
        "ip link add {} type vrf table 1001".format(VRF),
        "ip link set dev {} up".format(VRF),
        "ip link add name br100 up type bridge stp_state 0",
        "ip link set dev br100 master {}".format(VRF),
        "ip link set dev br100 up",
        "ip link add name vxlan100 type vxlan id 100 dstport 4789 "
        "dev r1-eth0 local 192.168.100.1 nolearning",
        "ip link set dev vxlan100 master br100",
        "ip link set dev vxlan100 up type bridge_slave "
        "learning off flood off mcast_flood off",
    ]:
        logger.info("r1: %s", command)
        r1.cmd_raises(command)

    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()


def _vrf_paths(router):
    "Return the (origin, best) pairs of the VRF paths for PREFIX."

    output = json.loads(
        router.vtysh_cmd("show bgp vrf {} ipv4 unicast {} json".format(VRF, PREFIX))
        or "{}"
    )
    return sorted(
        (path.get("origin"), bool(path.get("bestpath", {}).get("overall")))
        for path in output.get("paths", [])
    )


def _evpn_type5_origins(router):
    "Return the origins of the EVPN type-5 paths for PREFIX, all RDs."

    output = json.loads(
        router.vtysh_cmd("show bgp l2vpn evpn route type prefix json") or "{}"
    )
    origins = []
    for rd_routes in output.values():
        if not isinstance(rd_routes, dict):
            continue
        for path in rd_routes.get(EVPN_PREFIX, {}).get("paths", []):
            origins.extend(entry.get("origin") for entry in path)
    return sorted(origins)


def _wait_for(router, check, expected, what):
    _, result = topotest.run_and_expect(check, expected, count=30, wait=1)
    assert result == expected, "{} {}: expected {}, got {}\n{}\n{}".format(
        router.name,
        what,
        expected,
        result,
        router.vtysh_cmd("show bgp vrf {} ipv4 unicast {}".format(VRF, PREFIX)),
        router.vtysh_cmd("show bgp l2vpn evpn route type prefix"),
    )


def _check(vrf_paths, evpn_origins):
    r1 = get_topogen().gears["r1"]

    _wait_for(r1, lambda: _vrf_paths(r1), vrf_paths, "VRF paths")
    _wait_for(r1, lambda: _evpn_type5_origins(r1), evpn_origins, "EVPN type-5")


def _config(commands):
    r1 = get_topogen().gears["r1"]
    output = r1.vtysh_cmd("configure terminal\n{}\nend\n".format(commands))
    assert "% Unknown" not in output and "% Invalid" not in output, output


def _set_network(present):
    _config(
        "router bgp 65001 vrf {}\n"
        "address-family ipv4 unicast\n"
        "{}network {}".format(VRF, "" if present else "no ", PREFIX)
    )


def _set_static(present):
    _config(
        "vrf {}\n"
        "{}ip route {} blackhole".format(VRF, "" if present else "no ", PREFIX)
    )


def test_bgp_evpn_type5_initial():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("network path is best, EVPN has one type-5 exported from it")
    _check([("IGP", True), ("incomplete", False)], ["IGP"])


def test_bgp_evpn_type5_bestpath_moves():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove network path, the redistributed path becomes best")
    _set_network(False)
    _check([("incomplete", True)], ["incomplete"])

    step("Add network path back, it becomes best again")
    _set_network(True)
    _check([("IGP", True), ("incomplete", False)], ["IGP"])


def test_bgp_evpn_type5_non_best_removed():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove the static route, the best path does not change")
    _set_static(False)
    _check([("IGP", True)], ["IGP"])


def test_bgp_evpn_type5_last_path_removed():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Add the static route back and make the redistributed path best")
    _set_static(True)
    _set_network(False)
    _check([("incomplete", True)], ["incomplete"])

    step("Remove the static route, the VRF has no path left")
    _set_static(False)
    _check([], [])


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
