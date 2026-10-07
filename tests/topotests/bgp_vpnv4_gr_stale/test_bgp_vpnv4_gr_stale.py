#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Yuya Kusakabe <yuya.kusakabe@gmail.com>
#

"""
Check that a VPN path removed by graceful restart stale cleanup is also
withdrawn from the VRF that imported it.

peer1 advertises 10.0.1.1/32 and 10.0.2.1/32 as VPNv4 routes, which r1
imports into vrf1.  peer1 dies without sending a NOTIFICATION, so r1
keeps its paths as stale.  peer1 comes back advertising only
10.0.2.1/32, and its End-of-RIB makes r1 remove the stale 10.0.1.1/32.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

GONE = "10.0.1.1/32"
KEPT = "10.0.2.1/32"
RD = "65002:10"


def build_topo(tgen):
    tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="192.168.255.2/24", defaultRoute="via 192.168.255.1"
    )

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(peer1)


def start_peer1(tgen, cfg_dir):
    peer_dir = os.path.join(CWD, cfg_dir)
    tgen.gears["peer1"].start(peer_dir, os.path.join(peer_dir, "exabgp.env"))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    if not tgen.hasmpls:
        pytest.skip("MPLS is not available")
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.cmd_raises("ip link add vrf1 type vrf table 10")
    r1.cmd_raises("ip link set dev vrf1 up")
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()

    start_peer1(tgen, "peer1")


def teardown_module(mod):
    get_topogen().stop_topology()


def vpn_paths(router, prefix):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn json"))
    return (
        output.get("routes", {})
        .get("routeDistinguishers", {})
        .get(RD, {})
        .get(prefix, [])
    )


def vrf_paths(router, prefix):
    output = json.loads(
        router.vtysh_cmd("show bgp vrf vrf1 ipv4 unicast {} json".format(prefix))
    )
    return output.get("paths", [])


def kernel_has(router, prefix):
    output = json.loads(router.cmd("ip -j route show table 10 {}".format(prefix)))
    return bool(output)


def wait_for(func, expected):
    _, result = topotest.run_and_expect(func, expected, count=15, wait=1)
    return result


def test_bgp_vpnv4_gr_stale():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    peer1 = tgen.gears["peer1"]

    step("Check that r1 imports both VPN routes into vrf1")
    for prefix in (GONE, KEPT):
        assert wait_for(lambda: len(vrf_paths(r1, prefix)), 1) == 1
        assert wait_for(lambda: kernel_has(r1, prefix), True), "not in kernel"

    step("Kill peer1 and check that r1 keeps its VPN paths as stale")
    peer1.run("kill -9 `cat /var/run/exabgp/exabgp.pid`")
    peer1.run("rm -f /var/run/exabgp/exabgp.pid")

    def stale():
        paths = vpn_paths(r1, GONE)
        return bool(paths) and all(p.get("stale") for p in paths)

    assert wait_for(stale, True), "VPN path not kept as stale"

    step("Restart peer1 without {}".format(GONE))
    start_peer1(tgen, "peer1-restart")
    assert wait_for(lambda: len(vpn_paths(r1, KEPT)), 1) == 1
    assert wait_for(lambda: len(vpn_paths(r1, GONE)), 0) == 0, "stale VPN path kept"

    step("Check that {} is withdrawn from vrf1".format(GONE))
    assert wait_for(lambda: len(vrf_paths(r1, GONE)), 0) == 0, "import left in vrf1"
    assert wait_for(lambda: kernel_has(r1, GONE), False) is False, "left in kernel"
    assert len(vrf_paths(r1, KEPT)) == 1
    assert kernel_has(r1, KEPT)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
