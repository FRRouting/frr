#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_v6_pmsi_tunnel.py
#
# Copyright (c) 2025 Nvidia Inc.
#                    Donald Sharp

"""
Test that EVPN with an IPv6-only underlay correctly encodes and parses
the PMSI Tunnel attribute with an IPv6 tunnel identifier (length 21).

Type-3 IMET routes carry the PMSI Tunnel attribute, so this test verifies
that two FRR routers with IPv6-only EVPN peering and IPv6 VTEPs can
exchange type-3 routes and install remote VTEPs.
"""

import json
from functools import partial
import os
import sys
import pytest
import platform

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info(
            'BGP EVPN v6 PMSI tests require kernel >= 4.18 (have "{}")'.format(krel)
        )
        return pytest.skip("Kernel too old for EVPN NETNS test")

    cmds_vxlan = [
        "ip link add name bridge-101 up type bridge stp_state 0",
        "ip link set dev bridge-101 up",
        "ip link add name vxlan-101 type vxlan id 101 dstport 4789 dev {0}-eth0 local {1}",
        "ip link set dev vxlan-101 master bridge-101",
        "ip link set vxlan-101 up type bridge_slave learning off flood off mcast_flood off",
    ]

    for rname, vtep_ip in [("r1", "fd00:100::1"), ("r2", "fd00:100::2")]:
        router = tgen.gears[rname]
        for cmd in cmds_vxlan:
            formatted = cmd.format(rname, vtep_ip)
            logger.info("cmd to {}: {}".format(rname, formatted))
            output = router.cmd_raises(formatted)
            logger.info("result: " + output)

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """
    Assert that BGP EVPN sessions come up between r1 and r2 over IPv6.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("r1", "r2"):
        router = tgen.gears[rname]

        expected = {"peers": {}}
        if rname == "r1":
            expected["peers"]["fd00:100::2"] = {"state": "Established"}
        else:
            expected["peers"]["fd00:100::1"] = {"state": "Established"}

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp l2vpn evpn summary json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, '"{}" BGP session did not establish'.format(rname)


def test_evpn_type3_routes():
    """
    Verify EVPN type-3 IMET routes are received. These carry the PMSI Tunnel
    attribute. With IPv6-only peering, the PMSI tunnel identifier must be
    encoded as 21 bytes (IPv6). Without the fix, these routes would be
    rejected as malformed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        json_file = "{}/{}/evpn_type3.json".format(CWD, rname)
        expected = json.loads(open(json_file).read())

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show evpn vni json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, '"{}" EVPN type-3 route check failed'.format(rname)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
