#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# test_bgp_show_l2vpn_evpn_rt.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Diego Troy Lopez <troy@troys.network>
#

"""
test_bgp_show_l2vpn_evpn_rt.py: Test if `show bgp l2vpn evpn rt` filters EVPN RIB on RT
"""

import json
from functools import partial
import os
import sys
import pytest
import platform

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    sw = tgen.add_switch("s-r1-r2")
    for r in ("r1", "r2"):
        tgen.add_router(r)
        sw.add_link(tgen.gears[r], nodeif="eth-{}".format(r))


def _setup_vrfs(router, vrf):
    """
    Setup linux network namespaces and vrfs. Router names should be r<num> for
    proper indexing.
    """
    ns = f"vrf-{vrf}"
    idx = router.name[1:]
    ip = f"192.168.2.{idx}"
    mac = f"52:54:00:00:{idx}{idx}:{idx}{idx}"
    iface = f"eth-{router.name}"
    router.add_netns(ns)
    router.cmd_raises(
        f"""
ip link add loop{vrf} type dummy
ip link add vxlan-{vrf} type vxlan id {vrf} dstport 4789 dev {iface} local {ip}
"""
    )
    router.set_intf_netns(f"loop{vrf}", ns, up=True)
    router.set_intf_netns(f"vxlan-{vrf}", ns, up=True)
    router.cmd_raises(
        f"""
ip -n vrf-{vrf} link set lo up
ip -n vrf-{vrf} link add bridge-{vrf} address {mac} type bridge stp_state 0
ip -n vrf-{vrf} link set dev vxlan-{vrf} master bridge-{vrf}
ip -n vrf-{vrf} link set bridge-{vrf} up
ip -n vrf-{vrf} link set vxlan-{vrf} up
"""
    )


def setup_module(mod):
    """
    Setup environment
    """
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    kernelv = platform.release()
    if topotest.version_cmp(kernelv, "4.18") < 0:
        logger.info(
            "For EVPN, kernel version should be minimum 4.18. Kernel present {}".format(
                kernelv
            )
        )
        return pytest.skip("Skipping show bgp l2vpn evpn rt test. Kernel not supported")

    r1, r2 = tgen.net["r1"], tgen.net["r2"]

    for vrf in (101, 102):
        _setup_vrfs(r1, vrf)
        _setup_vrfs(r2, vrf)

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        router.use_netns_vrf()
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    """
    Teardown environment
    """
    tgen = get_topogen()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.net.delete_netns("vrf-101")
        router.net.delete_netns("vrf-102")
    tgen.stop_topology()


def test_bgp_show_l2vpn_evpn_rt():
    """
    Test to see if `show bgp l2vpn evpn rt <RT>` properly filters.
    6 prefixes have the 65000:101 RT, 4 have the 65000:102 RT. Only 6 should match.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    json_file = "{}/{}/bgp_l2vpn_evpn_routes.json".format(CWD, "r2")
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn rt 65000:101 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = "show bgp l2vpn evpn rt expected JSON output mismatches"
    assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
