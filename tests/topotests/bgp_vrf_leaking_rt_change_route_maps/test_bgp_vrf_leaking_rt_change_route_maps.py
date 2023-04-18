#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
If we overwrite import/export RT list via route-maps or even flush by using
`set extcommunity none`, then we must withdraw old paths from VRFs to avoid
stale paths.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.cmd_raises("ip link add vrf1 type vrf table 10")
    router.cmd_raises("ip link set up dev vrf1")
    router.cmd_raises("ip link add vrf2 type vrf table 20")
    router.cmd_raises("ip link set up dev vrf2")
    router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    router.start()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_vrf_leaking_rt_change_route_maps():
    tgen = get_topogen()

    router = tgen.gears["r1"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_path():
        output = json.loads(router.vtysh_cmd("show bgp vrf vrf2 ipv4 unicast json"))
        expected = {"routes": {"192.168.100.100/32": [{"nhVrfName": "vrf1"}]}}
        return topotest.json_cmp(output, expected)

    step("Initial converge")
    test_func = functools.partial(_bgp_check_path)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't see 192.168.100.100/32 leaked from vrf1 into vrf2."

    step("Overwrite RT list (remove rt 65500:11990 from route-map)")
    router.vtysh_cmd(
        """
        config terminal
        route-map rm permit 10
         set extcommunity rt 65500:10100
        exit
        """
    )

    step("Check if 192.168.100.100/32 was removed from vrf2")
    test_func = functools.partial(_bgp_check_path)
    _, result = topotest.run_and_expect(test_func, not None, count=20, wait=0.5)
    assert result is not None, "192.168.100.100/32 still exists in vrf2 as stale."


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
