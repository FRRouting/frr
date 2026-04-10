#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_mtu_ipv6_change():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Wait for BGP to converge and fdfd::/64 to be installed")

    def _bgp_route_installed():
        output = json.loads(r1.vtysh_cmd("show bgp ipv6 unicast fdfd::/64 json"))
        expected = {"prefix": "fdfd::/64", "paths": [{"valid": True}]}
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_bgp_route_installed, None, count=60, wait=1)
    assert result is None, "fdfd::/64 not installed initially"

    def _kernel_route_installed():
        output = json.loads(r1.run("ip -6 -j route show fdfd::/64"))
        return topotest.json_cmp(
            output, [{"dst": "fdfd::/64", "dev": "r1-eth0", "protocol": "bgp"}]
        )

    _, result = topotest.run_and_expect(_kernel_route_installed, None, count=30, wait=1)
    assert result is None, "fdfd::/64 not in kernel initially"

    step("Set MTU below IPv6 minimum (1280) — disables IPv6 on the interface")
    r1.run("ip link set r1-eth0 mtu 1200")

    def _kernel_route_gone():
        output = json.loads(r1.run("ip -6 -j route show fdfd::/64"))
        if len(output) == 0:
            return None
        return "fdfd::/64 still in kernel after MTU drop"

    _, result = topotest.run_and_expect(_kernel_route_gone, None, count=30, wait=1)
    assert result is None, "fdfd::/64 was not removed from kernel after MTU drop"

    step("Restore MTU above IPv6 minimum — zebra must reinstall the BGP route")
    r1.run("ip link set r1-eth0 mtu 1500")

    _, result = topotest.run_and_expect(_kernel_route_installed, None, count=60, wait=1)
    assert result is None, "fdfd::/64 was NOT reinstalled after MTU was restored"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
