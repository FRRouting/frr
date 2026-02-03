#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step


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


def test_bgp_conditional_advertisement_mrai():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_check_advertised_initial():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.1/32": {
                    "valid": True,
                }
            },
            "totalPrefixCounter": 1,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_advertised_initial,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 MUST advertise only 10.10.10.1/32 to r2"

    step("Delete static route which is the condition for advertising")

    r1.vtysh_cmd(
        """
    configure terminal
     no ip route 10.10.10.1/32 r1-eth0
    """
    )

    def _bgp_check_advertised_after_update():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.2/32": {
                    "valid": True,
                },
            },
            "totalPrefixCounter": 1,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_advertised_after_update,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 MUST advertise only 10.10.10.2/32 to r2"

    step("Add static route back which is the condition for advertising")

    r1.vtysh_cmd(
        """
    configure terminal
     ip route 10.10.10.1/32 r1-eth0
    """
    )

    test_func = functools.partial(
        _bgp_check_advertised_initial,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 MUST advertise only 10.10.10.1/32 to r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
