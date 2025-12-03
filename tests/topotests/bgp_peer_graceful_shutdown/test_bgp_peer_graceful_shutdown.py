#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if routes from R1 has local-preference set to 0 and graceful-shutdown
community. Also test R2 originated routes (network, connected, static).
"""

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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_orf():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.2.2 advertised-routes json"
            )
        )
        expected = {"advertisedRoutes": {"10.10.10.1/32": {"locPrf": 100}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge at R2"

    step("Mark routes from R1 as graceful-shutdown")
    r2.vtysh_cmd(
        """
        configure terminal
            router bgp
                neighbor 192.168.1.1 graceful-shutdown
    """
    )

    def _bgp_check_peer_graceful_shutdown():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast 10.10.10.1/32 json"))
        expected = {
            "paths": [
                {
                    "locPrf": 0,
                    "community": {"string": "graceful-shutdown"},
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_peer_graceful_shutdown)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "local-preference is not 0 and/or graceful-shutdown community missing"

    step("Remove graceful-shutdown from R1")
    r2.vtysh_cmd(
        """
        configure terminal
            router bgp
                no neighbor 192.168.1.1 graceful-shutdown
    """
    )


def test_bgp_peer_graceful_shutdown_originated_routes():
    """Test R2 originated routes (network, connected, static) with per-neighbor gshut"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Configure R2 to originate routes (network, connected, static)")
    r2.vtysh_cmd(
        """
        configure terminal
         interface lo
          ip address 10.10.10.2/32
          ip address 10.30.30.2/32
         exit
         ip route 10.20.20.2/32 Null0
         router bgp 65002
          address-family ipv4 unicast
           network 10.30.30.2/32
           redistribute connected
           redistribute static
          exit-address-family
         exit
        end
    """
    )

    step("Configure graceful-shutdown towards R3 (IBGP) only")
    r2.vtysh_cmd(
        """
        configure terminal
            router bgp
                neighbor 192.168.2.2 graceful-shutdown
    """
    )

    step("Check R2 originated routes at R3 (IBGP with gshut) have LOCAL_PREF=0")

    # R2 originated routes to check
    r2_originated_prefixes = [
        "10.30.30.2/32",  # network command
        "10.10.10.2/32",  # connected (loopback)
        "10.20.20.2/32",  # static
    ]

    def _bgp_check_r2_routes_at_r3_with_gshut():
        expected = {"paths": [{"locPrf": 0}]}
        for prefix in r2_originated_prefixes:
            output = json.loads(r3.vtysh_cmd(f"show bgp ipv4 unicast {prefix} json"))
            result = topotest.json_cmp(output, expected)
            if result:
                return result
        return None

    test_func = functools.partial(_bgp_check_r2_routes_at_r3_with_gshut)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "R2 originated routes don't have LOCAL_PREF=0 at R3"

    step("Check R2 originated routes at R1 (EBGP without gshut) are normal")

    def _bgp_check_r2_routes_at_r1_without_gshut():
        # Check that R2 originated routes at R1 don't have GSHUT community
        for prefix in r2_originated_prefixes:
            output = json.loads(r1.vtysh_cmd(f"show bgp ipv4 unicast {prefix} json"))
            if "community" in output.get("paths", [{}])[0]:
                if "graceful-shutdown" in output["paths"][0]["community"].get(
                    "string", ""
                ):
                    return f"R1 should not have gshut community on {prefix}"
        return None

    test_func = functools.partial(_bgp_check_r2_routes_at_r1_without_gshut)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "R2 originated routes at R1 incorrectly have gshut"

    step("Cleanup: Remove originated routes config and graceful-shutdown")
    r2.vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          no neighbor 192.168.2.2 graceful-shutdown
          address-family ipv4 unicast
           no network 10.30.30.2/32
           no redistribute connected
           no redistribute static
          exit-address-family
         exit
         no ip route 10.20.20.2/32 Null0
         interface lo
          no ip address 10.10.10.2/32
          no ip address 10.30.30.2/32
         exit
        end
    """
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
