#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_bgp_crypto_routes.py: basic coverage for the experimental BGP
crypto-routes AFI/SAFI.
"""

import functools
import json
import os
import sys

import pytest

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen


UNICAST_PREFIX = "10.10.10.1/32"
PEER_ID = "r1-key"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
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


def _bgp_established(router, neighbor):
    output = json.loads(router.vtysh_cmd("show bgp summary json"))
    expected = {
        "ipv4Unicast": {"peers": {neighbor: {"state": "Established"}}},
    }
    return topotest.json_cmp(output, expected)


def _crypto_route(router, peer_id, expected):
    output = json.loads(router.vtysh_cmd("show bgp crypto-routes json"))

    for route in output.get("routes", []):
        if route.get("peerId") != peer_id:
            continue
        for key, value in expected.items():
            if route.get(key) != value:
                return "{} is {!r}, expected {!r}".format(
                    key, route.get(key), value
                )
        return None

    return "crypto route {} not found in {}".format(peer_id, output)


def _crypto_route_absent(router, peer_id):
    output = json.loads(router.vtysh_cmd("show bgp crypto-routes json"))

    for route in output.get("routes", []):
        if route.get("peerId") == peer_id:
            return "crypto route {} still present in {}".format(peer_id, output)

    return None


def test_bgp_crypto_routes_advertise_update_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Wait for BGP convergence")
    for router, neighbor in ((r1, "192.168.255.2"), (r2, "192.168.255.1")):
        test_func = functools.partial(_bgp_established, router, neighbor)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "BGP did not converge for neighbor {}".format(neighbor)

    step("Verify initial crypto route advertisement")
    expected_initial = {
        "algorithm": "rsa-2048",
        "certificateId": "cert-r1",
        "publicKeyId": "key-r1",
        "capabilities": "sign,verify",
        "trustLevel": 80,
    }
    test_func = functools.partial(_crypto_route, r2, PEER_ID, expected_initial)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("Update crypto metadata on r1")
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          address-family crypto-routes
           crypto-peer r1-key algorithm ecdsa-p256 certificate-id cert-r1-v2 public-key-id key-r1-v2 capabilities sign,verify,encrypt trust-level 90
        """
    )

    expected_updated = {
        "algorithm": "ecdsa-p256",
        "certificateId": "cert-r1-v2",
        "publicKeyId": "key-r1-v2",
        "capabilities": "sign,verify,encrypt",
        "trustLevel": 90,
    }
    test_func = functools.partial(_crypto_route, r2, PEER_ID, expected_updated)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("Withdraw crypto metadata from r1")
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          address-family crypto-routes
           no crypto-peer r1-key
        """
    )

    test_func = functools.partial(_crypto_route_absent, r2, PEER_ID)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("Verify IPv4 unicast still works")
    output = json.loads(r2.vtysh_cmd("show ip bgp {} json".format(UNICAST_PREFIX)))
    expected = {"paths": [{"valid": True}]}
    assert topotest.json_cmp(output, expected) is None

    step("Verify crypto metadata is not installed in Zebra or kernel routes")
    zebra_routes = r2.vtysh_cmd("show ip route", isjson=False)
    kernel_routes = r2.run("ip route show")
    assert PEER_ID not in zebra_routes
    assert "crypto" not in zebra_routes.lower()
    assert PEER_ID not in kernel_routes
    assert "crypto" not in kernel_routes.lower()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
