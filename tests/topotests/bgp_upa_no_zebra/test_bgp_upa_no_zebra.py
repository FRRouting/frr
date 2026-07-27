#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>

"""
test_bgp_upa_no_zebra.py

A received UPA (Unreachable Prefix Announcement) route with the D-bit set
must NOT be installed as a blackhole/unreachable route into zebra unless the
receiving neighbor has explicitly opted in with 'neighbor X upa'.

Topology:

                     +---- r1 (FRR, AS 65001, NO 'neighbor upa')
                     |
    peer1 (ExaBGP) --+ s1
    AS 65002         |
                     +---- r2 (FRR, AS 65003, HAS 'neighbor upa')

peer1 advertises the same UPA route with the D-bit set to both receivers:

  192.168.2.0/24  UPA ExtCom  D-bit=1  originator=10.0.0.2

Expected:
  * r1 (not opted in): receives and recognizes the UPA route in the BGP RIB,
    but installs NOTHING into zebra - in particular no blackhole. This is the
    regression the fix addresses.
  * r2 (opted in via 'neighbor 10.0.0.2 upa'): honors the D-bit and installs a
    blackhole route into zebra. This guards against the fix silently disabling
    the feature altogether.
"""

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

PREFIX = "192.168.2.0/24"


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.0.0.2", defaultRoute="via 10.0.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)
    switch.add_link(peer1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name in ("r1", "r2"):
        router = tgen.gears[name]
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(name)))
        router.start()

    peer = tgen.gears["peer1"]
    peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bgp_has_prefix(router, prefix):
    """Return None once *prefix* is present in *router*'s BGP RIB."""
    output = router.vtysh_cmd("show bgp ipv4 unicast json")
    routes = json.loads(output).get("routes", {})
    if prefix not in routes:
        return "{} not yet in BGP RIB".format(prefix)
    return None


def _zebra_route(router, prefix):
    """Return the list of zebra route entries for *prefix*, or []."""
    output = router.vtysh_cmd("show ip route {} json".format(prefix))
    if not output.strip():
        return []
    return json.loads(output).get(prefix, [])


def _zebra_has_blackhole(router, prefix):
    """True if *prefix* is installed with a blackhole/unreachable nexthop."""
    for entry in _zebra_route(router, prefix):
        if entry.get("protocol") != "bgp":
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("blackhole") is True or nh.get("unreachable") is True:
                return True
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_convergence():
    """Both receivers learn the UPA route in their BGP RIB."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for name in ("r1", "r2"):
        router = tgen.gears[name]
        _, result = topotest.run_and_expect(
            lambda r=router: _bgp_has_prefix(r, PREFIX), None, count=60, wait=1
        )
        assert result is None, "{}: {}".format(name, result)


def test_r1_recognizes_upa_drop():
    """r1 receives and parses the UPA ExtCom (proves the route actually arrived)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check():
        output = r1.vtysh_cmd("show bgp ipv4 unicast {} json".format(PREFIX))
        data = json.loads(output)
        paths = data.get("paths")
        if not paths:
            return "prefix not in RIB"
        extcoms = paths[0].get("extendedCommunity", {}).get("string", "")
        if "upa:10.0.0.2:drop" not in extcoms:
            return "expected 'upa:10.0.0.2:drop', got: '{}'".format(extcoms)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result


def test_r1_no_blackhole_in_zebra():
    """
    THE FIX: r1 has not opted in to UPA, so it must not honor the D-bit and
    must not install an unreachable/blackhole route into zebra for the received
    UPA route.

    Wait long enough that a (buggy) blackhole install would have happened, then
    confirm none is present.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _has_blackhole():
        return _zebra_has_blackhole(r1, PREFIX)

    # Poll for a while; if a blackhole ever shows up, the fix regressed.
    _, appeared = topotest.run_and_expect(_has_blackhole, True, count=30, wait=1)
    assert appeared is not True, (
        "r1 installed an unreachable/blackhole route for {} without "
        "'neighbor upa'".format(PREFIX)
    )


def test_r2_installs_blackhole_when_opted_in():
    """
    Positive counterpart: r2 opted in with 'neighbor 10.0.0.2 upa', so it must
    honor the D-bit and install a blackhole route into zebra.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    _, result = topotest.run_and_expect(
        lambda: _zebra_has_blackhole(r2, PREFIX), True, count=30, wait=1
    )
    assert result is True, "r2 did not install a blackhole for {} despite 'neighbor upa'".format(
        PREFIX
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
