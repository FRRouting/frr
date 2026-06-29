#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Yuya Kusakabe
#
r"""
Test BGP-MUP SAFI (draft-ietf-bess-mup-safi) control-plane basics:

- BGP session establishment over BGP-MUP-only peerings
- BGP-MUP capability negotiation for both AFI=IPv4 and AFI=IPv6
- NLRI parse of all four route types (ISD / DSD / T1ST / T2ST)
  received from an ExaBGP peer
- Structured `show bgp ipv[46] mup all json` rendering
- Re-advertisement of the received routes to a second FRR speaker,
  which exercises the encode side of the NLRI codec on the wire
- The BGP-MUP extended community rendering in detailed show output
- Withdraw of every route when the announcing peer goes away, which
  exercises the withdraw side of the codec on the wire

Topology:

    +-----+         +-----+         +-------+
    | r1  |---------|  r2 |---------| peer1 |
    +-----+         +-----+         +-------+
     AS 65001        AS 65002        AS 65003
            eBGP (v6)       eBGP (v4) ExaBGP

peer1 (ExaBGP) announces one route of each MUP type to r2 on both
the IPv4 and IPv6 sub-AFIs.  r2 must parse and display them, and
re-advertise them to r1.
"""

import os
import sys
import json
import functools

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

# (afi, routeType, ip, expected NLRI fields) for every route peer1
# announces; checked on r2 (receive) and r1 (re-advertisement).
EXPECTED_MUP_ROUTES = [
    (
        "ipv4",
        1,
        "10.99.0.0",
        {"archType": 1, "ipFamily": "ipv4", "ipLen": 24, "rd": "100:100"},
    ),
    ("ipv4", 2, "10.0.0.250", {"ipFamily": "ipv4", "rd": "300:300"}),
    (
        "ipv4",
        3,
        "192.168.1.5",
        {
            "ipLen": 32,
            "teid": 12345,
            "qfi": 9,
            "endpointAddress": "10.99.0.5",
            "sourceAddress": "10.0.2.105",
        },
    ),
    ("ipv4", 4, "10.0.0.250", {"teid": 12345, "endpointAddressFamily": "ipv4"}),
    (
        "ipv6",
        1,
        "2001:db8:99::",
        {"ipFamily": "ipv6", "ipLen": 64, "rd": "200:200"},
    ),
    ("ipv6", 2, "2001:db8:99::250", {"ipFamily": "ipv6", "rd": "300:300"}),
    (
        "ipv6",
        3,
        "2001:db8:aa::",
        {
            "ipLen": 64,
            "teid": 12345,
            "qfi": 9,
            "endpointAddress": "2001:db8:99::5",
            "sourceAddress": "2001:db8:2::105",
        },
    ),
    (
        "ipv6",
        4,
        "2001:db8:99::250",
        {"teid": 12345, "endpointAddressFamily": "ipv6"},
    ),
]


def build_topo(tgen):
    """r1 <--s1--> r2 <--s2--> peer1 (ExaBGP)."""
    for i in (1, 2):
        tgen.add_router("r{}".format(i))

    sw = tgen.add_switch("s1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r2"])

    sw2 = tgen.add_switch("s2")
    sw2.add_link(tgen.gears["r2"])
    peer = tgen.add_exabgp_peer(
        "peer1", ip="10.0.2.105/24", defaultRoute="via 10.0.2.1"
    )
    sw2.add_link(peer)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The routes announced on the IPv6 sub-AFI carry an IPv6 next-hop;
    # put it on peer1's interface so r2 can validate it as on-link.
    tgen.gears["peer1"].run("ip addr add 2001:db8:2::105/64 dev peer1-eth0")

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    # Start ExaBGP after FRR is up so the BGP session establishes
    # against an already-listening r2.
    for pname, peer in tgen.exabgp_peers().items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        peer.start(peer_dir, env_file)
        logger.info("started %s", pname)


def teardown_module(mod):
    get_topogen().stop_topology()


def _open_json_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(path)


def _check_router_json(router, command, reffile, label):
    expected = _open_json_file(reffile)
    test_func = functools.partial(topotest.router_json_cmp, router, command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, '"{}" {} JSON output mismatches'.format(router.name, label)


def _check_show_contains(router, command, pattern):
    "Return None if `pattern` shows up in `command` output, else an error."
    if pattern in router.vtysh_cmd(command):
        return None
    return "'{}' not found in `{}`".format(pattern, command)


def _find_mup_route(routes, route_type, ip):
    """Walk a `routes` dict from `show bgp ipv* mup all json` and
    return the first path whose (routeType, ip) matches.  Keys are
    human-readable NLRI strings (e.g.
    `[1]:[3]:[28]:[192.168.1.5/32]:[teid=12345][qfi=9][ep=10.99.0.5]
    [src=10.0.2.105]`); we can't rely on exact key form, so scan each
    value list instead.
    """
    for paths in (routes or {}).values():
        if not isinstance(paths, list):
            continue
        for path in paths:
            if path.get("routeType") != route_type:
                continue
            if path.get("ip") == ip or path.get("endpointAddress") == ip:
                return path
    return None


def _mup_json_routes(router, afi):
    out = router.vtysh_cmd("show bgp {} mup all json".format(afi), isjson=True)
    key = "ipv4Mup" if afi == "ipv4" else "ipv6Mup"
    if not isinstance(out, dict) or key not in out:
        return None
    return out[key].get("routes", {})


def _check_all_mup_routes(router):
    """Return None when every EXPECTED_MUP_ROUTES entry is present with
    the expected structured NLRI fields, else an error string."""
    for afi, route_type, ip, fields in EXPECTED_MUP_ROUTES:
        routes = _mup_json_routes(router, afi)
        if routes is None:
            return "{} mup json output missing".format(afi)
        path = _find_mup_route(routes, route_type, ip)
        if path is None:
            return "type-{} route {} missing from {} mup json".format(
                route_type, ip, afi
            )
        for key, want in fields.items():
            if path.get(key) != want:
                return "type-{} route {}: {}={!r}, want {!r}".format(
                    route_type, ip, key, path.get(key), want
                )
    return None


def test_bgp_session_established():
    """The BGP session over the MUP-only AFs must reach Established."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying BGP session establishes over BGP-MUP")

    for rname in ("r1", "r2"):
        _check_router_json(
            tgen.gears[rname],
            "show bgp neighbor json",
            os.path.join(CWD, rname, "bgp_neighbor.json"),
            "neighbor",
        )


def test_bgp_mup_capability():
    """ipv4Mup AND ipv6Mup must show advertisedAndReceived on both sides."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying BGP-MUP multiprotocol capability negotiation")

    for rname in ("r1", "r2"):
        _check_router_json(
            tgen.gears[rname],
            "show bgp neighbor json",
            os.path.join(CWD, rname, "bgp_capability.json"),
            "MUP capability",
        )


def test_mup_routes_received_on_r2():
    """All routes announced by peer1 must reach r2's BGP-MUP RIB."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying peer1's MUP routes are received on r2")
    r2 = tgen.gears["r2"]

    for afi, route_type, ip, _ in EXPECTED_MUP_ROUTES:
        test_func = functools.partial(
            _check_show_contains, r2, "show bgp {} mup all".format(afi), ip
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "type-{} route on r2: {}".format(route_type, result)


def test_show_bgp_mup_json():
    """`show bgp ipv[46] mup all json` on r2 must decompose each NLRI
    into structured fields."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    test_func = functools.partial(_check_all_mup_routes, tgen.gears["r2"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 mup json: {}".format(result)


def test_mup_routes_propagated_to_r1():
    """r2 must re-advertise the routes to r1 with the NLRI intact;
    this exercises the encode path of the codec on a live session."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying MUP routes are re-advertised to r1")

    test_func = functools.partial(_check_all_mup_routes, tgen.gears["r1"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 mup json: {}".format(result)


def test_mup_extended_community():
    """The BGP-MUP extended community carried on the DSD/T2ST routes
    must render as MUP:<asn>:<id> in detailed show output."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    test_func = functools.partial(
        _check_show_contains,
        tgen.gears["r2"],
        "show bgp ipv4 mup all detail-routes",
        "MUP:65001:10",
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def _check_no_mup_routes(router):
    "Return None when both MUP RIBs are empty, else an error string."
    for afi in ("ipv4", "ipv6"):
        if _mup_json_routes(router, afi):
            return "{} still has {} mup routes".format(router.name, afi)
    return None


def test_mup_routes_withdrawn_on_peer_down():
    """Stopping ExaBGP must withdraw everything: r2 purges the routes on
    session down and sends MP_UNREACH to r1, which exercises the
    withdraw side of the codec on the wire.  Must run last."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Stopping peer1 and verifying MUP routes are withdrawn")
    peer = tgen.gears["peer1"]
    peer.stop()
    peer.run("pkill -f exabgp")

    for rname in ("r2", "r1"):
        test_func = functools.partial(_check_no_mup_routes, tgen.gears[rname])
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
