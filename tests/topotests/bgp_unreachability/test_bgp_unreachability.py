#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Nvidia Corporation
# Karthikeya Venkat Muppalla <kmuppalla@nvidia.com>
#

"""
test_bgp_unreachability.py: baseline coverage for BGP Unreachability Information SAFI.

Topology:

                link A (s1)               link A (s2)
        +------+ --------- +------+ --------- +------+
        |  r1  |           |  r2  |           |  r3  |
        |65001 |           |65002 |           |65003 |
        +------+ --------- +------+ --------- +------+
                link B (s3)               link B (s4)

The r1-r2 and r2-r3 pairs each carry two parallel eBGP sessions activating
ipv4 unicast, ipv6 unicast, ipv4 unreachability, and ipv6 unreachability;
the receiving side sees every SAFI_UNREACH NLRI via two paths and exercises
SAFI_UNREACH best-path selection (max-paths=1).

Addressing:
    r1 <-> r2 link A (s1): 192.168.12.0/24 / 2001:db8:12::/64
    r1 <-> r2 link B (s3): 192.168.13.0/24 / 2001:db8:13::/64
    r2 <-> r3 link A (s2): 192.168.23.0/24 / 2001:db8:23::/64
    r2 <-> r3 link B (s4): 192.168.24.0/24 / 2001:db8:24::/64

r1 also originates a couple of host unicast prefixes so the unicast
non-regression check has baseline prefixes flowing alongside SAFI_UNREACH
activity.
"""

import functools
import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


INJECT_V4 = "10.99.0.1/32"
INJECT_V6 = "2001:db8:99::1/128"

UNICAST_V4 = "10.10.10.1/32"
UNICAST_V6 = "2001:db8:100::1/128"


def build_topo(tgen):
    """r1 == r2 == r3 with two parallel links per pair.

    Switch / interface mapping (ordering chosen so r{n}-ethX indices match
    what zebra.conf expects):
        s1 -> r1-eth0, r2-eth0   (link A r1-r2)
        s3 -> r1-eth1, r2-eth1   (link B r1-r2)
        s2 -> r2-eth2, r3-eth0   (link A r2-r3)
        s4 -> r2-eth3, r3-eth1   (link B r2-r3)
    """
    for routern in range(1, 4):
        tgen.add_router(f"r{routern}")

    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["r2"])

    s3 = tgen.add_switch("s3")
    s3.add_link(tgen.gears["r1"])
    s3.add_link(tgen.gears["r2"])

    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r2"])
    s2.add_link(tgen.gears["r3"])

    s4 = tgen.add_switch("s4")
    s4.add_link(tgen.gears["r2"])
    s4.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, f"{rname}/zebra.conf")
        )
        router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, f"{rname}/bgpd.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _established(router, neighbor):
    """Return None when `neighbor` is in Established state on `router`.

    BGP keeps each peer under its own address-family bucket in `show bgp
    summary json`: IPv4 peers under `ipv4Unicast.peers`, IPv6 peers under
    `ipv6Unicast.peers`. Pick the right bucket based on whether the neighbor
    address contains a `:`.
    """
    output = json.loads(router.vtysh_cmd("show bgp summary json"))
    af = "ipv6Unicast" if ":" in neighbor else "ipv4Unicast"
    expected = {af: {"peers": {neighbor: {"state": "Established"}}}}
    return topotest.json_cmp(output, expected)


def _inject_unreach(router, afi, prefix, reason_code=None):
    """Inject a single SAFI_UNREACH prefix via the hidden inject CLI."""
    cmd = f"bgp inject unreachability {afi} {prefix}"
    if reason_code is not None:
        cmd += f" reason-code {reason_code}"
    router.vtysh_cmd(cmd)


def _withdraw_unreach(router, afi, prefix):
    router.vtysh_cmd(f"no bgp inject unreachability {afi} {prefix}")


def _paths_for_prefix(out, prefix):
    """Extract the paths array for `prefix` from a `show bgp <afi> unreachability
    json` output. The per-prefix summary shape is:

        {
          "<prefix>": {
            "prefix": "<prefix>",
            "paths": [{...}, {...}],
            "pathCount": N,
            ...
          },
          ...,
          "numPrefixes": K
        }
    """
    route = out.get(prefix)
    if not isinstance(route, dict):
        return []
    paths = route.get("paths")
    return paths if isinstance(paths, list) else []


def _reporter_match(path, reporter_id, reporter_as=None, reason_substr=None):
    """True iff a path's reporters object contains `reporter_id`, optionally
    with the given AS and reason substring.

    SAFI_UNREACH JSON schema:
        "reporters": {
            "<reporter_ip>": {
                "AS": <reporter_as>,
                "subtlv": {
                    "reason": "<reason_str>",
                    "timestamp": {...}    # detail JSON only
                }
            }
        }
    """
    reporters = path.get("reporters")
    if not isinstance(reporters, dict):
        return False
    entry = reporters.get(reporter_id)
    if not isinstance(entry, dict):
        return False
    if reporter_as is not None and entry.get("AS") != reporter_as:
        return False
    if reason_substr is not None:
        sub = entry.get("subtlv") or {}
        if reason_substr.lower() not in (sub.get("reason") or "").lower():
            return False
    return True


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------


def test_bgp_convergence():
    """All six eBGP sessions reach Established for both AFIs."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    sessions = [
        # r1 <-> r2 link A
        (r1, "192.168.12.2"),
        (r1, "2001:db8:12::2"),
        (r2, "192.168.12.1"),
        (r2, "2001:db8:12::1"),
        # r1 <-> r2 link B
        (r1, "192.168.13.2"),
        (r1, "2001:db8:13::2"),
        (r2, "192.168.13.1"),
        (r2, "2001:db8:13::1"),
        # r2 <-> r3 link A
        (r2, "192.168.23.3"),
        (r2, "2001:db8:23::3"),
        (r3, "192.168.23.2"),
        (r3, "2001:db8:23::2"),
        # r2 <-> r3 link B
        (r2, "192.168.24.3"),
        (r2, "2001:db8:24::3"),
        (r3, "192.168.24.2"),
        (r3, "2001:db8:24::2"),
    ]

    for router, neighbor in sessions:
        step(f"{router.name}: peer {neighbor} Established")
        test_func = functools.partial(_established, router, neighbor)
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assert result is None, f"{router.name} did not converge with {neighbor}"


def test_capability_negotiated():
    """SAFI_UNREACH multiprotocol capability is advertised and received on
    every session of every router. v4 sessions carry ipv4Unreachability;
    v6 sessions carry ipv6Unreachability."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_peer(router, peer_addr, cap_key):
        output = json.loads(router.vtysh_cmd(f"show bgp neighbors {peer_addr} json"))
        peer = output.get(peer_addr, {})
        mp = peer.get("neighborCapabilities", {}).get("multiprotocolExtensions", {})
        if not mp:
            return f"{router.name} peer {peer_addr}: multiprotocolExtensions missing"
        v = mp.get(cap_key, {})
        both = v.get("advertisedAndReceived") or (
            v.get("advertised") and v.get("received")
        )
        if not both:
            return f"{router.name} peer {peer_addr}: {cap_key} not negotiated both ways: {v}"
        return None

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    cases = [
        # r1's view of its 4 sessions to r2 (two parallel links, v4+v6 each).
        (r1, "192.168.12.2", "ipv4Unreachability"),
        (r1, "2001:db8:12::2", "ipv6Unreachability"),
        (r1, "192.168.13.2", "ipv4Unreachability"),
        (r1, "2001:db8:13::2", "ipv6Unreachability"),
        # r2's view of its 4 sessions to r1 + 4 sessions to r3.
        (r2, "192.168.12.1", "ipv4Unreachability"),
        (r2, "2001:db8:12::1", "ipv6Unreachability"),
        (r2, "192.168.13.1", "ipv4Unreachability"),
        (r2, "2001:db8:13::1", "ipv6Unreachability"),
        (r2, "192.168.23.3", "ipv4Unreachability"),
        (r2, "2001:db8:23::3", "ipv6Unreachability"),
        (r2, "192.168.24.3", "ipv4Unreachability"),
        (r2, "2001:db8:24::3", "ipv6Unreachability"),
        # r3's view of its 4 sessions to r2.
        (r3, "192.168.23.2", "ipv4Unreachability"),
        (r3, "2001:db8:23::2", "ipv6Unreachability"),
        (r3, "192.168.24.2", "ipv4Unreachability"),
        (r3, "2001:db8:24::2", "ipv6Unreachability"),
    ]

    for router, peer_addr, cap_key in cases:
        step(f"{router.name}: {cap_key} negotiated with {peer_addr}")
        test_func = functools.partial(_check_peer, router, peer_addr, cap_key)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


def test_show_summary_json():
    """show bgp ipv4|ipv6 unreachability summary json shows per-peer Established
    row for every peer whose remote end also activated the AF."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("r1", "r2", "r3"):
        router = tgen.gears[rname]
        for afi in ("ipv4", "ipv6"):
            step(f"{rname}: show bgp {afi} unreachability summary json")
            output = json.loads(
                router.vtysh_cmd(f"show bgp {afi} unreachability summary json")
            )
            peers = output.get("peers") or {}
            assert peers, (
                f"{rname}: show bgp {afi} unreachability summary json has no "
                f"'peers' object: {output}"
            )
            for peer, info in peers.items():
                assert info.get("state") == "Established", (
                    f"{rname}: peer {peer} not Established in {afi} unreachability "
                    f"summary: {info}"
                )


def test_inject_and_receive_ipv4():
    """r1 injects an IPv4 unreach prefix; r1 sees it self-originated, r2 sees
    it received via BOTH parallel sessions (two paths arriving from r1)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step(f"r1: inject {INJECT_V4}")
    _inject_unreach(r1, "ipv4", INJECT_V4)

    def _check_r1():
        out = json.loads(r1.vtysh_cmd("show bgp ipv4 unreachability json"))
        paths = _paths_for_prefix(out, INJECT_V4)
        if not paths:
            return f"r1: {INJECT_V4} not present (keys={list(out)[:5]})"
        for p in paths:
            if _reporter_match(p, "1.1.1.1", reporter_as=65001):
                return None
        return f"r1: no path with reporter=1.1.1.1 AS=65001 ({paths})"

    def _check_r2():
        out = json.loads(r2.vtysh_cmd("show bgp ipv4 unreachability json"))
        paths = _paths_for_prefix(out, INJECT_V4)
        if not paths:
            return f"r2: {INJECT_V4} not present (keys={list(out)[:5]})"
        # Two parallel sessions -> r2 must see two paths from r1, proving the
        # capability is negotiated on both sessions and NLRI is being decoded
        # on the receive side.
        matching = [
            p for p in paths if _reporter_match(p, "1.1.1.1", reporter_as=65001)
        ]
        if len(matching) < 2:
            return (
                f"r2: expected >=2 paths from r1 (one per parallel session), "
                f"got {len(matching)}: {paths}"
            )
        return None

    step(f"r1: {INJECT_V4} present with correct reporter/AS")
    test_func = functools.partial(_check_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step(f"r2: {INJECT_V4} received via both parallel sessions")
    test_func = functools.partial(_check_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_inject_and_receive_ipv6():
    """r1 injects an IPv6 unreach prefix; r1 sees it self-originated, r2 sees
    it received via BOTH parallel sessions (two paths arriving from r1)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step(f"r1: inject {INJECT_V6}")
    _inject_unreach(r1, "ipv6", INJECT_V6)

    def _check_r1():
        out = json.loads(r1.vtysh_cmd("show bgp ipv6 unreachability json"))
        paths = _paths_for_prefix(out, INJECT_V6)
        if not paths:
            return f"r1: {INJECT_V6} not present (keys={list(out)[:5]})"
        for p in paths:
            if _reporter_match(p, "1.1.1.1", reporter_as=65001):
                return None
        return f"r1: no path with reporter=1.1.1.1 AS=65001 ({paths})"

    def _check_r2():
        out = json.loads(r2.vtysh_cmd("show bgp ipv6 unreachability json"))
        paths = _paths_for_prefix(out, INJECT_V6)
        if not paths:
            return f"r2: {INJECT_V6} not present (keys={list(out)[:5]})"
        matching = [
            p for p in paths if _reporter_match(p, "1.1.1.1", reporter_as=65001)
        ]
        if len(matching) < 2:
            return (
                f"r2: expected >=2 paths from r1 (one per parallel session), "
                f"got {len(matching)}: {paths}"
            )
        return None

    step(f"r1: {INJECT_V6} present with correct reporter/AS")
    test_func = functools.partial(_check_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step(f"r2: {INJECT_V6} received via both parallel sessions")
    test_func = functools.partial(_check_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_propagation_two_hops():
    """r1-injected prefix appears on r3 with AS-path '65002 65001' arriving over
    BOTH parallel r2-r3 sessions. Exercises r2's update-group encode path on a
    SAFI_UNREACH NLRI and confirms the reporter TLV survives r2's
    re-advertisement to a different eBGP peer."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]

    _inject_unreach(r1, "ipv6", INJECT_V6)

    def _check_v6():
        out = json.loads(r3.vtysh_cmd("show bgp ipv6 unreachability json"))
        paths = _paths_for_prefix(out, INJECT_V6)
        matching = []
        for p in paths:
            if not _reporter_match(p, "1.1.1.1", reporter_as=65001):
                continue
            aspath = p.get("path", "")
            if "65002" in aspath and "65001" in aspath:
                matching.append(p)
        if len(matching) < 2:
            return (
                f"r3: expected >=2 paths via parallel r2-r3 sessions, "
                f"got {len(matching)}: {paths}"
            )
        return None

    step("r3: propagation path with AS-path 65002 65001 over both r2-r3 sessions")
    test_func = functools.partial(_check_v6)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_show_detail_one_prefix():
    """show bgp ipv6 unreachability <PREFIX> json (auto-detail) on r3."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]
    _inject_unreach(r1, "ipv6", INJECT_V6)

    def _check():
        out = json.loads(r3.vtysh_cmd(f"show bgp ipv6 unreachability {INJECT_V6} json"))
        paths = out.get("paths") or []
        if not paths:
            return f"no 'paths' in detail json: {out}"
        # Per-prefix detail JSON must carry the SAFI_UNREACH reporter fields
        # along with a valid eBGP path.
        for p in paths:
            if not _reporter_match(p, "1.1.1.1", reporter_as=65001):
                continue
            if not p.get("valid"):
                continue
            if p.get("pathFrom") != "external":
                continue
            aspath = p.get("aspath") or {}
            if "65002" in aspath.get("string", "") and "65001" in aspath.get(
                "string", ""
            ):
                return None
        return (
            f"r3: no detail-path matched reporter=1.1.1.1 AS=65001 / valid / "
            f"pathFrom=external / aspath 65002 65001: paths={paths}"
        )

    step("r3: auto-detail single-prefix JSON has reporters object and aspath")
    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_show_detail_all_prefixes():
    """show bgp ipv6 unreachability detail json - all-prefixes detail form.

    Schema is a top-level dict keyed by prefix mapping to a list of path
    objects, each carrying the SAFI_UNREACH-specific reporter / reporterAs
    fields."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]
    _inject_unreach(r1, "ipv6", INJECT_V6)

    def _check():
        out = json.loads(r3.vtysh_cmd("show bgp ipv6 unreachability detail json"))
        paths = out.get(INJECT_V6)
        if not isinstance(paths, list) or not paths:
            return (
                f"r3: 'show bgp ipv6 unreachability detail json' missing "
                f"{INJECT_V6}: keys={list(out)[:8]}"
            )
        if not any(
            _reporter_match(p, "1.1.1.1", reporter_as=65001) for p in paths
        ):
            return f"r3: detail JSON missing reporter=1.1.1.1 / AS=65001: {paths}"
        return None

    step("r3: all-prefixes detail JSON contains injected prefix with reporter info")
    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_reason_codes():
    """Inject with named, numeric-valid, and private-use reason codes; the reserved
    range 10..64535 must be rejected at the CLI."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]

    cases = [
        # (afi, prefix, reason-code arg, expected JSON 'reason' substring)
        ("ipv4", "10.99.1.1/32", "policy-blocked", "Policy"),  # named
        ("ipv4", "10.99.1.2/32", "2", "Security"),  # numeric, code 2 = security-filtered
        (
            "ipv4",
            "10.99.1.3/32",
            "64536",
            None,
        ),  # private-use, no friendly name expected
    ]

    for afi, prefix, code, expected_substr in cases:
        step(f"r1: inject {prefix} reason-code {code}")
        _inject_unreach(r1, afi, prefix, reason_code=code)

        def _check(prefix=prefix, expected_substr=expected_substr):
            out = json.loads(r3.vtysh_cmd("show bgp ipv4 unreachability json"))
            paths = _paths_for_prefix(out, prefix)
            if not paths:
                return f"r3: {prefix} not present"
            if expected_substr is None:
                return None  # presence is enough for private-use code
            for p in paths:
                if _reporter_match(p, "1.1.1.1", reason_substr=expected_substr):
                    return None
            return (
                f"r3: {prefix} no path with reason containing "
                f"'{expected_substr}': {paths}"
            )

        test_func = functools.partial(_check)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result

    step("r1: reserved range 10..64535 is rejected at CLI")
    bad = r1.vtysh_cmd("bgp inject unreachability ipv4 10.99.1.99/32 reason-code 100")
    # The CLI either prints an error string or refuses to apply; either way the
    # prefix MUST NOT appear in the UI-RIB.
    out = json.loads(r1.vtysh_cmd("show bgp ipv4 unreachability json"))
    assert "10.99.1.99/32" not in out, (
        f"r1: reserved reason-code 100 should have been rejected but prefix appeared: "
        f"output={out}, cli output={bad!r}"
    )


def test_multiple_prefixes():
    """5 IPv4 + 5 IPv6 prefixes injected on r1 all reach r3."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    v4_prefixes = [f"10.99.2.{i}/32" for i in range(1, 6)]
    v6_prefixes = [f"2001:db8:200::{i}/128" for i in range(1, 6)]

    step(f"r1: inject {len(v4_prefixes)} IPv4 + {len(v6_prefixes)} IPv6 prefixes")
    for p in v4_prefixes:
        _inject_unreach(r1, "ipv4", p)
    for p in v6_prefixes:
        _inject_unreach(r1, "ipv6", p)

    def _check():
        v4 = json.loads(r3.vtysh_cmd("show bgp ipv4 unreachability json"))
        v6 = json.loads(r3.vtysh_cmd("show bgp ipv6 unreachability json"))
        missing = [p for p in v4_prefixes if p not in v4]
        missing += [p for p in v6_prefixes if p not in v6]
        return None if not missing else f"r3 missing prefixes: {missing}"

    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    if result is not None:
        # Dump RIB state and BGP summary on all routers to localize where the
        # missing prefixes are lost in the pipeline.
        for rtr in (r1, r2, r3):
            for afi in ("ipv4", "ipv6"):
                out = rtr.vtysh_cmd(f"show bgp {afi} unreachability json")
                logger.error(
                    "DEBUG %s 'show bgp %s unreachability json':\n%s",
                    rtr.name, afi, out,
                )
        for rtr in (r1, r2, r3):
            out = rtr.vtysh_cmd("show bgp summary json")
            logger.error("DEBUG %s 'show bgp summary json':\n%s", rtr.name, out)
        for peer in ("192.168.12.1", "192.168.13.1", "2001:db8:12::1", "2001:db8:13::1"):
            out = r2.vtysh_cmd(f"show bgp neighbors {peer} graceful-restart json")
            logger.error(
                "DEBUG r2 'show bgp neighbors %s graceful-restart json':\n%s", peer, out,
            )
    assert result is None, result


def test_withdraw_prefix():
    """'no bgp inject unreachability ipv4 <PREFIX>' on r1 removes prefix from r2 and r3."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    step(f"r1: withdraw {INJECT_V4}")
    _withdraw_unreach(r1, "ipv4", INJECT_V4)

    def _check(router):
        out = json.loads(router.vtysh_cmd("show bgp ipv4 unreachability json"))
        if INJECT_V4 in out:
            return f"{router.name}: {INJECT_V4} still present after withdraw"
        return None

    for router in (r1, r2, r3):
        test_func = functools.partial(_check, router)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


def test_neighbor_adj_rib_views():
    """SAFI_UNREACH has no inbound soft-reconfiguration, so neighbor
    received-routes / filtered-routes views must be rejected with the
    documented warning. advertised-routes does not require soft-reconfig
    and is supported, returning the prefixes r2 is sending to r1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    needle = "Inbound soft reconfiguration is not supported for unreachability SAFI"

    for which in ("received-routes", "filtered-routes"):
        cmd = f"show bgp ipv4 unreachability neighbors 192.168.12.1 {which} json"
        step(f"r2: {cmd}")
        out_text = r2.vtysh_cmd(cmd)
        assert (
            needle in out_text
        ), f"r2: expected rejection text '{needle}' from `{cmd}`, got:\n{out_text}"

    # advertised-routes is supported for SAFI_UNREACH; it should return the
    # set of prefixes r2 is currently advertising to r1.
    cmd = "show bgp ipv4 unreachability neighbors 192.168.12.1 advertised-routes json"
    step(f"r2: {cmd}")
    out = json.loads(r2.vtysh_cmd(cmd))
    advertised = out.get("advertisedRoutes") or {}
    assert isinstance(advertised, dict) and advertised, (
        f"r2: 'advertised-routes' for SAFI_UNREACH returned empty/missing "
        f"advertisedRoutes: {out}"
    )


def test_no_fib_install():
    """Injected SAFI_UNREACH prefixes must NOT appear in the Linux FIB."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    step(f"r1: inject {INJECT_V4} for FIB-absence check")
    _inject_unreach(r1, "ipv4", INJECT_V4)

    def _present():
        out = json.loads(r3.vtysh_cmd("show bgp ipv4 unreachability json"))
        return None if INJECT_V4 in out else f"{INJECT_V4} not on r3 yet"

    test_func = functools.partial(_present)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    # Now confirm the kernel FIB does NOT have it.
    for router in (r2, r3):
        ip_route = router.run("ip route show")
        ip6_route = router.run("ip -6 route show")
        for needle in (INJECT_V4.split("/")[0], INJECT_V6.split("/")[0]):
            assert needle not in ip_route, (
                f"{router.name}: SAFI_UNREACH {needle} unexpectedly appeared in "
                f"IPv4 FIB:\n{ip_route}"
            )
            assert needle not in ip6_route, (
                f"{router.name}: SAFI_UNREACH {needle} unexpectedly appeared in "
                f"IPv6 FIB:\n{ip6_route}"
            )


def test_running_config_roundtrip():
    """show running-config has both unreachability address-family blocks on r1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    cfg = r1.vtysh_cmd("show running-config")

    assert re.search(r"address-family\s+ipv4\s+unreachability", cfg), (
        f"r1: 'address-family ipv4 unreachability' block missing from running-config:\n"
        f"{cfg}"
    )
    assert re.search(r"address-family\s+ipv6\s+unreachability", cfg), (
        f"r1: 'address-family ipv6 unreachability' block missing from running-config:\n"
        f"{cfg}"
    )
    # The neighbor activate lines must be inside.
    assert re.search(
        r"neighbor\s+192\.168\.12\.2\s+activate", cfg
    ), "r1: 'neighbor 192.168.12.2 activate' missing from running-config"


def test_show_neighbor_filter():
    """'show bgp ipv6 unreachability neighbors <peer> routes json' returns only
    paths learned from that peer. r3 has two parallel sessions to r2; selecting
    one peer address must restrict the listing to a single path per prefix."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]

    step(f"r1: inject {INJECT_V6} for neighbor-filter probe")
    _inject_unreach(r1, "ipv6", INJECT_V6)

    peer_a = "2001:db8:23::2"  # r2 side of link A
    peer_b = "2001:db8:24::2"  # r2 side of link B

    def _check(peer_addr):
        out = json.loads(
            r3.vtysh_cmd(
                f"show bgp ipv6 unreachability neighbors {peer_addr} routes json"
            )
        )
        paths = _paths_for_prefix(out, INJECT_V6)
        if not paths:
            return f"r3: {INJECT_V6} not present in filter for {peer_addr}: {out}"
        if len(paths) != 1:
            return (
                f"r3: neighbor-filter for {peer_addr} returned {len(paths)} "
                f"paths, expected 1: {paths}"
            )
        if not _reporter_match(paths[0], "1.1.1.1", reporter_as=65001):
            return (
                f"r3: neighbor-filter path missing reporter=1.1.1.1 AS=65001: "
                f"{paths[0]}"
            )
        return None

    for peer in (peer_a, peer_b):
        step(f"r3: neighbor-filter on {peer} returns exactly one path for {INJECT_V6}")
        test_func = functools.partial(_check, peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


def test_inject_per_vrf_default():
    """'bgp inject unreachability vrf default ...' targets the default BGP
    instance just like the bare form. Validates the optional [vrf NAME]
    grammar parses and resolves correctly."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    prefix = "10.99.5.1/32"

    step(f"r1: bgp inject unreachability vrf default ipv4 {prefix}")
    r1.vtysh_cmd(f"bgp inject unreachability vrf default ipv4 {prefix}")

    def _check_r1():
        out = json.loads(r1.vtysh_cmd("show bgp ipv4 unreachability json"))
        paths = _paths_for_prefix(out, prefix)
        if not paths:
            return f"r1: {prefix} not present after vrf-default inject: keys={list(out)[:5]}"
        for p in paths:
            if _reporter_match(p, "1.1.1.1", reporter_as=65001):
                return None
        return f"r1: no path with reporter=1.1.1.1 AS=65001 for {prefix}: {paths}"

    test_func = functools.partial(_check_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    def _check_r2():
        out = json.loads(r2.vtysh_cmd("show bgp ipv4 unreachability json"))
        paths = _paths_for_prefix(out, prefix)
        return None if paths else f"r2: {prefix} not propagated from r1"

    step(f"r2: vrf-default injected {prefix} propagates")
    test_func = functools.partial(_check_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    step(f"r1: no bgp inject unreachability vrf default ipv4 {prefix}")
    r1.vtysh_cmd(f"no bgp inject unreachability vrf default ipv4 {prefix}")

    def _withdrawn(router):
        out = json.loads(router.vtysh_cmd("show bgp ipv4 unreachability json"))
        return None if prefix not in out else f"{router.name}: {prefix} still present"

    for router in (r1, r2):
        test_func = functools.partial(_withdrawn, router)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


def test_unicast_unaffected():
    """IPv4 and IPv6 unicast paths on r3 are present, valid, FIB-installed, and
    unchanged after the SAFI_UNREACH activity of preceding tests."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    def _unicast_paths(out, prefix):
        # `show bgp <afi> unicast json` wraps prefixes under a 'routes' dict on
        # newer FRR. Fall back to a flat top-level on older FRR.
        routes = out.get("routes") if isinstance(out.get("routes"), dict) else out
        paths = routes.get(prefix)
        return paths if isinstance(paths, list) else []

    def _check_v4():
        out = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast json"))
        paths = _unicast_paths(out, UNICAST_V4)
        if not paths:
            return f"r3: {UNICAST_V4} missing from ipv4 unicast: keys={list(out)[:8]}"
        for p in paths:
            if p.get("valid") and "65002 65001" in (p.get("path", "")):
                return None
        return f"r3: no valid ipv4 unicast path with AS-path 65002 65001: {paths}"

    def _check_v6():
        out = json.loads(r3.vtysh_cmd("show bgp ipv6 unicast json"))
        paths = _unicast_paths(out, UNICAST_V6)
        if not paths:
            return f"r3: {UNICAST_V6} missing from ipv6 unicast: keys={list(out)[:8]}"
        for p in paths:
            if p.get("valid") and "65002 65001" in (p.get("path", "")):
                return None
        return f"r3: no valid ipv6 unicast path with AS-path 65002 65001: {paths}"

    step(f"r3: IPv4 unicast {UNICAST_V4} valid via 65002 65001")
    test_func = functools.partial(_check_v4)
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert result is None, result

    step(f"r3: IPv6 unicast {UNICAST_V6} valid via 65002 65001")
    test_func = functools.partial(_check_v6)
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert result is None, result

    step("r3: unicast routes are FIB-installed (Linux kernel)")
    ip_route = r3.run("ip route show")
    ip6_route = r3.run("ip -6 route show")
    assert (
        UNICAST_V4.split("/")[0] in ip_route
    ), f"r3: unicast {UNICAST_V4} not in IPv4 FIB:\n{ip_route}"
    assert (
        UNICAST_V6.split("/")[0] in ip6_route
    ), f"r3: unicast {UNICAST_V6} not in IPv6 FIB:\n{ip6_route}"


def test_gr_eor_with_f_bit_zero():
    """Bounce r1's sessions; r2 reports each Unreachability AF with EoR
    sent+received and F-bit cleared (no forwarding state preserved)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r1: clear bgp * (forces re-convergence on all sessions)")
    r1.vtysh_cmd("clear bgp *")

    def _check_peer(peer_addr, af_label):
        out = json.loads(
            r2.vtysh_cmd(f"show bgp neighbors {peer_addr} graceful-restart json")
        )
        peer = out.get(peer_addr) or {}
        gr = peer.get("gracefulRestartInfo") or {}
        row = gr.get(af_label) or {}
        if not row:
            return f"r2: peer {peer_addr} has no {af_label} GR row: keys={list(gr.keys())[:10]}"
        fbit = row.get("fBit")
        if fbit is None:
            fbit = row.get("f bit")
        if fbit is not False:
            return f"r2: peer {peer_addr} {af_label} fBit must be False, got {fbit!r}: {row}"
        eor = row.get("endOfRibStatus") or {}
        if not eor.get("endOfRibSend"):
            return f"r2: peer {peer_addr} {af_label} endOfRibSend not true: {row}"
        if not eor.get("endOfRibRecv"):
            return f"r2: peer {peer_addr} {af_label} endOfRibRecv not true: {row}"
        return None

    for peer_addr, af_label in (
        ("192.168.12.1", "ipv4Unreachability"),
        ("2001:db8:12::1", "ipv6Unreachability"),
    ):
        step(f"r2: peer {peer_addr} {af_label} EoR sent+received, F-bit false")
        test_func = functools.partial(_check_peer, peer_addr, af_label)
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assert result is None, result


def test_multi_prefix_withdraw():
    """Multiple SAFI_UNREACH prefixes withdrawn together must all be removed
    on the two-hop receiver.

    r1 injects several IPv6 unreach prefixes, they converge on r3, then all of
    them are withdrawn in a single vtysh session. BGP coalesces the resulting
    withdrawals into a batched MP_UNREACH UPDATE carrying multiple withdrawn
    NLRIs; the receive-side parser must walk every NLRI in that UPDATE (not
    just the first) so that all prefixes disappear from the UI-RIB."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    prefixes = [f"2001:db8:300::{i}/128" for i in range(1, 5)]

    step(f"r1: inject {len(prefixes)} IPv6 unreach prefixes")
    for p in prefixes:
        _inject_unreach(r1, "ipv6", p)

    def _all_present(router):
        out = json.loads(router.vtysh_cmd("show bgp ipv6 unreachability json"))
        missing = [p for p in prefixes if p not in out]
        return None if not missing else f"{router.name} missing: {missing}"

    step("r3: all injected prefixes present before withdraw")
    test_func = functools.partial(_all_present, r3)
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert result is None, result

    step("r1: withdraw all prefixes in a single vtysh session")
    r1.vtysh_cmd(
        "\n".join(f"no bgp inject unreachability ipv6 {p}" for p in prefixes)
    )

    def _all_withdrawn(router):
        out = json.loads(router.vtysh_cmd("show bgp ipv6 unreachability json"))
        remaining = [p for p in prefixes if p in out]
        return None if not remaining else f"{router.name} still has: {remaining}"

    for router in (r2, r3):
        step(f"{router.name}: every withdrawn prefix removed")
        test_func = functools.partial(_all_withdrawn, router)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


def _peer_object_ok(path):
    """A SAFI_UNREACH path's peer info must be a structured 'peer' object with
    routerId and either peerId or interface, and must not use the legacy flat
    'from' / 'peerHostname' keys."""
    if "from" in path or "peerHostname" in path:
        return f"legacy peer keys present: {sorted(path.keys())}"
    peer = path.get("peer")
    if not isinstance(peer, dict):
        return f"'peer' is not an object: {peer!r}"
    if "routerId" not in peer:
        return f"'peer' missing routerId: {peer}"
    if "peerId" not in peer and "interface" not in peer:
        return f"'peer' missing peerId/interface: {peer}"
    return None


def test_json_peer_info_unified():
    """The 'peer' object schema is identical across the summary, all-prefixes
    detail, and single-prefix SAFI_UNREACH JSON views."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1, r3 = tgen.gears["r1"], tgen.gears["r3"]
    prefix = "2001:db8:301::1/128"

    step(f"r1: inject {prefix} for peer-info schema check")
    _inject_unreach(r1, "ipv6", prefix)

    def _check():
        summary = json.loads(r3.vtysh_cmd("show bgp ipv6 unreachability json"))
        detail = json.loads(r3.vtysh_cmd("show bgp ipv6 unreachability detail json"))
        single = json.loads(
            r3.vtysh_cmd(f"show bgp ipv6 unreachability {prefix} json")
        )

        views = {
            "summary": _paths_for_prefix(summary, prefix),
            "detail": detail.get(prefix) if isinstance(detail.get(prefix), list) else [],
            "single": single.get("paths") or [],
        }
        for name, paths in views.items():
            if not paths:
                return f"r3: {name} view has no paths for {prefix} yet"
            for p in paths:
                err = _peer_object_ok(p)
                if err is not None:
                    return f"r3: {name} view path peer schema: {err}"
        return None

    step("r3: 'peer' object consistent across summary/detail/single-prefix views")
    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    _withdraw_unreach(r1, "ipv6", prefix)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
