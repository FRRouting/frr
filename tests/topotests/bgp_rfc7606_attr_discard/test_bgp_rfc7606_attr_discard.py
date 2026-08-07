#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""
RFC 7606 conformance: malformed attributes that must be discarded.

"Attribute discard" is the weakest of the three RFC 7606 error-handling
approaches: the UPDATE is accepted, the NLRI installed, and only the offending
attribute thrown away. Testing it therefore has two halves -- the route must
show up, and the attribute must not -- and the second half is only really
proven downstream, so this topology carries an extra FRR router r2 behind r1:

    peer1 (eBGP 65001)  \\
    peer2 (iBGP 65000)  --- s1 --- r1 --- s2 --- r2 (iBGP 65000)
    peer3 (eBGP-OAD 65002) /

r1 is a route reflector for r2 so that the iBGP peer's routes are re-advertised
as well, and uses next-hop-self so the eBGP-learned ones stay resolvable.

The case table lives in cases.py and the case model in ../lib/bgp_rfc7606.py;
both are copied into each peer directory at setup time, exactly as in
bgp_rfc7606_treat_as_withdraw/.
"""

import functools
import json
import os
import re
import shutil
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
# ../lib holds the shared case model, imported by its bare name because
# exa-send.py imports it the same way from inside /etc/exabgp.
sys.path.append(os.path.join(CWD, "../lib"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

from bgp_rfc7606 import (
    ALL_SORTS,
    DISCARD,
    PEER_ADDR,
    PEER_NAME,
    cases_for,
    sentinel_prefix,
)

# cases.py is imported through this directory's package rather than by its
# bare name. Every RFC 7606 directory ships a cases.py, and a bare
# `from cases import ...` off a sys.path entry would hand whichever module got
# imported first to all of them when pytest collects the directories together.
from bgp_rfc7606_attr_discard.cases import CASES, MUST_NOT_REACH_R2, MUST_REACH_R2

pytestmark = [pytest.mark.bgpd]

# (peer sort, case name) pairs where FRR knowingly departs from the clause the
# case cites. Strict, so fixing bgpd turns the xpass into a failure here.
KNOWN_DEVIATIONS = {}

SHARED_FILES = (
    os.path.join(CWD, "cases.py"),
    os.path.join(CWD, "../lib/bgp_rfc7606.py"),
)

# bgp_attr_unknown() in bgpd/bgp_attr.c, under `debug bgp updates in`.
UNKNOWN_ATTR_LOG = re.compile(
    r"Unknown attribute is received \(type (\d+), length (\d+)\)"
)


def _peer_dir(sort):
    return os.path.join(CWD, PEER_NAME[sort])


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    # r1's links are added first and in this order, so r1-eth0 faces the
    # ExaBGP peers and r1-eth1 faces r2, matching r1/frr.conf.
    s1 = tgen.add_switch("s1")
    s1.add_link(r1)

    s2 = tgen.add_switch("s2")
    s2.add_link(r1)
    s2.add_link(r2)

    for sort in ALL_SORTS:
        peer = tgen.add_exabgp_peer(
            PEER_NAME[sort], ip=PEER_ADDR[sort], defaultRoute="via 10.0.0.1"
        )
        s1.add_link(peer)


def setup_module(mod):
    for sort in ALL_SORTS:
        for src in SHARED_FILES:
            shutil.copy(src, os.path.join(_peer_dir(sort), os.path.basename(src)))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name in ("r1", "r2"):
        router = tgen.gears[name]
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(name)))
        router.start()

    for sort in ALL_SORTS:
        tgen.gears[PEER_NAME[sort]].start(
            _peer_dir(sort), os.path.join(CWD, "exabgp.env")
        )


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

    for sort in ALL_SORTS:
        for src in SHARED_FILES:
            copy = os.path.join(_peer_dir(sort), os.path.basename(src))
            if os.path.exists(copy):
                os.remove(copy)
        shutil.rmtree(os.path.join(_peer_dir(sort), "__pycache__"), ignore_errors=True)


def _established(router, addr):
    """None once the session with `addr` is Established."""
    output = json.loads(router.vtysh_cmd("show bgp neighbors {} json".format(addr)))
    return topotest.json_cmp(output, {addr: {"bgpState": "Established"}})


def _missing_sentinels(router):
    routes = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json")).get(
        "routes", {}
    )
    missing = [s for s in ALL_SORTS if sentinel_prefix(s) not in routes]
    return missing if missing else None


@pytest.fixture(scope="module")
def converged():
    """Every session up, and every sentinel reached both r1 and r2.

    The sentinel is announced after all the malformed routes, so its arrival on
    r1 proves r1 has parsed them, and its arrival on r2 proves r1 has finished
    re-advertising whatever survived. Both are needed before any absence
    assertion means anything.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    sessions = [(r1, PEER_ADDR[sort]) for sort in ALL_SORTS]
    sessions.append((r1, "10.1.0.2"))
    sessions.append((r2, "10.1.0.1"))

    for router, addr in sessions:
        test_func = functools.partial(_established, router, addr)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "session {} <-> {} not established".format(
            router.name, addr
        )

    for router in (r1, r2):
        test_func = functools.partial(_missing_sentinels, router)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, (
            "sentinel prefix never reached {} from peer sorts {}; the "
            "announcing ExaBGP process probably died, see exabgp.log".format(
                router.name, result
            )
        )

    return tgen


def _paths(router, prefix):
    """The path list `show bgp ipv4 unicast <prefix> json` reports."""
    output = json.loads(
        router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
    )
    return output.get("paths", [])


def _params():
    """Every (sort, case) pair expected to be an attribute discard."""
    params = []
    for sort in ALL_SORTS:
        for case in cases_for(CASES, sort, DISCARD):
            reason = KNOWN_DEVIATIONS.get((sort, case.name))
            marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
            params.append(
                pytest.param(
                    sort, case, id="{}-{}".format(sort, case.name), marks=marks
                )
            )
    return params


@pytest.mark.parametrize("sort,case", _params())
def test_route_accepted_on_r1(converged, sort, case):
    """Attribute discard keeps the NLRI: it must be in r1's BGP table."""
    r1 = converged.gears["r1"]
    prefix = case.prefix(sort)

    paths = _paths(r1, prefix)

    assert paths, (
        "case {}: prefix {} from the {} peer ({}) is absent from r1's BGP "
        "table, but {} requires the attribute to be discarded and the route "
        "accepted".format(
            case.name, prefix, sort, PEER_ADDR[sort], case.spec or "RFC 7606"
        )
    )


@pytest.mark.parametrize("sort,case", _params())
def test_attribute_dropped_on_r1(converged, sort, case):
    """The discarded attribute must not appear on the accepted path."""
    if case.json_key is None:
        pytest.skip(
            "attribute {} has no `show bgp ... json` surface; non-propagation "
            "is covered by the r2 log check where applicable".format(case.attr_type)
        )

    r1 = converged.gears["r1"]
    prefix = case.prefix(sort)

    paths = _paths(r1, prefix)
    assert paths, "case {}: prefix {} not on r1 at all".format(case.name, prefix)

    offenders = [p for p in paths if case.json_key in p]
    assert not offenders, (
        "case {}: r1 kept `{}` on prefix {} from the {} peer ({}), but {} "
        "requires attribute discard. Path: {}".format(
            case.name,
            case.json_key,
            prefix,
            sort,
            PEER_ADDR[sort],
            case.spec or "RFC 7606",
            json.dumps(offenders[0]),
        )
    )


@pytest.mark.parametrize("sort,case", _params())
def test_attribute_not_propagated_to_r2(converged, sort, case):
    """A discarded attribute must not be re-advertised downstream."""
    if case.json_key is None:
        pytest.skip(
            "attribute {} has no `show bgp ... json` surface".format(case.attr_type)
        )

    r2 = converged.gears["r2"]
    prefix = case.prefix(sort)

    paths = _paths(r2, prefix)
    assert paths, (
        "case {}: prefix {} never reached r2, so the non-propagation check "
        "would pass vacuously. r1 must re-advertise the accepted route.".format(
            case.name, prefix
        )
    )

    offenders = [p for p in paths if case.json_key in p]
    assert not offenders, (
        "case {}: r1 propagated `{}` on prefix {} to r2, but {} requires the "
        "attribute to be discarded and not passed along. Path: {}".format(
            case.name,
            case.json_key,
            prefix,
            case.spec or "RFC 7606",
            json.dumps(offenders[0]),
        )
    )


def _unknown_attr_types_seen_by_r2(tgen):
    """Attribute type codes r2 logged as unknown, from bgp_attr_unknown()."""
    path = os.path.join(tgen.logdir, "r2", "bgpd.log")
    with open(path) as logfile:
        body = logfile.read()
    assert body.strip(), (
        "r2's bgpd.log at {} is empty; the log-based unknown-attribute check "
        "cannot be trusted".format(path)
    )
    return set(int(m.group(1)) for m in UNKNOWN_ATTR_LOG.finditer(body))


def test_unknown_attribute_propagation_to_r2(converged):
    """Unknown non-transitive optional attributes must not be passed along.

    `show bgp` exposes nothing at all about unknown attributes -- there is no
    JSON key and no text line; bgp_attr_unknown() stores them in the opaque
    `struct transit` blob which is only ever re-emitted on the wire. The one
    observable is the "Unknown attribute is received" debug r2 emits under
    `debug bgp updates in`, so that is what this asserts, with the transitive
    case as a positive control: if r2 never logged the attribute it *must*
    receive, the negative result below would be meaningless.
    """
    tgen = converged
    seen = _unknown_attr_types_seen_by_r2(tgen)

    by_name = {c.name: c for c in CASES}

    expected = set(by_name[name].attr_type for name in MUST_REACH_R2)
    assert expected <= seen, (
        "positive control failed: r2 never logged unknown attribute type(s) "
        "{}, which RFC 4271 section 5 says an optional transitive attribute "
        "MUST be passed along as. Types r2 did log: {}. Without this the "
        "non-propagation assertion below proves nothing.".format(
            sorted(expected - seen), sorted(seen)
        )
    )

    forbidden = set(by_name[name].attr_type for name in MUST_NOT_REACH_R2)
    leaked = forbidden & seen
    assert not leaked, (
        "r1 passed unknown non-transitive optional attribute type(s) {} on to "
        "r2; RFC 4271 section 5 and RFC 7606 section 5.2 require them to be "
        "quietly ignored and not passed along.".format(sorted(leaked))
    )


def test_sessions_still_established(converged):
    """Attribute discard must not cost us a session."""
    tgen = converged
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    for router, addr in [(r1, PEER_ADDR[s]) for s in ALL_SORTS] + [
        (r1, "10.1.0.2"),
        (r2, "10.1.0.1"),
    ]:
        result = _established(router, addr)
        assert result is None, (
            "session {} <-> {} is no longer Established after the malformed "
            "announcements; attribute discard must not reset the session. "
            "Detail: {}".format(router.name, addr, result)
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
