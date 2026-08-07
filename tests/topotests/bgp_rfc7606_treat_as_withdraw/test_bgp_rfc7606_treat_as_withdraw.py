#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>

"""
RFC 7606 conformance: malformed attributes that must be treated as withdraw.

Three ExaBGP peers -- eBGP, iBGP and eBGP-OAD -- sit on one segment with r1
and announce the same set of deliberately malformed attributes, each peer into
its own /8 so a failure names the peer as well as the attribute. For every
case r1 must silently drop the NLRI (treat-as-withdraw) and keep the session
up.

The case table lives in cases.py and the case model in ../lib/bgp_rfc7606.py.
Both are copied into each peer directory at setup time, because
TopoExaBGP.start() populates /etc/exabgp from the peer directory alone; that
also guarantees the announced case and the asserted case are the same object
graph rather than two hand-kept copies.

Each peer announces a well-formed sentinel prefix last. Its arrival proves
every malformed announcement ahead of it has already been parsed, so the
absence assertions need no sleep.
"""

import functools
import json
import os
import shutil
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
# ../lib holds the shared case model, which exa-send.py also imports by bare
# name from inside /etc/exabgp.
sys.path.append(os.path.join(CWD, "../lib"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

from bgp_rfc7606 import (
    ALL_SORTS,
    IBGP,
    PEER_ADDR,
    PEER_NAME,
    WITHDRAW,
    cases_for,
    sentinel_prefix,
)

# Import cases.py package-qualified, NOT as a bare `from cases import ...`.
# All three bgp_rfc7606_* directories ship a top-level cases.py; when pytest
# collects them in one process -- which is how FRR CI runs topotests -- the
# first bare import wins in sys.modules and the other directories silently
# get the wrong case table.
from bgp_rfc7606_treat_as_withdraw.cases import CASES

pytestmark = [pytest.mark.bgpd]

# (peer sort, case name) pairs where FRR knowingly departs from the clause the
# case cites. Each entry is a bgpd bug to be fixed on its own, not a licence to
# weaken the expectation in cases.py, so the marks are strict: fixing bgpd
# turns the xpass into a failure here and the entry must then be removed.
KNOWN_DEVIATIONS = {
    (IBGP, "aspath-as-zero"): (
        "FRR applies the RFC 7607 AS 0 check only to eBGP peers -- see the "
        "`peer->sort == BGP_PEER_EBGP &&` guard on aspath_check_as_zero() in "
        "bgp_attr_aspath_check(), bgpd/bgp_attr.c. RFC 7607 section 2 draws no "
        "distinction between internal and external peers: an UPDATE carrying "
        "AS 0 in AS_PATH is malformed however it arrives."
    ),
}

# Copied into every peerN/ directory so ExaBGP can import them, removed again
# by teardown_module().
SHARED_FILES = (
    os.path.join(CWD, "cases.py"),
    os.path.join(CWD, "../lib/bgp_rfc7606.py"),
)


def _peer_dir(sort):
    return os.path.join(CWD, PEER_NAME[sort])


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)

    for sort in ALL_SORTS:
        peer = tgen.add_exabgp_peer(
            PEER_NAME[sort], ip=PEER_ADDR[sort], defaultRoute="via 10.0.0.1"
        )
        switch.add_link(peer)


def setup_module(mod):
    for sort in ALL_SORTS:
        for src in SHARED_FILES:
            shutil.copy(src, os.path.join(_peer_dir(sort), os.path.basename(src)))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
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


def _established(r1, sort):
    """None once the session with `sort` is Established."""
    output = json.loads(
        r1.vtysh_cmd("show bgp neighbors {} json".format(PEER_ADDR[sort]))
    )
    return topotest.json_cmp(
        output, {PEER_ADDR[sort]: {"bgpState": "Established"}}
    )


@pytest.fixture(scope="module")
def converged():
    """All three sessions up and all three sentinels received."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    for sort in ALL_SORTS:
        test_func = functools.partial(_established, r1, sort)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "session with {} peer {} not established".format(
            sort, PEER_ADDR[sort]
        )

    def _sentinels():
        routes = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json")).get(
            "routes", {}
        )
        missing = [s for s in ALL_SORTS if sentinel_prefix(s) not in routes]
        return missing if missing else None

    test_func = functools.partial(_sentinels)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, (
        "sentinel prefix never arrived from peer sorts {}; the announcing "
        "ExaBGP process probably died, see exabgp.log".format(result)
    )

    return r1


def _params():
    """Every (sort, case) pair expected to be treated as withdraw."""
    params = []
    for sort in ALL_SORTS:
        for case in cases_for(CASES, sort, WITHDRAW):
            reason = KNOWN_DEVIATIONS.get((sort, case.name))
            marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
            params.append(
                pytest.param(
                    sort, case, id="{}-{}".format(sort, case.name), marks=marks
                )
            )
    return params


@pytest.mark.parametrize("sort,case", _params())
def test_treat_as_withdraw(converged, sort, case):
    """The malformed NLRI must not be in the BGP table."""
    r1 = converged
    prefix = case.prefix(sort)

    routes = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json")).get("routes", {})

    assert prefix not in routes, (
        "case {}: prefix {} from the {} peer ({}) is in the BGP table, but "
        "{} requires treat-as-withdraw".format(
            case.name, prefix, sort, PEER_ADDR[sort], case.spec or "RFC 7606"
        )
    )


def test_sessions_still_established(converged):
    """Treat-as-withdraw must not cost us the session."""
    r1 = converged

    for sort in ALL_SORTS:
        result = _established(r1, sort)
        assert result is None, (
            "session with the {} peer ({}) is no longer Established after the "
            "malformed announcements; treat-as-withdraw must not reset the "
            "session. Detail: {}".format(sort, PEER_ADDR[sort], result)
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
