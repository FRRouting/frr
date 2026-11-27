#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_babel_empty_neighbour.py
#
# Copyright (c) 2026 by
# Bing Shui <bingshui@smail.nju.edu.cn>
#

"""
test_babel_empty_neighbour.py: Babel neighbour creation must be lazy.

A Babel packet with a valid header and an empty body (body length 0)
carries no TLV that acts on a neighbour.  parse_packet() must not create
a neighbour entry for it: at baseline (c4e94c4aaa) find_neighbour() ran
before the TLV loop, so every distinct link-local source address created
an entry and triggered find_neighbour()'s send_hello(), whose marginal
IHU fanned out over the whole (attacker-inflated) neighbour table.

Topology (one broadcast domain):

    r1-eth0 (victim) -- sw1 -- r2-eth0 (legit peer)
    h1-eth0 (packet injector) -- sw1

Checks:
  * empty-body packets from many distinct sources: no neighbour entry,
    no "Creating neighbour" log, no triggered Hellos beyond the periodic
    ones, count stable across neighbour-check ticks (GC nothing to reap);
  * malformed controls (bad magic / version / truncated body): same;
  * legitimate association is preserved: a valid Hello sequence creates
    an entry that survives the neighbour checks, and IHU / Router-Id +
    Update packets still create entries and install their route.
"""

import os
import re
import sys
import time

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.babeld]

# r2's link-local address is EUI-64 derived; captured at convergence
PEER_LL = None
PHANTOM_BASE = "100"  # sources fe80::100 .. fe80::11f
N_EMPTY = 32
RATE_EMPTY = 32.0
ROUTE = "2001:db8:63::/64"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_host("h1", "10.99.0.3/24", "via 10.99.0.1")

    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    tgen.start_router()

    h1 = tgen.gears["h1"]
    h1.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=0")
    h1.cmd("sysctl -qw net.ipv6.conf.h1-eth0.disable_ipv6=0")
    h1.cmd("ip -6 addr add fe80::a1/64 dev h1-eth0 2>/dev/null || true")


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def neighbour_lines(r1):
    out = r1.vtysh_cmd("show babel neighbor")
    return [ln for ln in out.splitlines() if ln.startswith("Neighbour ")]


def babeld_log_path(tgen):
    return os.path.join(tgen.logdir, "r1", "babeld.log")


def log_count(tgen, needle, offset=0):
    """Count needle occurrences in r1's babeld.log after byte offset."""
    try:
        with open(babeld_log_path(tgen), "rb") as fp:
            fp.seek(offset)
            return fp.read().count(needle.encode())
    except OSError:
        return -1


def log_size(tgen):
    try:
        return os.path.getsize(babeld_log_path(tgen))
    except OSError:
        return 0


def inject(h1, kind, src, count, rate=0.0):
    out = h1.cmd(
        "python3 {}/send_babel.py --iface h1-eth0 --kind {} --src {} "
        "--count {} --rate {}".format(CWD, kind, src, count, rate)
    )
    logger.info("inject {} x {} from {}: {}".format(count, kind, src, out.strip()))


def test_converge_protocols():
    "Wait for Babel convergence: r1 must see r2 as a neighbour"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check_convergence():
        up = [
            ln
            for ln in neighbour_lines(r1)
            if "reach 0000" not in ln
        ]
        if not up:
            return "r1 has no babel neighbour yet"
        return None

    _, result = topotest.run_and_expect(check_convergence, None, count=60, wait=1)
    assert result is None, "r1 failed to establish a babel neighbour"

    global PEER_LL
    peer = [ln for ln in neighbour_lines(r1) if "reach 0000" not in ln]
    PEER_LL = peer[0].split()[1]
    logger.info("r1 neighbours:\n{}".format(r1.vtysh_cmd("show babel neighbor")))


def test_empty_body_no_neighbour():
    "Empty-body packets must not create neighbour entries nor traffic"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    baseline = len(neighbour_lines(r1))

    off = log_size(tgen)
    t0 = time.time()
    inject(h1, "empty", "fe80::" + PHANTOM_BASE, N_EMPTY, RATE_EMPTY)
    time.sleep(1.0)

    creations = log_count(tgen, "Creating neighbour", off)
    hellos = log_count(tgen, "Sending hello", off)
    count_now = len(neighbour_lines(r1))

    # let two neighbour-check ticks pass, then re-check (GC): nothing may
    # appear late and nothing needs reaping on a fixed build
    time.sleep(3.0)
    count_later = len(neighbour_lines(r1))
    window = time.time() - t0

    logger.info(
        "empty-body injection: creations={} hellos={} count {}->{}->{} "
        "window {:.1f}s".format(creations, hellos, baseline, count_now,
                                count_later, window)
    )
    assert creations == 0, (
        "{} empty-body packets created {} neighbour entries "
        "(neighbour creation must be lazy)".format(N_EMPTY, creations)
    )
    assert count_now == baseline and count_later == baseline, (
        "neighbour count changed {}->{}->{} on empty-body packets".format(
            baseline, count_now, count_later
        )
    )
    # only r1's own periodic Hellos (hello-interval 1000) may appear:
    # allow the measured window at 1/s plus a small margin
    assert hellos <= window * 1.5 + 2, (
        "{} triggered Hellos for {} empty-body packets in {:.1f}s".format(
            hellos, N_EMPTY, window
        )
    )


def test_malformed_no_neighbour():
    "Malformed packets must not create neighbour entries (control)"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    baseline = len(neighbour_lines(r1))

    off = log_size(tgen)
    inject(h1, "badmagic", "fe80::200", 8, 8.0)
    inject(h1, "badversion", "fe80::210", 8, 8.0)
    inject(h1, "truncated", "fe80::220", 8, 8.0)
    time.sleep(1.0)

    creations = log_count(tgen, "Creating neighbour", off)
    count_now = len(neighbour_lines(r1))
    logger.info(
        "malformed injection: creations={} count {}->{}".format(
            creations, baseline, count_now
        )
    )
    assert creations == 0, "malformed packets created {} neighbours".format(creations)
    assert count_now == baseline, "neighbour count changed on malformed packets"


def test_valid_hello_creates_and_persists():
    "A valid Hello sequence must still create a neighbour that persists"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    baseline = len(neighbour_lines(r1))

    # 5 Hellos, seqno 1..5, one every 2s: survives multiple neighbour checks
    inject(h1, "validhello", "fe80::352", 5, 0.5)
    time.sleep(1.0)

    lines = neighbour_lines(r1)
    hello_up = [
        ln for ln in lines if "fe80::352" in ln and "reach 0000" not in ln
    ]
    assert len(lines) == baseline + 1, (
        "valid Hello must create exactly one neighbour ({} -> {})".format(
            baseline, len(lines)
        )
    )
    assert hello_up, "valid-Hello neighbour fe80::352 missing or reach 0000"

    # persistence across further neighbour-check ticks
    time.sleep(3.0)
    lines = neighbour_lines(r1)
    hello_up = [
        ln for ln in lines if "fe80::352" in ln and "reach 0000" not in ln
    ]
    assert hello_up, "valid-Hello neighbour fe80::352 did not survive neighbour checks"


def test_ihu_and_update_create():
    "IHU and Router-Id + Update must still create neighbours and install routes"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    # IHU from an unknown source still creates the neighbour entry; an
    # IHU-only entry has reach 0 and is reaped at the next check tick,
    # which is protocol-normal, so assert on the creation log
    off = log_size(tgen)
    inject(h1, "ihu", "fe80::350", 1)
    time.sleep(0.3)
    assert log_count(tgen, "Creating neighbour fe80::350", off) == 1, (
        "IHU from an unknown source did not create a neighbour entry"
    )

    # full association for the Update source: 3 Hellos (reach -> finite
    # rxcost), 1 IHU (finite txcost), then the Update installs its route
    inject(h1, "validhello", "fe80::351", 3, 1.0)
    inject(h1, "ihu", "fe80::351", 1)
    inject(h1, "update", "fe80::351", 1)
    time.sleep(1.0)

    lines = neighbour_lines(r1)
    assert any("fe80::351" in ln and "reach 0000" not in ln for ln in lines), (
        "associated neighbour fe80::351 missing or reach 0000:\n{}".format("\n".join(lines))
    )
    phantoms = [ln for ln in lines if re.match(r"Neighbour fe80::1[0-9a-f]{2} ", ln)]
    assert not phantoms, "phantom entries present:\n{}".format("\n".join(phantoms))

    routes = r1.vtysh_cmd("show babel route")
    assert ROUTE in routes, "Update route {} not installed:\n{}".format(ROUTE, routes)

    # the legitimate peer is still intact
    assert any(PEER_LL in ln and "reach 0000" not in ln for ln in lines), (
        "legit peer neighbour {} lost:\n{}".format(PEER_LL, "\n".join(lines))
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
