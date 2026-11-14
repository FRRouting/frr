#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_isis_iih_overflow.py
#
# Copyright (c) 2026 Bing Shui
#

"""
test_isis_iih_overflow.py
=========================

Regression for the silent broadcast IIH packing overflow in isisd.

Every adjacency (Up *or* Initializing) on a broadcast circuit is carried
in the LAN Neighbours TLV of the LAN IIH, and the IIH must fit into one
PDU - PDUs are not fragmented.  Nothing bounded the adjacency table, so
a few hundred distinct (system-id, SNPA) IIHs on the LAN made
send_hello() fail to pack the PDU; the failure was logged nowhere and
the whole IIH was dropped, cutting off the legitimate neighbours after
their holdtime expired.

The fix refuses new broadcast adjacencies once the LAN Neighbours TLV
cannot outgrow the IIH MTU (rate-limited warning plus an
"iih-adjacencies-refused" counter), so existing adjacencies are
protected and the IIH keeps flowing; a packing failure is now logged.

Topology
--------

    r1 (victim, DIS) ---- sw1 ---- r2 (legit peer)
                    |
                    h1 (injector + capture)

All three attach to one broadcast segment in area 49.0001, level 2.

Test plan
---------

1. test_isis_adjacency_up
     Baseline: the r1-r2 adjacency reaches Up on both sides.

2. test_iih_lan_neighbours_overflow
     Inject IIHs with distinct system IDs and distinct locally
     administered source MACs from h1, each listing r1's SNPA so the
     adjacency goes Up.  Controls: a small batch must not disturb the
     victim's IIH or the adjacency, and repeated copies of one system
     ID must not create new state.  The saturation batch must not stop
     the victim's L2 IIH, must not cut the legitimate adjacency, must
     cap the adjacency table at the IIH-derived capacity and count the
     refusals, and the injected adjacencies must expire afterwards.
"""

import json
import os
import re
import sys
import time

import pytest

from lib.topogen import Topogen, get_topogen, TopoRouter
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.isisd]

K_SMALL = 16
K_REPEAT = 64
K_SAT = 300
INJECT_RATE = 50
INJECT_HOLDTIME = 60
R1_IP = "10.0.0.1"
R2_IP = "10.0.0.2"
R2_LOOPBACK = "10.0.2.2"
HELPER = os.path.join(CWD, "iih_inject.py")


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_host("h1", "10.0.0.3/24", "via 10.0.0.1")

    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r2"])
    sw.add_link(tgen.gears["h1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The IIH capacity under test is derived from the interface MTU;
    # pin it so the test does not depend on the environment default.
    for rname in ("r1", "r2"):
        tgen.gears[rname].cmd(
            "ip link set {}-eth0 mtu 1500".format(rname))

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module():
    "Tears down the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def adjacency_rows(router):
    "Parse 'show isis neighbor' text into (interface, level, state) rows."
    # The JSON variant prints every adjacency of a circuit into one
    # object, so only the text output lists them all.
    raw = router.vtysh_cmd("show isis neighbor")
    rows = []
    for line in raw.splitlines():
        match = re.match(
            r"^\s*(\S+)\s+(\S+)\s+([12])\s+(Up|Initializing|Down)\s", line)
        if match:
            rows.append({
                "interface": match.group(2),
                "level": int(match.group(3)),
                "state": match.group(4),
            })
    return rows


def adj_count(router, iface, level):
    return sum(
        1 for row in adjacency_rows(router)
        if row["interface"] == iface and row["level"] == level
    )


def adjacency_up(router, peer):
    raw = router.vtysh_cmd("show isis neighbor detail")
    blocks = re.split(r"\n\s*\n", raw)
    return any(peer in block and "State: Up" in block for block in blocks)


def wait_adjacency_up(router, peer, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if adjacency_up(router, peer):
                return True
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(1)
    return False


def wait_adj_count(router, iface, level, wanted, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if adj_count(router, iface, level) == wanted:
                return True
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(2)
    return False


def refused_counter(router, iface, level_str):
    """"iih-adjacencies-refused" of one circuit/level.

    None when the running isisd has no such counter (unfixed builds).
    """
    data = json.loads(router.vtysh_cmd("show isis interface detail json"))

    def walk(value):
        if isinstance(value, dict):
            if value.get("name") == iface and isinstance(value.get("levels"),
                                                         list):
                for entry in value["levels"]:
                    if isinstance(entry, dict) \
                            and entry.get("level") == level_str:
                        return entry.get("iih-adjacencies-refused")
            for child in value.values():
                found = walk(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found is not None:
                    return found
        return None

    return walk(data)


def route_present(router, prefix):
    wanted = prefix + "/32"
    data = json.loads(router.vtysh_cmd("show isis route json"))

    def walk(value):
        if isinstance(value, dict):
            if value.get("prefix") == wanted:
                return True
            return any(walk(child) for child in value.values())
        if isinstance(value, list):
            return any(walk(child) for child in value)
        return False

    return walk(data)


def run_inject(tgen, victim_mac, start_index, count, tail, repeat=1):
    h1 = tgen.gears["h1"]
    cmd = (
        "python3 %s --iface h1-eth0 --victim-mac %s "
        "--start-index %d --count %d --rate %d --holdtime %d --tail %d "
        "--repeat %d"
        % (HELPER, victim_mac, start_index, count, INJECT_RATE,
           INJECT_HOLDTIME, tail, repeat)
    )
    raw = h1.cmd(cmd)
    for line in reversed(raw.splitlines()):
        if line.startswith("IIH_INJECT_JSON="):
            return json.loads(line.split("=", 1)[1])
    raise RuntimeError("iih_inject helper failed: %s" % raw)


def test_isis_adjacency_up():
    "Baseline: the r1-r2 adjacency reaches Up on both sides."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    assert wait_adjacency_up(r1, R2_IP), "r1-r2 adjacency did not come up"
    assert wait_adjacency_up(r2, R1_IP), "r2-r1 adjacency did not come up"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if route_present(r1, R2_LOOPBACK):
                break
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(2)
    assert route_present(r1, R2_LOOPBACK), "r1 has no route to r2 loopback"


def test_iih_lan_neighbours_overflow():
    "Distinct Up IIHs must not stop the victim's IIH or cut the adjacency."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    victim_mac = r1.cmd("cat /sys/class/net/r1-eth0/address").strip()

    # Control: a few extra adjacencies must not disturb the victim's
    # IIH or the legitimate adjacency.
    capture = run_inject(tgen, victim_mac, 0, K_SMALL, tail=4)
    assert capture["sent"] == K_SMALL
    assert capture["victim_l2_iih_after"] >= 2, (
        "victim L2 IIH stopped after only %d injected adjacencies"
        % K_SMALL)
    assert adj_count(r1, "r1-eth0", 2) == 1 + K_SMALL
    assert adjacency_up(r1, R2_IP) and adjacency_up(r2, R1_IP)

    # Control: repeated copies of one injected system ID must not
    # create new state.
    capture = run_inject(tgen, victim_mac, 0, 1, tail=3, repeat=K_REPEAT)
    assert capture["sent"] == K_REPEAT
    assert capture["victim_l2_iih_after"] >= 1
    assert adj_count(r1, "r1-eth0", 2) == 1 + K_SMALL, (
        "duplicate system IDs created new adjacencies")

    # Trigger: distinct (system-id, SNPA) IIHs until the LAN Neighbours
    # TLV outgrows the IIH MTU.
    capture = run_inject(tgen, victim_mac, 1000, K_SAT, tail=8)
    assert capture["sent"] == K_SAT
    assert capture["total_isis_frames"] > 0, "capture saw no IS-IS frames"

    # The victim's L2 IIH must keep flowing: before the fix the whole
    # IIH was dropped silently once the PDU outgrew the MTU.
    assert capture["victim_l2_iih_after"] >= 2, (
        "victim L2 IIH stopped after the saturation batch "
        "(%d of its IIHs in the %ds post-injection window)"
        % (capture["victim_l2_iih_after"], capture["tail_seconds"]))

    # The legitimate adjacency must stay Up on both sides.
    assert wait_adjacency_up(r1, R2_IP, timeout=10), (
        "legitimate adjacency fell on r1 after the saturation batch")
    assert wait_adjacency_up(r2, R1_IP, timeout=10), (
        "legitimate adjacency fell on r2 after the saturation batch")

    # The adjacency table must be capped at the IIH-derived capacity,
    # and every refused creation must be counted.
    count = adj_count(r1, "r1-eth0", 2)
    total = 1 + K_SMALL + K_SAT
    assert count < total, (
        "adjacency table not capped: %d entries for %d injected IDs"
        % (count, total))
    refused = refused_counter(r1, "r1-eth0", "L2")
    assert refused is not None, "no iih-adjacencies-refused counter"
    assert refused == total - count, (
        "iih-adjacencies-refused %d != admitted %d (table at %d)"
        % (refused, total - count, count))

    # GC: the injected adjacencies expire after their holdtime; the
    # adjacency table drains back to the legitimate neighbour only.
    assert wait_adj_count(r1, "r1-eth0", 2, 1, timeout=120), (
        "injected adjacencies did not expire")
    assert adjacency_up(r1, R2_IP) and adjacency_up(r2, R1_IP)

    # End to end: the route to the legitimate peer's loopback is back.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if route_present(r1, R2_LOOPBACK):
                break
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(2)
    assert route_present(r1, R2_LOOPBACK), (
        "route to r2 loopback not re-installed after the drain")
