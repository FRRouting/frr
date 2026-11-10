#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_clear_peer_group_family.py
# Copyright (c) 2026 by Ruben Herold
#
"""
Test that a hard clear of a peer-group is batched when an address family is
given, and that the family still selects the peers.

r1 has a peer-group PG with two members: r2 (IPv4 unicast only) and r3 (IPv6
unicast only). A hard clear resets the whole session, so
"clear bgp ipv4 unicast peer-group PG" must reset r2 and leave r3 alone. As for
a clear without a family, the peers are cleared in one batch (a single RIB
walk) and not one by one, which shows in the neighbor-events debug log.
"""

import functools
import json
import os
import sys
import pytest

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

R2 = "10.0.0.2"
R3 = "2001:db8::3"
BATCH_LOG = "bgp_clearing_batch_completed"


def build_topo(tgen):
    for name in ["r1", "r2", "r3"]:
        tgen.add_router(name)

    switch = tgen.add_switch("s1")
    for name in ["r1", "r2", "r3"]:
        switch.add_link(tgen.gears[name])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _neighbor(router, address):
    output = json.loads(router.vtysh_cmd(f"show bgp neighbors {address} json"))
    return output.get(address, {})


def _established(router, address):
    state = _neighbor(router, address).get("bgpState")
    return None if state == "Established" else {"bgpState": state}


def _connections(router, address):
    return _neighbor(router, address).get("connectionsEstablished", 0)


def _drops(router, address):
    return _neighbor(router, address).get("connectionsDropped", 0)


def _batches():
    "Number of finished clearing batches in the bgpd log of r1"
    tgen = get_topogen()
    path = os.path.join(tgen.logdir, "r1", "bgpd.log")
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8", errors="replace") as logfile:
        return sum(1 for line in logfile if BATCH_LOG in line)


def _reconnected(router, address, before):
    count = _connections(router, address)
    if count <= before:
        return {"connectionsEstablished": count, "before": before}
    return None


def _wait_established(router):
    for address in [R2, R3]:
        test_func = functools.partial(_established, router, address)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, f"{address} is not Established: {result}"


def test_sessions_established():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _wait_established(tgen.gears["r1"])


def test_clear_group_with_family_is_batched():
    "A hard clear with an address family resets the matching members in a batch"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # the batch only shows in the neighbor-events debug log
    r1.vtysh_cmd("debug bgp neighbor-events")

    r2_before = _connections(r1, R2)
    r3_drops_before = _drops(r1, R3)
    batches_before = _batches()

    r1.vtysh_cmd("clear bgp ipv4 unicast peer-group PG")

    # r2 carries IPv4 unicast, its session is reset and comes back
    test_func = functools.partial(_reconnected, r1, R2, r2_before)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"r2 was not reset by the clear: {result}"

    # r3 has no IPv4 unicast, it must not be touched: no session drop, and it
    # is still Established (a reset r3 could still be reconnecting here)
    assert (
        _drops(r1, R3) == r3_drops_before
    ), "r3 has no IPv4 unicast but was reset as well"
    assert _established(r1, R3) is None, "r3 is not Established after the clear"

    # the clear went through a clearing batch
    test_func = functools.partial(lambda: None if _batches() > batches_before else 1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "the clear with an address family was not batched"


def test_clear_group_without_family_is_batched():
    "A clear without an address family still resets all members in a batch"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _wait_established(r1)
    r2_before = _connections(r1, R2)
    r3_before = _connections(r1, R3)
    batches_before = _batches()

    r1.vtysh_cmd("clear bgp peer-group PG")

    for address, before in [(R2, r2_before), (R3, r3_before)]:
        test_func = functools.partial(_reconnected, r1, address, before)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, f"{address} was not reset by the clear: {result}"

    test_func = functools.partial(lambda: None if _batches() > batches_before else 1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "the clear without an address family was not batched"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
