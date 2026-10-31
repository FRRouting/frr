#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Yoann Lopez
#

"""
test_isis_p2p_csnp_adj_up.py: Test that a point-to-point adjacency that
comes back up resynchronizes the link-state databases at once, without
waiting for a periodic CSNP.

    +----+ 192.0.2.0/30 +----+ 192.0.2.4/30 +----+
    | r1 |--------------| r2 |--------------| r3 |
    +----+              +----+              +----+

The r1-r2 link runs with "isis csnp-interval 600". Its traffic is dropped
while both interfaces stay up, until the adjacency expires, and r3 changes
its LSP in the meantime. When the traffic flows again, r1 must get r3's
new LSP from the CSNPs exchanged as the adjacency comes up (RFC 5303
section 1). The CSNP scheduled on adjacency up used to be dropped because
the periodic CSNP timer was already armed, so r1 kept the old LSP until
the next periodic CSNP, up to 600 s later.

The traffic is dropped with ``tc netem`` (kernel ``sch_netem``). The setup
tries ``modprobe sch_netem``; if the qdisc is still not available, the
whole module is skipped.
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen

pytestmark = [pytest.mark.isisd]

# Dropping the r1-r2 traffic on both ends keeps the interfaces, and so the
# circuits, up: only the adjacency goes down, as when the path under a
# tunnel fails.
LINK = {"r1": "r1-eth0", "r2": "r2-eth0"}
NEW_PREFIX = "203.0.113.3/32"


def build_topo(tgen):
    "Build function"
    for router in ("r1", "r2", "r3"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def tc_netem_supported(gear):
    """Whether sch_netem is available, loading it if needed. Kernel modules
    are global, so loading it from one namespace is enough."""
    check = "lsmod 2>/dev/null | grep -q sch_netem"
    status, _, _ = gear.net.cmd_status(check, warn=False)
    if status == 0:
        return True
    gear.net.cmd_status("modprobe sch_netem", warn=False)
    status, _, _ = gear.net.cmd_status(check, warn=False)
    return status == 0


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    if not tc_netem_supported(tgen.gears["s1"]):
        tgen.stop_topology()
        pytest.skip(
            "tc qdisc netem (Linux sch_netem) is required for this topotest; "
            "load the module / use a fuller kernel image"
        )

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def _database(router):
    """The router's level-2 database as {LSP ID: sequence number}, purged
    LSPs left out (FRR shows their holdtime in parentheses)."""
    output = json.loads(router.vtysh_cmd("show isis database json"))
    return {
        lsp["lsp"]["id"]: lsp["seqNumber"]
        for area in output.get("areas", [])
        for level in area.get("levels", [])
        if level.get("id") == 2
        for lsp in level.get("lsps", [])
        if not str(lsp.get("holdtime", "")).startswith("(")
    }


def _check_synchronized(tgen):
    """All three routers hold the same LSPs of r1, r2 and r3."""
    databases = {name: _database(router) for name, router in tgen.routers().items()}
    expected = {"r1.00-00", "r2.00-00", "r3.00-00"}
    if set(databases["r1"]) != expected or any(
        db != databases["r1"] for db in databases.values()
    ):
        return "databases differ: {}".format(databases)
    return None


def _check_adjacencies(tgen, up):
    """The r1-r2 adjacency is up on both ends, or gone on both."""
    for name, interface in LINK.items():
        output = json.loads(tgen.gears[name].vtysh_cmd("show isis neighbor json"))
        states = [
            circuit.get("state")
            for area in output.get("areas", [])
            for circuit in area.get("circuits", [])
            if circuit.get("interface") == interface
        ]
        if up and states != ["Up"]:
            return "{} {}: adjacency {}".format(name, interface, states)
        if not up and "Up" in states:
            return "{} {}: adjacency still up".format(name, interface)
    return None


def _check_r3_lsp_newer(router, sequence):
    """The router holds an r3 LSP newer than the given sequence number."""
    current = _database(router).get("r3.00-00", "0x0")
    if int(current, 16) <= int(sequence, 16):
        return "{}: r3.00-00 still {}".format(router.name, current)
    return None


def test_databases_synchronized(tgen):
    "All databases are synchronized once the topology is up"
    test_func = functools.partial(_check_synchronized, tgen)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_resync_on_adjacency_up(tgen):
    "r1 gets r3's new LSP as soon as its adjacency to r2 is back up"
    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    step("Drop the r1-r2 traffic until the adjacency expires")
    for name, interface in LINK.items():
        tgen.gears[name].cmd_raises(
            "tc qdisc add dev {} root netem loss 100%".format(interface)
        )
    test_func = functools.partial(_check_adjacencies, tgen, False)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("Change r3's LSP while r1 cannot hear it")
    before = _database(r2)["r3.00-00"]
    r3.vtysh_cmd("configure terminal\ninterface lo\nip address {}".format(NEW_PREFIX))
    test_func = functools.partial(_check_r3_lsp_newer, r2, before)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("Let the r1-r2 traffic through again")
    for name, interface in LINK.items():
        tgen.gears[name].cmd_raises("tc qdisc del dev {} root".format(interface))
    test_func = functools.partial(_check_adjacencies, tgen, True)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    # Without CSNPs on adjacency up, r1 keeps r3's old LSP until the next
    # periodic CSNP on r1-r2, up to 600 s later: well beyond these 30 s.
    step("r1 gets r3's new LSP and route")
    test_func = functools.partial(_check_synchronized, tgen)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    expected = {NEW_PREFIX: [{"protocol": "isis"}]}
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route {} json".format(NEW_PREFIX),
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "r1 has no IS-IS route to {}".format(NEW_PREFIX)


def test_memory_leak(tgen):
    "Run the memory leak test and report results."
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
