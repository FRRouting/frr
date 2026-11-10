#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Yoann Lopez
#

"""
Test "no isis periodic-csnp" on a point-to-point circuit.

    +----+  10.0.12.0/24  +----+
    | r1 |----------------| r2 |
    +----+                +----+

Both circuits have a 1 s CSNP interval; r1 has periodic CSNPs disabled.
r1 must send a CSNP when the adjacency comes up and none after, while r2
keeps sending them. Enabling them again on r1 restarts them, and
disabling them on the running adjacency stops them at once.
"""

import functools
import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]

# Several CSNP intervals of r2: long enough to see periodic CSNPs.
QUIET_S = 5


def build_topo(tgen):
    for router in ("r1", "r2"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _csnp_sent(router):
    """Level-2 CSNPs the router has sent."""
    output = json.loads(router.vtysh_cmd("show isis summary json"))
    return output["vrfs"][0]["areas"][0]["tx-pdu-type"].get("l2-csnp", 0)


def _check_synchronized():
    """Both routers are up and have each other's LSP."""
    tgen = get_topogen()
    for router in tgen.routers().values():
        output = json.loads(router.vtysh_cmd("show isis neighbor json"))
        states = [
            c["state"]
            for area in output.get("areas", [])
            for c in area.get("circuits", [])
            if "adj" in c
        ]
        if states != ["Up"]:
            return "{}: adjacencies {}".format(router.name, states)
        database = router.vtysh_cmd("show isis database")
        for lsp in ("r1.00-00", "r2.00-00"):
            if lsp not in database:
                return "{}: no {}".format(router.name, lsp)
    return None


def _wait_synchronized():
    _, result = topotest.run_and_expect(_check_synchronized, None, count=60, wait=0.5)
    assert result is None, result


def _sent_while_quiet():
    """CSNPs each router sends over QUIET_S seconds."""
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    before = (_csnp_sent(r1), _csnp_sent(r2))
    time.sleep(QUIET_S)
    return _csnp_sent(r1) - before[0], _csnp_sent(r2) - before[1]


def test_no_periodic_csnp():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("The adjacency is up and the databases are synchronized")
    _wait_synchronized()
    assert _csnp_sent(r1) > 0, "r1 sent no CSNP when the adjacency came up"
    assert "no isis periodic-csnp" in r1.vtysh_cmd("show running-config")

    step("r1 sends no periodic CSNPs, r2 does")
    r1_sent, r2_sent = _sent_while_quiet()
    assert r1_sent == 0, "r1 sent {} CSNPs".format(r1_sent)
    assert r2_sent > 0, "r2 sent no CSNPs"


def test_warning():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Setting both the CSNP interval and no periodic CSNPs warns")
    for command in ("isis csnp-interval 1", "no isis periodic-csnp"):
        output = r1.vtysh_cmd(
            "configure terminal\ninterface r1-eth0\n{}".format(command)
        )
        assert "csnp-interval is not used" in output, "{}: {}".format(command, output)


def test_adjacency_up_csnp():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("r1 sends a CSNP when the adjacency comes back up")
    before = _csnp_sent(r1)
    r1.cmd("ip link set r1-eth0 down")
    time.sleep(1)
    r1.cmd("ip link set r1-eth0 up")
    _wait_synchronized()
    test_func = lambda: _csnp_sent(r1) > before
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=0.5)
    assert result, "r1 sent no CSNP when the adjacency came back up"

    step("and none after it")
    r1_sent, _ = _sent_while_quiet()
    assert r1_sent == 0, "r1 sent {} CSNPs".format(r1_sent)


def test_periodic_csnp_again():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Enabling periodic CSNPs on r1 restarts them")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nisis periodic-csnp")
    assert "no isis periodic-csnp" not in r1.vtysh_cmd("show running-config")
    r1_sent, _ = _sent_while_quiet()
    assert r1_sent > 0, "r1 sent no CSNPs"
    _wait_synchronized()


def test_disable_on_running_adjacency():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Disabling periodic CSNPs on the running adjacency stops them at once")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth0\nno isis periodic-csnp")
    assert "no isis periodic-csnp" in r1.vtysh_cmd("show running-config")
    r1_sent, r2_sent = _sent_while_quiet()
    assert r1_sent == 0, "r1 sent {} CSNPs".format(r1_sent)
    assert r2_sent > 0, "r2 sent no CSNPs"


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
