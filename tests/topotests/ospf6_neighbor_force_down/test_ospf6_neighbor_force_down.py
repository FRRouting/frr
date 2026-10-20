#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf6_neighbor_force_down.py
#
# Copyright 2026 6WIND S.A.
#

"""
test_ospf6_neighbor_force_down.py: delete an OSPFv3 neighbor while its
forced InactivityTimer event is pending.

Changing the interface MTU or setting the interface passive brings the
neighbors down by scheduling an immediate InactivityTimer event for each of
them. If a neighbor is deleted before this event runs, the event must be
cancelled, otherwise it runs on the freed neighbor and ospf6d crashes.

To delete the neighbor before the event runs, the command that schedules the
event and a network type change (which resets the interface and deletes its
neighbors) are sent to ospf6d in a single vty read.
"""

import os
import sys
import shlex
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospf6d]

# Without ASAN, a run on freed memory does not always crash: try several times
ITERATIONS = 3


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def expect_neighbor_full(router, neighbor_id):
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show ipv6 ospf6 neighbor json",
        {"neighbors": [{"neighborId": neighbor_id, "state": "Full"}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "{}: no Full adjacency with {}".format(
        router.name, neighbor_id
    )


def vty_batch(router, daemon, commands):
    output = router.cmd(
        "python3 {} /var/run/frr/{}.vty {}".format(
            os.path.join(CWD, "vty_batch.py"),
            daemon,
            " ".join(shlex.quote(c) for c in commands),
        )
    )
    logger.info("vty batch on %s %s: %s", router.name, daemon, output)
    assert "vty batch done" in output, output


def configure_r1_eth0(router, commands):
    router.vtysh_cmd(
        "\n".join(["configure terminal", "interface r1-eth0"] + commands)
    )


def force_down_and_delete_neighbor(force_cmds, restore_cmds):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    restore_cmds = restore_cmds + ["ipv6 ospf6 network broadcast"]

    configure_r1_eth0(r1, restore_cmds)
    for i in range(ITERATIONS):
        logger.info("iteration %d: %s", i, force_cmds)
        expect_neighbor_full(r1, "10.254.254.2")

        # force_cmds schedule the InactivityTimer event of the neighbor, then
        # the network type change deletes the neighbor before the event runs
        vty_batch(
            r1,
            "ospf6d",
            ["enable", "configure terminal", "interface r1-eth0"]
            + force_cmds
            + ["ipv6 ospf6 network point-to-point"],
        )

        # This vtysh command is processed by ospf6d after the event
        configure_r1_eth0(r1, restore_cmds)
        assert not tgen.routers_have_failure(), tgen.errors

    expect_neighbor_full(r1, "10.254.254.2")


def test_ospf6_ifmtu():
    force_down_and_delete_neighbor(
        ["ipv6 ospf6 ifmtu 1400"], ["no ipv6 ospf6 ifmtu"]
    )


def test_ospf6_no_ifmtu():
    force_down_and_delete_neighbor(
        ["no ipv6 ospf6 ifmtu"], ["ipv6 ospf6 ifmtu 1400"]
    )


def test_ospf6_passive():
    force_down_and_delete_neighbor(
        ["ipv6 ospf6 passive"], ["no ipv6 ospf6 passive"]
    )


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
