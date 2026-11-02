#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_rl_neighbor.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
r"""
test_ospf_rl_neighbor.py:

Neighbor table quota.  A Hello that passes the checks creates a neighbor
for every previously unseen source address (ospf_nbr_get/ospf_nbr_add);
nothing bounds oi->nbrs.  Runtime confirmation on the unpatched build
(c4e94c4aaa4f): 4/8/12 distinct one-way Hellos created 4/8/12 Init
neighbors, and all of them were reclaimed once injection stopped.

With a small configured quota this test checks: creation below the cap,
invalid-checksum control, the table stopping at neighbor-limit with the
excess counted, the real adjacency untouched, and admission of a fresh
identity after the injected ones expire on the dead interval.  On the
unpatched build the quota command does not exist and the growth
assertion fails (12 injected neighbors past the small quota).
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.insert(0, CWD)

# pylint: disable=C0413
from lib.topogen import get_topogen
from lib.topolog import logger
import ospf_rl_common as rc

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    rc.setup_module(mod)


def teardown_module(mod):
    rc.teardown_module(mod)


def test_neighbor_limit():
    "Distinct one-way Hellos create Init neighbors, capped and counted."
    tgen = get_topogen()
    r1, _, inj = rc.baseline(tgen)

    # The quota commands only exist on the patched build; on the unpatched
    # build their rejection is recorded and the unbounded growth assertion
    # below is the one that must fail.
    if not rc.apply_limit(r1, "neighbor-limit %d" % rc.NBR_CAP):
        logger.info("neighbor-limit rejected by the running ospfd")

    expected_ids = {rc.rogue_identity(index)[1] for index in range(rc.GRADES[-1])}

    def rogue_entries():
        return [e for e in rc.neighbors(r1) if e.get("router_id") in expected_ids]

    # Control: an invalid-checksum Hello creates no neighbor.
    assert inj.inject([inj.hello(0.2, rc.INVALID_IP, rc.INVALID_RID,
                                 corrupt=True)]) == 1
    rc.wait_until(
        "invalid-checksum hello leaves no neighbor",
        lambda: rc.neighbor(r1, rc.INVALID_RID, rc.INVALID_IP) is None, 5,
    )

    # Gradient: 4, 8, 12 distinct identities offered.
    for count in rc.GRADES:
        frames = []
        for index in range(count):
            source_ip, router_id = rc.rogue_identity(index)
            frames.append(
                inj.hello(0.2 + index * 0.3, source_ip, router_id,
                          include_target=False)
            )
        assert inj.inject(frames) == count
        rc.wait_until(
            "neighbor round %d present" % count,
            lambda count=count: len(rogue_entries()) >= min(count, rc.NBR_CAP - 1),
            10,
        )

    entries = rogue_entries()
    dropped = rc.find_key(
        rc.vty_json(r1, "show ip ospf interface eth1 json"), "neighborsDropped"
    )
    assert len(entries) == rc.NBR_CAP - 1, (
        "neighbor table not capped at %d (real peer + injected): %d injected"
        % (rc.NBR_CAP, len(entries))
    )
    assert dropped == rc.GRADES[-1] - (rc.NBR_CAP - 1), (
        "excess neighbor creations not counted: dropped=%r" % dropped
    )
    assert {rc.neighbor_state(entry) for entry in entries} == {"Init"}
    rc.require_full("neighbor saturation")

    # Cleanup: injected identities expire on the dead interval; a fresh
    # identity is admitted again once a slot frees up.
    rc.wait_until(
        "injected neighbors expire",
        lambda: not rogue_entries() and rc.real_full(),
        rc.RECOVERY_TIMEOUT + 15,
    )
    fresh_ip, fresh_rid = "10.222.20.199", "10.255.20.199"
    assert inj.inject([inj.hello(0.2, fresh_ip, fresh_rid,
                                 include_target=False)]) == 1
    rc.wait_until("fresh identity admitted",
                  lambda: rc.neighbor(r1, fresh_rid, fresh_ip) is not None, 5)
    rc.require_full("after neighbor drain")
