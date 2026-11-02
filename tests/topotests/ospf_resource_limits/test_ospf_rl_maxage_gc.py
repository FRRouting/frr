#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_rl_maxage_gc.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
r"""
test_ospf_rl_maxage_gc.py:

MaxAge GC deferral is protocol-mandated, not a bug.  RFC 2328 section
14: a MaxAge LSA must be removed only when a) it is on no neighbor's
retransmission list and b) no neighbor is in Exchange or Loading.
Runtime confirmation on the unpatched build (c4e94c4aaa4f): with no
Exchange/Loading neighbor the MaxAge LSA was deleted 61.232s after the
trigger; with a rogue held in Exchange and an empty retransmission list
it was still present at 72.730s and was deleted after the rogue cleared.

This test pins both arms as regression guards for the resource-limit
patch (which must not alter GC semantics): the blocked arm asserts the
LSA survives past 65s while the rogue is in Exchange and is deleted
after it clears; the control arm asserts deletion inside the ~60s
window (45-90s) with no Exchange/Loading neighbor.  Both arms pass on
the unpatched and the patched build.
"""

import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.insert(0, CWD)

# pylint: disable=C0413
from lib.topogen import get_topogen
import ospf_rl_common as rc

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    rc.setup_module(mod)


def teardown_module(mod):
    rc.teardown_module(mod)


def test_maxage_gc_exchange_deferral():
    "RFC 2328 section 14: MaxAge removal waits for Exchange/Loading to clear."
    tgen = get_topogen()
    r1, _, inj = rc.baseline(tgen)

    control_id = "10.224.22.1"
    blocked_id = "10.224.22.2"

    def exchange_loading():
        return [
            entry for entry in rc.neighbors(r1)
            if rc.neighbor_state(entry) in ("Exchange", "Loading")
        ]

    def ready(lsa_id, blocked):
        entry = rc.external_entry(r1, lsa_id)
        ok = (
            entry is not None
            and entry.get("lsaAge") == 3600
            and lsa_id in rc.maxage_map(r1)
            and rc.retransmit_total(r1) == 0
            and rc.real_full()
        )
        if blocked:
            ok = ok and rc.neighbor_state(
                rc.neighbor(r1, rc.GC_RID, rc.GC_IP)) == "Exchange"
        else:
            ok = ok and not exchange_loading()
        return ok

    # Blocked arm: a rogue held in Exchange defers MaxAge removal.  Let the
    # real adjacency's initial router-LSA exchange settle first: r1 re-floods
    # every retransmitted router-LSA to the rogue, and the rogue never acks,
    # which would leave its retransmission list non-empty and break the
    # zero-retransmission precondition below.
    rc.wait_retrans_quiet(r1)
    frames = [
        inj.hello(0.2, rc.GC_IP, rc.GC_RID),
        inj.dd(1.0, rc.GC_IP, rc.GC_RID, rc.GC_DD_SEQ, 0x07),
    ]
    assert inj.inject(frames) == 2
    rc.wait_until("GC rogue in Exchange",
                  lambda: rc.neighbor_state(
                      rc.neighbor(r1, rc.GC_RID, rc.GC_IP)) == "Exchange", 10)

    assert inj.inject([
        inj.lsu_external(0.2, rc.R2_IP, rc.R2_RID, [blocked_id], rc.GC_ADV_RID)
    ]) == 1
    rc.wait_until("blocked LSA installed",
                  lambda: rc.external_entry(r1, blocked_id) is not None, 6)
    # MinLSArrival (1s) would discard the MaxAge update if it arrives too
    # soon after the normal instance; keep the manul's phase gap.
    time.sleep(1.5)

    trigger = [
        inj.lsu_external(0.2, rc.R2_IP, rc.R2_RID, [blocked_id], rc.GC_ADV_RID,
                         age=3600),
        inj.hello(0.5, rc.GC_IP, rc.GC_RID),
        inj.ack(0.9, rc.GC_IP, rc.GC_RID, blocked_id, rc.GC_ADV_RID),
        inj.ack(1.3, rc.R2_IP, rc.R2_RID, blocked_id, rc.GC_ADV_RID),
    ]
    trigger_wall = time.time()
    assert inj.inject(trigger) == 4
    rc.wait_until("MaxAge LSA installed with zero retransmissions",
                  lambda: ready(blocked_id, True), 10, 0.25)

    keepalives = [
        inj.hello(0.2 + index * 2.0, rc.GC_IP, rc.GC_RID)
        for index in range(rc.GC_BLOCKED_HOLD // 2)
    ]
    assert inj.inject(keepalives) == len(keepalives)
    elapsed = time.time() - trigger_wall
    assert elapsed >= 65, "hold window too short: %.1fs" % elapsed
    assert rc.external_entry(r1, blocked_id) is not None and (
        rc.external_entry(r1, blocked_id).get("lsaAge") == 3600
    ), "MaxAge LSA deleted while a neighbor was in Exchange"
    assert blocked_id in rc.maxage_map(r1)
    assert rc.retransmit_total(r1) == 0
    rc.require_full("GC block hold")

    # Once the rogue clears, the MaxAge LSA is removed.
    rc.wait_until(
        "GC rogue expires",
        lambda: rc.neighbor(r1, rc.GC_RID, rc.GC_IP) is None and rc.real_full(),
        rc.RECOVERY_TIMEOUT + 15,
    )
    rc.wait_until(
        "MaxAge LSA deleted after Exchange cleared",
        lambda: rc.external_entry(r1, blocked_id) is None
        and blocked_id not in rc.maxage_map(r1),
        rc.GC_DELETE_TIMEOUT,
    )

    # Control arm: with no Exchange/Loading neighbor the same MaxAge LSA
    # is removed at ~60s.
    assert inj.inject([
        inj.lsu_external(0.2, rc.R2_IP, rc.R2_RID, [control_id], rc.GC_ADV_RID)
    ]) == 1
    rc.wait_until("control LSA installed",
                  lambda: rc.external_entry(r1, control_id) is not None, 6)
    # MinLSArrival gap, as in the blocked arm.
    time.sleep(1.5)
    control_trigger = time.time()
    assert inj.inject([
        inj.lsu_external(0.2, rc.R2_IP, rc.R2_RID, [control_id], rc.GC_ADV_RID,
                         age=3600),
        inj.ack(0.7, rc.R2_IP, rc.R2_RID, control_id, rc.GC_ADV_RID),
    ]) == 2
    rc.wait_until("control MaxAge LSA installed with zero retransmissions",
                  lambda: ready(control_id, False), 10, 0.25)

    def deleted():
        return rc.external_entry(r1, control_id) is None and (
            control_id not in rc.maxage_map(r1)
        )

    # Not removed immediately, but within the ~60s remover window.
    time.sleep(40)
    assert not deleted(), "control MaxAge LSA removed before ~60s"
    rc.wait_until("control MaxAge LSA deleted at ~60s", deleted,
                  rc.GC_DELETE_TIMEOUT)
    since = time.time() - control_trigger
    assert 45 <= since <= rc.GC_DELETE_TIMEOUT + 15, (
        "control MaxAge deletion outside ~60s window: %.1fs" % since
    )
    rc.require_full("GC control")
