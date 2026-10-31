#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_rl_lsdb.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
r"""
test_ospf_rl_lsdb.py:

LSDB quota.  ospf_lsa_install() installs every distinct valid LSA into
the area or AS-scope LSDB; nothing bounds the database.  Runtime
confirmation on the unpatched build (c4e94c4aaa4f): 4/8/12 distinct
valid Type-5 LSAs grew the test LSDB to 4/8/12 entries.

With a small configured quota this test checks: installs below the cap,
the database stopping at max-lsa with the excess counted, the real
adjacency untouched, MaxAge updates of held keys still installing with a
full database (replacement, not a new entry) and being removed at ~60s
with no Exchange/Loading neighbor (RFC 2328 section 14), and new LSAs
being admitted once the GC frees slots.  On the unpatched build the
quota command does not exist and the growth assertion fails (12 test
LSAs past the small quota).
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
from lib.topolog import logger
import ospf_rl_common as rc

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    rc.setup_module(mod)


def teardown_module(mod):
    rc.teardown_module(mod)


def test_lsdb_limit():
    "Distinct valid Type-5 LSAs install below the cap and stop at max-lsa."
    tgen = get_topogen()
    r1, _, inj = rc.baseline(tgen)

    if not rc.apply_limit(r1, "max-lsa %d" % rc.MAX_LSA_CAP):
        logger.info("max-lsa rejected by the running ospfd")

    ids = ["10.224.20.%d" % (index + 1) for index in range(rc.GRADES[-1])]

    def test_entries():
        return [e for e in rc.external_entries(r1) if e.get("linkStateId") in ids]

    try:
        for count in rc.GRADES:
            new_ids = ids[count - 4:count] if count > 4 else ids[:count]
            assert inj.inject([
                inj.lsu_external(0.2, rc.R2_IP, rc.R2_RID, new_ids,
                                 rc.LSA_ADV_RID)
            ]) == 1
            rc.wait_until(
                "LSDB round %d installed" % count,
                lambda count=count: len(test_entries()) >= min(count, rc.MAX_LSA_CAP),
                10,
            )

        entries = test_entries()
        dropped = rc.find_key(rc.vty_json(r1, "show ip ospf json"),
                              "lsasDropped")
        assert len(entries) == rc.MAX_LSA_CAP, (
            "LSDB not capped at %d test LSAs: %d" % (rc.MAX_LSA_CAP, len(entries))
        )
        assert dropped == rc.GRADES[-1] - rc.MAX_LSA_CAP, (
            "excess LSAs not counted: lsasDropped=%r" % dropped
        )
        assert all(entry.get("lsaAge", 3600) < 3600 for entry in entries)
        rc.require_full("LSDB saturation")
    finally:
        # Protocol-mandated GC: MaxAge updates of the held keys install
        # even with a full LSDB (they replace existing keys; MaxAge for a
        # key we do not hold is acked and discarded per RFC 2328 13 step
        # 4) and are removed at ~60s with no Exchange/Loading neighbor.
        # MinLSArrival (1s) would discard the MaxAge updates if they
        # arrive too soon after the last normal install.
        time.sleep(1.5)
        assert inj.inject([
            inj.lsu_external(0.2, rc.R2_IP, rc.R2_RID, ids, rc.LSA_ADV_RID,
                             age=3600)
        ]) == 1
        rc.wait_until(
            "all test LSAs at MaxAge",
            lambda: all(
                rc.external_entry(r1, lsa_id) is not None
                and rc.external_entry(r1, lsa_id).get("lsaAge") == 3600
                for lsa_id in ids[:rc.MAX_LSA_CAP]
            ),
            10,
        )
        # Not removed immediately: the MaxAge remover runs at ~60s.
        time.sleep(40)
        assert len(test_entries()) >= rc.MAX_LSA_CAP, (
            "MaxAge LSAs removed too early (before ~60s)"
        )
        rc.wait_until("MaxAge LSAs GC'd", lambda: not test_entries(),
                      rc.GC_DELETE_TIMEOUT)
        # A freed slot is offered to new LSAs again.
        assert inj.inject([
            inj.lsu_external(0.2, rc.R2_IP, rc.R2_RID, ["10.224.20.99"],
                             rc.LSA_ADV_RID)
        ]) == 1
        rc.wait_until("fresh LSA admitted after GC",
                      lambda: rc.external_entry(r1, "10.224.20.99") is not None,
                      6)
        # MinLSArrival gap before the MaxAge flush, as above.
        time.sleep(1.5)
        assert inj.inject([
            inj.lsu_external(0.2, rc.R2_IP, rc.R2_RID, ["10.224.20.99"],
                             rc.LSA_ADV_RID, age=3600)
        ]) == 1
        rc.wait_until("cleanup LSA GC'd",
                      lambda: rc.external_entry(r1, "10.224.20.99") is None,
                      rc.GC_DELETE_TIMEOUT)
