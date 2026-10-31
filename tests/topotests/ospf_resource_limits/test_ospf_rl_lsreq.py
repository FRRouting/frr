#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_rl_lsreq.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
r"""
test_ospf_rl_lsreq.py:

Link State Request list quota.  During Exchange a rogue DD master can
stream LSA headers the victim does not have; each is queued on the
neighbor's ls_req (ospf_ls_request_add) with no bound.  Runtime
confirmation on the unpatched build (c4e94c4aaa4f): 4/8/12 headers in
three DD rounds grew ls_req to 4/8/12 while the neighbor sat in
Exchange, and the neighbor was deleted on the dead interval once
injection stopped.

With a small configured quota this test checks: ls_req growing to the
cap, the excess counted, the rogue staying in Exchange, the real
adjacency untouched, and full reclaim after injection stops.  On the
unpatched build the quota command does not exist and the growth
assertion fails (ls_req 8 past the small quota at the second round).
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


def test_ls_request_limit():
    "A rogue DD master's ls_req stops at ls-request-limit; drops counted."
    tgen = get_topogen()
    r1, _, inj = rc.baseline(tgen)

    if not rc.apply_limit(r1, "ls-request-limit %d" % rc.LS_REQ_CAP):
        logger.info("ls-request-limit rejected by the running ospfd")

    header_ids = ["10.224.21.%d" % (index + 1) for index in range(rc.GRADES[-1])]

    def request_neighbor():
        return rc.neighbor(r1, rc.REQ_RID, rc.REQ_IP)

    try:
        for round_index, count in enumerate(rc.GRADES):
            frames = [inj.hello(0.2, rc.REQ_IP, rc.REQ_RID)]
            new_ids = header_ids[count - 4:count] if count > 4 else header_ids[:count]
            if round_index == 0:
                frames.append(
                    inj.dd(1.0, rc.REQ_IP, rc.REQ_RID, rc.DD_BASE_SEQ, 0x07)
                )
                dd_at = 2.0
            else:
                dd_at = 1.0
            frames.append(
                inj.dd(dd_at, rc.REQ_IP, rc.REQ_RID,
                       rc.DD_BASE_SEQ + round_index + 1, 0x03,
                       headers=[rc.header_hex(lsa_id, rc.REQ_RID)
                                for lsa_id in new_ids])
            )
            assert inj.inject(frames) == len(frames)

            entry = request_neighbor()
            rc.wait_until(
                "rogue in Exchange after round %d" % count,
                lambda: rc.neighbor_state(request_neighbor()) == "Exchange", 10,
            )
            rc.wait_until(
                "ls_req reaches cap after round %d" % count,
                lambda: (request_neighbor() or {}).get(
                    "linkStateRequestListCounter", 0) >= rc.LS_REQ_CAP, 10,
            )
            entry = request_neighbor()
            assert entry is not None, "rogue neighbor missing after round %d" % count
            assert entry.get("linkStateRequestListCounter") == rc.LS_REQ_CAP, (
                "ls_req not capped at %d: %s (round offering %d)"
                % (rc.LS_REQ_CAP, entry.get("linkStateRequestListCounter"), count)
            )
        dropped = entry.get("linkStateRequestListDropped")
        assert dropped == rc.GRADES[-1] - rc.LS_REQ_CAP, (
            "excess ls_req additions not counted: dropped=%r" % dropped
        )
        rc.require_full("rogue DD master")
    finally:
        # Cleanup: once injection stops the rogue neighbor is deleted on
        # the dead interval and the real adjacency stays Full.
        rc.wait_until(
            "rogue DD neighbor expires",
            lambda: request_neighbor() is None and rc.real_full(),
            rc.RECOVERY_TIMEOUT + 15,
        )
