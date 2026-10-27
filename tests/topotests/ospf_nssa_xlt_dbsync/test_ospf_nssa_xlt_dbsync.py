#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_nssa_xlt_dbsync.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Sri Chandraja Reddy Allala
#

"""
test_ospf_nssa_xlt_dbsync.py: an NSSA ABR must include its translated
Type-5 LSAs in database exchange with a newly formed normal-area neighbor.

Topology:

              area 1 (NSSA)              area 0
   r1 (ASBR) --------------- r2 (ABR) ----------- r3
   redistribute static

r1 redistributes 203.0.113.0/24 as a Type-7. r2 translates it into a
Type-5. Only after that does r3 enable OSPF on its link to r2, so r3 starts
with an empty LSDB and can only learn the Type-5 through database exchange.

r1 re-originates its Type-7 once shortly after startup, and every new
Type-7 instance makes r2 re-translate and flood a new Type-5. That flood
would hand r3 the Type-5 regardless of database exchange, so the test waits
for r2's translated Type-5 to stop changing before bringing r3 up.

Without the fix, ospf_db_summary_add() skips every LSA flagged
OSPF_LSA_LOCAL_XLT, so the translated Type-5 is left out of the Database
Summary List. r3 reaches Full but never gets the Type-5 until the next LSA
refresh (~30 minutes).
"""

import os
import sys
import time
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

R2_ROUTER_ID = "2.2.2.2"
PREFIX = "203.0.113.0/24"
LSID = "203.0.113.0"


def build_topo(tgen):
    "Build function"
    for n in (1, 2, 3):
        tgen.add_router("r%d" % n)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _adjacency_full(rname):
    tgen = get_topogen()
    if "Full" in tgen.gears[rname].vtysh_cmd("show ip ospf neighbor"):
        return None
    return "adjacency not Full on %s" % rname


def _xlt_type5(rname, present):
    "Return None when r2's translated Type-5 presence on rname matches `present`."
    tgen = get_topogen()
    output = tgen.gears[rname].vtysh_cmd(
        "show ip ospf database external json", isjson=True
    )
    has = any(
        lsa.get("linkStateId") == LSID and lsa.get("advertisingRouter") == R2_ROUTER_ID
        for lsa in output.get("asExternalLinkStates", [])
    )
    if has == present:
        return None
    return "translated type5 on %s present=%s, expected=%s" % (rname, has, present)


def _r2_xlt_seq():
    "Return the sequence number of r2's translated Type-5, or None."
    tgen = get_topogen()
    output = tgen.gears["r2"].vtysh_cmd(
        "show ip ospf database external json", isjson=True
    )
    for lsa in output.get("asExternalLinkStates", []):
        if (
            lsa.get("linkStateId") == LSID
            and lsa.get("advertisingRouter") == R2_ROUTER_ID
        ):
            return lsa.get("lsaSeqNumber")
    return None


def _wait_xlt_stable(quiet=10, timeout=60):
    "Wait until r2's translated Type-5 is unchanged for `quiet` seconds."
    prev, stable = None, 0
    for _ in range(timeout):
        seq = _r2_xlt_seq()
        stable = stable + 1 if seq is not None and seq == prev else 0
        if stable >= quiet:
            return True
        prev = seq
        time.sleep(1)
    return False


def _r3_route():
    "Return None once r3 has installed the prefix via OSPF."
    tgen = get_topogen()
    output = tgen.gears["r3"].vtysh_cmd("show ip route %s json" % PREFIX, isjson=True)
    routes = output.get(PREFIX) if isinstance(output, dict) else None
    if routes and any(r.get("protocol") == "ospf" for r in routes):
        return None
    return "route not installed via OSPF on r3"


def test_ospf_nssa_xlt_dbsync():
    "Translated Type-5 must be sent to a new normal-area neighbor in DB exchange."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for r1-r2 adjacency")
    _, result = topotest.run_and_expect(
        partial(_adjacency_full, "r1"), None, count=30, wait=1
    )
    assert result is None, "r1-r2 adjacency did not reach Full"

    logger.info("waiting for r2 to translate the Type-7 into a Type-5")
    _, result = topotest.run_and_expect(
        partial(_xlt_type5, "r2", True), None, count=30, wait=1
    )
    assert result is None, "r2 did not translate the Type-7 (%s)" % result

    # Make sure no further Type-7/Type-5 re-origination is pending, so the
    # only way r3 can learn the Type-5 is through database exchange.
    logger.info("waiting for r2's translated Type-5 to settle")
    assert _wait_xlt_stable(), "r2's translated Type-5 kept changing"
    seq = _r2_xlt_seq()

    logger.info("enabling OSPF on r3 after translation")
    tgen.gears["r3"].vtysh_cmd(
        "configure terminal\nrouter ospf\nnetwork 198.51.100.0/30 area 0\nend"
    )

    _, result = topotest.run_and_expect(
        partial(_adjacency_full, "r3"), None, count=30, wait=1
    )
    assert result is None, "r2-r3 adjacency did not reach Full"

    # Well below the ~30 minute LSA refresh, so r3 can only have learned
    # the Type-5 through database exchange.
    _, result = topotest.run_and_expect(
        partial(_xlt_type5, "r3", True), None, count=20, wait=1
    )
    assert result is None, (
        "r3 did not receive the translated Type-5 during database exchange "
        "(%s)" % result
    )

    # If r2 re-originated the Type-5 meanwhile, r3 may have got it by
    # flooding instead of database exchange, so the check above proves nothing.
    assert (
        _r2_xlt_seq() == seq
    ), "r2's translated Type-5 changed while r3 joined (%s -> %s)" % (
        seq,
        _r2_xlt_seq(),
    )

    _, result = topotest.run_and_expect(_r3_route, None, count=20, wait=1)
    assert result is None, "r3 did not install %s" % PREFIX

    logger.info("translated Type-5 must not be sent into the NSSA")
    assert _xlt_type5("r1", False) is None, "translated Type-5 leaked into area 1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
