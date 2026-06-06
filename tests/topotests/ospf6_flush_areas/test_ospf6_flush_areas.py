#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf6_flush_areas.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by Olasupo Okunaiya
#

"""
test_ospf6_flush_areas.py: Test that OSPFv3 flushes self-originated LSAs in
*all* areas when the process is reset.

When an OSPFv3 process is reset or removed, ospf6d sets its self-originated
LSAs to MaxAge and refloods them (RFC 2328 section 14.1) so neighbours can
remove them from their link-state databases. This must happen for every area
the router participates in, not just the first one.

Topology:

           area 0            area 1
   r2 ------------- r1 ------------- r3

r1 is an ABR with one interface in area 0 (towards r2) and one in area 1
(towards r3). Once OSPFv3 has converged, both r2 and r3 hold r1's
self-originated Router-LSA in their respective area databases.

The test resets the OSPFv3 process on r1 ("clear ipv6 ospf6 process") and
verifies that r1's Router-LSA is aged out (set to MaxAge) on BOTH neighbours.

Regression test for the bug where ospf6_flush_self_originated_lsas_now()
reused the area-loop listnode for the inner interface loop, so the area
iteration stopped after the first area and self-originated LSAs in all
other areas were never flushed (the area 1 neighbour kept the stale LSA).
"""

import os
import sys
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospf6d]

R1_ROUTER_ID = "10.0.0.1"
OSPF6_LSA_MAXAGE = 3600


def build_topo(tgen):
    "Build function"

    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # r1-eth0 <-> r2-eth0 (area 0), r1-eth1 <-> r3-eth0 (area 1)
    tgen.gears["r1"].add_link(tgen.gears["r2"])
    tgen.gears["r1"].add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _r1_router_lsa_age(router):
    """Return the age of r1's area-scoped Router-LSA as seen by `router`,
    or None if it is not present."""
    tgen = get_topogen()
    output = tgen.gears[router].vtysh_cmd("show ipv6 ospf6 database router")
    for line in output.splitlines():
        fields = line.split()
        # Type LSId AdvRouter Age SeqNum ...
        # Rtr  0.0.0.0  10.0.0.1  11  80000002  ...
        if len(fields) >= 5 and fields[0] == "Rtr" and fields[2] == R1_ROUTER_ID:
            try:
                return int(fields[3])
            except ValueError:
                return None
    return None


def _r1_full_neighbor_count():
    "Return how many of r1's neighbours are in Full state."
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd("show ipv6 ospf6 neighbor json", isjson=True)
    return len([n for n in output.get("neighbors", []) if n.get("state") == "Full"])


def _converged():
    """Return None once r1 has both adjacencies Full and both neighbours
    hold r1's Router-LSA."""
    if _r1_full_neighbor_count() < 2:
        return "adjacencies not Full"
    for rname in ("r2", "r3"):
        if _r1_router_lsa_age(rname) is None:
            return "r1 Router-LSA missing on {}".format(rname)
    return None


def _expect_maxage(router):
    age = _r1_router_lsa_age(router)
    # The LSA must actually be observed at MaxAge. A missing LSA (age is
    # None) must NOT be treated as success: during "clear ipv6 ospf6
    # process" the unfixed code path also makes the area 1 neighbour's copy
    # disappear transiently (adjacency bounce / re-origination), so accepting
    # None here would let the buggy code pass this regression test.
    if age is not None and age >= OSPF6_LSA_MAXAGE:
        return None
    return "age={}".format(age)


def test_ospf6_converge():
    "Wait until both adjacencies are Full and both neighbours have r1's LSA."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for OSPFv3 to converge")
    _, result = topotest.run_and_expect(_converged, None, count=90, wait=1)
    assert result is None, "OSPFv3 did not converge: {}".format(result)

    # Let the link-state databases settle so the flush is reliably flooded.
    topotest.sleep(3, "settling LSDBs before flush")


def test_ospf6_flush_all_areas_on_reset():
    "Reset the OSPFv3 process on r1 and check it is flushed from all areas."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Sanity: both neighbours currently hold a non-expired copy of r1's LSA.
    for rname in ("r2", "r3"):
        age = _r1_router_lsa_age(rname)
        assert (
            age is not None and age < OSPF6_LSA_MAXAGE
        ), "precondition failed on {}: r1 Router-LSA age={}".format(rname, age)

    # Trigger the self-originated LSA flush across all areas.
    tgen.gears["r1"].vtysh_cmd("clear ipv6 ospf6 process")

    # r1's Router-LSA must be set to MaxAge on BOTH the area 0 neighbour (r2)
    # and the area 1 neighbour (r3). Without the fix, the flush stops after
    # the first area and r3 keeps r1's LSA at its normal age.
    for rname in ("r2", "r3"):
        logger.info("checking r1's Router-LSA reaches MaxAge on %s", rname)
        test_func = partial(_expect_maxage, rname)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, (
            "r1's self-originated Router-LSA was not flushed (set to MaxAge) "
            "on {} - self-originated LSAs not flushed in all areas".format(rname)
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
