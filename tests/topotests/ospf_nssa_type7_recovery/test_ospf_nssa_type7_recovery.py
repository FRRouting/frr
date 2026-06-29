#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_nssa_type7_recovery.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by Olasupo Okunaiya
#

"""
test_ospf_nssa_type7_recovery.py: NSSA Type-7 LSA recovery once an NSSA
forwarding address becomes available again.

If a self-originated external route is redistributed while the ASBR has no
usable OSPF interface address in the NSSA area, ospfd cannot build a Type-7
forwarding address and discards the Type-7 LSA. A redistribution-update
that runs while the interface is still down fails the same way. Nothing
re-attempts origination when the interface later comes back up, so the
Type-7 LSA stays missing until redistribution is manually refreshed or OSPF
is restarted.

Topology:

            area 1 (NSSA)
   r1 (ASBR) -------------- r2
   redistribute static

r1 is a pure NSSA ASBR whose only NSSA interface is r1-eth0. The test:
  1. brings r1-eth0 down (no usable NSSA forwarding address),
  2. redistributes a static route (Type-7 cannot be originated),
  3. forces a redistribution update while the interface is still down so it
     runs and fails to build a forwarding address,
  4. brings r1-eth0 back up.

After recovery the Type-7 LSA must be re-originated on r1 and the route
learned by the NSSA neighbour r2. Without the fix nothing reschedules the
redistribution update on interface up, so the Type-7 stays missing.
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

pytestmark = [pytest.mark.ospfd]

R1_ROUTER_ID = "10.255.1.1"
STATIC_PREFIX = "10.20.40.0/24"
STATIC_LSID = "10.20.40.0"


def build_topo(tgen):
    "Build function"
    for n in (1, 2):
        tgen.add_router("r%d" % n)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


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


def _adjacency_full():
    tgen = get_topogen()
    if "Full" in tgen.gears["r1"].vtysh_cmd("show ip ospf neighbor"):
        return None
    return "adjacency not Full"


def _r1_type7(present):
    "Return None when the presence of r1's NSSA Type-7 LSA matches `present`."
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd(
        "show ip ospf database nssa-external json", isjson=True
    )
    lsas = output.get("nssaExternalLinkStates", {}).get("areas", {}).get("0.0.0.1", [])
    has = any(
        lsa.get("linkStateId") == STATIC_LSID
        and lsa.get("advertisingRouter") == R1_ROUTER_ID
        for lsa in lsas
    )
    if has == present:
        return None
    return "type7 present=%s, expected=%s" % (has, present)


def _r2_route():
    "Return None once r2 has installed the redistributed prefix via OSPF."
    tgen = get_topogen()
    output = tgen.gears["r2"].vtysh_cmd(
        "show ip route %s json" % STATIC_PREFIX, isjson=True
    )
    routes = output.get(STATIC_PREFIX) if isinstance(output, dict) else None
    if routes and any(r.get("protocol") == "ospf" for r in routes):
        return None
    return "route not installed via OSPF on r2"


def _fwd_addr_failures():
    "Count the Type-7 forwarding-address failures logged by r1's ospfd."
    tgen = get_topogen()
    path = os.path.join(tgen.logdir, "r1", "ospfd.log")
    try:
        with open(path) as logf:
            return logf.read().count("Could not build FWD-ADDR")
    except OSError:
        return 0


def test_ospf_nssa_type7_recovery():
    "Type-7 must be re-originated once the NSSA interface (and FA) recovers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Log Type-7 forwarding-address failures so the test can detect, by
    # polling the log (instead of sleeping), that a redistribution update has
    # actually run while the interface is down.
    r1.vtysh_cmd("debug ospf nssa")

    logger.info("waiting for the OSPF adjacency to reach Full")
    _, result = topotest.run_and_expect(_adjacency_full, None, count=30, wait=1)
    assert result is None, "adjacency did not reach Full"

    # 1. Remove the only usable NSSA forwarding address.
    logger.info("bringing r1-eth0 down (no usable NSSA forwarding address)")
    r1.run("ip link set r1-eth0 down")

    # 2. Redistribute a static route while no forwarding address exists; the
    #    Type-7 origination attempt fails to build a forwarding address.
    logger.info("redistributing a static route while the interface is down")
    r1.vtysh_cmd("configure terminal\nip route 10.20.40.0/24 Null0\nend")
    _, result = topotest.run_and_expect(
        lambda: None if _fwd_addr_failures() >= 1 else "no FA failure yet",
        None,
        count=30,
        wait=1,
    )
    assert result is None, "Type-7 origination did not fail while interface down"

    # 3. Force a redistribution update while the interface is still down and
    #    wait (by polling the log, not sleeping) until it too runs and fails to
    #    build a forwarding address. After this no redistribution update is
    #    pending, so only interface recovery can re-originate the Type-7 LSA.
    failures = _fwd_addr_failures()
    r1.vtysh_cmd("configure terminal\nrouter ospf\ndefault-metric 10\nend")
    _, result = topotest.run_and_expect(
        lambda: (
            None if _fwd_addr_failures() > failures else "redist update not run yet"
        ),
        None,
        count=30,
        wait=1,
    )
    assert result is None, "redistribution update did not run while interface down"

    # Precondition: the Type-7 LSA could not be originated.
    assert _r1_type7(False) is None, (
        "precondition failed: NSSA Type-7 unexpectedly present while the "
        "NSSA interface is down"
    )

    # 4. Bring the NSSA interface back up: a forwarding address is now
    #    available, so the Type-7 must be re-originated and the route learned.
    logger.info("bringing r1-eth0 back up; Type-7 must now be re-originated")
    r1.run("ip link set r1-eth0 up")

    _, result = topotest.run_and_expect(
        partial(_r1_type7, True), None, count=45, wait=1
    )
    assert result is None, (
        "NSSA Type-7 LSA was not re-originated on r1 after the NSSA interface "
        "recovered (%s)" % result
    )

    _, result = topotest.run_and_expect(_r2_route, None, count=30, wait=1)
    assert result is None, (
        "NSSA neighbour r2 did not learn %s after recovery" % STATIC_PREFIX
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
