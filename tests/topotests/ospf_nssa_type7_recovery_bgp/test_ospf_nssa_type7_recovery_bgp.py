#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_nssa_type7_recovery_bgp.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by Olasupo Okunaiya
#

"""
test_ospf_nssa_type7_recovery_bgp.py: NSSA Type-7 LSA recovery for a
BGP-redistributed route once an NSSA forwarding address becomes available.

Same recovery scenario as test_ospf_nssa_type7_recovery, but the external
route is learned via BGP instead of a local static route, to confirm the
interface-up reschedule re-originates the Type-7 LSA regardless of the
redistributed route's source protocol.

Topology:

            area 1 (NSSA)            eBGP
   r2 -------------- r1 (ASBR) -------------- r4
                  redistribute bgp

r1 is a pure NSSA ASBR. Its only NSSA interface is r1-eth0 (towards r2);
the eBGP session with r4 runs over r1-eth1, which stays up. The test:
  1. brings r1-eth0 down (no usable NSSA forwarding address),
  2. has r4 advertise a prefix that r1 redistributes from BGP (Type-7
     cannot be originated),
  3. forces a redistribution update while the interface is still down so it
     runs and fails to build a forwarding address,
  4. brings r1-eth0 back up.

After recovery the Type-7 LSA must be re-originated on r1 and the route
learned by the NSSA neighbour r2.
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

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]

R1_ROUTER_ID = "10.255.1.1"
BGP_PREFIX = "172.16.20.0/24"
BGP_LSID = "172.16.20.0"


def build_topo(tgen):
    "Build function"
    for n in (1, 2, 4):
        tgen.add_router("r%d" % n)
    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["r2"])
    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r1"])
    s2.add_link(tgen.gears["r4"])


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


def _r1_has_bgp_route():
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd("show ip route bgp json", isjson=True)
    if isinstance(output, dict) and BGP_PREFIX in output:
        return None
    return "r1 has not learned the BGP route yet"


def _r1_type7(present):
    "Return None when the presence of r1's NSSA Type-7 LSA matches `present`."
    tgen = get_topogen()
    output = tgen.gears["r1"].vtysh_cmd(
        "show ip ospf database nssa-external json", isjson=True
    )
    lsas = output.get("nssaExternalLinkStates", {}).get("areas", {}).get("0.0.0.1", [])
    has = any(
        lsa.get("linkStateId") == BGP_LSID
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
        "show ip route %s json" % BGP_PREFIX, isjson=True
    )
    routes = output.get(BGP_PREFIX) if isinstance(output, dict) else None
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


def test_ospf_nssa_type7_recovery_bgp():
    "Type-7 for a BGP route must be re-originated once the NSSA FA recovers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

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

    # 2. Have r4 advertise a prefix that r1 redistributes from BGP while no
    #    forwarding address exists; the Type-7 origination attempt fails to
    #    build a forwarding address.
    logger.info("advertising a BGP prefix while the NSSA interface is down")
    r4.vtysh_cmd(
        "configure terminal\n"
        "ip route 172.16.20.0/24 Null0\n"
        "router bgp 65004\n"
        "address-family ipv4 unicast\n"
        "network 172.16.20.0/24\n"
        "end"
    )
    _, result = topotest.run_and_expect(_r1_has_bgp_route, None, count=30, wait=1)
    assert result is None, "r1 did not learn the BGP route"
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
        "NSSA neighbour r2 did not learn %s after recovery" % BGP_PREFIX
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
