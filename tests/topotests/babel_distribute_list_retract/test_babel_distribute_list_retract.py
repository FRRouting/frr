#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_babel_distribute_list_retract.py
#
# Copyright (c) 2026 by
# Evelyn0828
#

"""
test_babel_distribute_list_retract.py: Babel must retract a previously
advertised route when an outbound distribute-list change starts denying it,
instead of leaving the stale route reachable on the neighbor until it times
out.

Topology:

    r1-eth1 (stub 10.1.1.0/24)
       |
    [ r1 ] --- r1-eth0 --- sw1 --- r2-eth0 --- [ r2 ]

r1 originates 10.1.1.0/24 (redistribute connected) and advertises it to r2 over
Babel. The test then applies an outbound distribute-list on r1's Babel interface
denying 10.1.1.0/24 and verifies r2 stops forwarding to it promptly (Babel sends
an explicit metric-infinity retraction, so the route is withdrawn / turned into
an unreachable route well before its natural hold time of several update
intervals). Finally it removes the filter and verifies the route is
re-advertised and reachable again.
"""

import os
import sys
import pytest
from functools import partial

pytestmark = [pytest.mark.babeld]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

PREFIX = "10.1.1.0/24"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Babel link: r1-eth0 <-> r2-eth0
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    # Stub on r1 carrying the originated prefix: r1-eth1
    sw2 = tgen.add_switch("sw2")
    sw2.add_link(tgen.gears["r1"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BABEL, os.path.join(CWD, "{}/babeld.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _forwarding_nexthops(router):
    """Return the list of active forwarding nexthops for PREFIX on router.

    A retracted/unreachable route stays in the RIB with a reject ("unreachable")
    nexthop and no gateway, so it is not counted here.
    """
    output = router.vtysh_cmd("show ip route {} json".format(PREFIX), isjson=True)
    if not output or PREFIX not in output:
        return []
    fwd = []
    for entry in output[PREFIX]:
        if entry.get("protocol") != "babel":
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("unreachable") or nh.get("reject") or nh.get("blackhole"):
                continue
            if nh.get("ip"):
                fwd.append(nh)
    return fwd


def _prefix_reachable(router):
    "Return None when PREFIX is installed via babel with a forwarding nexthop."
    if _forwarding_nexthops(router):
        return None
    return "{} is not reachable via babel on {}".format(PREFIX, router.name)


def _prefix_retracted(router):
    "Return None when PREFIX is gone or has no forwarding nexthop left."
    if not _forwarding_nexthops(router):
        return None
    return "{} still has a forwarding nexthop on {}".format(PREFIX, router.name)


def test_converge_protocols():
    "Wait for Babel adjacency between r1 and r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2"]:
        router = tgen.gears[rname]

        def check_convergence(router=router):
            output = router.vtysh_cmd("show babel neighbor")
            if "Neighbour" not in output:
                return "{} has no babel neighbor yet".format(router.name)
            return None

        _, result = topotest.run_and_expect(check_convergence, None, count=60, wait=1)
        assert result is None, "{} failed to establish babel neighbor".format(rname)


def test_route_learned():
    "r2 must learn 10.1.1.0/24 from r1 via Babel as a reachable route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    _, result = topotest.run_and_expect(
        partial(_prefix_reachable, r2), None, count=60, wait=1
    )
    assert result is None, "r2 did not learn a reachable {} via babel".format(PREFIX)


def test_outbound_filter_retracts_route():
    "Denying 10.1.1.0/24 outbound on r1 must retract it from r2 promptly."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Make sure r2 really has it before we deny it.
    _, result = topotest.run_and_expect(
        partial(_prefix_reachable, r2), None, count=60, wait=1
    )
    assert result is None, "r2 never had a reachable {} to retract".format(PREFIX)

    logger.info("Applying outbound distribute-list denying {} on r1-eth0".format(PREFIX))
    r1.vtysh_cmd(
        "configure terminal\n"
        "ip prefix-list DENY10 seq 5 deny {}\n".format(PREFIX)
        + "ip prefix-list DENY10 seq 10 permit any\n"
        "router babel\n"
        "distribute-list prefix DENY10 out r1-eth0\n"
    )

    # The Babel update-interval is 20s, so the route's natural hold time is well
    # over a minute; the explicit retraction makes r2 drop the forwarding path
    # within this much shorter window.
    _, result = topotest.run_and_expect(
        partial(_prefix_retracted, r2), None, count=30, wait=1
    )
    assert result is None, "r2 did not retract {} after outbound deny".format(PREFIX)


def test_route_readvertised_when_filter_removed():
    "Removing the outbound deny must re-advertise 10.1.1.0/24 to r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Removing outbound distribute-list on r1-eth0")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router babel\n"
        "no distribute-list prefix DENY10 out r1-eth0\n"
    )

    _, result = topotest.run_and_expect(
        partial(_prefix_reachable, r2), None, count=60, wait=1
    )
    assert result is None, "r2 did not relearn a reachable {} after filter removal".format(
        PREFIX
    )


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        router.stop()
        for daemon in ["babeld", "zebra"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
