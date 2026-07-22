#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_reconnect_route_replay.py
#
# Copyright (c) 2026 by
# Evelyn0828
#

"""
test_zebra_reconnect_route_replay.py: when zebra restarts while a routing
daemon keeps running, the daemon must replay its already computed/selected
routes to zebra on reconnect, so they are reinstalled without waiting for a
topology change.

r1 originates one distinct prefix into each of OSPF, RIP, IS-IS and BGP and
advertises them to r2 over a shared link:

    [ r1 ] --- r1-eth0 --- sw0 --- r2-eth0 --- [ r2 ]

    r1 stubs:  OSPF 10.0.1.0/24, RIP 10.0.2.0/24, IS-IS 10.0.3.0/24
    r1 BGP network: 10.0.4.0/24

After r2 has installed all four, only zebra is restarted on r2 (the protocol
daemons keep running). The test verifies every prefix is reinstalled in r2's
RIB after zebra comes back, which only happens if each daemon replays its
routes on the zebra reconnect.
"""

import os
import sys
import pytest
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import kill_router_daemons, start_router_daemons

pytestmark = [
    pytest.mark.bgpd,
    pytest.mark.ospfd,
    pytest.mark.ripd,
    pytest.mark.isisd,
]

# prefix -> protocol that should install it on r2
PREFIXES = {
    "10.0.1.0/24": "ospf",
    "10.0.2.0/24": "rip",
    "10.0.3.0/24": "isis",
    "10.0.4.0/24": "bgp",
}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Shared link carrying every protocol adjacency.
    sw0 = tgen.add_switch("sw0")
    sw0.add_link(tgen.gears["r1"])
    sw0.add_link(tgen.gears["r2"])

    # r1 stub interfaces, one per IGP prefix (r1-eth1/2/3).
    for i in range(1, 4):
        sw = tgen.add_switch("sw{}".format(i))
        sw.add_link(tgen.gears["r1"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    daemons = [
        (TopoRouter.RD_ZEBRA, "zebra.conf"),
        (TopoRouter.RD_OSPF, "ospfd.conf"),
        (TopoRouter.RD_RIP, "ripd.conf"),
        (TopoRouter.RD_ISIS, "isisd.conf"),
        (TopoRouter.RD_BGP, "bgpd.conf"),
    ]
    for rname, router in tgen.routers().items():
        for daemon, fname in daemons:
            router.load_config(daemon, os.path.join(CWD, "{}/{}".format(rname, fname)))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _route_installed(router, prefix, proto):
    """Return None when prefix is installed on router via proto with a nexthop."""
    output = router.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
    if not output or prefix not in output:
        return "{} missing from {} RIB".format(prefix, router.name)
    for entry in output[prefix]:
        if entry.get("protocol") != proto:
            continue
        if not entry.get("selected"):
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("ip") and nh.get("active"):
                return None
    return "{} on {} not installed via {}".format(prefix, router.name, proto)


def _all_routes_installed(router):
    for prefix, proto in PREFIXES.items():
        err = _route_installed(router, prefix, proto)
        if err:
            return err
    return None


def test_converge():
    "All four prefixes must be installed on r2 via their protocols."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    _, result = topotest.run_and_expect(
        partial(_all_routes_installed, r2), None, count=120, wait=1
    )
    assert result is None, "r2 did not install all prefixes initially: {}".format(result)
    logger.info("r2 initial routes:\n{}".format(r2.vtysh_cmd("show ip route")))


def test_zebra_reconnect_replays_routes():
    "After only zebra restarts on r2, every protocol must replay its routes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # Make sure we start from a fully converged state.
    _, result = topotest.run_and_expect(
        partial(_all_routes_installed, r2), None, count=120, wait=1
    )
    assert result is None, "preconditions not met: {}".format(result)

    logger.info("Restarting only zebra on r2 (protocol daemons keep running)")
    kill_router_daemons(tgen, "r2", ["zebra"])
    start_router_daemons(tgen, "r2", ["zebra"])

    # On reconnect each daemon must replay its routes; they should reappear
    # without waiting for a topology change.
    _, result = topotest.run_and_expect(
        partial(_all_routes_installed, r2), None, count=60, wait=1
    )
    assert result is None, "r2 did not get routes replayed after zebra restart: {}".format(
        result
    )
    logger.info("r2 routes after zebra restart:\n{}".format(r2.vtysh_cmd("show ip route")))


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        router.stop()
        for daemon in ["zebra", "ospfd", "ripd", "isisd", "bgpd"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
