#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nick Bouliane <nbouliane@coreweave.com>
#

"""
bgpd must free a deleted peer whose routes are still being cleared at exit.

r2 is a dynamic neighbor of r1 (bgp listen range) and announces ROUTE_COUNT
routes to it. When the session of a dynamic neighbor goes down, r1 deletes
the peer: it is taken out of the list of peers of the instance, and its
routes are cleared in the background by a work queue that holds a reference
on the peer and that starts 10 ms later.

The test resets the session on r1 and terminates bgpd right after, in one
shell command, so that bgpd exits while that work queue still has routes to
clear. bgpd writes the memory that it did not free at exit to its stderr,
which must be empty. Without the fix it has, among others:

  bgpd: memstats:  BGP instance                  :      1 * ...
  bgpd: memstats:  BGP peer                      :      1 * ...
  bgpd: memstats:  BGP node clear queue          :  ..... * ...

If bgpd is terminated too late, after the routes are cleared, the test passes
whether the fix is there or not: it cannot fail because of the timing.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]

R2_IP = "192.168.1.2"
# Not the address of r1, which would not accept its own address as next hop
NEXTHOP = "192.168.1.3"
ROUTE_COUNT = 20000


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        daemons = ["zebra", "bgpd"]
        if rname == "r2":
            daemons.append("sharpd")
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)), daemons=daemons
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_dynamic_neighbor_routes():
    "r1 has ROUTE_COUNT routes from its dynamic neighbor r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        "sharp install routes 172.16.0.0 nexthop {} {}".format(NEXTHOP, ROUTE_COUNT)
    )

    def _routes_received():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        peer = output.get("ipv4Unicast", output).get("peers", {}).get(R2_IP, {})
        if not peer.get("dynamicPeer"):
            return "{} is not a dynamic neighbor of r1 (yet)".format(R2_IP)
        if peer.get("state") != "Established":
            return "state {}".format(peer.get("state"))
        if peer.get("pfxRcd") != ROUTE_COUNT:
            return "{} routes received".format(peer.get("pfxRcd"))
        return None

    _, result = topotest.run_and_expect(_routes_received, None, count=120, wait=1)
    assert result is None, "r1 does not have {} routes from r2: {}".format(
        ROUTE_COUNT, result
    )


def test_nothing_left_at_exit():
    "bgpd frees everything when it exits right after the neighbor is deleted."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    pid = r1.cmd("cat /var/run/frr/bgpd.pid").strip()
    assert pid.isdigit(), "no pid for bgpd on r1: {!r}".format(pid)

    # One shell command: the routes of the deleted neighbor are cleared a few
    # milliseconds after the session is reset.
    r1.cmd("vtysh -c 'clear bgp {}'; kill -TERM {}".format(R2_IP, pid))

    def _bgpd_gone():
        # A process that exited and that nobody waited for is still in /proc
        status = r1.cmd("cat /proc/{}/status 2>/dev/null || true".format(pid))
        state = [
            line.split()[1]
            for line in status.splitlines()
            if line.startswith("State:")
        ]
        return None if state in ([], ["Z"]) else "bgpd is still running"

    _, result = topotest.run_and_expect(_bgpd_gone, None, count=60, wait=1)
    assert result is None, result

    left = [
        line
        for line in r1.net.getStdErr("bgpd").splitlines()
        if "memstats:" in line or "showing active allocations" in line
    ]

    # bgpd is expected to run when the topology is stopped
    r1.cmd("rm -f /var/run/frr/bgpd.pid")
    r1.startDaemons(["bgpd"])

    assert not left, "bgpd did not free everything at exit:\n{}".format(
        "\n".join(left)
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
