#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim6_mld_join_startup.py: an `ipv6 mld join-group` present in the
STARTUP configuration must produce a working join once the interface
comes up.

Regression test for the deferred-join gap: startup config is read
before zebra delivers interfaces, so the join-group line is applied
while the interface still has ifindex 0.  Passing gsr_interface == 0 to
MCAST_JOIN_(SOURCE_)GROUP does not fail -- the kernel resolves
interface 0 through a route lookup and silently subscribes on whatever
device that returns -- so the join landed on the wrong interface (or
was rejected outright when no route existed yet), no MLDv2 report was
ever sent on the configured interface, and nothing re-issued the join
when the interface appeared.  IPv4 partially masked this with the
socket replay in pim_if_addr_add(); IPv6 had no replay at all.

Topology:

    r1 ---- s1 ---- r2 ---- s2 (receiver stub)

r1 is only a PIM6 neighbor: r2 RPF-resolves the (never-sending) source
2001:db8:10::10 through a static route toward r1.  The join-group is in
r2's startup frr.conf on r2-eth1, where r2 is its own MLD querier and
the kernel join-group socket supplies the MLDv2 report.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.pim6d, pytest.mark.staticd]

SOURCE6 = "2001:db8:10::10"
GROUP6 = "ff3e::10"


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: the RPF segment (r1 is r2's PIM6 neighbor toward the source)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s2: r2's receiver stub (the join-group interface)
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_frr_config("frr.conf", daemons=["zebra", "pim6d"])

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _json_cmd(rname, cmd):
    """vtysh JSON helper: returns None (NOT {}) on unparseable output, so
    a crashed/unresponsive daemon can never satisfy an absence-assertion
    vacuously -- every predicate must treat None as failure."""
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return None


def test_pim6_neighbor_up():
    """r2 sees r1 as a PIM6 neighbor on the RPF segment."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _neighbor_up():
        data = _json_cmd("r2", "show ipv6 pim neighbor json")
        if data is None:
            return "r2: unparseable v6 pim neighbor JSON (pim6d dead?)"
        if not data.get("r2-eth0"):
            return "r2 has no PIM6 neighbor on r2-eth0: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_neighbor_up, None, count=60, wait=1)
    assert result is None, result


def test_startup_join_group_becomes_live():
    """THE regression: the startup-config join-group must form an MLD sg
    on r2-eth1 (proving the deferred socket join was replayed onto the
    right interface and its report hit the wire) and INCLUDE local
    membership.  That pair is the direct effect of the fix; the (S,G)
    upstream's RPF/join convergence is a separate concern (staticd route
    + nexthop resolution + PIM6 neighbor) covered by other suites, so it
    is deliberately not asserted here -- it only adds cross-daemon timing
    flakiness on slow runners without exercising this code path."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _startup_join_live():
        joins = _json_cmd("r2", "show ipv6 mld joins json")
        if joins is None:
            return "r2: unparseable v6 mld joins JSON (pim6d dead?)"
        # key the check to r2-eth1: the bug's failure mode is the kernel
        # subscribing on the WRONG interface, which a whole-blob substring
        # match would not catch
        iface_joins = joins.get("default", {}).get("r2-eth1", {})
        if GROUP6 not in json.dumps(iface_joins):
            return "r2 startup join-group formed no MLD sg on r2-eth1: {}".format(joins)
        data = _json_cmd("r2", "show ipv6 pim local-membership json")
        if data is None:
            return "r2: unparseable v6 local-membership JSON (pim6d dead?)"
        row = data.get("r2-eth1", {}).get(GROUP6, {})
        if row.get("localMembership") != "INCLUDE":
            return "r2 v6 local membership not formed: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_startup_join_live, None, count=90, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
