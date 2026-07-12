#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim_igmp_join_startup.py: an `ip igmp join-group` present in the
STARTUP configuration must produce a working join once the interface
comes up -- the IPv4 twin of pim6_mld_join_startup.

Before the deferred-join fix, IPv4 behavior at config load (interface
still at ifindex 0) was a race: the kernel either route-resolved the
ifindex-0 join onto some wrong device (later healed by the address-add
socket replay) or rejected it outright, in which case gm_join_new()
dropped the entry and nothing ever joined.  The fix replaces both
outcomes with a deterministic defer-then-replay, and this test pins
that determinism: unlike the IPv6 twin it is a regression guard for
the new deferral path rather than a fail-leg reproducer, because the
pre-fix outcome depended on kernel route state at daemon start.

Topology:

    r1 ---- s1 ---- r2 ---- s2 (receiver stub)

r1 is only a PIM neighbor: r2 RPF-resolves the (never-sending) source
10.10.10.10 through a static route toward r1.  The join-group is in
r2's startup frr.conf on r2-eth1, where r2 is its own IGMP querier
and the kernel join-group socket supplies the IGMPv3 report.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

SOURCE = "10.10.10.10"
GROUP = "232.1.1.10"


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: the RPF segment (r1 is r2's PIM neighbor toward the source)
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
        router.load_frr_config("frr.conf", daemons=["zebra", "pimd"])

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


def test_pim_neighbor_up():
    """r2 sees r1 as a PIM neighbor on the RPF segment."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _neighbor_up():
        data = _json_cmd("r2", "show ip pim neighbor json")
        if data is None:
            return "r2: unparseable pim neighbor JSON (pimd dead?)"
        if not data.get("r2-eth0"):
            return "r2 has no PIM neighbor on r2-eth0: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_neighbor_up, None, count=60, wait=1)
    assert result is None, result


def test_startup_join_group_becomes_live():
    """THE regression guard: the startup-config join-group must form an
    IGMP group on r2-eth1 (proving the deferred socket join was replayed
    onto the right interface and its report hit the wire) and INCLUDE
    local membership.  That pair is the direct effect of the fix; the
    (S,G) upstream's RPF/join convergence is a separate concern (staticd
    route + nexthop resolution + PIM neighbor) covered by other suites,
    so it is deliberately not asserted here -- it only adds cross-daemon
    timing flakiness on slow runners without exercising this code path."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _startup_join_live():
        groups = _json_cmd("r2", "show ip igmp groups json")
        if groups is None:
            return "r2: unparseable igmp groups JSON (pimd dead?)"
        # key the check to r2-eth1: the bug's failure mode is the kernel
        # subscribing on the WRONG interface, which a whole-blob substring
        # match would not catch
        iface_groups = groups.get("r2-eth1", {})
        if GROUP not in json.dumps(iface_groups):
            return "r2 startup join-group formed no IGMP group on r2-eth1: {}".format(
                groups
            )
        data = _json_cmd("r2", "show ip pim local-membership json")
        if data is None:
            return "r2: unparseable local-membership JSON (pimd dead?)"
        row = data.get("r2-eth1", {}).get(GROUP, {})
        if row.get("localMembership") != "INCLUDE":
            return "r2 local membership not formed: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_startup_join_live, None, count=90, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
