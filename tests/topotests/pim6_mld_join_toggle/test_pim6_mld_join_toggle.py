#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Blockcast
#

"""
test_pim6_mld_join_toggle.py: `ipv6 mld join-group` (S,G) state must
survive -- and, critically, must remain *removable* -- across an
`ipv6 pim` disable/enable cycle on the receiver interface.

Regression test for a pim6d state-strand: saved configs write the
`ipv6 mld` + `ipv6 mld join-group` lines BEFORE `ipv6 pim`, so on a
config (re)apply the sg's TIB join is refused while PIM is disabled
("PIM is not configured on this interface").  When `ipv6 pim` came
back, pim_if_membership_refresh() used to feed such never-joined sgs
straight into pim_ifchannel_local_membership_add(), bypassing
tib_sg_gm_join(): sg->tib_joined stayed false, every later
gm_sg_update() join retry failed on the duplicate-oif check, and
removing the join-group skipped the prune -- the INCLUDE membership
(and with it the oif and the upstream) was stranded until pim6d
restarted, immune even to join-group add/remove cycles.

Topology:

    r1 ---- s1 ---- r2 ---- s2 (receiver stub)

r1 is only a PIM6 neighbor: r2 RPF-resolves the (never-sending) source
2001:db8:10::10 through a static route toward r1, so the (S,G) upstream
has a real RPF interface and oil -- required to enter the vulnerable
state.  The join-group lives on r2-eth1, where r2 is its own MLD
querier and the kernel join-group socket supplies the MLDv2 report.
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
    (membership gone, upstream gone) vacuously -- every predicate must
    treat None as failure."""
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


def test_baseline_join():
    """Adding the join-group produces INCLUDE local membership on r2-eth1
    and a Joined (S,G) upstream -- the module's steady state.  The join is
    added at runtime, NOT in the startup config: a join-group configured
    before zebra delivers the interface (ifindex still 0 at config-from-file
    time) never issues the kernel socket join, so no MLDv2 report is ever
    emitted for the querier to learn from."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 mld join-group {0} {1}
""".format(GROUP6, SOURCE6)
    )

    def _baseline():
        data = _json_cmd("r2", "show ipv6 pim local-membership json")
        if data is None:
            return "r2: unparseable v6 local-membership JSON (pim6d dead?)"
        row = data.get("r2-eth1", {}).get(GROUP6, {})
        if row.get("localMembership") != "INCLUDE":
            return "r2 v6 local membership not formed: {}".format(data)
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        if ups.get(GROUP6, {}).get(SOURCE6, {}).get("joinState") != "Joined":
            return "r2 (S,G) upstream not Joined: {}".format(ups)
        return None

    _, result = topotest.run_and_expect(_baseline, None, count=90, wait=1)
    assert result is None, result


def test_join_group_pim_toggle_leaves_cleanly():
    """Disable `ipv6 pim`, cycle the join-group inside the pim-off window
    (forming a FRESH sg whose first TIB join is refused), re-enable
    `ipv6 pim`, then remove the join-group: the membership, oif and
    upstream must all tear down, and a re-add must be claimable again."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ipv6 pim
"""
    )

    def _membership_torn_down():
        data = _json_cmd("r2", "show ipv6 pim upstream json")
        if data is None:
            # a dead pim6d must NOT satisfy this absence-assertion
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        if data.get(GROUP6, {}).get(SOURCE6, {}).get("joinState") == "Joined":
            return "r2 v6 upstream survived pim disable: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_membership_torn_down, None, count=30, wait=1)
    assert result is None, result

    # Cycle the join-group INSIDE the pim-off window: the removal tears
    # down the old sg (which still owned TIB state from the pim-on era),
    # and the re-add creates a FRESH sg whose very first TIB join is
    # refused ("PIM is not configured on this interface") -- the exact
    # vulnerable state pim_if_membership_refresh() used to mishandle.
    # Merely toggling pim around an already-joined sg never enters it.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ipv6 mld join-group {0} {1}
""".format(GROUP6, SOURCE6)
    )

    # The old sg must be FULLY gone before the re-add, or the fresh join
    # just refreshes it and the vulnerable state never forms.  sg death
    # needs the last-member query cycle to run out.
    def _sg_gone():
        data = _json_cmd("r2", "show ipv6 mld joins json")
        if data is None:
            return "r2: unparseable v6 mld joins JSON (pim6d dead?)"
        if GROUP6 in json.dumps(data):
            return "r2 old MLD sg still alive: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_sg_gone, None, count=60, wait=1)
    assert result is None, result

    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 mld join-group {0} {1}
""".format(GROUP6, SOURCE6)
    )

    def _fresh_sg_formed():
        data = _json_cmd("r2", "show ipv6 mld joins json")
        if data is None:
            return "r2: unparseable v6 mld joins JSON (pim6d dead?)"
        if GROUP6 not in json.dumps(data):
            return "r2 fresh MLD sg not formed under pim-off: {}".format(data)
        return None

    _, result = topotest.run_and_expect(_fresh_sg_formed, None, count=30, wait=1)
    assert result is None, result

    # re-enable in saved-config order: the mld + join-group lines are
    # already present, `ipv6 pim` comes last, so membership_refresh runs
    # against a live-but-never-joined sg.  The clear nudges the querier so
    # the kernel's join-group socket re-reports promptly instead of
    # waiting out a general query interval.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 pim
"""
    )
    tgen.gears["r2"].vtysh_cmd("clear ipv6 mld interfaces")

    def _membership_reformed():
        data = _json_cmd("r2", "show ipv6 pim local-membership json")
        if data is None:
            return "r2: unparseable v6 local-membership JSON (pim6d dead?)"
        row = data.get("r2-eth1", {}).get(GROUP6, {})
        if row.get("localMembership") != "INCLUDE":
            return "r2 v6 local membership not re-formed: {}".format(data)
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        if ups.get(GROUP6, {}).get(SOURCE6, {}).get("joinState") != "Joined":
            return "r2 v6 upstream not re-Joined after pim toggle: {}".format(ups)
        return None

    _, result = topotest.run_and_expect(_membership_reformed, None, count=90, wait=1)
    assert result is None, result

    # THE regression: removing the join-group must tear everything down.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 no ipv6 mld join-group {} {}
""".format(GROUP6, SOURCE6)
    )

    def _leave_cleans_up():
        data = _json_cmd("r2", "show ipv6 pim local-membership json")
        if data is None:
            return "r2: unparseable v6 local-membership JSON (pim6d dead?)"
        row = data.get("r2-eth1", {}).get(GROUP6, {})
        if row.get("localMembership") == "INCLUDE":
            return "r2 v6 local membership stranded after leave: {}".format(data)
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        if ups.get(GROUP6, {}).get(SOURCE6, {}).get("joinState") == "Joined":
            return "r2 v6 upstream stranded after leave: {}".format(ups)
        return None

    _, result = topotest.run_and_expect(_leave_cleans_up, None, count=90, wait=1)
    assert result is None, result

    # re-add: a leaked oif would make this join unclaimable ("OIF twice"),
    # so a working re-join doubles as proof nothing was left behind.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
interface r2-eth1
 ipv6 mld join-group {} {}
""".format(GROUP6, SOURCE6)
    )

    def _rejoin_works():
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        if ups.get(GROUP6, {}).get(SOURCE6, {}).get("joinState") != "Joined":
            return "r2 v6 upstream did not re-Join after re-add: {}".format(ups)
        return None

    _, result = topotest.run_and_expect(_rejoin_works, None, count=90, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
