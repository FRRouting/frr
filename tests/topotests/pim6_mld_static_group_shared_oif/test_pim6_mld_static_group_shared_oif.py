#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_pim6_mld_static_group_shared_oif.py: an `ipv6 mld static-group` and a
learned MLD membership for the SAME (S,G) on the SAME interface are two
independent subscribers to one OIF, and neither may tear it down while the
other still wants it.

Regression test for a shared-flag strand: PIM_OIF_FLAG_PROTO_GM is one bit
per (channel_oil, vif) with NO reference count, and both subscribers claim it
through tib_sg_gm_join().  pim_channel_add_oif() refuses the second with -3
and tib_sg_gm_prune() then removed the OIF, the PIM local membership and the
upstream proxy join on the FIRST leave -- whichever subscriber it belonged to.

Both orderings lose, and neither self-heals:

  * add static-group while a receiver is already joined (what `frr reload`
    does on a running router) is a silent no-op; when that receiver leaves,
    the OIF leaves with it.  The static group is still in the running config
    and still in static_group_list, with no OIF.

  * remove a static-group while a receiver is still joined pulls the OIF out
    from under the live receiver.  gm_sg_update() then takes neither branch,
    so it never comes back.

The failure is invisible to every other signal: the configuration still reads
correctly, `show ipv6 mld static-group` still lists the entry, and only the
OIL disagrees.  That is why this test asserts on the OIL and not on config.

Topology (same shape as pim6_mld_join_toggle):

    r1 ---- s1 ---- r2 ---- s2 (receiver stub)

r1 is only a PIM6 neighbor: r2 RPF-resolves the (never-sending) source
through a static route toward r1, so the (S,G) upstream has a real RPF
interface and the OIL can be built.  Both subscribers live on r2-eth1, where
r2 is its own MLD querier and the kernel join-group socket supplies the
MLDv2 report that creates the LEARNED membership.
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
OIF = "r2-eth1"


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # s1: the RPF segment (r1 is r2's PIM6 neighbor toward the source)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # s2: r2's receiver stub -- both subscribers attach here
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
    """vtysh JSON helper: returns None (NOT {}) on unparseable output, so a
    crashed or unresponsive daemon can never satisfy a presence-assertion
    vacuously -- every predicate must treat None as failure."""
    out = get_topogen().gears[rname].vtysh_cmd(cmd)
    try:
        return json.loads(out)
    except ValueError:
        return None


def _oif_present():
    """None when r2 has the (S,G) OIL entry on OIF, else a reason string.

    The OIL is the ONLY signal that separates the bug from correct behaviour:
    the running config, static_group_list and `show ipv6 mld static-group` all
    still show the entry after the OIF has been torn out from under it."""
    data = _json_cmd("r2", "show ipv6 mroute json")
    if data is None:
        return "r2: unparseable v6 mroute JSON (pim6d dead?)"
    sg = data.get(GROUP6, {}).get(SOURCE6, {})
    if not sg:
        return "r2 has no ({}, {}) mroute at all: {}".format(SOURCE6, GROUP6, data)
    # The outgoing interfaces are a SUB-object under "oil", not keys of the (S,G)
    # entry itself -- the entry's own keys are iif/flags/installed/refCount. Reading
    # the entry directly finds no interface and reports a missing OIF on a perfectly
    # good OIL.
    oil = sg.get("oil", {})
    if OIF not in oil:
        return "r2 ({}, {}) OIL is missing {}: oil={}".format(SOURCE6, GROUP6, OIF, oil)
    return None


def _add_join_group():
    get_topogen().gears["r2"].vtysh_cmd(
        """
configure terminal
interface {0}
 ipv6 mld join-group {1} {2}
""".format(OIF, GROUP6, SOURCE6)
    )


def _del_join_group():
    get_topogen().gears["r2"].vtysh_cmd(
        """
configure terminal
interface {0}
 no ipv6 mld join-group {1} {2}
""".format(OIF, GROUP6, SOURCE6)
    )


def _add_static_group():
    get_topogen().gears["r2"].vtysh_cmd(
        """
configure terminal
interface {0}
 ipv6 mld static-group {1} {2}
""".format(OIF, GROUP6, SOURCE6)
    )


def _del_static_group():
    get_topogen().gears["r2"].vtysh_cmd(
        """
configure terminal
interface {0}
 no ipv6 mld static-group {1} {2}
""".format(OIF, GROUP6, SOURCE6)
    )


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


def test_learned_membership_builds_oil():
    """A learned MLD membership alone builds the OIL -- the starting state
    for both orderings below.

    The join is added at RUNTIME, not in the startup config: a join-group
    configured before zebra delivers the interface (ifindex still 0 at
    config-from-file time) never issues the kernel socket join, so no MLDv2
    report is ever emitted for r2's own querier to learn from."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _add_join_group()

    # RPF must resolve before the OIL can exist at all.
    def _rpf_resolved():
        ups = _json_cmd("r2", "show ipv6 pim upstream json")
        if ups is None:
            return "r2: unparseable v6 pim upstream JSON (pim6d dead?)"
        sg = ups.get(GROUP6, {}).get(SOURCE6, {})
        if not sg:
            return "r2 (S,G) upstream not created yet: {}".format(ups)
        if sg.get("inboundInterface", "Unknown") == "Unknown":
            return "r2 (S,G) upstream RPF not resolved yet: {}".format(ups)
        return None

    _, result = topotest.run_and_expect(_rpf_resolved, None, count=60, wait=1)
    assert result is None, result

    _, result = topotest.run_and_expect(_oif_present, None, count=90, wait=1)
    assert result is None, result


def test_static_group_added_second_survives_receiver_leave():
    """DIRECTION A -- the `frr reload` case.

    Add the static-group while the learned membership already holds the OIF
    (tib_sg_gm_join() takes pim_channel_add_oif()'s -3 / PIM_OIF_ADD_EXISTS
    path), then drop the receiver.  The static group is the last subscriber
    standing and MUST retain the OIF.

    Before the fix the second claim was a silent no-op, so the receiver's
    leave took the OIF with it and nothing ever restored it.

    COVERAGE CAVEAT, measured: this direction PASSES on unfixed master, so it
    does not currently reproduce that half of the defect and must not be counted
    as protecting it. Run against master + this test only, the module scores
    1 failed / 3 passed -- the failure is the REVERSE direction below, which is
    the one this file genuinely guards. Kept because it documents the intended
    invariant and costs nothing; strengthening it (a different add/leave
    interleaving, or asserting on oilSize rather than membership) is open work."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _add_static_group()

    # Both subscribers now hold it; the OIL must be unchanged.
    _, result = topotest.run_and_expect(_oif_present, None, count=30, wait=1)
    assert result is None, result

    _del_join_group()

    # Give a wrong implementation time to tear the OIF down before asserting
    # it is still there: run_and_expect returns on the FIRST success, so
    # without this settle the assertion can pass on stale pre-leave state.
    topotest.sleep(5, "waiting for the receiver leave to be processed")

    result = _oif_present()
    assert result is None, (
        "static-group did not retain the OIF after the learned membership "
        "left (PROTO_GM shared-bit strand): {}".format(result)
    )


def test_static_group_removed_leaves_receiver_oif_intact():
    """DIRECTION B -- the reverse ordering.

    With the static-group holding the OIF, re-add the receiver, then remove
    the static-group.  The learned membership is now the last subscriber and
    MUST keep the OIF.

    Before the fix the static-group's removal pruned the OIF out from under
    the live receiver, and gm_sg_update() then took neither branch, so it
    never came back.

    THIS is the assertion that actually catches the regression: verified to FAIL
    on unfixed master and PASS with the fix, same test binary, same topology."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _add_join_group()

    _, result = topotest.run_and_expect(_oif_present, None, count=60, wait=1)
    assert result is None, result

    _del_static_group()

    topotest.sleep(5, "waiting for the static-group removal to be processed")

    result = _oif_present()
    assert result is None, (
        "removing the static-group tore the OIF out from under the still-joined "
        "receiver (PROTO_GM shared-bit strand): {}".format(result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
