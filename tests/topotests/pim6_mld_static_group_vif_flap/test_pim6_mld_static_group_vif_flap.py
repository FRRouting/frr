#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_pim6_mld_static_group_vif_flap.py: a configured `ipv6 mld static-group`
must come back after its interface's VIF is deleted and re-created (link
flap, address change).

Regression test for a stale-activation strand: pim_if_del_vif() tears down
the VIF and every OIF on it but never touches static_group_list, so
stgrp->oilp survives holding a stale channel OIL reference.  Both paths that
could revive the entry test that pointer -- static_group_activate() returns
early when it is set, and pim_if_static_group_replay() only activates entries
whose oilp is NULL -- so after a link flap the static group is silently dead
until the configuration is removed and re-added.

The static-group is added at RUNTIME, not in the startup config: startup
activation strands on its own, independently of the flap defect this file
guards.  Measured on this topology with `debug pimv6 events`: the northbound
applies `ipv6 mld static-group` BEFORE `ipv6 pim` inside the same startup
transaction, so the first activation fails in
pim_ifchannel_local_membership_add() ("PIM is not configured on this
interface"), and the replay that fires moments later still finds no usable
RPF interface; nothing re-activates on pim-enable or on NHT resolution, so
the entry never recovers.  That is a separate upstream defect (activation is
replayed only on VIF/address events, never reconciled) and would mask this
test's baseline.

Topology (same shape as pim6_mld_static_group_shared_oif):

    r1 ---- s1 ---- r2 ---- s2 (receiver stub)

r1 is only a PIM6 neighbor: r2 RPF-resolves the (never-sending) source
through a static route toward r1, so the (S,G) upstream has a real RPF
interface and the OIL can be built.  The static group is the ONLY subscriber
on r2-eth1 -- no learned MLD membership anywhere, so nothing can mask the
strand by re-joining.
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

    # s2: r2's receiver stub -- the static group's interface
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
    the running config and `show ipv6 mld static-group` still show the entry
    while stgrp->oilp holds its stale reference."""
    data = _json_cmd("r2", "show ipv6 mroute json")
    if data is None:
        return "r2: unparseable v6 mroute JSON (pim6d dead?)"
    sg = data.get(GROUP6, {}).get(SOURCE6, {})
    if not sg:
        return "r2 has no ({}, {}) mroute at all".format(SOURCE6, GROUP6)
    # The outgoing interfaces are a SUB-object under "oil", not keys of the
    # (S,G) entry itself.
    oil = sg.get("oil", {})
    if OIF not in oil:
        return "r2 ({}, {}) OIL is missing {}: oil={}".format(SOURCE6, GROUP6, OIF, oil)
    return None


def _oif_absent():
    """Inverse predicate, used to prove the flap really tore the state down
    before asserting on the recovery."""
    if _oif_present() is None:
        return "r2 ({}, {}) still has {} in the OIL".format(SOURCE6, GROUP6, OIF)
    return None


def _add_static_group():
    get_topogen().gears["r2"].vtysh_cmd(
        """
configure terminal
interface {0}
 ipv6 mld static-group {1} {2}
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


def test_static_group_builds_oil():
    """A static group added at runtime, as the only subscriber, builds the
    OIL -- the baseline state the flap below must restore."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _add_static_group()

    _, result = topotest.run_and_expect(_oif_present, None, count=90, wait=1)
    assert result is None, result


def test_static_group_survives_link_flap():
    """Down/up the static group's interface; the OIF must come back.

    The down leg is asserted too: if the flap did not actually delete the
    VIF and its OIF, the recovery assertion would pass vacuously and this
    test would guard nothing.

    Before the fix the recovery times out: pim_if_del_vif() left
    stgrp->oilp pointing at the torn-down channel OIL, so
    pim_if_static_group_replay() on the way back up skips the entry and
    static_group_activate() short-circuits on it forever after."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.run("ip link set dev {} down".format(OIF))

    _, result = topotest.run_and_expect(_oif_absent, None, count=30, wait=1)
    assert result is None, (
        "link down did not tear down the ({}, {}) OIF -- the flap premise "
        "does not hold on this platform: {}".format(SOURCE6, GROUP6, result)
    )

    r2.run("ip link set dev {} up".format(OIF))

    _, result = topotest.run_and_expect(_oif_present, None, count=90, wait=1)
    assert result is None, (
        "static-group did not reactivate after the link flap (stale "
        "stgrp->oilp strand): {}".format(result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
