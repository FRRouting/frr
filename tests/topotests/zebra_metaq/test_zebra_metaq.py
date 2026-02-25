#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_metaq_plug.py
#
# Test that with the meta queue plugged, NHG updates are deduplicated in the
# meta queue (one entry per nexthop-group id), and that after unplugging
# both groups are processed and created.
#

import json
import os
import sys

import pytest

pytestmark = [pytest.mark.sharpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    "Build single router topology"
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Set up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "frr.conf"),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_SHARP, None)],
        )

    tgen.start_router()


def teardown_module():
    "Tear down the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _get_nhg_current(router):
    """Return current NHG Objects count from 'show zebra metaq json', or None on error."""
    try:
        output = router.vtysh_cmd("show zebra metaq json")
        j = json.loads(output)
        # subqueues[0] is NHG Objects
        return j["subqueues"][0]["Current"]
    except (KeyError, json.JSONDecodeError) as e:
        logger.info("Failed to parse metaq json: %s", e)
        return None


def test_zebra_metaq_plug_dedup():
    "Plug metaq, create NHGs, verify dedup in queue, unplug and verify both groups"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # a) Plug the meta queue
    step("Plug the meta queue")
    r1.vtysh_cmd("zebra test metaq disable")

    # b) Create nexthop-group A
    step("Create nexthop-group A")
    r1.vtysh_cmd(
        """
        configure terminal
        nexthop-group A
        """
    )

    # c) Add first nexthop to A
    step("Add nexthop 10.1.1.1 to nexthop-group A")
    r1.vtysh_cmd(
        """
        configure terminal
        nexthop-group A
        nexthop 10.1.1.1 r1-eth0
        """
    )

    # d) Show metaq has one NHG entry
    step("Verify metaq has 1 entry in NHG Objects")
    nhg_current = _get_nhg_current(r1)
    assert nhg_current == 1, "Expected NHG Objects current 1, got {}".format(
        nhg_current
    )

    # e) Add second nexthop to A, metaq should still have 1 entry
    step("Add second nexthop to A, verify metaq still 1")
    r1.vtysh_cmd(
        """
        configure terminal
        nexthop-group A
        nexthop 10.1.1.2 r1-eth0
        """
    )
    nhg_current = _get_nhg_current(r1)
    assert (
        nhg_current == 1
    ), "Expected NHG Objects current 1 after 2nd nexthop, got {}".format(nhg_current)

    # f) Add 3–4 more nexthops to A, each time metaq should still have 1 entry
    for i in range(3, 7):
        step("Add nexthop 10.1.1.{} to A, verify metaq still 1".format(i))
        r1.vtysh_cmd(
            """
            configure terminal
            nexthop-group A
            nexthop 10.1.1.{i} r1-eth0
            """
        )
        nhg_current = _get_nhg_current(r1)
        assert nhg_current == 1, (
            "Expected NHG Objects current 1 after nexthop 10.1.1.{}, got {}"
        ).format(i, nhg_current)

    # g) Create nexthop-group B, add one nexthop, metaq should have 2 NHG entries
    step("Create nexthop-group B and add one nexthop")
    r1.vtysh_cmd(
        """
        configure terminal
        nexthop-group B
        nexthop 10.1.2.1 r1-eth0
        """
    )
    step("Verify metaq has 2 entries in NHG Objects")
    nhg_current = _get_nhg_current(r1)
    assert nhg_current == 2, "Expected NHG Objects current 2, got {}".format(
        nhg_current
    )

    # h) Add another nexthop to A, metaq should still have 2 NHG entries
    step("Add another nexthop to A, verify metaq still 2")
    r1.vtysh_cmd(
        """
        configure terminal
        nexthop-group A
        nexthop 10.1.1.7 r1-eth0
        """
    )
    nhg_current = _get_nhg_current(r1)
    assert nhg_current == 2, (
        "Expected NHG Objects current 2 after adding nexthop to A, got {}"
    ).format(nhg_current)

    # Unplug the meta queue
    step("Unplug the meta queue")
    r1.vtysh_cmd("no zebra test metaq disable")

    # Wait for meta queue to drain and verify 2 sharp non-singleton NHGs (A and B)
    step("Wait for 2 sharp non-singleton nexthop groups")

    def _two_sharp_nonsingleton_nhgs():
        output = r1.vtysh_cmd("show nexthop-group rib sharp json", isjson=True)
        if not output or "default" not in output:
            return False
        vrf = output["default"]
        if not isinstance(vrf, dict):
            return False
        # Non-singleton = sharp NHG with more than one nexthop, or has "depends"
        # (group that references other NHGs). We expect 2: group A (multi-nh) and B.
        count = 0
        for g in vrf.values():
            if g.get("type") != "sharp":
                continue
            if g.get("nexthopCount", 0) > 1:
                count += 1
            elif "depends" in g:
                count += 1
        return count == 2

    _, result = topotest.run_and_expect(
        _two_sharp_nonsingleton_nhgs, True, count=30, wait=1
    )
    assert (
        result
    ), "Expected 2 sharp non-singleton nexthop groups (A and B) after unplug"
