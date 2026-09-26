#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_metaq_plug.py
#
# Test that with the meta queue plugged, NHG updates are deduplicated in the
# meta queue (one entry per nexthop-group id), and that after unplugging
# both groups are processed and created.
#
# Test that when a client goes away, only its own routes are purged from
# the early route queue: the queued routes of another client, of another
# type but with the same instance, are kept and installed.
#

import json
import os
import sys
from functools import partial

import pytest

pytestmark = [pytest.mark.sharpd, pytest.mark.staticd, pytest.mark.freebsd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, step
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

    for router in tgen.routers().values():
        router.load_frr_config(extra_daemons=["sharpd", "staticd"])

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


def test_zebra_metaq_client_close():
    "Plug metaq, queue routes of sharpd and staticd, kill staticd, unplug"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    sharp_routes = 10

    def _get_early_route_current():
        output = json.loads(r1.vtysh_cmd("show zebra metaq json"))
        for subq in output["subqueues"]:
            if subq["SubQ"] == "Early Route Processing":
                return subq["Current"]
        return None

    def _check_early_route_queued(base, expected):
        # Routes of other sources (e.g. an address still coming up) may be
        # queued too: only check that ours are.
        current = _get_early_route_current()
        if current is None or current < base + expected:
            return "Expected at least {} Early Route Processing entries, got {}".format(
                base + expected, current
            )
        return None

    def _check_connected(prefix):
        output = json.loads(r1.vtysh_cmd("show ip route {} json".format(prefix)))
        for entry in output.get(prefix, []):
            if entry.get("protocol") == "connected" and entry.get("selected"):
                return None
        return "Expected connected route {} installed".format(prefix)

    def _check_client_gone(name):
        output = r1.vtysh_cmd("show zebra client summary")
        for line in output.splitlines():
            if line.split() and line.split()[0] == name:
                return "Expected client {} gone: {}".format(name, line)
        return None

    def _check_route_count(proto, expected):
        output = json.loads(r1.vtysh_cmd("show ip route {} json".format(proto)))
        if len(output) != expected:
            return "Expected {} {} routes, got {}: {}".format(
                expected, proto, len(output), sorted(output)
            )
        return None

    # Before plugging, the address of r1-eth0 (the nexthop of the routes of
    # the test) must be up, not queued along with the routes of the test.
    step("Wait for the connected route of r1-eth0")
    _, result = topotest.run_and_expect(
        partial(_check_connected, "10.1.1.0/24"), None, count=30, wait=1
    )
    assert result is None, result

    step("Plug the meta queue")
    r1.vtysh_cmd("zebra test metaq disable")

    try:
        step("Queue {} sharpd routes and 1 static route".format(sharp_routes))
        base = _get_early_route_current()
        r1.vtysh_cmd(
            "sharp install routes 10.10.0.0 nexthop 10.1.1.1 {}".format(sharp_routes)
        )
        r1.vtysh_cmd(
            """
            configure terminal
            ip route 10.20.0.0/24 10.1.1.1
            """
        )
        _, result = topotest.run_and_expect(
            partial(_check_early_route_queued, base, sharp_routes + 1),
            None,
            count=30,
            wait=1,
        )
        assert result is None, result

        # The routes of staticd and sharpd both have instance 0: only the
        # one of staticd must be purged, checked once the meta queue is
        # unplugged (the routes of sharpd installed, not the one of staticd).
        step("Kill staticd, wait for zebra to see it gone")
        kill_router_daemons(tgen, "r1", ["staticd"])
        _, result = topotest.run_and_expect(
            partial(_check_client_gone, "static"), None, count=30, wait=1
        )
        assert result is None, result
    finally:
        step("Unplug the meta queue")
        r1.vtysh_cmd("no zebra test metaq disable")

    step("Verify the sharpd routes are installed")
    _, result = topotest.run_and_expect(
        partial(_check_route_count, "sharp", sharp_routes),
        None,
        count=30,
        wait=1,
    )
    assert result is None, result

    step("Verify the static route is not installed")
    result = _check_route_count("static", 0)
    assert result is None, result
