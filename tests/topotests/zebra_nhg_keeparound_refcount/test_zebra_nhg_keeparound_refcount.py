#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_nhg_keeparound_refcount.py
#
# Copyright (c) 2026 by
# Pica8, Inc.
# Vic Lan
#

"""Verify NHG dependency references across keep-around reuse."""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_keeparound_reuse_keeps_dependency_refs():
    """Reusing a kept parent must not add dependency references."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    prefix = "203.0.113.0/24"
    nexthops = ["192.168.1.2", "192.168.1.3"]

    def route_cmd(action):
        r1.vtysh_cmd(
            "configure terminal\n"
            f" {action} ip route {prefix} {nexthops[0]}\n"
            f" {action} ip route {prefix} {nexthops[1]}\n"
            "end"
        )

    def nhg(nhg_id):
        output = json.loads(r1.vtysh_cmd(f"show nexthop-group rib {nhg_id} json"))
        return output.get(str(nhg_id))

    def route_nexthops():
        """Return the set of nexthop addresses currently in the RIB route."""
        route = json.loads(r1.vtysh_cmd(f"show ip route {prefix} json"))
        if prefix not in route:
            return set()
        return {nh["ip"] for nh in route[prefix][0].get("nexthops", []) if "ip" in nh}

    def wait_for_nexthops(expected):
        _, result = topotest.run_and_expect(
            lambda: route_nexthops() == expected, True, count=30, wait=1
        )
        assert result, f"Route {prefix} nexthops are not {sorted(expected)}"

    def get_parent_id():
        route = json.loads(r1.vtysh_cmd(f"show ip route {prefix} json"))
        if prefix not in route:
            return None
        return route[prefix][0].get("receivedNexthopGroupId")

    try:
        # Staticd sends nexthop additions/removals one at a time, so zebra
        # can see the route transiently with a single nexthop and create a
        # singleton NHG that depends on one of the ECMP parent's
        # dependencies.  Whether that happens is timing dependent, and such
        # an NHG legitimately holds references on the dependency.  Create
        # (and keep around) both singleton NHGs up front so they are already
        # present when the baseline is recorded and cannot change it later.
        step("Create the single nexthop NHGs used by the transient route states")
        r1.vtysh_cmd(f"configure terminal\n ip route {prefix} {nexthops[0]}\nend")
        wait_for_nexthops({nexthops[0]})
        r1.vtysh_cmd(f"configure terminal\n ip route {prefix} {nexthops[1]}\nend")
        wait_for_nexthops(set(nexthops))
        r1.vtysh_cmd(f"configure terminal\n no ip route {prefix} {nexthops[0]}\nend")
        wait_for_nexthops({nexthops[1]})
        r1.vtysh_cmd(f"configure terminal\n no ip route {prefix} {nexthops[1]}\nend")
        wait_for_nexthops(set())

        step("Install a static ECMP route")
        route_cmd("")
        wait_for_nexthops(set(nexthops))

        parent_id = get_parent_id()
        assert parent_id is not None, "Static ECMP route has no received NHG"

        parent = nhg(parent_id)
        assert parent and len(parent.get("depends", [])) == 2
        dependency_ids = list(parent["depends"])

        def get_dependency_refs():
            refs = {}
            for dependency_id in dependency_ids:
                dependency = nhg(dependency_id)
                if dependency is None:
                    return None
                refs[dependency_id] = dependency["refCount"]
            return refs

        def wait_for_stable_refs():
            """Return the dependency refcounts once two reads in a row match."""
            reads = []

            def refs_stable():
                current = get_dependency_refs()
                stable = current is not None and len(reads) > 0 and reads[-1] == current
                reads.append(current)
                return stable

            _, result = topotest.run_and_expect(refs_stable, True, count=30, wait=1)
            assert result, "Dependency NHG refcounts did not stabilize"
            return reads[-1]

        step("Record the dependency refcounts with the parent route installed")
        dependency_refs = wait_for_stable_refs()
        logger.info(
            "Parent NHG %s dependency refcounts before removal: %s",
            parent_id,
            dependency_refs,
        )

        step("Delete and re-add the route before the keep-around timer expires")
        route_cmd("no")

        def parent_kept():
            parent = nhg(parent_id)
            return parent and parent.get("keepAround") and parent["refCount"] == 1

        _, result = topotest.run_and_expect(parent_kept, True, count=30, wait=1)
        assert result, f"Parent NHG {parent_id} did not enter keep-around"

        route_cmd("")

        def parent_reused():
            parent = nhg(parent_id)
            return parent and not parent.get("keepAround")

        _, result = topotest.run_and_expect(parent_reused, True, count=30, wait=1)
        assert result, f"Parent NHG {parent_id} was not reused"
        wait_for_nexthops(set(nexthops))

        # The route is re-added in several steps, so give zebra a moment to
        # finish before comparing.  A leaked reference never goes away.
        current_refs = wait_for_stable_refs()
        logger.info(
            "Parent NHG %s dependency refcounts after reuse: %s",
            parent_id,
            current_refs,
        )
        assert current_refs == dependency_refs
    finally:
        route_cmd("no")


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
