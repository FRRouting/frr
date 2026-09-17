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

    try:
        step("Install a static ECMP route")
        route_cmd("")

        def get_parent_id():
            route = json.loads(r1.vtysh_cmd(f"show ip route {prefix} json"))
            if prefix not in route:
                return None
            return route[prefix][0].get("receivedNexthopGroupId")

        _, result = topotest.run_and_expect(
            lambda: get_parent_id() is not None, True, count=30, wait=1
        )
        assert result, "Static ECMP route has no received NHG"
        parent_id = get_parent_id()

        parent = nhg(parent_id)
        assert parent and len(parent.get("depends", [])) == 2
        dependency_refs = {
            dependency_id: nhg(dependency_id)["refCount"]
            for dependency_id in parent["depends"]
        }
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

        for dependency_id, refcount in dependency_refs.items():
            current_refcount = nhg(dependency_id)["refCount"]
            logger.info(
                "Dependency NHG %s refcount after reuse: %s",
                dependency_id,
                current_refcount,
            )
            assert current_refcount == refcount
    finally:
        route_cmd("no")


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
