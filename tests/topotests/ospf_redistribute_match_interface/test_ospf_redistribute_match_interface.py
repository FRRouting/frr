#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if `match interface` works for recursive routes.
"""

import os
import re
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def build_topo(tgen):
    tgen.add_router("leaf1")
    tgen.add_router("leaf2")
    tgen.add_router("spine1")
    tgen.add_router("spine2")
    tgen.add_router("exit1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["leaf1"])
    switch.add_link(tgen.gears["spine1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["leaf1"])
    switch.add_link(tgen.gears["spine2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["leaf2"])
    switch.add_link(tgen.gears["spine1"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["leaf2"])
    switch.add_link(tgen.gears["spine2"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["leaf2"])
    switch.add_link(tgen.gears["exit1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_redistribute_match_interface():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    exit1 = tgen.gears["exit1"]

    def _check_routes():
        output = json.loads(exit1.vtysh_cmd("show ip route ospf json"))
        expected = {
            "10.10.10.10/32": [
                {
                    "installed": True,
                    "metric": 1,
                }
            ],
            "192.168.1.0/31": [
                {
                    "installed": True,
                    "metric": 1,
                }
            ],
            "192.168.1.2/31": [
                {
                    "installed": True,
                    "metric": 2,
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _check_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "Some/all redistributed routes have incorrect metric attribute assigned"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
