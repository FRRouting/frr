#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Mehran Hashemi <mehranstock1383@gmail.com>
#

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]

def build_topo(tgen):
    tgen.add_router("r1")

def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def test_show_ip_route_redistribute_json():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_route_json():
        output = r1.vtysh_cmd("show ip route 192.168.100.0 json")
        try:
            data = json.loads(output)
            prefix_data = data.get("192.168.100.0/24", [])
            if not prefix_data:
                return "Prefix not found in JSON"

            if "redistributingVia" in prefix_data[0]:
                if "ospf" in prefix_data[0]["redistributingVia"]:
                    return None

            return "redistributingVia key missing or does not contain ospf"
        except json.JSONDecodeError:
            return "Invalid JSON output"

    success, result = topotest.run_and_expect(_check_route_json, None, count=20, wait=1)
    assert success, "JSON test failed: {}".format(result)

def test_show_ip_route_redistribute_cli():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_route_cli():
        output = r1.vtysh_cmd("show ip route 192.168.100.0")
        if "Redistributing via ospf" in output:
            return None
        return "CLI output did not contain 'Redistributing via ospf'"

    success, result = topotest.run_and_expect(_check_route_cli, None, count=20, wait=1)
    assert success, "CLI test failed: {}".format(result)

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
