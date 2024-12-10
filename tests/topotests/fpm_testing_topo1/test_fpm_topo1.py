#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_route_scale1.py
#
# Copyright (c) 2024 by
# Nvidia, Inc.
# Donald Sharp
#

"""
test_fpm_topo1.py: Testing FPM module

"""
import os
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


pytestmark = [pytest.mark.fpm, pytest.mark.sharpd]


def build_topo(tgen):
    "Build function"

    # Populate routers
    tgen.add_router("r1")

    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])


def setup_module(module):
    "Setup topology"

    # fpm_stub = os.system("which fpm-stub")
    # if fpm-stub:
    #    pytest.skip("")

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
            "-M dplane_fpm_nl",
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_FPM_LISTENER,
            os.path.join(CWD, "{}/fpm_stub.conf".format(rname)),
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_fpm_connection_made():
    "Test that the fpm starts up and a connection is made"

    tgen = get_topogen()
    router = tgen.gears["r1"]

    fpm_counters = "{}/r1/fpm_counters.json".format(CWD)
    expected = json.loads(open(fpm_counters).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show fpm status json", expected
    )

    success, result = topotest.run_and_expect(test_func, None, 30, 1)
    assert success, "Unable to connect to the fpm:\n{}".format(result)


def test_fpm_install_routes():
    "Test that simple routes installed appears to work"

    tgen = get_topogen()
    router = tgen.gears["r1"]

    # Let's install 10000 routes
    router.vtysh_cmd("sharp install routes 10.0.0.0 nexthop 192.168.44.33 10000")
    routes_file = "{}/r1/routes_summ.json".format(CWD)
    expected = json.loads(open(routes_file).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route summ json", expected
    )

    success, result = topotest.run_and_expect(test_func, None, 60, 1)
    assert success, "Unable to successfully install 10000 routes: {}".format(result)

    # Let's remove 10000 routes
    router.vtysh_cmd("sharp remove routes 10.0.0.0 10000")

    routes_file_removed = "{}/r1/routes_summ_removed.json".format(CWD)
    expected = json.loads(open(routes_file_removed).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route summ json", expected
    )

    success, result = topotest.run_and_expect(test_func, None, 60, 1)
    assert success, "Unable to remove 10000 routes: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
