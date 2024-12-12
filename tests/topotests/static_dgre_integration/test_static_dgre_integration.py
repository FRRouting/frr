#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2024 6WIND S.A.
#
"""
Test static route integration with DGRE
"""

import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA)

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_static_dgre_add_vrf():
    """Add 800 VRF interface using a shell script"""

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    out = r1.cmd("bash %s reconf" % os.path.join(CWD, "r1/test.sh"))
    count = r1.cmd("ip -br l show type vrf | wc -l")
    assert int(count) == 800, "800 VRF interface were expected"


def test_static_dgre_add_routes():
    """
    Add 4000 dgre interfaces in the 800 VRFs.
    Add one IPv4 and one IPv6 route via each interface - total 8000.
    This process uses the test.sh script that calls in parallel dgre.py

    test.sh checks that all the routes are present during 60 seconds after
    the configuration process.
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.cmd("bash %s add" % os.path.join(CWD, "r1/test.sh"))
    count = r1.cmd(
        "ip route show table all | grep dgre | egrep -v '^local|^anycast|^multicast|^fe80::/64' | wc -l"
    )
    assert int(count) == 8000, "8000 routes were expected"


def test_static_dgre_del_routes():
    """
    Remove all dgre interfaces and their routes.
    This process uses the test.sh script that calls in parallel dgre.py

    test.sh checks that all the routes are removing during 60 seconds after
    the unconfiguration process.
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.cmd("bash %s del" % os.path.join(CWD, "r1/test.sh"))
    count = r1.cmd(
        "ip route show table all | grep dgre | egrep -v '^local|^anycast|^multicast|^fe80::/64' | wc -l"
    )
    assert int(count) == 0, "No routes were expected"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
