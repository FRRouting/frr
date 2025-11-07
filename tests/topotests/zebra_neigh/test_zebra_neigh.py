#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_neigh.py
#

"""
test_zebra_neigh.py: Test some basic zebra <-> kernel neighbor interactions
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Import topogen and topotest helpers
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from time import sleep


def build_topo(tgen):
    "Build function"

    # Create routers
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, "-s 90000000"), (TopoRouter.RD_MGMTD, None)],
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_neighbors():
    "Test kernel routes should be removed after interface changes vrf"

    tgen = get_topogen()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.run(
        "ip neigh add 192.168.0.2 lladdr 12:21:80:11:b1:18 dev r1-eth0 nud reachable"
    )
    r1.run(
        "ip neigh add 192.168.0.3 lladdr 12:21:80:11:b1:19 dev r1-eth0 nud reachable extern_learn  proto zebra"
    )
    r1.run(
        "ip neigh add 192.168.0.4 lladdr 12:21:80:11:b1:20 dev r1-eth0 nud reachable extern_learn"
    )

    output = r1.vtysh_cmd("show ip neigh").strip()
    expected = """
Interface            Neighbor                       MAC                #Rules
r1-eth0              192.168.0.2                    12:21:80:11:b1:18  0
r1-eth0              192.168.0.4                    12:21:80:11:b1:20  0
"""
    expected = expected.strip()

    assert output == expected, '"r1" neighbor output mismatches'


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
