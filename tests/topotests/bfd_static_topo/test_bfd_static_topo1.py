#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_static_topo1.py
#
# Copyright (c) 2024 by Varun Hegde

"""
test_bfd_static_topo1.py: Test the FRR multiple static routes over same gateway with BFD tracking.
"""

import os
import sys
import json
import platform
from functools import partial
import pytest

pytestmark = [pytest.mark.staticd, pytest.mark.bfdd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("rt1:eth-rt1", "rt2:eth-rt2"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()

def filter_dynamic_fields(json_data):
    if isinstance(json_data, str):
        json_data = json.loads(json_data)

    # If it's a list of BFD sessions
    for entry in json_data:
        entry.pop("id", None)
        entry.pop("remote-id", None)
        entry.pop("uptime", None)
    return json_data

def filtered_router_json_cmp(router, command, expected):
    output = router.vtysh_cmd(command)
    return topotest.json_cmp(filter_dynamic_fields(output),
                             filter_dynamic_fields(expected))


def router_compare_json_output(rname, command, reference, count=5, wait=5, is_down=False):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    if not is_down:
        expected = json.loads(open(filename).read())
    else:
        # If the BFD session is down, we expect the output to be empty
        expected = []

    # print("Output filtered: {}\n".format(output_filtered))
    # print("Expected: {}\n".format(expected))
    test_func = partial(filtered_router_json_cmp, tgen.gears[rname], command, expected)

    # Run test function until we get an result. Wait at most 25 seconds.
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg



#### Test cases for BFD static routes ####

def test_bfd_static_routes_step1():
    logger.info("Test (step 1): verify BFD peers for staic routes peer")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # BFD is just used on three routers
    for rt in ["rt1", "rt2"]:
        router_compare_json_output(
            rt, "show bfd peers json", "show_bfd_peers.ref"
        )

def test_bfd_static_routes_step2():
    logger.info("Test (step 2): verify BFD static routes")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    
    # Now we will remove the BFD static routes and check that the BFD session is still up
    tgen.gears["rt1"].vtysh_cmd("no ip route 192.170.1.3/32 10.0.1.2 bfd")
    tgen.gears["rt2"].vtysh_cmd("no ip route 192.169.1.3/32 10.0.1.1 bfd")
    # Check that the BFD session is still up
    for rt in ["rt1", "rt2"]:
        router_compare_json_output(
            rt, "show bfd peers json", "show_bfd_peers.ref"
        )

    tgen.gears["rt1"].vtysh_cmd("no ip route 192.170.1.2/32 10.0.1.2 bfd")
    tgen.gears["rt2"].vtysh_cmd("no ip route 192.169.1..2/32 10.0.1.1 bfd")
    
    # Check that the BFD session is still up
    for rt in ["rt1", "rt2"]:
        router_compare_json_output(
            rt, "show bfd peers json", "show_bfd_peers.ref"
        )

    # Now remove the last static route which has BFD tracking and veryfy that the BFD session is down
    tgen.gears["rt1"].vtysh_cmd("no ip route 192.170.1.4/32 10.0.1.2 bfd")
    tgen.gears["rt2"].vtysh_cmd("no ip route 192.169.1.4/32 10.0.1.1 bfd")
    for rt in ["rt1", "rt2"]:
        router_compare_json_output(
            rt, "show bfd peers json", "show_bfd_peers.ref", is_down=True
        )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
