#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_import.py
#
# Copyright (c) 2024 ATCorp
# Nathan Bahr
#

import os
import sys
from functools import partial
import pytest
import json
import platform

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step, write_test_header

"""
test_zebra_import.py: Test zebra table import functionality
"""

TOPOLOGY = """
    Single router zebra functionality

                 +---+---+
    10.0.0.1/24  |       |  10.10.0.1/24
            <--->+  R1   +<--->
                 |       |
                 +---+---+
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.sharpd]
krel = platform.release()

def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")
    sw1 = tgen.add_switch("sw1")
    sw2 = tgen.add_switch("sw2")
    sw1.add_link(tgen.gears["r1"], "r1-eth0")
    sw2.add_link(tgen.gears["r1"], "r1-eth1")

def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr-import.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_urib_import(request):
    "Verify router starts with the initial URIB"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify initial main routing table")
    initial_json_file = "{}/r1/import_init_table.json".format(CWD)
    expected = json.loads(open(initial_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 
        """)
    
    import_json_file = "{}/r1/import_table_2.json".format(CWD)
    expected = json.loads(open(import_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Add a new static route and verify it gets added")
    r1.vtysh_cmd(
        """
        conf term
         ip route 10.20.0.0/24 10.10.0.2 table 10
        """
    )

    sync_json_file = "{}/r1/import_table_3.json".format(CWD)
    expected = json.loads(open(sync_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Remove the static route and verify it gets removed")
    r1.vtysh_cmd(
        """
        conf term
         no ip route 10.20.0.0/24 10.10.0.2 table 10
        """
    )

    expected = json.loads(open(import_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Disable table import and verify it goes back to the initial table")
    r1.vtysh_cmd(
        """
        conf term
         no ip import-table 10 
        """
    )

    expected = json.loads(open(initial_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Re-import with distance and verify correct distance")
    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 distance 123
        """)
    
    import_json_file = "{}/r1/import_table_4.json".format(CWD)
    expected = json.loads(open(import_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

def test_zebra_mrib_import(request):
    "Verify router starts with the initial MRIB"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify initial main MRIB routing table")
    initial_json_file = "{}/r1/import_init_mrib_table.json".format(CWD)
    expected = json.loads(open(initial_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip rpf json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 mrib
        """)
    
    import_json_file = "{}/r1/import_mrib_table_2.json".format(CWD)
    expected = json.loads(open(import_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip rpf json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Add a new static route and verify it gets added")
    r1.vtysh_cmd(
        """
        conf term
         ip route 10.20.0.0/24 10.10.0.2 table 10
        """
    )

    sync_json_file = "{}/r1/import_mrib_table_3.json".format(CWD)
    expected = json.loads(open(sync_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip rpf json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Remove the static route and verify it gets removed")
    r1.vtysh_cmd(
        """
        conf term
         no ip route 10.20.0.0/24 10.10.0.2 table 10
        """
    )

    expected = json.loads(open(import_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip rpf json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Disable table import and verify it goes back to the initial table")
    r1.vtysh_cmd(
        """
        conf term
         no ip import-table 10 mrib
        """
    )

    expected = json.loads(open(initial_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip rpf json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Re-import with distance and verify correct distance")
    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 mrib distance 123
        """)
    
    import_json_file = "{}/r1/import_mrib_table_4.json".format(CWD)
    expected = json.loads(open(import_json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip rpf json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
