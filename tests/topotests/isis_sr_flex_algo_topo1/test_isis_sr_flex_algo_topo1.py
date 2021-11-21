#!/usr/bin/env python

#
# test_isis_flex_algo_srv6_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# LINE Corporation, Hiroki Shirokura <hiroki.shirokura@linecorp.com>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_isis_sr_flex_algo_topo1.py:

[+] Flex-Algos 201 exclude red
[+] Flex-Algos 202 exclude blue
[+] Flex-Algos 203 exclude green
[+] Flex-Algos 204 include-any blue green
[+] Flex-Algos 205 include-any red green
[+] Flex-Algos 206 include-any red blue
[+] Flex-Algos 207 include-all yellow orange

     +--------+  10.12.0.0/24  +--------+
     |        |       red      |        |
     |   RT1  |----------------|   RT2  |
     |        |                |        |
     +--------+                +--------+
  10.13.0.0/24 \\             / 10.23.0.0/24
          green \\           / blue
         yellow  \\         / yellow
          orange  +--------+ orange
                  |        |
                  |   RT3  |
                  |        |
                  +--------+
"""

import os
import sys
import pytest
import json
import tempfile
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.isisd]

# Global multi-dimensional dictionary containing all expected outputs
outputs = {}


def build_topo(tgen):
    "Build function"

    def connect_routers(tgen, left_idx, right_idx):
        left = "rt{}".format(left_idx)
        right = "rt{}".format(right_idx)
        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))
        l_addr = "52:54:00:{}:{}:{}".format(left_idx, right_idx, left_idx)
        tgen.gears[left].run("ip link set eth-{} down".format(right))
        tgen.gears[left].run("ip link set eth-{} address {}".format(right, l_addr))
        tgen.gears[left].run("ip link set eth-{} up".format(right))
        r_addr = "52:54:00:{}:{}:{}".format(left_idx, right_idx, right_idx)
        tgen.gears[right].run("ip link set eth-{} down".format(left))
        tgen.gears[right].run("ip link set eth-{} address {}".format(left, r_addr))
        tgen.gears[right].run("ip link set eth-{} up".format(left))

    tgen.add_router("rt1")
    tgen.add_router("rt2")
    tgen.add_router("rt3")
    connect_routers(tgen, 1, 2)
    connect_routers(tgen, 2, 3)
    connect_routers(tgen, 3, 1)

    #
    # Populate multi-dimensional dictionary containing all expected outputs
    #
    number_of_steps = 10
    filenames = [
        "show_mpls_table.ref",
    ]
    for rname in ["rt1", "rt2", "rt3"]:
        outputs[rname] = {}
        for step in range(1, number_of_steps + 1):
            outputs[rname][step] = {}
            for filename in filenames:
                if step == 1:
                    # Get snapshots relative to the expected initial network convergence
                    filename_pullpath = "{}/{}/step{}/{}".format(CWD, rname, step, filename)
                    outputs[rname][step][filename] = open(filename_pullpath).read()
                else:
                    # Get diff relative to the previous step
                    filename_pullpath = "{}/{}/step{}/{}.diff".format(CWD, rname, step, filename)

                    # Create temporary filenames in order to apply the diff
                    f_in = tempfile.NamedTemporaryFile(mode="w")
                    f_in.write(outputs[rname][step - 1][filename])
                    f_in.flush()
                    f_out = tempfile.NamedTemporaryFile(mode="r")
                    os.system(
                        "patch -s -o %s %s %s" % (f_out.name, f_in.name, filename_pullpath)
                    )

                    # Store the updated snapshot and remove the temporary filenames
                    outputs[rname][step][filename] = open(f_out.name).read()
                    f_in.close()
                    f_out.close()


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    if not os.path.isfile(os.path.join(frrdir, "pathd")):
        pytest.skip("pathd daemon wasn't built")
    tgen.start_topology()
    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config( TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname)))
        router.load_config( TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname)))
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def setup_testcase(msg):
    logger.info(msg)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def router_compare_json_output(rname, command, reference):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    expected = json.loads(reference)

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    #TODO(slankdev): count 20->120
    _, diff = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


#
# Step 1
#
# Test initial network convergenece
#
# All flex-algo are defined and its fib entries are installed
#
def test_step1_mpls_lfib():
    logger.info("Test (step 1)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][1]["show_mpls_table.ref"])


#
# Step 2
#
# Action(s):
# - Disable flex-algo-203 definition advertisement on rt1
#
# Expected change(s):
# - Nothing
#
# Description:
#   No change occurs because it refers to the FAD set in rt2.
#
# TODO(slankdev): additional test case should be exist for FAD ownership check
#   FAD order is compared by isis systemID if the order has the same priority.
#   When the FAD publicity from rt1 is lost, the FAD of rt2 becomes effective,
#   but it is not currently managed by the operational state, but we should
#   check in this step that the FAD owner will be changed in the future.
#
def test_step2_mpls_lfib():
    logger.info("Test (step 2)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          flex-algo 203
           no advertise-definition
        """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][2]["show_mpls_table.ref"])


#
# Step 3
#
# Action(s):
# - Disable flex-algo-203 definition advertisement on rt2
#
# Expected change(s):
# - rt1,rt2,rt3 should uninstall all Prefix-SIDs of flex-algo-203
#
# Description:
#   When all FADs are disappeared, all their prefix sid routes are withdrawn.
#
def test_step3_mpls_lfib():
    logger.info("Test (step 3)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt2"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          flex-algo 203
           no advertise-definition
        """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][3]["show_mpls_table.ref"])


#
# Step 4
#
# Action(s):
# - Enable flex-algo-203 definition advertisement on rt2
#
# Expected change(s):
# - rt1,rt2,rt3 should install all Prefix-SIDs of flex-algo-203
#
# Description:
#   Since the FAD is restored, the reachability to the Prefix-SID is restored.
#
# TODO(slankdev): additional test case should be exist for FAD ownership check
#
def test_step4_mpls_lfib():
    logger.info("Test (step 4)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt2"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          flex-algo 203
           advertise-definition
        """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][4]["show_mpls_table.ref"])


#
# Step 5
#
# Action(s):
# - Enable flex-algo-203 definition advertisement on rt1
#
# Expected change(s):
# - Nothing
#
# Description:
#   This does not affect the FIB, since there is already a FAD for rt2.
#   However, the FAD owner will be changed from rt2 to rt1.
#
# TODO(slankdev): additional test case should be exist for FAD ownership check
#
def test_step5_mpls_lfib():
    logger.info("Test (step 5)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          flex-algo 203
           advertise-definition
        """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][5]["show_mpls_table.ref"])


#
# Step 6
#
# Action(s):
# - Disable flex-algo-203 all configuration on rt1
# - Disable flex-algo-203 all configuration on rt2
# - Disable flex-algo-203 all configuration on rt3
#
# Expected change(s):
# - rt1,rt2,rt3 should uninstall all Prefix-SIDs of flex-algo-203
#
# Description:
#   Clear the Flex-Algo 203 whole settings on each routers. All routes related
#   to it will be withdrawn.
#
def test_step6_mpls_lfib():
    logger.info("Test (step 6)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3"]:
        tgen.gears[rname].vtysh_cmd(
            """
            configure terminal
             router isis 1
              no flex-algo 203
            """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][6]["show_mpls_table.ref"])


#
# Step 7
#
# Action(s):
# - Enable flex-algo-203 all configuration on rt1
# - Enable flex-algo-203 all configuration on rt2
# - Enable flex-algo-203 all configuration on rt3
#
# Expected change(s):
# - rt1,rt2,rt3 should install all Prefix-SIDs of flex-algo-203
#
# Description:
#   All configurations were backed.
#
def test_step7_mpls_lfib():
    logger.info("Test (step 7)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          flex-algo 203
           advertise-definition
           affinity exclude-any green
        """)

    tgen.gears["rt2"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          flex-algo 203
           advertise-definition
           affinity exclude-any green
        """)

    tgen.gears["rt3"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          flex-algo 203
        """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][7]["show_mpls_table.ref"])


#
# Step 8
#
# Action(s):
# - Disable algorithm prefix-sid of algo-203 on rt1
#
# Expected change(s):
# - rt1 should uninstall all Prefix-SIDs of flex-algo-203
# - rt2 should uninstall Prefix-SIDs of rt1's flex-algo-203
# - rt3 should uninstall Prefix-SIDs of rt1's flex-algo-203
#
def test_step8_mpls_lfib():
    logger.info("Test (step 8)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          no segment-routing prefix 1.1.1.1/32 algorithm 203 index 301
          no segment-routing prefix 2001:db8:1000::1/128 algorithm 203 index 1301
        """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][8]["show_mpls_table.ref"])


#
# Step 9
#
# Action(s):
# - Enable algorithm prefix-sid of algo-203 on rt1
#
# Expected change(s):
# - rt1 should install all Prefix-SIDs of flex-algo-203
# - rt2 should install Prefix-SIDs of rt1's flex-algo-203
# - rt3 should install Prefix-SIDs of rt1's flex-algo-203
#
def test_step9_mpls_lfib():
    logger.info("Test (step 9)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          segment-routing prefix 1.1.1.1/32 algorithm 203 index 301
          segment-routing prefix 2001:db8:1000::1/128 algorithm 203 index 1301
        """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][9]["show_mpls_table.ref"])


#
# Step 10
#
# Action(s):
# - Update algorithm prefix-sid of algo-203 on rt1 from 301 to 311
#
# Expected change(s):
# - rt2 should update Prefix-SIDs of rt1's flex-algo-203 from 301 to 311
# - rt3 should update Prefix-SIDs of rt1's flex-algo-203 from 301 to 311
#
def test_step10_mpls_lfib():
    logger.info("Test (step 10)")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          segment-routing prefix 1.1.1.1/32 algorithm 203 index 311
          segment-routing prefix 2001:db8:1000::1/128 algorithm 203 index 1311
        """)

    # For Developers
    # tgen.mininet_cli()
    for rname in ["rt1", "rt2", "rt3"]:
        router_compare_json_output(
            rname, "show mpls table json",
            outputs[rname][10]["show_mpls_table.ref"])


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
