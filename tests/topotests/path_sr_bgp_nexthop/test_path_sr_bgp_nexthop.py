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
"""

import os
import sys
import pytest
import json
import tempfile
from functools import partial
import re

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
    connect_routers(tgen, 1, 2)

    #
    # Populate multi-dimensional dictionary containing all expected outputs
    #
    number_of_steps = 10
    filenames = [
        "show_mpls_table.ref",
    ]
    for rname in ["rt1", "rt2"]:
        outputs[rname] = {}
        for step in range(1, number_of_steps + 1):
            outputs[rname][step] = {}


#            for filename in filenames:
#                if step == 1:
#                    # Get snapshots relative to the expected initial network convergence
#                    filename_pullpath = "{}/{}/step{}/{}".format(CWD, rname, step, filename)
#                    outputs[rname][step][filename] = open(filename_pullpath).read()
#                else:
#                    # Get diff relative to the previous step
#                    filename_pullpath = "{}/{}/step{}/{}.diff".format(CWD, rname, step, filename)
#
#                    # Create temporary filenames in order to apply the diff
#                    f_in = tempfile.NamedTemporaryFile(mode="w")
#                    f_in.write(outputs[rname][step - 1][filename])
#                    f_in.flush()
#                    f_out = tempfile.NamedTemporaryFile(mode="r")
#                    os.system(
#                        "patch -s -o %s %s %s" % (f_out.name, f_in.name, filename_pullpath)
#                    )
#
#                    # Store the updated snapshot and remove the temporary filenames
#                    outputs[rname][step][filename] = open(f_out.name).read()
#                    f_in.close()
#                    f_out.close()


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
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
        )
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

    # Run test function until we get a result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def _router_patmatch_cmd(router, command, pat, re_flags=0):
    """Run command and try to match pattern"""

    cstr = router.vtysh_cmd(command)
    m = re.search(pat, cstr, re_flags)
    if m:
        return True
    return False


def router_patmatch_output(rname, command, pat, re_flags=0):
    """Compare router text output"""
    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()

    test_func = partial(_router_patmatch_cmd, tgen.gears[rname], command, pat, re_flags)
    _, matched = topotest.run_and_expect(test_func, True, count=120, wait=0.5)
    assertmsg = '"{}" cmd output mismatches the expected result'.format(rname)
    assert matched is True, assertmsg


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

    #
    # rt1: verify that policy is active
    #
    router_patmatch_output(
        "rt1",
        "show sr-te policy detail",
        r"Endpoint\:\s*2\.2\.2\.2\s+Color\:\s*1\s.*Status\:\s*Active",
        re.IGNORECASE,
    )

    #
    # rt1: verify that bgp route is valid and best
    #
    router_patmatch_output(
        "rt1", "show bgp ipv4", r"^\s*\*\>i10\.200\.0\.0\/24\s+2\.2\.2\.2", re.MULTILINE
    )

    #
    # rt1: verify route is installed and has expected labeled nexthop
    #
    router_patmatch_output(
        "rt1",
        "show ip route 10.200.0.0/24",
        r"\s+\*\s*10\.12\.0\.2,\s*via\s+eth-rt2,\s+label\s+32500",
        0,
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
