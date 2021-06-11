#!/usr/bin/env python
#
# test_zebra_rib.py
#
# Copyright (c) 2019 by
# Cumulus Networks, Inc
# Donald Sharp
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
test_zebra_rib.py: Test some basic zebra <-> kernel interactions
"""

import os
import re
import sys
from functools import partial
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from time import sleep

# Required to instantiate the topology builder class.
from mininet.topo import Topo


class ZebraTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        tgen.add_router("r1")

        # Create a empty network for router 1
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(ZebraTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_kernel_admin_distance():
    "Test some basic kernel routes added that should be accepted"
    logger.info("Test some basic kernel routes that should be accepted")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # Route with 255/8192 metric
    r1.run("ip route add 4.5.1.0/24 via 192.168.210.2 dev r1-eth0 metric 4278198272")
    # Route with 1/1 metric
    r1.run("ip route add 4.5.2.0/24 via 192.168.211.2 dev r1-eth1 metric 16777217")
    # Route with 10/1 metric
    r1.run("ip route add 4.5.3.0/24 via 192.168.212.2 dev r1-eth2 metric 167772161")
    # Same route with a 160/1 metric
    r1.run("ip route add 4.5.3.0/24 via 192.168.213.2 dev r1-eth3 metric 2684354561")

    # Currently I believe we have a bug here with the same route and different
    # metric.  That needs to be properly resolved.  Making a note for
    # coming back around later and fixing this.
    # tgen.mininet_cli()
    for i in range(1, 2):
        json_file = "{}/r1/v4_route_{}.json".format(CWD, i)
        expected = json.loads(open(json_file).read())

        test_func = partial(
            topotest.router_json_cmp,
            r1,
            "show ip route 4.5.{}.0 json".format(i),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=2, wait=0.5)
        assertmsg = '"r1" JSON output mismatches'
        assert result is None, assertmsg
    # tgen.mininet_cli()


def test_zebra_kernel_override():
    "Test that a FRR route with a lower admin distance takes over"
    logger.info("Test kernel override with a better admin distance")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf\nip route 4.5.1.0/24 192.168.216.3")
    json_file = "{}/r1/v4_route_1_static_override.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 4.5.1.0 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=2, wait=0.5)
    assert result is None, '"r1" JSON output mismatches'

    logger.info(
        "Test that the removal of the static route allows the kernel to take back over"
    )
    r1.vtysh_cmd("conf\nno ip route 4.5.1.0/24 192.168.216.3")
    json_file = "{}/r1/v4_route_1.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 4.5.1.0 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=2, wait=0.5)
    assert result is None, '"r1" JSON output mismatches'


def test_route_map_usage():
    "Test that FRR only reruns over routes associated with the routemap"
    logger.info("Test that FRR runs on selected re's on route-map changes")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("Skipped because of previous test failure")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    r1 = tgen.gears["r1"]
    # set the delay timer to 1 to improve test coverage (HA)
    r1.vtysh_cmd("conf\nzebra route-map delay-timer 1")
    r1.vtysh_cmd("conf\nroute-map static permit 10\nset src 192.168.215.1")
    r1.vtysh_cmd("conf\naccess-list 5 seq 5 permit 10.0.0.44/32")
    r1.vtysh_cmd("conf\naccess-list 10 seq 5 permit 10.0.1.0/24")
    r1.vtysh_cmd(
        "conf\nroute-map sharp permit 10\nmatch ip address 10\nset src 192.168.214.1"
    )
    r1.vtysh_cmd("conf\nroute-map sharp permit 20\nset src 192.168.213.1")
    r1.vtysh_cmd("conf\nip protocol static route-map static")
    r1.vtysh_cmd("conf\nip protocol sharp route-map sharp")
    sleep(4)
    r1.vtysh_cmd("conf\nip route 10.100.100.100/32 192.168.216.3")
    r1.vtysh_cmd("conf\nip route 10.100.100.101/32 10.0.0.44")
    r1.vtysh_cmd("sharp install route 10.0.0.0 nexthop 192.168.216.3 500")
    sleep(4)

    static_rmapfile = "%s/r1/static_rmap.ref" % (thisDir)
    expected = open(static_rmapfile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()
    actual = r1.vtysh_cmd("show route-map static")
    actual = ("\n".join(actual.splitlines()) + "\n").rstrip()
    logger.info(
        "Does the show route-map static command run the correct number of times"
    )

    diff = topotest.get_textdiff(
        actual,
        expected,
        title1="Actual Route-map output",
        title2="Expected Route-map output",
    )
    if diff:
        logger.info("Actual:")
        logger.info(actual)
        logger.info("Expected:")
        logger.info(expected)
        srun = r1.vtysh_cmd("show run")
        srun = ("\n".join(srun.splitlines()) + "\n").rstrip()
        logger.info("Show run")
        logger.info(srun)
        assert 0, "r1 static route processing:\n"

    sharp_rmapfile = "%s/r1/sharp_rmap.ref" % (thisDir)
    expected = open(sharp_rmapfile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()
    actual = r1.vtysh_cmd("show route-map sharp")
    actual = ("\n".join(actual.splitlines()) + "\n").rstrip()
    logger.info("Does the show route-map sharp command run the correct number of times")

    diff = topotest.get_textdiff(
        actual,
        expected,
        title1="Actual Route-map output",
        title2="Expected Route-map output",
    )
    if diff:
        logger.info("Actual:")
        logger.info(actual)
        logger.info("Expected:")
        logger.info(expected)
        srun = r1.vtysh_cmd("show run")
        srun = ("\n".join(srun.splitlines()) + "\n").rstrip()
        logger.info("Show run:")
        logger.info(srun)
        assert 0, "r1 sharp route-map processing:\n"

    logger.info(
        "Add a extension to the static route-map to see the static route go away"
    )
    r1.vtysh_cmd("conf\nroute-map sharp deny 5\nmatch ip address 5")
    sleep(2)
    # we are only checking the kernel here as that this will give us the implied
    # testing of both the route-map and staticd withdrawing the route
    # let's spot check that the routes were installed correctly
    # in the kernel
    logger.info("Test that the routes installed are correct")
    sharp_ipfile = "%s/r1/iproute.ref" % (thisDir)
    expected = open(sharp_ipfile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()
    actual = r1.run("ip route show")
    actual = ("\n".join(actual.splitlines()) + "\n").rstrip()
    actual = re.sub(r" nhid [0-9][0-9]", "", actual)
    actual = re.sub(r" proto sharp", " proto XXXX", actual)
    actual = re.sub(r" proto static", " proto XXXX", actual)
    actual = re.sub(r" proto 194", " proto XXXX", actual)
    actual = re.sub(r" proto 196", " proto XXXX", actual)
    actual = re.sub(r" proto kernel", " proto XXXX", actual)
    actual = re.sub(r" proto 2", " proto XXXX", actual)
    # Some platforms have double spaces?  Why??????
    actual = re.sub(r"  proto XXXX  ", " proto XXXX ", actual)
    actual = re.sub(r"  metric", " metric", actual)
    actual = re.sub(r" link  ", " link ", actual)
    diff = topotest.get_textdiff(
        actual, expected, title1="Actual ip route show", title2="Expected ip route show"
    )

    if diff:
        logger.info("Actual:")
        logger.info(actual)
        logger.info("Expected:")
        logger.info(expected)
        srun = r1.vtysh_cmd("show run")
        srun = ("\n".join(srun.splitlines()) + "\n").rstrip()
        logger.info("Show run:")
        logger.info(srun)
        assert 0, "r1 ip route show is not correct:"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
