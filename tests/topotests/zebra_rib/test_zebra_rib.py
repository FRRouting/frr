#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_rib.py
#
# Copyright (c) 2019 by
# Cumulus Networks, Inc
# Donald Sharp
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
import platform

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from time import sleep


pytestmark = [pytest.mark.sharpd]
krel = platform.release()


def config_macvlan(tgen, r_str, device, macvlan):
    "Creates specified macvlan interace on physical device"

    if topotest.version_cmp(krel, "5.1") < 0:
        return

    router = tgen.gears[r_str]
    router.run(
        "ip link add {} link {} type macvlan mode bridge".format(macvlan, device)
    )
    router.run("ip link set {} up".format(macvlan))


def setup_module(mod):
    "Sets up the pytest environment"
    # 8 links to 8 switches on r1
    topodef = {"s{}".format(x): ("r1",) for x in range(1, 9)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )

    # Macvlan interface for protodown func test */
    config_macvlan(tgen, "r1", "r1-eth0", "r1-eth0-macvlan")
    # Initialize all routers.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_kernel_route_vrf():
    "Test kernel routes should be removed after interface changes vrf"
    logger.info("Test kernel routes should be removed after interface changes vrf")
    vrf = "RED"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    # Add kernel routes, the interface is initially in default vrf
    r1.run("ip route add 3.5.1.0/24 via 192.168.210.1 dev r1-eth0")
    json_file = "{}/r1/v4_route_1_vrf_before.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 3.5.1.0/24 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, '"r1" JSON output mismatches'

    # Change the interface's vrf
    r1.run("ip link add {} type vrf table 1".format(vrf))
    r1.run("ip link set {} up".format(vrf))
    r1.run("ip link set dev r1-eth0 master {}".format(vrf))

    expected = "{}"
    test_func = partial(
        topotest.router_output_cmp, r1, "show ip route 3.5.1.0/24 json", expected
    )
    result, diff = topotest.run_and_expect(test_func, "", count=5, wait=1)
    assertmsg = "{} should not have the kernel route.\n{}".format('"r1"', diff)
    assert result, assertmsg

    # Clean up
    r1.run("ip link set dev r1-eth0 nomaster")
    r1.run("ip link del dev {}".format(vrf))


def test_zebra_kernel_admin_distance():
    "Test some basic kernel routes added that should be accepted"
    logger.info("Test some basic kernel routes that should be accepted")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # Route with 255/8192 metric

    distance = 255
    metric = 8192

    def makekmetric(dist, metric):
        return (dist << 24) + metric

    r1.run(
        "ip route add 4.5.1.0/24 via 192.168.210.2 dev r1-eth0 metric "
        + str(makekmetric(255, 8192))
    )
    # Route with 1/1 metric
    r1.run(
        "ip route add 4.5.2.0/24 via 192.168.211.2 dev r1-eth1 metric "
        + str(makekmetric(1, 1))
    )
    # Route with 10/1 metric
    r1.run(
        "ip route add 4.5.3.0/24 via 192.168.212.2 dev r1-eth2 metric "
        + str(makekmetric(10, 1))
    )
    # Same route with a 160/1 metric
    r1.run(
        "ip route add 4.5.3.0/24 via 192.168.213.2 dev r1-eth3 metric "
        + str(makekmetric(160, 1))
    )

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
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
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
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
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
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
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

    def check_initial_routes_installed(router):
        output = json.loads(router.vtysh_cmd("show ip route summ json"))
        expected = {
            "routes": [{"type": "static", "rib": 2}, {"type": "sharp", "rib": 500}]
        }
        return topotest.json_cmp(output, expected)

    test_func = partial(check_initial_routes_installed, r1)
    success, result = topotest.run_and_expect(test_func, None, count=40, wait=1)

    static_rmapfile = "%s/r1/static_rmap.ref" % (thisDir)
    expected = open(static_rmapfile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()
    logger.info(
        "Does the show route-map static command run the correct number of times"
    )

    def check_static_map_correct_runs():
        actual = r1.vtysh_cmd("show route-map static")
        actual = ("\n".join(actual.splitlines()) + "\n").rstrip()
        return topotest.get_textdiff(
            actual,
            expected,
            title1="Actual Route-map output",
            title2="Expected Route-map output",
        )

    ok, result = topotest.run_and_expect(
        check_static_map_correct_runs, "", count=10, wait=1
    )
    assert ok, result

    sharp_rmapfile = "%s/r1/sharp_rmap.ref" % (thisDir)
    expected = open(sharp_rmapfile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()
    logger.info("Does the show route-map sharp command run the correct number of times")

    def check_sharp_map_correct_runs():
        actual = r1.vtysh_cmd("show route-map sharp")
        actual = ("\n".join(actual.splitlines()) + "\n").rstrip()
        return topotest.get_textdiff(
            actual,
            expected,
            title1="Actual Route-map output",
            title2="Expected Route-map output",
        )

    ok, result = topotest.run_and_expect(
        check_sharp_map_correct_runs, "", count=10, wait=1
    )
    assert ok, result

    logger.info(
        "Add a extension to the static route-map to see the static route go away"
        " and test that the routes installed are correct"
    )

    r1.vtysh_cmd("conf\nroute-map sharp deny 5\nmatch ip address 5")
    # we are only checking the kernel here as that this will give us the implied
    # testing of both the route-map and staticd withdrawing the route
    # let's spot check that the routes were installed correctly
    # in the kernel
    sharp_ipfile = "%s/r1/iproute.ref" % (thisDir)
    expected = open(sharp_ipfile).read().rstrip()
    expected = ("\n".join(expected.splitlines()) + "\n").rstrip()

    def check_routes_installed():
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
        return topotest.get_textdiff(
            actual,
            expected,
            title1="Actual ip route show",
            title2="Expected ip route show",
        )

    ok, result = topotest.run_and_expect(check_routes_installed, "", count=5, wait=1)
    assert ok, result


def test_protodown():
    "Run protodown basic functionality test and report results."
    pdown = False
    count = 0
    tgen = get_topogen()
    if topotest.version_cmp(krel, "5.1") < 0:
        tgen.errors = "kernel 5.1 needed for protodown tests"
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Set interface protodown on
    r1.vtysh_cmd("sharp interface r1-eth0-macvlan protodown")

    # Timeout to wait for dplane to handle it
    while count < 10:
        count += 1
        output = r1.vtysh_cmd("show interface r1-eth0-macvlan")
        if re.search(r"protodown reasons:.*sharp", output):
            pdown = True
            break
        sleep(1)

    assert pdown is True, "Interface r1-eth0-macvlan not set protodown"

    # Set interface protodown off
    r1.vtysh_cmd("no sharp interface r1-eth0-macvlan protodown")

    # Timeout to wait for dplane to handle it
    while count < 10:
        count += 1
        output = r1.vtysh_cmd("show interface r1-eth0-macvlan")
        if not re.search(r"protodown reasons:.*sharp", output):
            pdown = False
            break
        sleep(1)

    assert pdown is False, "Interface r1-eth0-macvlan not set protodown off"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
