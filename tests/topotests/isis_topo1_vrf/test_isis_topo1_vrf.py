#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by  Niral Networks, Inc. ("Niral Networks")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
test_isis_topo1_vrf.py: Test ISIS vrf topology.
"""

import functools
import json
import os
import re
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.topotest import iproute2_is_vrf_capable
from lib.common_config import required_linux_kernel_version


pytestmark = [pytest.mark.isisd]

VERTEX_TYPE_LIST = [
    "pseudo_IS",
    "pseudo_TE-IS",
    "IS",
    "TE-IS",
    "ES",
    "IP internal",
    "IP external",
    "IP TE",
    "IP6 internal",
    "IP6 external",
    "UNKNOWN",
]


def build_topo(tgen):
    "Build function"

    # Add ISIS routers:
    # r1      r2
    #  | sw1  | sw2
    # r3     r4
    #  |      |
    # sw3    sw4
    #   \    /
    #     r5
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    # r1 <- sw1 -> r3
    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r3"])

    # r2 <- sw2 -> r4
    sw = tgen.add_switch("sw2")
    sw.add_link(tgen.gears["r2"])
    sw.add_link(tgen.gears["r4"])

    # r3 <- sw3 -> r5
    sw = tgen.add_switch("sw3")
    sw.add_link(tgen.gears["r3"])
    sw.add_link(tgen.gears["r5"])

    # r4 <- sw4 -> r5
    sw = tgen.add_switch("sw4")
    sw.add_link(tgen.gears["r4"])
    sw.add_link(tgen.gears["r5"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    logger.info("Testing with VRF Lite support")

    cmds = [
        "ip link add {0}-cust1 type vrf table 1001",
        "ip link add loop1 type dummy",
        "ip link set {0}-eth0 master {0}-cust1",
    ]

    eth1_cmds = ["ip link set {0}-eth1 master {0}-cust1"]

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        # create VRF rx-cust1 and link rx-eth0 to rx-cust1
        for cmd in cmds:
            output = tgen.net[rname].cmd(cmd.format(rname))

        # If router has an rX-eth1, link that to vrf also
        if "{}-eth1".format(rname) in router.links.keys():
            for cmd in eth1_cmds:
                output = output + tgen.net[rname].cmd(cmd.format(rname))

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    # move back rx-eth0 to default VRF
    # delete rx-vrf
    tgen.stop_topology()


def test_isis_convergence():
    "Wait for the protocol to converge before starting to test"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for ISIS protocol to converge")

    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_topology.json".format(CWD, rname)
        expected = json.loads(open(filename).read())

        def compare_isis_topology(router, expected):
            "Helper function to test ISIS vrf topology convergence."
            actual = json.loads(
                router.vtysh_cmd(f"show isis vrf {router.name}-cust1 topology json")
            )
            return topotest.json_cmp(actual, expected)

        test_func = functools.partial(compare_isis_topology, router, expected)
        (result, diff) = topotest.run_and_expect(test_func, None, wait=0.5, count=120)
        assert result, "ISIS did not converge on {}:\n{}".format(rname, diff)


def test_isis_route_installation():
    "Check whether all expected routes are present"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS vrf routes")
    # Check for routes in 'show ip route vrf {}-cust1 json'
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())

        def compare_routing_table(router, expected):
            "Helper function to ensure zebra rib convergence"

            actual = router.vtysh_cmd(
                "show ip route vrf {0}-cust1 json".format(rname), isjson=True
            )
            return topotest.json_cmp(actual, expected)

        test_func = functools.partial(compare_routing_table, router, expected)
        (result, diff) = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = "Router '{}' routes mismatch diff: {}".format(rname, diff)
        assert result, assertmsg


def test_isis_linux_route_installation():
    "Check whether all expected routes are present and installed in the OS"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # iproute2 needs to support VRFs for this suite to run.
    if not iproute2_is_vrf_capable():
        pytest.skip("Installed iproute2 version does not support VRFs")

    logger.info("Checking routers for installed ISIS vrf routes in OS")
    # Check for routes in `ip route show vrf {}-cust1`
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route_linux.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        actual = topotest.ip4_vrf_route(router)
        assertmsg = "Router '{}' OS routes mismatch".format(rname)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_isis_route6_installation():
    "Check whether all expected routes are present"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS vrf IPv6 routes")
    # Check for routes in 'show ipv6 route vrf {}-cust1 json'
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route6.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())

        def compare_routing_table(router, expected):
            "Helper function to ensure zebra rib convergence"
            actual = router.vtysh_cmd(
                "show ipv6 route vrf {}-cust1 json".format(rname), isjson=True
            )
            return topotest.json_cmp(actual, expected)

        test_func = functools.partial(compare_routing_table, router, expected)
        (result, diff) = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = "Router '{}' routes mismatch diff: ".format(rname, diff)
        assert result, assertmsg


def test_isis_linux_route6_installation():
    "Check whether all expected routes are present and installed in the OS"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # iproute2 needs to support VRFs for this suite to run.
    if not iproute2_is_vrf_capable():
        pytest.skip("Installed iproute2 version does not support VRFs")

    logger.info("Checking routers for installed ISIS vrf IPv6 routes in OS")
    # Check for routes in `ip -6 route show vrf {}-cust1`
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route6_linux.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        actual = topotest.ip6_vrf_route(router)
        assertmsg = "Router '{}' OS routes mismatch".format(rname)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


#
# Auxiliary functions
#


def dict_merge(dct, merge_dct):
    """
    Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.
    :param dct: dict onto which the merge is executed
    :param merge_dct: dct merged into dct
    :return: None

    Source:
    https://gist.github.com/angstwad/bf22d1822c38a92ec0a9
    """
    for k, _ in merge_dct.items():
        if k in dct and isinstance(dct[k], dict) and topotest.is_mapping(merge_dct[k]):
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


def parse_topology(lines, level):
    """
    Parse the output of 'show isis topology level-X' into a Python dict.
    """
    areas = {}
    area = None
    ipv = None
    vertex_type_regex = "|".join(VERTEX_TYPE_LIST)

    for line in lines:
        area_match = re.match(r"Area (.+):", line)
        if area_match:
            area = area_match.group(1)
            if area not in areas:
                areas[area] = {level: {"ipv4": [], "ipv6": []}}
            ipv = None
            continue
        elif area is None:
            continue

        if re.match(r"IS\-IS paths to level-. routers that speak IPv6", line):
            ipv = "ipv6"
            continue
        if re.match(r"IS\-IS paths to level-. routers that speak IP", line):
            ipv = "ipv4"
            continue

        item_match = re.match(
            r"([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)", line
        )
        if (
            item_match is not None
            and item_match.group(1) == "Vertex"
            and item_match.group(2) == "Type"
            and item_match.group(3) == "Metric"
            and item_match.group(4) == "Next-Hop"
            and item_match.group(5) == "Interface"
            and item_match.group(6) == "Parent"
        ):
            # Skip header
            continue

        item_match = re.match(
            r"([^\s]+) ({}) ([0]|([1-9][0-9]*)) ([^\s]+) ([^\s]+) ([^\s]+)".format(
                vertex_type_regex
            ),
            line,
        )
        if item_match is not None:
            areas[area][level][ipv].append(
                {
                    "vertex": item_match.group(1),
                    "type": item_match.group(2),
                    "metric": item_match.group(3),
                    "next-hop": item_match.group(5),
                    "interface": item_match.group(6),
                    "parent": item_match.group(7),
                }
            )
            continue

        item_match = re.match(
            r"([^\s]+) ({}) ([0]|([1-9][0-9]*)) ([^\s]+)".format(vertex_type_regex),
            line,
        )

        if item_match is not None:
            areas[area][level][ipv].append(
                {
                    "vertex": item_match.group(1),
                    "type": item_match.group(2),
                    "metric": item_match.group(3),
                    "parent": item_match.group(5),
                }
            )
            continue

        item_match = re.match(r"([^\s]+)", line)
        if item_match is not None:
            areas[area][level][ipv].append({"vertex": item_match.group(1)})
            continue

    return areas
