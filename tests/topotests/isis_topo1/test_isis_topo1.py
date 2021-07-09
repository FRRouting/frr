#!/usr/bin/env python

#
# test_isis_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
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
test_isis_topo1.py: Test ISIS topology.
"""

import collections
import functools
import json
import os
import re
import sys
import pytest
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from mininet.topo import Topo

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


class ISISTopo1(Topo):
    "Simple two layer ISIS topology"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

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
    tgen = Topogen(ISISTopo1, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_isis_convergence():
    "Wait for the protocol to converge before starting to test"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for ISIS protocol to converge")
    # Code to generate the json files.
    # for rname, router in tgen.routers().items():
    #     open('/tmp/{}_topology.json'.format(rname), 'w').write(
    #         json.dumps(show_isis_topology(router), indent=2, sort_keys=True)
    #     )

    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_topology.json".format(CWD, rname)
        expected = json.loads(open(filename).read())

        def compare_isis_topology(router, expected):
            "Helper function to test ISIS topology convergence."
            actual = show_isis_topology(router)
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

    logger.info("Checking routers for installed ISIS routes")

    # Check for routes in 'show ip route json'
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        actual = router.vtysh_cmd("show ip route json", isjson=True)
        assertmsg = "Router '{}' routes mismatch".format(rname)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_isis_linux_route_installation():
    "Check whether all expected routes are present and installed in the OS"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS routes in OS")

    # Check for routes in `ip route`
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route_linux.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        actual = topotest.ip4_route(router)
        assertmsg = "Router '{}' OS routes mismatch".format(rname)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_isis_route6_installation():
    "Check whether all expected routes are present"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS IPv6 routes")

    # Check for routes in 'show ip route json'
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route6.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        actual = router.vtysh_cmd("show ipv6 route json", isjson=True)
        assertmsg = "Router '{}' routes mismatch".format(rname)
        assert topotest.json_cmp(actual, expected) is None, assertmsg


def test_isis_linux_route6_installation():
    "Check whether all expected routes are present and installed in the OS"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking routers for installed ISIS IPv6 routes in OS")

    # Check for routes in `ip route`
    for rname, router in tgen.routers().items():
        filename = "{0}/{1}/{1}_route6_linux.json".format(CWD, rname)
        expected = json.loads(open(filename, "r").read())
        actual = topotest.ip6_route(router)
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
    for k, v in merge_dct.items():
        if (
            k in dct
            and isinstance(dct[k], dict)
            and isinstance(merge_dct[k], collections.Mapping)
        ):
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


def show_isis_topology(router):
    """
    Get the ISIS topology in a dictionary format.

    Sample:
    {
      'area-name': {
        'level-1': [
          {
            'vertex': 'r1'
          }
        ],
        'level-2': [
          {
            'vertex': '10.0.0.1/24',
            'type': 'IP',
            'parent': '0',
            'metric': 'internal'
          }
        ]
      },
      'area-name-2': {
        'level-2': [
          {
            "interface": "rX-ethY",
            "metric": "Z",
            "next-hop": "rA",
            "parent": "rC(B)",
            "type": "TE-IS",
            "vertex": "rD"
          }
        ]
      }
    }
    """
    l1out = topotest.normalize_text(
        router.vtysh_cmd("show isis topology level-1")
    ).splitlines()
    l2out = topotest.normalize_text(
        router.vtysh_cmd("show isis topology level-2")
    ).splitlines()

    l1 = parse_topology(l1out, "level-1")
    l2 = parse_topology(l2out, "level-2")

    dict_merge(l1, l2)
    return l1
