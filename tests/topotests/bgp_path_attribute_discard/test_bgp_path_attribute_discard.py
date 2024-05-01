#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if `neighbor path-attribute discard` command works correctly,
can discard unwanted attributes from UPDATE messages, and ignore them
by continuing to process UPDATE messages.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.0.0.254", defaultRoute="via 10.0.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)
    switch.add_link(peer1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    peer = tgen.gears["peer1"]
    peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_path_attribute_discard():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json detail"))
        expected = {
            "routes": {
                "192.168.100.101/32": {
                    "paths": [
                        {
                            "valid": True,
                            "atomicAggregate": True,
                            "community": {
                                "string": "65001:101",
                            },
                        }
                    ],
                },
                "192.168.100.102/32": {
                    "paths": [
                        {
                            "valid": True,
                            "originatorId": None,
                            "community": {
                                "string": "65001:102",
                            },
                        }
                    ],
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Failed bgp convergence"

    step("Discard atomic-aggregate, and community attributes from peer1")
    r1.vtysh_cmd(
        """
    configure terminal
        router bgp
            neighbor 10.0.0.254 path-attribute discard 6 8
    """
    )

    def _bgp_check_if_attributes_discarded():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json detail"))
        expected = {
            "routes": {
                "192.168.100.101/32": {
                    "paths": [
                        {
                            "valid": True,
                            "atomicAggregate": None,
                            "community": None,
                        }
                    ],
                },
                "192.168.100.102/32": {
                    "paths": [
                        {
                            "valid": True,
                            "originatorId": None,
                            "community": None,
                        }
                    ],
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_if_attributes_discarded)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert (
        result is None
    ), "Failed to discard path attributes (atomic-aggregate, community)"

    def _bgp_check_if_aigp_invalid_attribute_discarded():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json detail"))
        expected = {
            "routes": {
                "192.168.100.101/32": {
                    "paths": [
                        {
                            "valid": True,
                            "aigpMetric": None,
                        }
                    ],
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_if_aigp_invalid_attribute_discarded)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert (
        result is None
    ), "Failed to discard AIGP invalid path attribute (iBGP session)"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
