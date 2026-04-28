#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_join_prune_packet_split.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_join_prune_packet_split.py: topology to test the PIM join
prune message type with a lots of entries.
"""

import math
import ipaddress
import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd, pytest.mark.pimd]

def r3_generate_static_joins(tgen):
    #
    # Configure 2000 IGMP static joins
    #
    igmp_static_joins_cmd = """
    configure terminal
    interface r3-eth0
    """

    net_start = 0x0A000000 # 10.0.0.0
    for network in range(0, 2000):
        current_subnet = (math.trunc(network / 254) << 8)
        current_address = (network % 254) + 1
        source_string = "{}".format(ipaddress.IPv4Address(net_start + current_subnet + current_address))

        igmp_static_joins_cmd += f" ip igmp join 232.0.1.1 {source_string}\n"

    tgen.gears["r3"].vtysh_multicmd(igmp_static_joins_cmd, pretty_output=False)



def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3")
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(f"{CWD}/{rname}/frr.conf")

    tgen.start_router()

    r3_generate_static_joins(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def expect_ospf_neighbor(router, neighbor):
    tgen = get_topogen()

    expected = {
        "neighbors": {
            neighbor: [{
                "converged": "Full"
            }]
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf neighbor json",
        expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Router {router} failed to converge"


def test_ospf_neighbor_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_ospf_neighbor("r1", "192.168.1.2")
    expect_ospf_neighbor("r2", "192.168.2.1")
    expect_ospf_neighbor("r3", "192.168.2.1")


def expect_pim_state(router, state):
    tgen = get_topogen()

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip pim state json",
        state)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, f"PIM {router} failed to converge"


def test_pim_join_prune_packet_split():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1_expected_state = {
        "232.0.1.1": {
        }
    }
    r2_expected_state = {
        "232.0.1.1": {
        }
    }

    net_start = 0x0A000000 # 10.0.0.0
    for network in range(0, 2000):
        current_subnet = (math.trunc(network / 254) << 8)
        current_address = (network % 254) + 1
        source_string = "{}".format(ipaddress.IPv4Address(net_start + current_subnet + current_address))

        r1_expected_state["232.0.1.1"][source_string] = {
            "r1-eth0": {
                "r1-eth1": {
                    "source": source_string,
                    "group": "232.0.1.1",
                    "inboundInterface": "r1-eth0",
                    "outboundInterface": "r1-eth1",
                }
            }
        }

        r2_expected_state["232.0.1.1"][source_string] = {"refCount": 1}

    expect_pim_state("r1", r1_expected_state)
    expect_pim_state("r2", r2_expected_state)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
