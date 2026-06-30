#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_default_information.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_default_information.py: Test OSPF default information.
"""

import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topolog import logger

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_neighbor_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].expect_ospfv2_neighbor("192.168.0.2")
    tgen.gears["r2"].expect_ospfv2_neighbor("192.168.0.1")


def expect_router_ospf_lsa(router, lsa, missing=False):
    tgen = get_topogen()

    def router_lsa_exists():
        output = tgen.gears[router].vtysh_cmd("show ip ospf database detail json", isjson=True)
        result = topotest.json_cmp(output, lsa)
        if result is None:
            return True
        else:
            return False

    if missing:
        expect = False
        message = f"LSA {lsa} present in router {router}"
    else:
        expect = True
        message = f"LSA {lsa} is missing from {router}"

    _, result = topotest.run_and_expect(router_lsa_exists, expect, count=120, wait=1)
    assert result is expect, message


def test_default_route_generation():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Expect that default route doesn't exist
    logger.info("Expect default route missing")
    expect_router_ospf_lsa("r2", {
        "asExternalLinkStates": [{
            "forwardAddress": "0.0.0.0"
        }]
    }, missing=True)

    # Create default route and expect it to exist
    tgen.gears["r1"].vtysh_cmd("""
    configure terminal
    ip route 0.0.0.0/0 lo
    router ospf
     default-information originate
    """)

    logger.info("Expect default route learned from 'default-information originate'")
    expect_router_ospf_lsa("r2", {
        "asExternalLinkStates": [{
            "forwardAddress": "0.0.0.0"
        }]
    })

    # Re-use default route with originate always
    tgen.gears["r1"].vtysh_cmd("""
    configure terminal
    router ospf
     default-information originate always
    """)

    logger.info("Expect default route learned from 'default-information originate always'")
    expect_router_ospf_lsa("r2", {
        "asExternalLinkStates": [{
            "forwardAddress": "0.0.0.0"
        }]
    })

    # Remove static default route
    tgen.gears["r1"].vtysh_cmd("""
    configure terminal
    no ip route 0.0.0.0/0 lo
    """)

    logger.info("Expect default route still present from 'default-information originate always'")
    expect_router_ospf_lsa("r2", {
        "asExternalLinkStates": [{
            "forwardAddress": "0.0.0.0"
        }]
    })

    # Remove default route
    tgen.gears["r1"].vtysh_cmd("""
    configure terminal
    router ospf
     no default-information originate always
    """)

    expect_router_ospf_lsa("r2", {
        "asExternalLinkStates": [{
            "forwardAddress": "0.0.0.0"
        }]
    }, missing=True)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
