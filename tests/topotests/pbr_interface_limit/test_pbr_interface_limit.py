#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pbr_interface_limit.py
#
# Copyright (c) 2026 FRRouting
#
# Test to verify PBR map interface limit (PBR_MAP_INTERFACE_MAX = 512)
#

"""
test_pbr_interface_limit.py: Test PBR interface limit handling

This test verifies that:
1. PBR maps can handle up to 512 interfaces
2. When the 512 interface limit is reached, a warning is logged
3. Additional interfaces beyond 512 are rejected gracefully
"""

import os
import sys
import pytest
import json
import platform
import re
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.pbrd]

# PBR_MAP_INTERFACE_MAX as defined in pbr_map.h
PBR_MAP_INTERFACE_MAX = 512

# Number of interfaces to test with (slightly over the limit)
TEST_INTERFACE_COUNT = 520


def build_topo(tgen):
    """Build function - create topology with multiple switches/interfaces"""
    # Create router
    tgen.add_router("r1")

    # Create switches that will create interfaces r1-eth0, r1-eth1, etc.
    # We need more than 512 to test the limit
    for switchn in range(1, TEST_INTERFACE_COUNT + 1):
        switch = tgen.add_switch("sw{}".format(switchn))
        switch.add_link(tgen.gears["r1"])


def setup_module(module):
    """Setup topology"""
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.10") < 0:
        tgen.errors = "Newer kernel than 4.9 needed for pbr tests"
        pytest.skip(tgen.errors)

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PBRD, os.path.join(CWD, "{}/pbrd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_converge_protocols():
    """Wait for protocol convergence"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, "Waiting for PBR convergence")


def test_pbr_interface_limit():
    """
    Test PBR interface limit handling.
    
    This test verifies:
    1. We can add interfaces up to the PBR_MAP_INTERFACE_MAX limit
    2. When the limit is reached, a warning is logged
    3. Interfaces beyond the limit are rejected
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    
    logger.info("=" * 60)
    logger.info("Testing PBR interface limit (max = {})".format(PBR_MAP_INTERFACE_MAX))
    logger.info("=" * 60)

    # Apply PBR policy to all interfaces via vtysh
    logger.info("Applying PBR policy TESTMAP to {} interfaces".format(TEST_INTERFACE_COUNT))
    
    # Build vtysh commands in batches for efficiency
    batch_size = 100
    for batch_start in range(0, TEST_INTERFACE_COUNT, batch_size):
        batch_end = min(batch_start + batch_size, TEST_INTERFACE_COUNT)
        
        cmds = ["configure terminal"]
        for i in range(batch_start, batch_end):
            ifname = "r1-eth{}".format(i)
            cmds.append("interface {}".format(ifname))
            cmds.append("pbr-policy TESTMAP")
        cmds.append("end")
        
        router.vtysh_multicmd("\n".join(cmds))

    # Wait for pbrd to process all interfaces
    topotest.sleep(5, "Waiting for PBR to process interfaces")

    # Check the number of interfaces in the PBR map
    def get_interface_count():
        output = router.vtysh_cmd("show pbr interface json")
        try:
            data = json.loads(output)
            if data and isinstance(data, list):
                count = sum(1 for entry in data if entry.get("policy") == "TESTMAP")
                return count
        except Exception as e:
            logger.error("Failed to parse JSON: {}".format(e))
        return 0

    def check_interface_count(expected_min):
        count = get_interface_count()
        if count >= expected_min:
            return None
        return "Expected at least {} interfaces, got {}".format(expected_min, count)

    # Wait for interfaces to be registered (up to 60 seconds)
    test_func = partial(check_interface_count, PBR_MAP_INTERFACE_MAX)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    
    iface_count = get_interface_count()
    logger.info("Interfaces in PBR map TESTMAP: {}".format(iface_count))

    # Debug output
    output = router.vtysh_cmd("show pbr interface")
    logger.info("show pbr interface (first 3000 chars):\n{}".format(output[:3000]))

    # The count should be capped at PBR_MAP_INTERFACE_MAX
    assert iface_count <= PBR_MAP_INTERFACE_MAX, \
        "Interface count {} exceeds maximum {}".format(iface_count, PBR_MAP_INTERFACE_MAX)
    
    assert iface_count == PBR_MAP_INTERFACE_MAX, \
        "Expected {} interfaces, got {}".format(PBR_MAP_INTERFACE_MAX, iface_count)

    # Verify warning was logged
    logger.info("Checking for limit warning in pbrd log")
    log_output = router.run("cat pbrd.log 2>/dev/null | grep -i 'maximum interface limit' || echo ''")
    logger.info("Log search result: {}".format(log_output[:500]))
    
    assert "maximum interface limit" in log_output.lower(), \
        "Expected warning about interface limit not found in log"
    
    logger.info("SUCCESS: Interface limit is enforced correctly")
    logger.info("=" * 60)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
