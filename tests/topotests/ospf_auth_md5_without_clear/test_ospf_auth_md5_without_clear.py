#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test OSPF MD5 authentication full cycle without using clear_ospf.

This test verifies that OSPF can transition through MD5 authentication states
naturally without forcing session resets:
1. Start without MD5 authentication - adjacency established
2. Add MD5 authentication on R1 only - adjacency goes down (auth mismatch)
3. Add MD5 authentication on R2 - adjacency re-established
4. Remove MD5 authentication from R1 - adjacency goes down (auth mismatch)
5. Remove MD5 authentication from R2 - adjacency re-established

Uses small hello/dead intervals (1s/4s) to speed up session teardown
and establishment.
"""

import os
import sys
import time
import pytest
from time import sleep

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    step,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.ospf import verify_ospf_neighbor, config_ospf_interface

pytestmark = [pytest.mark.ospfd]

topo = None


def setup_module(mod):
    """Set up the pytest environment."""
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    json_file = "{}/ospf_auth_md5_topo.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    start_topology(tgen)
    build_config_from_json(tgen, topo)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment."""
    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


def test_ospf_md5_auth_full_cycle_without_clear(request):
    """
    Test OSPF MD5 authentication full cycle without using clear_ospf.

    This test verifies proper OSPF behavior during authentication transitions
    by configuring one router at a time and observing session teardown/re-establishment.

    Steps:
    1. Verify initial adjacency without authentication
    2. Add MD5 authentication on R1 only - adjacency should go down
    3. Add MD5 authentication on R2 - adjacency should re-establish
    4. Remove MD5 authentication from R1 - adjacency should go down
    5. Remove MD5 authentication from R2 - adjacency should re-establish
    """
    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    global topo

    dut = "r1"

    # Step 1: Verify initial adjacency without authentication
    step("Step 1: Verify initial OSPF adjacency is established without authentication")

    ospf_convergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_convergence is True, (
        "Initial adjacency failed - neighbors not FULL. Error: {}".format(
            ospf_convergence
        )
    )
    logger.info("Initial OSPF adjacency established successfully")

    # Step 2: Add MD5 authentication on R1 only - adjacency should go down
    step("Step 2: Configure MD5 authentication on R1 only")

    r1_ospf_auth = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospfkey",
                        "message-digest-key": "10",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)
    assert result is True, "Failed to configure MD5 auth on R1. Error: {}".format(
        result
    )

    step("Step 2b: Verify adjacency goes down due to authentication mismatch")
    sleep(6)
    ospf_convergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=10
    )
    assert ospf_convergence is not True, (
        "Adjacency should be down due to auth mismatch. Error: {}".format(
            ospf_convergence
        )
    )
    logger.info("OSPF adjacency is down as expected (auth mismatch)")

    # Step 3: Add MD5 authentication on R2 - adjacency should re-establish
    step("Step 3: Configure MD5 authentication on R2")

    r2_ospf_auth = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospfkey",
                        "message-digest-key": "10",
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth)
    assert result is True, "Failed to configure MD5 auth on R2. Error: {}".format(
        result
    )

    step("Step 3b: Verify OSPF adjacency is re-established with MD5 authentication")

    ospf_convergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_convergence is True, (
        "Adjacency with MD5 auth failed - neighbors not FULL. Error: {}".format(
            ospf_convergence
        )
    )
    logger.info("OSPF adjacency with MD5 authentication established successfully")

    # Step 4: Remove MD5 authentication from R1 - adjacency should go down
    step("Step 4: Remove MD5 authentication from R1")

    r1_ospf_auth_del = {
        "r1": {
            "links": {
                "r2": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospfkey",
                        "message-digest-key": "10",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth_del)
    assert result is True, "Failed to remove MD5 auth from R1. Error: {}".format(
        result
    )

    step("Step 4b: Verify adjacency goes down due to authentication mismatch")
    sleep(6)
    ospf_convergence = verify_ospf_neighbor(
        tgen, topo, dut=dut, expected=False, retry_timeout=10
    )
    assert ospf_convergence is not True, (
        "Adjacency should be down due to auth mismatch after R1 removal. Error: {}".format(
            ospf_convergence
        )
    )
    logger.info("OSPF adjacency is down as expected after R1 auth removal")

    # Step 5: Remove MD5 authentication from R2 - adjacency should re-establish
    step("Step 5: Remove MD5 authentication from R2")

    r2_ospf_auth_del = {
        "r2": {
            "links": {
                "r1": {
                    "ospf": {
                        "authentication": "message-digest",
                        "authentication-key": "ospfkey",
                        "message-digest-key": "10",
                        "del_action": True,
                    }
                }
            }
        }
    }
    result = config_ospf_interface(tgen, topo, r2_ospf_auth_del)
    assert result is True, "Failed to remove MD5 auth from R2. Error: {}".format(
        result
    )

    step("Step 5b: Verify OSPF adjacency is re-established without authentication")

    ospf_convergence = verify_ospf_neighbor(tgen, topo, dut=dut)
    assert ospf_convergence is True, (
        "Adjacency without auth failed after removal - neighbors not FULL. Error: {}".format(
            ospf_convergence
        )
    )
    logger.info(
        "OSPF adjacency without authentication re-established successfully after MD5 removal"
    )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
