#!/usr/bin/python

from lib.topogen import Topogen, get_topogen
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    step,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
from lib.ospf import create_router_ospf, verify_ospf6_neighbor
import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413

pytestmark = [pytest.mark.ospfd]


# Global variables
topo = None

"""
TOPOOLOGY

      +---+   0.0.0.0  +---+   1.1.1.1  +---+
      +R1 +------------+R2 |------------+R3 |
      +-+-+            +--++            +--++

TESTCASES =
1. OSPF Verify E-bit mismatch between R2 and R3
2. OSPF Verify N-bit mismatch between R2 and R3
"""


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/ospfv3_nssa.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_ospf6_neighbor(tgen, topo)
    assert result is True, "setup_module: Failed \n Error:  {}".format(result)

    logger.info("Running setup_module() done")


def teardown_module():
    """
    Teardown the pytest environment.

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


# ##################################
# Test cases start here.
# ##################################


def test_ospfv3_bit_mismatch(request):
    """OSPF verify E-bit and N-bit mismatch."""

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global topo
    step("Bring up the base config as per the topology")
    reset_config_on_routers(tgen)

    input_dict = {"r3": {"ospf6": {"neighbors": []}}}

    step("Configure r3 as stub router")
    stub = {"r3": {"ospf6": {"area": [{"id": "1.1.1.1", "type": "stub"}]}}}
    result = create_router_ospf(tgen, topo, stub)
    assert result is True, "Testcase {}: Failed \n Error: {}".format(tc_name, result)
    # Verify r3 lost its adjacency with r2 due to E-bit mismatch
    result = verify_ospf6_neighbor(tgen, topo, dut="r3", input_dict=input_dict)
    assert result is True, "Testcase {}: Failed \n Error: {}".format(tc_name, result)

    step("Configure r2 as stub router")
    stub = {"r2": {"ospf6": {"area": [{"id": "1.1.1.1", "type": "stub"}]}}}
    result = create_router_ospf(tgen, topo, stub)
    assert result is True, "Testcase {}: Failed \n Error: {}".format(tc_name, result)
    # Verify r3 has an adjacency up with r2 again
    result = verify_ospf6_neighbor(tgen, topo, dut="r3")
    assert result is True, "Testcase {}: Failed \n Error: {}".format(tc_name, result)

    step("Configure r3 as NSSA router")
    nssa = {"r3": {"ospf6": {"area": [{"id": "1.1.1.1", "type": "nssa"}]}}}
    result = create_router_ospf(tgen, topo, nssa)
    # Verify r3 lost its adjacency with r2 due to N-bit mismatch
    result = verify_ospf6_neighbor(tgen, topo, dut="r3", input_dict=input_dict)
    assert result is True, "Testcase {}: Failed \n Error: {}".format(tc_name, result)

    step("Configure r2 as NSSA router")
    nssa = {"r2": {"ospf6": {"area": [{"id": "1.1.1.1", "type": "nssa"}]}}}
    result = create_router_ospf(tgen, topo, nssa)
    # Verify r3 has an adjacency up with r2 again
    result = verify_ospf6_neighbor(tgen, topo, dut="r3")
    assert result is True, "Testcase {}: Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
