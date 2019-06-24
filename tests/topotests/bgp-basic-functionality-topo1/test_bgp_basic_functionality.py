#!/usr/bin/env python

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Following tests are covered to test BGP basic functionality:

Test steps
- Create topology (setup module)
  Creating 4 routers topology, r1, r2, r3 are in IBGP and
  r3, r4 are in EBGP
- Bring up topology
- Verify for bgp to converge
- Modify/Delete and verify router-id
"""

import os
import sys
import json
import time
import pytest
from copy import deepcopy

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))
sys.path.append(os.path.join(CWD, '../lib/'))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo

from lib.common_config import (
    start_topology, stop_topology, write_test_header,
    write_test_footer
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence, create_router_bgp, verify_router_id
)
from lib.topojson import build_topo_from_json, build_config_from_json

# Reading the data from JSON File for topology creation
jsonFile = "{}/bgp_basic_functionality.json".format(CWD)
try:
    with open(jsonFile, 'r') as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)


class CreateTopo(Topo):
    """
    Test BasicTopo - topology 1

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        """Build function"""
        tgen = get_topogen(self)

        # Building topology from json file
        build_topo_from_json(tgen, topo)


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
    tgen = Topogen(CreateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global BGP_CONVERGENCE
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}". \
        format(BGP_CONVERGENCE)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    stop_topology(tgen)

    logger.info("Testsuite end time: {}".
                format(time.asctime(time.localtime(time.time()))))
    logger.info("=" * 40)


#####################################################
#
#   Testcases
#
#####################################################


def test_modify_and_delete_router_id(request):
    """ Test to modify, delete and verify router-id. """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Modify router id
    input_dict = {
        'r1': {
            "bgp": {
                'router_id': '12.12.12.12'
            }
        },
        'r2': {
            "bgp": {
                'router_id': '22.22.22.22'
            }
        },
        'r3': {
            "bgp": {
                'router_id': '33.33.33.33'
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".\
        format(tc_name, result)

    # Verifying router id once modified
    result = verify_router_id(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".\
        format(tc_name, result)

    # Delete router id
    input_dict = {
        'r1': {
            "bgp": {
                'del_router_id': True
            }
        },
        'r2': {
            "bgp": {
                'del_router_id': True
            }
        },
        'r3': {
            "bgp": {
                'del_router_id': True
            }
        },
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, result)

    # Verifying router id once deleted
    # Once router-id is deleted, highest interface ip should become
    # router-id
    result = verify_router_id(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
