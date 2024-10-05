#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_suppres_fa.py
# Carles Kishimoto
#

"""
test_ospf_suppres_fa.py: Test OSPF suppress-fa feature
- Topology: r1 --- R2 (ABR) --- R3 (redistribute static)

test_ospf_set_suppress_fa()
    1) R1: Get a dict[LSA_ID] = fwd_addr for all type 5 LSA
    2) R2: Configure: area 1 nssa suppress-fa
    3) R1: Get a dict[LSA_ID] and compare fwd_address with 0.0.0.0

test_ospf_unset_suppress_fa()
    4) R2: Configure: no area 1 nssa suppress-fa
    5) R1: Get a dict[LSA_ID] = fwd_addr and compare it with the dict obtained in 1)
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    # Create routers
    for router in range(1, 4):
        tgen.add_router("r{}".format(router))

    # R1-R2 backbone area
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # R2-R3 NSSA area
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registered routers, load the zebra and ospf configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )

    logger.info("Module Setup")
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    json_file = "{}/r1/neighbor.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip ospf neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 has not converged"

    logger.info("Converged Protocol")


def ospf_configure_suppress_fa(router_name, area):
    "Configure OSPF suppress-fa in router_name"

    tgen = get_topogen()
    router = tgen.gears[router_name]
    router.vtysh_cmd(
        "conf t\nrouter ospf\narea {} nssa suppress-fa\nexit\n".format(area)
    )


def ospf_unconfigure_suppress_fa(router_name, area):
    "Remove OSPF suppress-fa in router_name"

    tgen = get_topogen()
    router = tgen.gears[router_name]
    router.vtysh_cmd("conf t\nrouter ospf\narea {} nssa\nexit\n".format(area))


def test_ospf_set_suppress_fa():
    "Test OSPF area [x] nssa suppress-fa"

    logger.info("Testing Turning on/off suppress-fa")
    tgen = get_topogen()

    # Get current forwarding address for each LSA type-5 in r1
    logger.info("Get Initial State")
    router = tgen.gears["r1"]
    json_file = "{}/r1/initial.json".format(CWD)
    expected_initial = json.loads(open(json_file).read())

    test_func_initial = partial(
        topotest.router_json_cmp,
        router,
        "show ip ospf data external json",
        expected_initial,
    )
    _, result = topotest.run_and_expect(test_func_initial, None, count=30, wait=1)
    assert result is None, "Unable to get expected initial states"

    logger.info("Configure suppress-fa")
    # Configure suppres-fa in r2 area 1
    ospf_configure_suppress_fa("r2", "1")

    logger.info("Ensure that OSPF has converged on new values")
    json_file = "{}/r1/post.json".format(CWD)
    expected_post = json.loads(open(json_file).read())

    test_func_post = partial(
        topotest.router_json_cmp,
        router,
        "show ip ospf data external json",
        expected_post,
    )

    _, result = topotest.run_and_expect(test_func_post, None, count=30, wait=1)
    assert result is None, "Unable to get expected state after turning on suppress-fa"

    logger.info("Test OSPF no area [x] nssa suppress-fa")

    # Remove suppress-fa in r2 area 1
    ospf_unconfigure_suppress_fa("r2", "1")

    logger.info("Has OSPF returned to original values")
    _, result = topotest.run_and_expect(test_func_post, None, count=30, wait=1)
    assert (
        result is None
    ), "Unable to return to original state after turning off suppress-fa"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
