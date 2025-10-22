#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_startup_of_speeds.py: Test router startup with multiple interfaces
"""

import os
import sys
import json
import pytest
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step
from time import sleep



def build_topo(tgen):
    "Build function"

    # Create 1 router
    tgen.add_router("r1")

    # Create 10 switches and connect each to r1 to generate 10 interfaces (eth0-eth9)
    for i in range(10):
        switch = tgen.add_switch(f"s{i}")
        switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"

    logger.info("\n\n---- Starting startup_of_speeds test ----\n")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the unified configuration file
    for rname, router in tgen.routers().items():
        router.load_frr_config("frr.conf")

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()

    logger.info("\n\n---- startup_of_speeds test End ----\n")


def check_speed_checked(router, interface_name, expected_count):
    """Check if interface has speedChecked >= expected_count"""
    output = router.vtysh_cmd(f"show interface {interface_name} json", isjson=True)

    if not output:
        return "No output from command"

    if interface_name not in output:
        return f"{interface_name} interface not found in output"

    if "speedChecked" not in output[interface_name]:
        return f"speedChecked field not found in {interface_name} interface"

    speed_checked = output[interface_name]["speedChecked"]
    if speed_checked < expected_count:
        return f"speedChecked is {speed_checked}, expected >= {expected_count}"

    return None


def test_non_existent_interface_speeds():
    "Test that dummy1 interface that has not been created has had speed checked one time"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    router = tgen.gears["r1"]

    step("Ensure that speed is checked at least 1 time for the dummy1 interface")
    # Use run_and_expect to poll until speedChecked >= 1
    test_func = partial(check_speed_checked, router, "dummy1", 1)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)

    step("Ensure that speed checked does not grow beyond 1 for the dummy1 interface")
    test_func = partial(check_speed_checked, router, "dummy1", 2)
    # Expect a string result (which means the check failed as intended)
    success, result = topotest.run_and_expect_type(test_func, str, count=20, wait=1)

    assert (
        success
    ), f"dummy1 interface speedChecked unexpectedly grew beyond 1: {result}"


def test_bond_coming_up():
    "Test bond interface behavior when interfaces come up"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    router = tgen.gears["r1"]

    step("Shutdown r1-eth[0-9] interfaces")
    for i in range(10):
        router.cmd(f"ip link set r1-eth{i} down")

    step("Create bond0")
    router.cmd(f"ip link add bond0 type bond")

    router.cmd(f"ip link set bond0 up")
    # This is intentionally sleeping 3 seconds between
    # the addition of each member to the bond.  I want
    # the speed to be checked multiple times in zebra
    step("Add interfaces to the bond")
    for i in range(10):
        router.cmd(f"ip link set r1-eth{i} master bond0")
        router.cmd(f"ip link set r1-eth{i} up")
        sleep(3)

    speed_checked = 0

    def check_bond_speed(expected_speed):
        """Check if bond0 interface has the expected speed"""
        nonlocal speed_checked
        output = router.vtysh_cmd("show interface bond0 json", isjson=True)

        if not output:
            return "No output from command"

        if "bond0" not in output:
            return "bond0 interface not found in output"

        if "speed" not in output["bond0"]:
            return "speed field not found in bond0 interface"

        actual_speed = output["bond0"]["speed"]

        if "speedChecked" not in output["bond0"]:
            return "speedChecked field not found in bond0 interface"

        speed_checked = output["bond0"]["speedChecked"]

        if actual_speed != expected_speed:
            return f"bond0 speed is {actual_speed}, expected {expected_speed}"

        return None

    step("Check that bond0 speed is 100000")
    test_func = partial(check_bond_speed, 100000)
    success, result = topotest.run_and_expect(test_func, None, count=20, wait=1)

    assert success, f"bond0 speed check failed: {result}"

    step(
        f"Ensure that bond0 speedChecked does not increment beyond {speed_checked + 1}"
    )
    # Wait a bit to ensure multiple checks would have happened if they were going to
    test_func = partial(check_speed_checked, router, "bond0", speed_checked + 2)
    # Expect a string result (which means the check failed as intended)
    success, result = topotest.run_and_expect_type(test_func, str, count=20, wait=1)

    assert (
        success
    ), f"bond0 speedChecked unexpectedly incremented beyond {speed_checked + 1}: {result}"


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
