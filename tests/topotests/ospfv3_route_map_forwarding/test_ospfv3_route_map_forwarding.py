#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_ospfv3_route_map_forwarding.py:

Test OSPFv3 route-map forwarding-address handling.

This test demonstrates a bug where explicitly configured forwarding addresses
in route-maps get overwritten when the route-map is modified to remove the
forwarding-address configuration.

Topology:

    +--------+         +--------+
    |   R1   |---------|   R2   |
    | (ASBR) |  eth0   | (ABR)  |
    +--------+         +--------+
       |
     lo    (connected route redistributed into OSPFv3)

Test Scenario:
1. R1 redistributes connected route from lo with route-map setting explicit forwarding address
2. Verify R2 receives LSA with correct forwarding address
3. Modify route-map on R1 to remove forwarding address configuration
4. Verify forwarding address is NOT overwritten (demonstrates fix for bug)
"""

import os
import sys
import pytest
import json

# Save the Current Working Directory
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospf6d]


def build_topo(tgen):
    """Build the topology for testing"""
    # Create 2 routers
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Create switch connecting r1 and r2
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    """Set up the pytest environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    logger.info("** %s: Setup Topology" % mod.__name__)

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_OSPF6, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospfv3_neighbor_established():
    """Test that OSPFv3 neighbor relationship is established"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Waiting for OSPFv3 neighbor to establish")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Check R1 has R2 as neighbor
    def check_r1_neighbor():
        output = r1.vtysh_cmd("show ipv6 ospf6 neighbor json")
        try:
            data = json.loads(output)
            if "neighbors" in data:
                for neighbor in data["neighbors"]:
                    if (
                        neighbor.get("neighborId") == "10.0.0.2"
                        and neighbor.get("state") == "Full"
                    ):
                        return True
            return False
        except:
            return False

    test_func = check_r1_neighbor
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result, "R1 neighbor with R2 did not reach Full state"

    logger.info("OSPFv3 neighbor R1<->R2 established")


def test_initial_convergence():
    """Test that OSPFv3 converges and routes are exchanged"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Waiting for OSPFv3 to converge and routes to be exchanged")

    r2 = tgen.gears["r2"]

    # Wait for R2 to see the external LSA from R1
    def check_r2_has_external_lsa():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external json")
        try:
            data = json.loads(output)
            # Look for LSA with prefix 2001:db8:100::/64
            if "asScopedLinkStateDb" in data:
                for db in data["asScopedLinkStateDb"]:
                    if "lsa" in db:
                        for lsa in db["lsa"]:
                            if lsa.get("payload") == "2001:db8:100::/64":
                                return True
            return False
        except:
            return False

    test_func = check_r2_has_external_lsa
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result, "R2 did not receive external LSA from R1"

    logger.info("External LSA for 2001:db8:100::/64 successfully received on R2")


def test_initial_forwarding_address():
    """Test that initial forwarding address is set correctly by route-map"""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    logger.info("Checking initial forwarding address from route-map")

    def check_initial_forwarding_address():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external 0.0.0.1 10.0.0.1")
        return "2001:db8:ffff::1" in output

    _, result = topotest.run_and_expect(
        check_initial_forwarding_address, True, count=30, wait=1
    )
    assert result, "Initial forwarding address not set correctly by route-map"

    logger.info("Initial forwarding address correctly set to 2001:db8:ffff::1")


def test_modify_routemap_no_forwarding():
    """
    Test that forwarding address is cleared when route-map is modified
    to remove forwarding-address configuration (CORRECT BEHAVIOR)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Capture the initial LSA sequence number BEFORE modifying the route-map
    initial_output = r2.vtysh_cmd("show ipv6 ospf6 database as-external json")
    initial_data = json.loads(initial_output)
    initial_seq = None
    for scope in initial_data.get("asScopedLinkStateDb", []):
        for lsa in scope.get("lsa", []):
            if lsa.get("lsId") == "0.0.0.1" and lsa.get("advRouter") == "10.0.0.1":
                initial_seq = lsa.get("seqNum")
                break

    logger.info("Modifying route-map to remove forwarding-address")

    # Modify route-map on R1 - remove forwarding-address, only set metric
    r1.vtysh_cmd(
        """
        configure terminal
        no route-map REDIS_MAP permit 10
        route-map REDIS_MAP permit 10
         set metric 200
        """
    )

    # Wait for LSA to be updated (sequence number should increment)

    def check_lsa_updated():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external json")
        data = json.loads(output)
        for scope in data.get("asScopedLinkStateDb", []):
            for lsa in scope.get("lsa", []):
                if lsa.get("lsId") == "0.0.0.1" and lsa.get("advRouter") == "10.0.0.1":
                    # Check if sequence number has incremented
                    current_seq = lsa.get("seqNum")
                    if initial_seq is not None and current_seq is not None:
                        return current_seq > initial_seq
                    return False
        return False

    test_func = check_lsa_updated
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
    assert result, "LSA was not updated after route-map change"

    def check_forwarding_cleared():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external 0.0.0.1 10.0.0.1")
        return "2001:db8:ffff::1" not in output

    _, result = topotest.run_and_expect(
        check_forwarding_cleared, True, count=30, wait=1
    )
    assert result, "Forwarding address should be cleared when removed from route-map"

    logger.info(
        "PASS: Forwarding address correctly cleared when removed from route-map"
    )


def test_explicitly_clear_forwarding():
    """
    Test that explicitly setting forwarding address to :: in route-map
    allows auto-calculation
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("Explicitly setting forwarding-address to :: in route-map")

    # Set forwarding address explicitly to :: (unspecified)
    r1.vtysh_cmd(
        """
        configure terminal
        route-map REDIS_MAP permit 10
         set forwarding-address ::
        """
    )

    # Wait for LSA to be updated after route-map change
    def check_lsa_updated():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external 0.0.0.1 10.0.0.1")
        # After setting to ::, the original forwarding address should be gone
        if "2001:db8:ffff::1" in output:
            return False  # Still has old forwarding address
        return True

    test_func = check_lsa_updated
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=0.5)
    assert result, "LSA was not updated after route-map change"

    def check_forwarding_cleared_to_unspecified():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external 0.0.0.1 10.0.0.1")
        return "2001:db8:ffff::1" not in output

    _, result = topotest.run_and_expect(
        check_forwarding_cleared_to_unspecified, True, count=30, wait=1
    )
    assert (
        result
    ), "Forwarding address should have been cleared when explicitly set to ::"

    logger.info("PASS: Explicit :: correctly cleared forwarding address")


def test_change_forwarding_address():
    """
    Test that changing forwarding-address to a new value in route-map
    properly updates the LSA with the new forwarding address
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Capture the initial LSA sequence number BEFORE modifying the route-map
    initial_output = r2.vtysh_cmd("show ipv6 ospf6 database as-external json")
    initial_data = json.loads(initial_output)
    initial_seq = None
    for scope in initial_data.get("asScopedLinkStateDb", []):
        for lsa in scope.get("lsa", []):
            if lsa.get("lsId") == "0.0.0.1" and lsa.get("advRouter") == "10.0.0.1":
                initial_seq = lsa.get("seqNum")
                break

    logger.info("Changing forwarding-address to a new value (2001:db8:eeee::1)")

    # Change forwarding address to a new value
    r1.vtysh_cmd(
        """
        configure terminal
        route-map REDIS_MAP permit 10
         set forwarding-address 2001:db8:eeee::1
         set metric 300
        """
    )

    # Wait for LSA to be updated (sequence number should increment)
    def check_lsa_updated():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external json")
        data = json.loads(output)
        for scope in data.get("asScopedLinkStateDb", []):
            for lsa in scope.get("lsa", []):
                if lsa.get("lsId") == "0.0.0.1" and lsa.get("advRouter") == "10.0.0.1":
                    # Check if sequence number has incremented
                    current_seq = lsa.get("seqNum")
                    if initial_seq is not None and current_seq is not None:
                        return current_seq > initial_seq
                    return False
        return False

    test_func = check_lsa_updated
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
    assert result, "LSA was not updated after route-map change"

    def check_forwarding_changed():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external 0.0.0.1 10.0.0.1")
        return "2001:db8:eeee::1" in output and "2001:db8:ffff::1" not in output

    _, result = topotest.run_and_expect(
        check_forwarding_changed, True, count=30, wait=1
    )
    assert result, "Forwarding address did not converge to the new value"

    logger.info(
        "PASS: Forwarding address successfully changed to new value 2001:db8:eeee::1"
    )


def test_change_forwarding_to_unspecified():
    """
    Test that changing forwarding-address from a value to :: clears it
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Capture the initial LSA sequence number BEFORE modifying the route-map
    initial_output = r2.vtysh_cmd("show ipv6 ospf6 database as-external json")
    initial_data = json.loads(initial_output)
    initial_seq = None
    for scope in initial_data.get("asScopedLinkStateDb", []):
        for lsa in scope.get("lsa", []):
            if lsa.get("lsId") == "0.0.0.1" and lsa.get("advRouter") == "10.0.0.1":
                initial_seq = lsa.get("seqNum")
                break

    logger.info("Changing forwarding-address from 2001:db8:eeee::1 to ::")

    # Change forwarding address to :: (unspecified)
    r1.vtysh_cmd(
        """
        configure terminal
        route-map REDIS_MAP permit 10
         set forwarding-address ::
         set metric 400
        """
    )

    # Wait for LSA to be updated (sequence number should increment)
    def check_lsa_updated():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external json")
        data = json.loads(output)
        for scope in data.get("asScopedLinkStateDb", []):
            for lsa in scope.get("lsa", []):
                if lsa.get("lsId") == "0.0.0.1" and lsa.get("advRouter") == "10.0.0.1":
                    # Check if sequence number has incremented
                    current_seq = lsa.get("seqNum")
                    if initial_seq is not None and current_seq is not None:
                        return current_seq > initial_seq
                    return False
        return False

    test_func = check_lsa_updated
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
    assert result, "LSA was not updated after route-map change"

    def check_forwarding_and_metric_updated():
        output = r2.vtysh_cmd("show ipv6 ospf6 database as-external 0.0.0.1 10.0.0.1")
        metric_ok = "Metric:   400" in output or "Metric: 400" in output
        return (
            "2001:db8:eeee::1" not in output
            and "2001:db8:ffff::1" not in output
            and metric_ok
        )

    _, result = topotest.run_and_expect(
        check_forwarding_and_metric_updated, True, count=30, wait=1
    )
    assert result, "Forwarding address/metric did not converge to expected values"

    logger.info("PASS: Forwarding address correctly cleared when changed to ::")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
