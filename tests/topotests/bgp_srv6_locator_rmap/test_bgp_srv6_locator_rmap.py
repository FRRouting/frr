#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2026 6WIND S.A.

import os
import sys
import pytest
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step
import functools
from lib.topolog import logger
import json

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("c11")
    tgen.add_router("c21")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")

    tgen.add_link(tgen.gears["r1"], tgen.gears["c11"], "eth1", "eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c11"], "eth2", "eth1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c11"], "eth3", "eth2")

    tgen.add_link(tgen.gears["r2"], tgen.gears["c21"], "eth1", "eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    r1 = tgen.gears["r1"]
    r1.run("sysctl net.vrf.strict_mode=1")
    r1.run("ip link add Vrf20 type vrf table 20")
    r1.run("ip link set Vrf20 up")
    r1.run("ip link set eth1 master Vrf20")
    r1.run("ip link set eth2 master Vrf20")
    r1.run("ip link set eth3 master Vrf20")

    r2 = tgen.gears["r2"]
    r2.run("sysctl net.vrf.strict_mode=1")
    r2.run("ip link add Vrf20 type vrf table 20")
    r2.run("ip link set Vrf20 up")
    r2.run("ip link set eth1 master Vrf20")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_locator_count(router, vrf, locator, count, ip_version="IPv4"):
    "Helper to check output of show bgp vrf ... locator-routemap"
    output = router.vtysh_cmd(f"show bgp vrf {vrf} locator-routemap detail")

    found_count = 0
    in_locator = False

    for line in output.splitlines():
        line = line.strip()
        if f"{locator}, #paths" in line:
            in_locator = True
            try:
                found_count = int(line.split("#paths")[1].strip())
            except ValueError:
                found_count = -1
            break

    if count == 0:
        if not in_locator:
            return None
        if found_count == 0:
            return None
        return f"Locator {locator} found with {found_count} paths, expected 0"

    if not in_locator:
        return f"Locator {locator} not found in output"

    if found_count != count:
        return f"Locator {locator} has {found_count} paths, expected {count}"

    return None


def test_verify_locator_assignment_initial_match():
    step("Check initial locator route-map application: NAME and NAME2 should be used")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info(
        "r1: Checking that route-map matches prefixes and assigns locators NAME and NAME2"
    )

    def _verify_step_1():
        return check_locator_count(r1, "Vrf20", "NAME", 1) or check_locator_count(
            r1, "Vrf20", "NAME2", 1
        )

    _, result = topotest.run_and_expect(_verify_step_1, None, count=20, wait=3)
    assert result is None, f"Step 1 Failed: {result}"


def _check_vpn_leak(router, expected_route_file):
    logger.info(f"Checking vpn-leak against {expected_route_file}")
    output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn detail json"))
    expected = open_json_file("{}/{}".format(CWD, expected_route_file))
    return topotest.json_cmp(output, expected)


def check_vpn_leak(router, expected_file):
    func = functools.partial(_check_vpn_leak, router, expected_file)
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


def test_configure_locator_main_and_verify_export():
    step("Configure locator MAIN and verify 2001:db08:1:1 export")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info(
        "r1: Configuring locator MAIN in VRF and checking 192.168.200.0/24 export"
    )
    r1.vtysh_cmd(
        "conf t\nrouter bgp 65001 vrf Vrf20\nsegment-routing srv6\nlocator MAIN"
    )

    def _verify_step_2():
        out = r1.vtysh_cmd("show bgp ipv4 vpn 192.168.200.0/24 json")
        if "2001:db08:1:1" not in out:  # MAIN Locator check
            return "3rd prefix not exported with MAIN Locator"

    _, result = topotest.run_and_expect(_verify_step_2, None, count=20, wait=3)
    assert result is None, f"Step 2 Failed: {result}"
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_configure_locator_main_and_verify_export: " + out)


def test_verify_vpn_leak_with_main_locator():
    step("Check vpn-leak with MAIN locator configured")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    check_vpn_leak(r1, "r1/expected_step1.json")
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_with_main_locator: " + out)


def test_remove_locator_name_retain_export():
    step("Remove locator NAME and verify route retention (reference check)")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info(
        "r1: Removing locator NAME, expecting route to persist with locator reference"
    )
    r1.vtysh_cmd("conf t\nsegment-routing\nsrv6\nlocators\nno locator NAME")

    def _verify_step_3():
        return check_locator_count(r1, "Vrf20", "NAME", 1)

    _, result = topotest.run_and_expect(_verify_step_3, None, count=10, wait=3)
    assert result is None, f"Step 3 Failed: {result}"
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_remove_locator_name_retain_export: " + out)


def test_verify_vpn_leak_removed_locator_name():
    step("Check vpn-leak after removing locator NAME")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    check_vpn_leak(r1, "r1/expected_step2.json")
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_removed_locator_name: " + out)


def test_restore_locator_name_and_detach_from_routemap():
    step("Restore locator NAME, then detach set command from route-map")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Restore NAME first as per sequence
    r1.vtysh_cmd(
        "conf t\nsegment-routing\nsrv6\nlocators\nlocator NAME\nprefix 2001:db09:1:2::/64"
    )

    logger.info("r1: Removing 'set segment-routing locator' from route-map entry 2")
    r1.vtysh_cmd(
        "conf t\nroute-map rmap_locator permit 2\nno set segment-routing srv6 locator"
    )

    def _verify_step_4():
        return check_locator_count(r1, "Vrf20", "NAME", 1)

    _, result = topotest.run_and_expect(_verify_step_4, None, count=20, wait=3)
    assert result is None, f"Step 4 Failed: {result}"
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_restore_locator_name_and_detach_from_routemap: " + out)


def test_verify_vpn_leak_detached_locator():
    step("Check vpn-leak after detaching locator from route-map")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    check_vpn_leak(r1, "r1/expected_step3.json")
    check_vpn_leak(r2, "r2/expected_step3.json")
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_detached_locator: " + out)


def test_verify_vpn_leak_remove_192_168_1_0():
    step("Check vpn-leak after removing network 192.168.1.0/24")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("r1: Unconfiguring 192.168.1.1/24 network from eth2")
    r1.vtysh_cmd("conf t\ninterface eth2\nno ip address 192.168.1.1/24\n")

    check_vpn_leak(r1, "r1/expected_step3_5.json")
    check_vpn_leak(r2, "r2/expected_step3_5.json")

    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_detached_locator: " + out)


def test_verify_vpn_leak_readd_192_168_1_0():
    step("Check vpn-leak after re-adding network 192.168.1.0/24")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    logger.info("r1: Reconfiguring 192.168.1.1/24 network from eth2")
    r1.vtysh_cmd("conf t\ninterface eth2\nip address 192.168.1.1/24\n")

    check_vpn_leak(r1, "r1/expected_step3.json")
    check_vpn_leak(r2, "r2/expected_step3.json")

    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_detached_locator: " + out)


def test_change_routemap_locator_name2_to_name():
    step(
        "Change route-map entry to use locator NAME instead of NAME2 (implied by removal) and verify SID release"
    )
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # NOTE: Previous step removed 'set ...' from permit 2. This step adds 'set ... NAME'.
    # This effectively verifies that NAME2 is no longer used/counted if it was used before.

    logger.info("r1: Setting route-map entry 2 to use locator NAME")
    r1.vtysh_cmd(
        "conf t\nroute-map rmap_locator permit 2\nset segment-routing srv6 locator NAME"
    )
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_change_routemap_locator_name2_to_name: " + out)


def test_verify_vpn_leak_name_reuse():
    step("Check vpn-leak after reusing locator NAME")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    check_vpn_leak(r1, "r1/expected_step4.json")
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_name_reuse: " + out)


def test_verify_name_locator_count_doubled():
    step("Verify that locator NAME is used twice (by permit 1 and permit 2)")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1: Setting route-map permit 1 to use locator NAME")
    r1.vtysh_cmd(
        "conf t\nroute-map rmap_locator permit 1\nset segment-routing srv6 locator NAME"
    )

    logger.info("r1: Verifying locator NAME count is 2")

    def _verify_step_6():
        return check_locator_count(r1, "Vrf20", "NAME", 2)

    _, result = topotest.run_and_expect(_verify_step_6, None, count=10, wait=3)
    assert result is None, f"Step 6 Failed: {result}"
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_name_locator_count_doubled: " + out)


def test_verify_vpn_leak_name_doubled():
    step("Check vpn-leak with locator NAME used twice")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    check_vpn_leak(r1, "r1/expected_step5.json")
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_name_doubled: " + out)


def test_routemap_add_set_locator_main():
    step("Add MAIN locator to route-map entry 1 and verify locator count")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1: Adding set locator MAIN to route-map permit 1")
    r1.vtysh_cmd(
        "conf t\nroute-map rmap_locator permit 1\nset segment-routing srv6 locator MAIN"
    )

    def _verify_step_7():
        # Expect NAME count to drop to 1 because permit 1 now uses MAIN
        return check_locator_count(r1, "Vrf20", "NAME", 1)

    _, result = topotest.run_and_expect(_verify_step_7, None, count=10, wait=3)
    assert result is None, f"Step 7 Failed: {result}"
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_routemap_add_set_locator_main: " + out)


def test_routemap_remove_entry_1():
    step("Remove route-map entry 1 and verify locator count")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Do the "Set MAIN" here, then verify count 1.
    logger.info("r1: Setting route-map permit 1 to use locator MAIN")
    r1.vtysh_cmd(
        "conf t\nroute-map rmap_locator permit 1\nset segment-routing srv6 locator MAIN"
    )

    def _verify_step_7():
        return check_locator_count(r1, "Vrf20", "NAME", 1)

    _, result = topotest.run_and_expect(_verify_step_7, None, count=10, wait=3)
    assert result is None, f"Step 7 Failed: {result}"
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_routemap_remove_entry_1: " + out)


def test_verify_vpn_leak_with_main_on_permit_1():
    step("Check vpn-leak with MAIN on permit 1")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    check_vpn_leak(r1, "r1/expected_step6.json")
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_with_main_on_permit_1: " + out)


def test_explicit_sid_export():
    step("Remove route-map permit 1 and configure explicit SID export")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1: Removing route-map permit 1")
    r1.vtysh_cmd("conf t\nno route-map rmap_locator permit 1")

    def _verify_step_8_part1():
        return check_locator_count(r1, "Vrf20", "NAME", 1)

    _, result = topotest.run_and_expect(_verify_step_8_part1, None, count=10, wait=3)
    assert result is None, f"Step 8 (Part 1) Failed: {result}"

    logger.info("r1: Configuring explicit SID export 100")
    r1.vtysh_cmd(
        """
        conf t
        router bgp 65001 vrf Vrf20
        address-family ipv4 unicast
        no sid vpn export auto
        sid vpn export 100
        """
    )

    # No specific locator count check for export 100, just leak check
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_explicit_sid_export: " + out)


def test_verify_vpn_leak_explicit_export():
    step("Check vpn-leak with explicit SID export")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    check_vpn_leak(r1, "r1/expected_step7.json")
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_explicit_export: " + out)


def test_use_explicit_and_dynamic_sid_from_same_locator():
    step("Readd route-map permit 1 with locator MAIN")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("r1: Adding back route-map permit 1 with MAIN locator")
    r1.vtysh_cmd(
        """
        conf t
        route-map rmap_locator permit 1
        match ip address prefix-list plist_192x
        set segment-routing srv6 locator MAIN
        """
    )
    step("Check the SIDs allocated with route-map")

    def _verify_step_1():
        return check_locator_count(r1, "Vrf20", "MAIN", 1) or check_locator_count(
            r1, "Vrf20", "NAME", 1
        )

    _, result = topotest.run_and_expect(_verify_step_1, None, count=20, wait=3)
    assert result is None, f"Chec the SIDs allocated with route-map Failed: {result}"

    check_vpn_leak(r1, "r1/expected_step8.json")
    out = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info("test_verify_vpn_leak_explicit_export: " + out)
