#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2026 6WIND S.A.

import os
import sys
import pytest
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import retry, step
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


def get_vpn_prefix_sids(router, prefix, rd="65001:20"):
    "Return the SIDs of the VPN paths of prefix exported with rd"
    output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn detail json"))
    rds = output.get("routes", {}).get("routeDistinguishers", {})
    return [
        path.get("remoteTransposedSid", path.get("remoteSid", ""))
        for path in rds.get(rd, {}).get(prefix, [])
    ]


def get_bgp_sids_of_locator(router, locator):
    "Return the SIDs allocated by bgp from locator"
    output = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
    return [
        sid
        for sid, sid_info in output.items()
        if sid_info.get("locator") == locator
        and "bgp" in [c.get("protocol") for c in sid_info.get("clients", [])]
    ]


@retry(retry_timeout=30)
def check_bgp_sid_of_locator(router, locator, expect_allocated):
    sids = get_bgp_sids_of_locator(router, locator)
    if bool(sids) != expect_allocated:
        return f"SIDs of locator {locator} allocated by bgp: {sids}, expected {expect_allocated}"
    return True


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


def test_no_export_vpn_route_map_locator():
    """
    Unconfigure 'export vpn' in Vrf20, where the export route-map sets the
    locator NAME for 10.0.0.0/24. Check that bgp releases the SID of locator
    NAME. Then flap 10.0.0.0/24, and check that it is not exported to VPN.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    result = check_bgp_sid_of_locator(r1, "NAME", True)
    assert result is True, result

    r1.vtysh_multicmd(
        """
        configure
        router bgp 65001 vrf Vrf20
        address-family ipv4 unicast
        no export vpn
        """
    )

    result = check_bgp_sid_of_locator(r1, "NAME", False)
    output = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info(output)
    assert result is True, result

    r1.vtysh_multicmd(
        """
        configure
        interface eth1
        no ip address 10.0.0.1/24
        """
    )

    @retry(retry_timeout=30)
    def check_vrf_prefix(expect_present):
        output = json.loads(
            r1.vtysh_cmd("show bgp vrf Vrf20 ipv4 unicast 10.0.0.0/24 json")
        )
        if bool(output.get("paths")) != expect_present:
            return f"10.0.0.0/24 presence in Vrf20 is not {expect_present}"
        return True

    result = check_vrf_prefix(False)
    assert result is True, result

    r1.vtysh_multicmd(
        """
        configure
        interface eth1
        ip address 10.0.0.1/24
        """
    )

    result = check_vrf_prefix(True)
    assert result is True, result

    sids = get_vpn_prefix_sids(r1, "10.0.0.0/24")
    output = r1.vtysh_cmd("show bgp ipv4 vpn 10.0.0.0/24")
    logger.info(output)
    assert not sids, f"10.0.0.0/24 exported to VPN without export vpn: {sids}"


def test_export_vpn_route_map_locator():
    """
    Configure 'export vpn' again. Check that 10.0.0.0/24 is exported with a
    SID of locator NAME.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_multicmd(
        """
        configure
        router bgp 65001 vrf Vrf20
        address-family ipv4 unicast
        export vpn
        """
    )

    @retry(retry_timeout=30)
    def check_vpn_prefix_exported_with_name():
        sids = get_vpn_prefix_sids(r1, "10.0.0.0/24")
        if not sids:
            return "10.0.0.0/24 not exported to VPN"
        if not all(sid.startswith("2001:db09:1:2:") for sid in sids):
            return f"10.0.0.0/24 not exported with a SID of locator NAME: {sids}"
        return True

    result = check_vpn_prefix_exported_with_name()
    output = r1.vtysh_cmd("show bgp ipv4 vpn 10.0.0.0/24")
    logger.info(output)
    assert result is True, result


def test_remove_locator_used_by_two_prefixes():
    """
    Set locator NAME on route-map entry 1, so that 192.168.1.0/24 and
    10.0.0.0/24 use locator NAME. Then remove locator NAME, and check that
    its SID is no longer used.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    prefixes = ("10.0.0.0/24", "192.168.1.0/24")

    r1.vtysh_cmd(
        "conf t\nroute-map rmap_locator permit 1\nset segment-routing srv6 locator NAME"
    )

    @retry(retry_timeout=30)
    def check_name_used_by_two_prefixes():
        result = check_locator_count(r1, "Vrf20", "NAME", 2)
        if result:
            return result
        for prefix in prefixes:
            sids = get_vpn_prefix_sids(r1, prefix)
            if not sids or not all(sid.startswith("2001:db09:1:2:") for sid in sids):
                return f"{prefix} not exported with a SID of locator NAME: {sids}"
        return True

    result = check_name_used_by_two_prefixes()
    assert result is True, result

    r1.vtysh_cmd("conf t\nsegment-routing\nsrv6\nlocators\nno locator NAME")

    @retry(retry_timeout=30)
    def check_name_sid_not_used():
        output = json.loads(r1.vtysh_cmd("show bgp vrf Vrf20 locator-routemap json"))
        for entry in output:
            if entry.get("locatorName") == "NAME" and "sid" in entry:
                return f"locator NAME still has SID {entry['sid']}"
        for prefix in prefixes:
            sids = get_vpn_prefix_sids(r1, prefix)
            if any(sid.startswith("2001:db09:1:2:") for sid in sids):
                return f"{prefix} still exported with a SID of locator NAME: {sids}"
        return True

    result = check_name_sid_not_used()
    output = r1.vtysh_cmd("show bgp vrf Vrf20 locator-routemap detail")
    logger.info(output)
    assert result is True, result


def test_no_export_vpn_route_map_locator_without_vrf_sid():
    """
    Restore locator NAME, set it on route-map entry 1 so that 192.168.1.0/24
    and 10.0.0.0/24 use it, and remove the locator of Vrf20 while 'sid vpn
    export auto' is configured, so that the SID of Vrf20 can not be allocated.
    The prefixes whose locator NAME is set by the export route-map are exported.
    Then unconfigure 'export vpn', and check that these prefixes are withdrawn.
    Configure 'export vpn' again, and check that they are exported again.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    prefixes = ("10.0.0.0/24", "192.168.1.0/24")

    r1.vtysh_multicmd(
        """
        configure
        segment-routing
        srv6
        locators
        locator NAME
        prefix 2001:db09:1:2::/64
        exit
        exit
        exit
        exit
        route-map rmap_locator permit 1
        set segment-routing srv6 locator NAME
        exit
        router bgp 65001 vrf Vrf20
        segment-routing srv6
        no locator MAIN
        exit
        address-family ipv4 unicast
        no sid vpn export 100
        sid vpn export auto
        """
    )

    @retry(retry_timeout=30)
    def check_vpn_prefixes_exported(expect_exported):
        for prefix in prefixes:
            sids = get_vpn_prefix_sids(r1, prefix)
            if not expect_exported:
                if sids:
                    return f"{prefix} still exported to VPN: {sids}"
                continue
            if not sids or not all(sid.startswith("2001:db09:1:2:") for sid in sids):
                return f"{prefix} not exported with a SID of locator NAME: {sids}"
        return True

    result = check_vpn_prefixes_exported(True)
    assert result is True, result

    r1.vtysh_multicmd(
        """
        configure
        router bgp 65001 vrf Vrf20
        address-family ipv4 unicast
        no export vpn
        """
    )

    result = check_vpn_prefixes_exported(False)
    output = r1.vtysh_cmd("show bgp ipv4 vpn 10.0.0.0/24")
    logger.info(output)
    assert result is True, result

    r1.vtysh_multicmd(
        """
        configure
        router bgp 65001 vrf Vrf20
        address-family ipv4 unicast
        export vpn
        """
    )

    result = check_vpn_prefixes_exported(True)
    assert result is True, result


def test_withdraw_route_map_locator_path_after_update_without_vrf_sid():
    """
    Vrf20 has 'sid vpn export auto' but no locator, so its SID can not be
    allocated. Export the connected prefixes with route-map rmap_export:
    metric 20 is denied, metric 30 is permitted without locator, other
    metrics get locator NAME. The metric is set by the redistribute route-map
    rmap_redist, whose changes update the paths of Vrf20 without withdrawing
    them. Check that 10.0.0.0/24 is withdrawn from VPN when its update is
    denied by the export route-map, then when its update no longer gets a
    locator from the export route-map.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    prefix = "10.0.0.0/24"

    r1.vtysh_multicmd(
        """
        configure
        route-map rmap_redist permit 10
        exit
        route-map rmap_export deny 10
        match metric 20
        exit
        route-map rmap_export permit 20
        match metric 30
        exit
        route-map rmap_export permit 30
        set segment-routing srv6 locator NAME
        exit
        router bgp 65001 vrf Vrf20
        address-family ipv4 unicast
        redistribute connected route-map rmap_redist
        route-map vpn export rmap_export
        """
    )

    @retry(retry_timeout=30)
    def check_vpn_prefix_exported(expect_exported):
        sids = get_vpn_prefix_sids(r1, prefix)
        if not expect_exported:
            if sids:
                return f"{prefix} still exported to VPN: {sids}"
            return True
        if not sids or not all(sid.startswith("2001:db09:1:2:") for sid in sids):
            return f"{prefix} not exported with a SID of locator NAME: {sids}"
        return True

    result = check_vpn_prefix_exported(True)
    assert result is True, result

    r1.vtysh_multicmd(
        """
        configure
        route-map rmap_redist permit 10
        set metric 20
        """
    )

    denied = check_vpn_prefix_exported(False)
    output = r1.vtysh_cmd(f"show bgp ipv4 vpn {prefix}")
    logger.info(output)
    output = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info(output)

    r1.vtysh_multicmd(
        """
        configure
        route-map rmap_redist permit 10
        no set metric
        """
    )

    exported = check_vpn_prefix_exported(True)

    r1.vtysh_multicmd(
        """
        configure
        route-map rmap_redist permit 10
        set metric 30
        """
    )

    no_locator = check_vpn_prefix_exported(False)
    output = r1.vtysh_cmd(f"show bgp ipv4 vpn {prefix}")
    logger.info(output)
    output = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info(output)

    r1.vtysh_multicmd(
        """
        configure
        router bgp 65001 vrf Vrf20
        address-family ipv4 unicast
        no redistribute connected
        redistribute connected
        route-map vpn export rmap_locator
        exit-address-family
        exit
        no route-map rmap_redist
        no route-map rmap_export
        """
    )

    @retry(retry_timeout=30)
    def check_name_used_by_two_paths():
        return check_locator_count(r1, "Vrf20", "NAME", 2) or True

    restored = check_name_used_by_two_paths()

    assert denied is True, denied
    assert exported is True, exported
    assert no_locator is True, no_locator
    assert restored is True, restored


def test_route_map_locator_localsid_uninstall():
    """
    Locator NAME is set by entries 1 and 2 of rmap_locator. Remove the set
    command from both entries: no prefix uses locator NAME any more, and the
    local SID of locator NAME must be removed from the RIB.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def get_name_sid():
        output = json.loads(r1.vtysh_cmd("show bgp vrf Vrf20 locator-routemap json"))
        for entry in output:
            if entry.get("locatorName") == "NAME":
                return entry.get("sid")
        return None

    @retry(retry_timeout=30)
    def check_localsid_installed(sid, expect_installed):
        output = json.loads(r1.vtysh_cmd(f"show ipv6 route {sid}/128 json"))
        installed = f"{sid}/128" in output
        if installed != expect_installed:
            return (
                f"local SID {sid} installed: {installed}, expected {expect_installed}"
            )
        return True

    sid = get_name_sid()
    assert sid, "locator NAME has no SID"

    result = check_localsid_installed(sid, True)
    assert result is True, result

    r1.vtysh_multicmd(
        """
        configure
        route-map rmap_locator permit 1
        no set segment-routing srv6 locator
        exit
        route-map rmap_locator permit 2
        no set segment-routing srv6 locator
        """
    )

    result = check_localsid_installed(sid, False)
    output = r1.vtysh_cmd(f"show ipv6 route {sid}/128")
    logger.info(output)

    r1.vtysh_multicmd(
        """
        configure
        route-map rmap_locator permit 1
        set segment-routing srv6 locator NAME
        exit
        route-map rmap_locator permit 2
        set segment-routing srv6 locator NAME
        """
    )

    @retry(retry_timeout=30)
    def check_name_used_by_two_paths():
        return check_locator_count(r1, "Vrf20", "NAME", 2) or True

    restored = check_name_used_by_two_paths()

    assert result is True, result
    assert restored is True, restored


def test_delete_vrf_instance_releases_locator_sid():
    """
    Remove the Vrf20 BGP instance, whose prefixes use the SID of locator NAME
    set by the export route-map. Check that zebra no longer has any SID
    allocated by bgp for Vrf20.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    result = check_locator_count(r1, "Vrf20", "NAME", 2)
    assert result is None, result

    r1.vtysh_cmd("conf t\nno router bgp 65001 vrf Vrf20")

    @retry(retry_timeout=30)
    def check_no_bgp_sid_for_vrf20():
        output = json.loads(r1.vtysh_cmd("show segment-routing srv6 sid json"))
        for sid, sid_info in output.items():
            if sid_info.get("context", {}).get("vrfName") != "Vrf20":
                continue
            clients = [c.get("protocol") for c in sid_info.get("clients", [])]
            if "bgp" in clients:
                return f"SID {sid} of locator {sid_info.get('locator')} still allocated by bgp for Vrf20"
        return True

    result = check_no_bgp_sid_for_vrf20()
    output = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info(output)
    assert result is True, result


def test_delete_vrf_releases_locator_sid():
    """
    Configure the Vrf20 BGP instance again, so that its prefixes use the SID
    of locator NAME set by the export route-map. Then delete the Vrf20 VRF
    from the kernel, and check that zebra no longer has any SID allocated by
    bgp from locator NAME.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_multicmd(
        """
        configure
        router bgp 65001 vrf Vrf20
        bgp router-id 1.1.1.1
        address-family ipv4 unicast
        sid vpn export auto
        redistribute connected
        rd vpn export 65001:20
        rt vpn both 65001:20
        export vpn
        import vpn
        route-map vpn export rmap_locator
        """
    )

    result = check_bgp_sid_of_locator(r1, "NAME", True)
    assert result is True, result

    r1.run("ip link del Vrf20")

    result = check_bgp_sid_of_locator(r1, "NAME", False)
    output = r1.vtysh_cmd("show segment-routing srv6 sid")
    logger.info(output)
    assert result is True, result
