#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_kernel_nhg.py
#
# Copyright (c) 2026 Nvidia Inc.
#                    Donald Sharp
#

"""
test_zebra_kernel_nhg.py: verify kernel nexthop-group routes in zebra.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    r1 = tgen.gears["r1"]
    _install_kernel_nhgs(r1)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _install_kernel_nhgs(r1):
    step("Create kernel nexthops and nexthop-groups")
    r1.cmd("ip nexthop add id 101 via 192.168.1.10 dev r1-eth0")
    r1.cmd("ip nexthop add id 102 via 192.168.1.11 dev r1-eth0")
    r1.cmd("ip nexthop add id 103 via 192.168.1.12 dev r1-eth0")

    r1.cmd("ip nexthop add id 201 group 101/102")
    r1.cmd("ip nexthop add id 202 group 102/103")
    r1.cmd("ip nexthop add id 203 group 101/103")

    step("Create kernel routes using nhg IDs")
    r1.cmd("ip route add 10.10.0.0/24 nhid 201")
    r1.cmd("ip route add 10.20.0.0/24 nhid 202")
    r1.cmd("ip route add 10.30.0.0/24 nhid 203")

    step("Create kernel routes using traditional nexthops")
    r1.cmd("ip route add 10.40.0.0/24 via 192.168.1.20 dev r1-eth0")
    r1.cmd("ip route add 10.50.0.0/24 via 192.168.1.21 dev r1-eth0")
    r1.cmd("ip route add 10.60.0.0/24 via 192.168.1.20 dev r1-eth0")


def _get_route_entry(r1, prefix):
    route_json = r1.vtysh_cmd(f"show ip route {prefix} json", isjson=True)
    routes = route_json.get(prefix, [])
    if not routes:
        return None
    return routes[0]


def _get_route_nhg_id(r1, prefix):
    route = _get_route_entry(r1, prefix)
    if not route:
        return None
    return route.get("nexthopGroupId")


def _get_unused_nhg_ids(r1, count):
    nhg_json = r1.vtysh_cmd("show nexthop-group rib json", isjson=True)
    used_ids = set()

    for vrf_data in nhg_json.values():
        if not isinstance(vrf_data, dict):
            continue
        for nhg_id in vrf_data:
            try:
                used_ids.add(int(nhg_id))
            except ValueError:
                continue

    candidate = (max(used_ids) + 1) if used_ids else 1
    return list(range(candidate, candidate + count))


def test_kernel_nhg_routes():
    "Verify kernel routes reflect expected NHG IDs in zebra"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    expected = {
        "10.10.0.0/24": 201,
        "10.20.0.0/24": 202,
        "10.30.0.0/24": 203,
    }
    traditional = ["10.40.0.0/24", "10.50.0.0/24", "10.60.0.0/24"]

    def _check_nhg_summary():
        output = r1.vtysh_cmd("show ip route nexthop-group summary json")
        try:
            route_json = json.loads(output)
        except json.JSONDecodeError as err:
            logger.info("Failed to parse JSON: %s", err)
            return False

        for prefix, expected_nhg in expected.items():
            if prefix not in route_json:
                logger.info("Prefix %s not found in summary output", prefix)
                return False

            route = route_json[prefix][0]
            received_nhg = route.get("receivedNexthopGroupId")
            if received_nhg != expected_nhg:
                logger.info(
                    "Prefix %s expected NHG %s, got %s",
                    prefix,
                    expected_nhg,
                    received_nhg,
                )
                return False

        for prefix in traditional:
            if prefix not in route_json:
                logger.info("Traditional prefix %s missing in summary output", prefix)
                return False

        nhg_40 = route_json["10.40.0.0/24"][0].get("receivedNexthopGroupId")
        nhg_60 = route_json["10.60.0.0/24"][0].get("receivedNexthopGroupId")
        if nhg_40 != nhg_60:
            logger.info(
                "Traditional prefixes 10.40.0.0/24 and 10.60.0.0/24 have different NHG IDs: %s vs %s",
                nhg_40,
                nhg_60,
            )
            return False

        return True

    step("Verify routes have expected received NHG IDs")
    success, _ = topotest.run_and_expect(_check_nhg_summary, True, count=20, wait=1)
    assert success, "Kernel routes missing expected received NHG IDs"


def test_frr_owned_nhg_replace_is_reverted():
    "Verify zebra restores FRR-owned NHGs after external replace"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    prefix = "10.80.0.0/24"
    original_ip = "192.168.1.30"
    replacement_ip = "192.168.1.31"

    step("Create FRR-owned static route")
    r1.vtysh_cmd(
        f"""
        configure terminal
         ip route {prefix} {original_ip}
        """
    )

    def _get_frr_owned_nhg():
        nhg_id = _get_route_nhg_id(r1, prefix)
        if nhg_id is None:
            logger.info("Failed to get NHG ID for FRR-owned route %s", prefix)
            return None

        nhg_json = r1.vtysh_cmd(f"show nexthop-group rib {nhg_id} json", isjson=True)
        nhg = nhg_json.get(str(nhg_id))
        if not nhg:
            logger.info("FRR-owned NHG %s not found", nhg_id)
            return None

        if nhg.get("type") != "zebra":
            logger.info(
                "Expected FRR-owned NHG %s to be type zebra, got %s",
                nhg_id,
                nhg.get("type"),
            )
            return None

        return nhg_id

    step("Wait for FRR-owned NHG to be installed")
    success, nhg_id = topotest.run_and_expect_type(
        _get_frr_owned_nhg, int, count=20, wait=1
    )
    assert success, f"FRR-owned NHG for route {prefix} was not installed"

    step("Externally replace FRR-owned kernel nexthop")
    r1.cmd(f"ip nexthop replace id {nhg_id} via {replacement_ip} dev r1-eth0")

    def _check_frr_owned_replace_reverted():
        nhg_json = r1.vtysh_cmd(f"show nexthop-group rib {nhg_id} json", isjson=True)
        nhg = nhg_json.get(str(nhg_id))
        if not nhg:
            logger.info("FRR-owned NHG %s disappeared after replace", nhg_id)
            return False

        if nhg.get("type") != "zebra":
            logger.info(
                "FRR-owned NHG %s type mismatch after replace: %s",
                nhg_id,
                nhg.get("type"),
            )
            return False

        nexthops = nhg.get("nexthops", [])
        if len(nexthops) != 1 or nexthops[0].get("ip") != original_ip:
            logger.info(
                "FRR-owned NHG %s not restored to %s: %s", nhg_id, original_ip, nexthops
            )
            return False

        kernel_nh = r1.cmd(f"ip nexthop show id {nhg_id}")
        if original_ip not in kernel_nh or replacement_ip in kernel_nh:
            logger.info("Kernel NHG %s not restored, output: %s", nhg_id, kernel_nh)
            return False

        return True

    step("Verify zebra restored FRR-owned NHG to its original state")
    success, _ = topotest.run_and_expect(
        _check_frr_owned_replace_reverted, True, count=20, wait=1
    )
    assert success, "FRR-owned NHG replace was not reverted by zebra"

    step("Remove FRR-owned static route")
    r1.vtysh_cmd(
        f"""
        configure terminal
         no ip route {prefix} {original_ip}
        """
    )


def test_frr_owned_nhg_delete_is_recreated():
    "Verify zebra recreates FRR-owned NHGs after external delete"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    prefix = "10.81.0.0/24"
    gateway = "192.168.1.32"

    step("Create FRR-owned static route for delete test")
    r1.vtysh_cmd(
        f"""
        configure terminal
         ip route {prefix} {gateway}
        """
    )

    def _get_frr_owned_nhg():
        nhg_id = _get_route_nhg_id(r1, prefix)
        if nhg_id is None:
            logger.info("Failed to get NHG ID for FRR-owned route %s", prefix)
            return None

        nhg_json = r1.vtysh_cmd(f"show nexthop-group rib {nhg_id} json", isjson=True)
        nhg = nhg_json.get(str(nhg_id))
        if not nhg or nhg.get("type") != "zebra":
            logger.info("FRR-owned NHG %s missing or wrong type: %s", nhg_id, nhg)
            return None

        return nhg_id

    step("Wait for FRR-owned NHG to be installed")
    success, nhg_id = topotest.run_and_expect_type(
        _get_frr_owned_nhg, int, count=20, wait=1
    )
    assert success, f"FRR-owned NHG for route {prefix} was not installed"

    step("Externally delete FRR-owned kernel nexthop")
    r1.cmd(f"ip nexthop del id {nhg_id}")

    def _check_frr_owned_delete_recreated():
        route = _get_route_entry(r1, prefix)
        if not route or route.get("nexthopGroupId") != nhg_id:
            logger.info(
                "FRR-owned route %s missing or changed NHG after delete: %s",
                prefix,
                route,
            )
            return False

        nhg_json = r1.vtysh_cmd(f"show nexthop-group rib {nhg_id} json", isjson=True)
        nhg = nhg_json.get(str(nhg_id))
        if not nhg or nhg.get("type") != "zebra":
            logger.info(
                "FRR-owned NHG %s missing or wrong type after delete: %s", nhg_id, nhg
            )
            return False

        kernel_nh = r1.cmd(f"ip nexthop show id {nhg_id}")
        if gateway not in kernel_nh:
            logger.info(
                "Kernel NHG %s was not recreated, output: %s", nhg_id, kernel_nh
            )
            return False

        return True

    step("Verify zebra recreated FRR-owned NHG")
    success, _ = topotest.run_and_expect(
        _check_frr_owned_delete_recreated, True, count=20, wait=1
    )
    assert success, "FRR-owned NHG delete was not recreated by zebra"

    step("Remove FRR-owned static route")
    r1.vtysh_cmd(
        f"""
        configure terminal
         no ip route {prefix} {gateway}
        """
    )


def test_kernel_nhg_replace_group_members():
    "Verify zebra tracks runtime kernel NHG membership updates"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Replace kernel nexthop-group 201 members")
    r1.cmd("ip nexthop replace id 201 group 101/103")

    def _check_replaced_group():
        nhg_json = r1.vtysh_cmd("show nexthop-group rib 201 json", isjson=True)
        nhg = nhg_json.get("201")
        if not nhg:
            logger.info("Kernel NHG 201 not found after replace")
            return False

        depends = nhg.get("depends", [])
        if sorted(depends) != [101, 103]:
            logger.info("Kernel NHG 201 depends mismatch after replace: %s", depends)
            return False

        route_json = r1.vtysh_cmd(
            "show ip route nexthop-group summary json", isjson=True
        )
        route = route_json.get("10.10.0.0/24", [{}])[0]
        if route.get("receivedNexthopGroupId") != 201:
            logger.info(
                "Route 10.10.0.0/24 expected received NHG 201, got %s",
                route.get("receivedNexthopGroupId"),
            )
            return False

        return True

    step("Verify zebra updated NHG 201 membership")
    success, _ = topotest.run_and_expect(_check_replaced_group, True, count=20, wait=1)
    assert success, "Kernel NHG 201 membership change not reflected in zebra"


def test_kernel_nhg_delete_notifications():
    "Verify zebra tracks runtime kernel nexthop object deletions"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    singleton_id, group_id = _get_unused_nhg_ids(r1, 2)

    step(
        "Create temporary kernel nexthop {} and nexthop-group {}".format(
            singleton_id, group_id
        )
    )
    r1.cmd_raises(f"ip nexthop add id {singleton_id} via 192.168.1.13 dev r1-eth0")
    r1.cmd_raises(f"ip nexthop add id {group_id} group 101/{singleton_id}")

    def _check_temp_group_present():
        nhg_json = r1.vtysh_cmd(f"show nexthop-group rib {group_id} json", isjson=True)
        nhg = nhg_json.get(str(group_id))
        if not nhg:
            logger.info("Temporary kernel NHG %s not found", group_id)
            return False

        depends = nhg.get("depends", [])
        if sorted(depends) != [101, singleton_id]:
            logger.info("Kernel NHG %s depends mismatch: %s", group_id, depends)
            return False

        return True

    step("Verify temporary kernel nexthop-group {} is present".format(group_id))
    success, _ = topotest.run_and_expect(
        _check_temp_group_present, True, count=20, wait=1
    )
    assert success, f"Temporary kernel NHG {group_id} was not learned by zebra"

    step(
        "Delete temporary kernel nexthop-group {} and singleton nexthop {}".format(
            group_id, singleton_id
        )
    )
    r1.cmd(f"ip nexthop del id {group_id}")
    r1.cmd_raises(f"ip nexthop del id {singleton_id}")

    def _check_temp_objects_removed():
        nhg_json = r1.vtysh_cmd("show nexthop-group rib json", isjson=True)
        default_vrf = nhg_json.get("default", {})
        if str(group_id) in default_vrf:
            logger.info("Temporary kernel NHG %s still present in zebra", group_id)
            return False
        if str(singleton_id) in default_vrf:
            logger.info(
                "Temporary singleton kernel NH %s still present in zebra",
                singleton_id,
            )
            return False
        return True

    step(
        "Verify zebra processed kernel delete notifications for {} and {}".format(
            group_id, singleton_id
        )
    )
    success, _ = topotest.run_and_expect(
        _check_temp_objects_removed, True, count=20, wait=1
    )
    assert success, "Kernel nexthop delete notification not reflected in zebra"


def test_kernel_deleted_nhg_with_references_is_not_kept_around():
    "Verify kernel NHGs drop deleted members without entering keep-around"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    singleton_id, group_id = _get_unused_nhg_ids(r1, 2)

    step(
        "Create referenced kernel singleton {} and dependent kernel NHG {}".format(
            singleton_id, group_id
        )
    )
    r1.cmd_raises(f"ip nexthop add id {singleton_id} via 192.168.1.14 dev r1-eth0")
    r1.cmd_raises(f"ip nexthop add id {group_id} group 101/{singleton_id}")

    def _check_dependent_nhg_present():
        nhg_json = r1.vtysh_cmd(f"show nexthop-group rib {group_id} json", isjson=True)
        nhg = nhg_json.get(str(group_id))
        if not nhg:
            logger.info("Dependent kernel NHG %s not found", group_id)
            return False

        depends = nhg.get("depends", [])
        if sorted(depends) != [101, singleton_id]:
            logger.info(
                "Dependent kernel NHG %s depends mismatch: %s", group_id, depends
            )
            return False

        return True

    step("Verify dependent kernel NHG {} is present".format(group_id))
    success, _ = topotest.run_and_expect(
        _check_dependent_nhg_present, True, count=20, wait=1
    )
    assert success, f"Dependent kernel NHG {group_id} was not learned by zebra"

    step(
        "Delete referenced kernel singleton {} while dependent NHG {} still exists".format(
            singleton_id, group_id
        )
    )
    r1.cmd(f"ip nexthop del id {singleton_id}")

    def _check_deleted_member_removed_from_group():
        nhg_json = r1.vtysh_cmd(f"show nexthop-group rib {group_id} json", isjson=True)
        nhg = nhg_json.get(str(group_id))
        if not nhg:
            logger.info("Dependent kernel NHG %s disappeared unexpectedly", group_id)
            return False

        depends = nhg.get("depends", [])
        if depends != [101]:
            logger.info(
                "Dependent kernel NHG %s was not updated after deleting %s: %s",
                group_id,
                singleton_id,
                depends,
            )
            return False

        all_nhgs = r1.vtysh_cmd("show nexthop-group rib json", isjson=True).get(
            "default", {}
        )
        singleton = all_nhgs.get(str(singleton_id))
        if singleton:
            if singleton.get("keepAround", False) or "timeToDeletion" in singleton:
                logger.info(
                    "Deleted kernel NHG %s incorrectly entered keep-around: %s",
                    singleton_id,
                    singleton,
                )
                return False
            if singleton.get("installed", False):
                logger.info(
                    "Deleted kernel NHG %s should no longer be installed: %s",
                    singleton_id,
                    singleton,
                )
                return False

        return True

    step(
        "Verify kernel NHG {} drops deleted member {} without keep-around".format(
            group_id, singleton_id
        )
    )
    success, _ = topotest.run_and_expect(
        _check_deleted_member_removed_from_group, True, count=20, wait=1
    )
    assert (
        success
    ), f"Kernel NHG {group_id} was not updated correctly after deleting {singleton_id}"

    def _check_deleted_singleton_removed():
        nhg_json = r1.vtysh_cmd("show nexthop-group rib json", isjson=True)
        default_vrf = nhg_json.get("default", {})
        if str(singleton_id) in default_vrf:
            logger.info(
                "Deleted kernel NHG %s still present after dependent update",
                singleton_id,
            )
            return False
        return True

    step(
        "Verify deleted kernel singleton {} is removed after NHG {} update".format(
            singleton_id, group_id
        )
    )
    success, _ = topotest.run_and_expect(
        _check_deleted_singleton_removed, True, count=20, wait=1
    )
    assert success, f"Deleted kernel NHG {singleton_id} was not fully removed"

    step("Delete dependent kernel NHG {}".format(group_id))
    r1.cmd_raises(f"ip nexthop del id {group_id}")

    def _check_deleted_dependency_chain_removed():
        nhg_json = r1.vtysh_cmd("show nexthop-group rib json", isjson=True)
        default_vrf = nhg_json.get("default", {})
        if str(group_id) in default_vrf:
            logger.info("Deleted dependent kernel NHG %s still present", group_id)
            return False
        return True

    step("Verify dependent kernel NHG {} is fully removed".format(group_id))
    success, _ = topotest.run_and_expect(
        _check_deleted_dependency_chain_removed, True, count=20, wait=1
    )
    assert success, f"Deleted dependent kernel NHG {group_id} was not fully removed"


def test_kernel_blackhole_nexthop():
    "Verify zebra receives kernel blackhole nexthops through dplane"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    (nhg_id,) = _get_unused_nhg_ids(r1, 1)

    step("Create kernel blackhole nexthop {} and route".format(nhg_id))
    r1.cmd_raises(f"ip nexthop add id {nhg_id} blackhole")
    r1.cmd_raises(f"ip route add 10.70.0.0/24 nhid {nhg_id}")

    def _check_blackhole_nexthop():
        route_json = r1.vtysh_cmd(
            "show ip route nexthop-group summary json", isjson=True
        )
        route = route_json.get("10.70.0.0/24", [{}])[0]
        if route.get("receivedNexthopGroupId") != nhg_id:
            logger.info(
                "Route 10.70.0.0/24 expected received NHG %s, got %s",
                nhg_id,
                route.get("receivedNexthopGroupId"),
            )
            return False

        nhg_json = r1.vtysh_cmd(f"show nexthop-group rib {nhg_id} json", isjson=True)
        nhg = nhg_json.get(str(nhg_id))
        if not nhg:
            logger.info("Kernel blackhole NHG %s not found", nhg_id)
            return False

        if nhg.get("type") != "kernel":
            logger.info(
                "Kernel blackhole NHG %s type mismatch: %s", nhg_id, nhg.get("type")
            )
            return False

        nexthops = nhg.get("nexthops", [])
        if len(nexthops) != 1:
            logger.info(
                "Kernel blackhole NHG %s expected 1 nexthop, got %s",
                nhg_id,
                len(nexthops),
            )
            return False

        nexthop = nexthops[0]
        if not nexthop.get("unreachable", False):
            logger.info(
                "Kernel blackhole NHG %s is missing unreachable flag: %s",
                nhg_id,
                nexthop,
            )
            return False

        if "interfaceName" in nexthop:
            logger.info(
                "Kernel blackhole NHG %s unexpectedly has interface data: %s",
                nhg_id,
                nexthop,
            )
            return False

        return True

    step("Verify zebra learned kernel blackhole nexthop {}".format(nhg_id))
    success, _ = topotest.run_and_expect(
        _check_blackhole_nexthop, True, count=20, wait=1
    )
    assert success, "Kernel blackhole nexthop was not reflected correctly in zebra"

    step("Remove kernel blackhole nexthop {} and route".format(nhg_id))
    r1.cmd("ip route del 10.70.0.0/24")
    r1.cmd(f"ip nexthop del id {nhg_id}")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
