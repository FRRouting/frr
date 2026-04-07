#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_import.py
#
# Copyright (c) 2024 ATCorp
# Nathan Bahr
#

import os
import sys
from functools import partial
import pytest
import json
import platform

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step, write_test_header

"""
test_zebra_import.py: Test zebra table import functionality
"""

TOPOLOGY = """
    Single router zebra functionality

                 +---+---+
    10.0.0.1/24  |       |  10.10.0.1/24
            <--->+  R1   +<--->
                 |       |
                 +---+---+
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.sharpd]
krel = platform.release()


def _route_missing(route_output, prefix):
    return prefix not in route_output or route_output[prefix] is None


def _check_route_present_in_table_only(router, prefix, table_id):
    source_output = json.loads(
        router.vtysh_cmd(f"show ip route table {table_id} {prefix} json")
    )
    if _route_missing(source_output, prefix):
        return (
            f"Route {prefix} is missing from source table {table_id}: {source_output}"
        )

    imported_output = json.loads(router.vtysh_cmd(f"show ip route {prefix} json"))
    if not _route_missing(imported_output, prefix):
        return f"Route {prefix} was imported unexpectedly: {imported_output}"

    return None


def _check_imported_route_nexthop(router, prefix, nexthop_ip, ifname, distance):
    output = json.loads(router.vtysh_cmd(f"show ip route {prefix} json"))
    if _route_missing(output, prefix):
        return f"Route {prefix} is missing from imported table: {output}"

    routes = output[prefix]
    if len(routes) != 1:
        return f"Route {prefix} should have exactly one path: {output}"

    route = routes[0]
    if route.get("protocol") != "table" or route.get("instance") != 10:
        return f"Route {prefix} is not the imported table route: {output}"
    if not route.get("installed") or route.get("distance") != distance:
        return f"Route {prefix} has unexpected install state or distance: {output}"

    nexthops = route.get("nexthops", [])
    if len(nexthops) != 1:
        return f"Route {prefix} should have exactly one nexthop: {output}"

    nexthop = nexthops[0]
    if (
        nexthop.get("ip") != nexthop_ip
        or nexthop.get("interfaceName") != ifname
        or not nexthop.get("active")
        or not nexthop.get("fib")
    ):
        return f"Route {prefix} has unexpected nexthop state: {output}"

    return None


def _check_source_route_nexthop(router, prefix, table_id, protocol, nexthop_ip, ifname):
    output = json.loads(
        router.vtysh_cmd(f"show ip route table {table_id} {prefix} json")
    )
    if _route_missing(output, prefix):
        return f"Route {prefix} is missing from source table {table_id}: {output}"

    for route in output[prefix]:
        if route.get("protocol") != protocol:
            continue

        nexthops = route.get("nexthops", [])
        if len(nexthops) != 1:
            return f"Route {prefix} should have exactly one nexthop: {output}"

        nexthop = nexthops[0]
        if (
            route.get("installed")
            and route.get("selected")
            and route.get("destSelected")
            and nexthop.get("ip") == nexthop_ip
            and nexthop.get("interfaceName") == ifname
            and nexthop.get("active")
            and nexthop.get("fib")
        ):
            return None

    return f"Route {prefix} is not selected via {protocol} {nexthop_ip}: {output}"


def _cleanup_added_import_test_routes(router):
    router.run(
        "vtysh -c 'sharp remove routes 10.21.0.0 1 table 10' >/dev/null 2>&1 || true"
    )
    router.run(
        "vtysh -c 'sharp remove routes 10.50.50.50 1 table 10' >/dev/null 2>&1 || true"
    )
    router.run(
        "ip route del table 10 10.22.0.0/24 via 10.10.0.2 dev r1-eth1 >/dev/null 2>&1 || true"
    )
    router.run(
        "ip route del table 10 10.22.0.0/24 via 10.0.0.2 dev r1-eth0 >/dev/null 2>&1 || true"
    )
    router.run(
        "ip route del table 10 10.50.50.50/32 via 10.0.0.2 dev r1-eth0 >/dev/null 2>&1 || true"
    )


def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")
    sw1 = tgen.add_switch("sw1")
    sw2 = tgen.add_switch("sw2")
    sw1.add_link(tgen.gears["r1"], "r1-eth0")
    sw2.add_link(tgen.gears["r1"], "r1-eth1")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(
            os.path.join(CWD, "{}/frr-import.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_SHARP, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def check_show_running(r1, present=None, absent=None):
    showrun = r1.vtysh_cmd("show running")

    for entry in present or []:
        if entry not in showrun:
            return f"Missing '{entry}' in show running:\n{showrun}"

    for entry in absent or []:
        if entry in showrun:
            return f"Unexpected '{entry}' in show running:\n{showrun}"

    return None


def test_zebra_urib_import(request):
    "Verify router starts with the initial URIB"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify initial main routing table")
    initial_json_file = "{}/r1/import_init_table.json".format(CWD)
    expected = json.loads(open(initial_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip route json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, '"r1" JSON output mismatches'

    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 
        """
    )

    import_json_file = "{}/r1/import_table_2.json".format(CWD)
    expected = json.loads(open(import_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip route json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, '"r1" JSON output mismatches'

    test_func = partial(check_show_running, r1, present=["ip import-table 10"])
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    step("Add a new static route and verify it gets added")
    r1.vtysh_cmd(
        """
        conf term
         ip route 10.20.0.0/24 10.10.0.2 table 10
        """
    )

    sync_json_file = "{}/r1/import_table_3.json".format(CWD)
    expected = json.loads(open(sync_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip route json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, '"r1" JSON output mismatches'

    step("Remove the static route and verify it gets removed")
    r1.vtysh_cmd(
        """
        conf term
         no ip route 10.20.0.0/24 10.10.0.2 table 10
        """
    )

    expected = json.loads(open(import_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip route json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Disable table import and verify it goes back to the initial table")
    r1.vtysh_cmd(
        """
        conf term
         no ip import-table 10 
        """
    )

    expected = json.loads(open(initial_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip route json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    test_func = partial(check_show_running, r1, absent=["ip import-table 10"])
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    step("Re-import with distance and verify correct distance")
    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 distance 123
        """
    )

    import_json_file = "{}/r1/import_table_4.json".format(CWD)
    expected = json.loads(open(import_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip route json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Add a sharp route that fails installation and verify it is not imported")
    failed_prefix_start = "10.21.0.0"
    failed_prefix = "10.21.0.0/32"
    r1.vtysh_cmd(
        f"sharp install routes {failed_prefix_start} nexthop 192.0.2.1 1 table 10"
    )

    test_func = partial(_check_route_present_in_table_only, r1, failed_prefix, 10)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    r1.vtysh_cmd(f"sharp remove routes {failed_prefix_start} 1 table 10")

    step("Replace an installed source-table route and verify imported nexthop updates")
    replace_prefix = "10.22.0.0/24"
    r1.run(f"ip route add table 10 {replace_prefix} via 10.10.0.2 dev r1-eth1")

    test_func = partial(
        _check_imported_route_nexthop, r1, replace_prefix, "10.10.0.2", "r1-eth1", 123
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    r1.run(f"ip route replace table 10 {replace_prefix} via 10.0.0.2 dev r1-eth0")

    test_func = partial(
        _check_imported_route_nexthop, r1, replace_prefix, "10.0.0.2", "r1-eth0", 123
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    r1.run(f"ip route del table 10 {replace_prefix} via 10.0.0.2 dev r1-eth0")

    test_func = partial(
        check_show_running, r1, present=["ip import-table 10 distance 123"]
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    step("Re-import with route-map and verify show running")
    r1.vtysh_cmd(
        """
        conf term
         no ip import-table 10 distance 123
         route-map IMPORT-FILTER permit 10
         ip import-table 10 distance 123 route-map IMPORT-FILTER
        """
    )

    expected = json.loads(open(import_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip route json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    test_func = partial(
        check_show_running,
        r1,
        present=[
            "route-map IMPORT-FILTER permit 10",
            "ip import-table 10 distance 123 route-map IMPORT-FILTER",
        ],
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    r1.vtysh_cmd(
        """
        conf term
         no ip import-table 10 route-map IMPORT-FILTER
         no route-map IMPORT-FILTER
        """
    )

    test_func = partial(
        check_show_running,
        r1,
        absent=[
            "ip import-table 10 distance 123 route-map IMPORT-FILTER",
            "route-map IMPORT-FILTER permit 10",
        ],
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result


def test_zebra_static_route_preferred_over_sharp_import(request):
    "Verify a static route remains the imported winner when sharp adds the same prefix"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _cleanup_added_import_test_routes(r1)

    prefix = "10.50.50.50/32"
    prefix_start = "10.50.50.50"

    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 distance 123
        """
    )

    step("Install a static route into table 10")
    r1.vtysh_cmd(
        f"""
        conf term
         ip route {prefix} 10.0.0.2 table 10
        """
    )

    step(
        "Verify the static route is installed in table 10 and imported into the main table"
    )
    test_func = partial(
        _check_source_route_nexthop, r1, prefix, 10, "static", "10.0.0.2", "r1-eth0"
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result

    test_func = partial(
        _check_imported_route_nexthop, r1, prefix, "10.0.0.2", "r1-eth0", 123
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result

    step("Install a sharp route for the same prefix into table 10")
    r1.vtysh_cmd(f"sharp install routes {prefix_start} nexthop 10.0.0.3 1 table 10")

    step("Verify the static route still wins in table 10")
    test_func = partial(
        _check_source_route_nexthop, r1, prefix, 10, "static", "10.0.0.2", "r1-eth0"
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result

    step("Verify the imported main-table route still uses the static nexthop")
    test_func = partial(
        _check_imported_route_nexthop, r1, prefix, "10.0.0.2", "r1-eth0", 123
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result

    _cleanup_added_import_test_routes(r1)


def test_zebra_mrib_import(request):
    "Verify router starts with the initial MRIB"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _cleanup_added_import_test_routes(r1)

    step("Verify initial main MRIB routing table")
    initial_json_file = "{}/r1/import_init_mrib_table.json".format(CWD)
    expected = json.loads(open(initial_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip rpf json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 mrib
        """
    )

    import_json_file = "{}/r1/import_mrib_table_2.json".format(CWD)
    expected = json.loads(open(import_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip rpf json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    test_func = partial(check_show_running, r1, present=["ip import-table 10 mrib"])
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    step("Add a new static route and verify it gets added")
    r1.vtysh_cmd(
        """
        conf term
         ip route 10.20.0.0/24 10.10.0.2 table 10
        """
    )

    sync_json_file = "{}/r1/import_mrib_table_3.json".format(CWD)
    expected = json.loads(open(sync_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip rpf json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Remove the static route and verify it gets removed")
    r1.vtysh_cmd(
        """
        conf term
         no ip route 10.20.0.0/24 10.10.0.2 table 10
        """
    )

    expected = json.loads(open(import_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip rpf json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    step("Disable table import and verify it goes back to the initial table")
    r1.vtysh_cmd(
        """
        conf term
         no ip import-table 10 mrib
        """
    )

    expected = json.loads(open(initial_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip rpf json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    test_func = partial(check_show_running, r1, absent=["ip import-table 10 mrib"])
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result

    step("Re-import with distance and verify correct distance")
    r1.vtysh_cmd(
        """
        conf term
         ip import-table 10 mrib distance 123
        """
    )

    import_json_file = "{}/r1/import_mrib_table_4.json".format(CWD)
    expected = json.loads(open(import_json_file).read())
    test_func = partial(topotest.router_json_cmp, r1, "show ip rpf json", expected)
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, '"r1" JSON output mismatches'

    test_func = partial(
        check_show_running, r1, present=["ip import-table 10 mrib distance 123"]
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, result


def test_zebra_import_bad_values(request):
    "Verify router starts with the initial MRIB"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _cleanup_added_import_test_routes(r1)

    invids = [0, 252, 254, 255]
    step("Verify invalid table IDs are rejected")
    for tid in invids:
        json = f"""{{"import-kernel-table":[{{"afi-safi":"frr-routing:ipv4-unicast","table-id":{tid}}}]}}"""
        rc, stdout, _ = r1.net.cmd_status(
            f"vtysh -c 'conf term' -c 'mgmt edit create /frr-zebra:zebra lock commit {json}'",
            warn=False,
        )
        assert rc, f"Pass with invalid table ID {tid}: {stdout}"

    valids = [1, 253, 1000]
    step("Verify valid table IDs are accepted")
    for tid in valids:
        json = f"""{{"import-kernel-table":[{{"afi-safi":"frr-routing:ipv4-unicast","table-id":{tid}}}]}}"""
        rc, stdout, _ = r1.net.cmd_status(
            f"vtysh -c 'conf term' -c 'mgmt edit create /frr-zebra:zebra lock commit {json}'",
            warn=False,
        )
        assert rc == 0, f"Failure with valid table ID {tid}: {stdout}"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
