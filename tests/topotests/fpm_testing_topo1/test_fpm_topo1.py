#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_route_scale1.py
#
# Copyright (c) 2024 by
# Nvidia, Inc.
# Donald Sharp
#

"""
test_fpm_topo1.py: Testing FPM module

"""
import os
import re
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


pytestmark = [pytest.mark.fpm, pytest.mark.sharpd]


def build_topo(tgen):
    "Build function"

    # Populate routers
    tgen.add_router("r1")

    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])


def setup_module(module):
    "Setup topology"

    # fpm_stub = os.system("which fpm-stub")
    # if fpm-stub:
    #    pytest.skip("")

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
            "-M dplane_fpm_nl --asic-offload=notify_on_offload",
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )
        # Use the router's log directory path for fpm test data
        fpm_data_path = os.path.join(router.gearlogdir, "fpm_test.data")
        router.load_config(
            TopoRouter.RD_FPM_LISTENER,
            os.path.join(CWD, "{}/fpm_stub.conf".format(rname)),
            "-r -z {}".format(fpm_data_path),
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_fpm_connection_made():
    "Test that the fpm starts up and a connection is made"

    tgen = get_topogen()
    router = tgen.gears["r1"]

    fpm_counters = "{}/r1/fpm_counters.json".format(CWD)
    expected = json.loads(open(fpm_counters).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show fpm status json", expected
    )

    success, result = topotest.run_and_expect(test_func, None, 30, 1)
    assert success, "Unable to connect to the fpm:\n{}".format(result)


def test_fpm_install_routes():
    "Test that simple routes installed appears to work"

    tgen = get_topogen()
    router = tgen.gears["r1"]

    # Let's install 10000 routes
    router.vtysh_cmd("sharp install routes 10.0.0.0 nexthop 192.168.44.33 10000")
    routes_file = "{}/r1/routes_summ.json".format(CWD)
    expected = json.loads(open(routes_file).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route summ json", expected
    )

    success, result = topotest.run_and_expect(test_func, None, 120, 1)
    assert success, "Unable to successfully install 10000 routes: {}".format(result)

    # Let's remove 10000 routes
    router.vtysh_cmd("sharp remove routes 10.0.0.0 10000")

    routes_file_removed = "{}/r1/routes_summ_removed.json".format(CWD)
    expected = json.loads(open(routes_file_removed).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show ip route summ json", expected
    )

    success, result = topotest.run_and_expect(test_func, None, 120, 1)
    assert success, "Unable to remove 10000 routes: {}".format(result)


def test_fpm_connected_and_local_routes():
    "Test that conneted and local routes"

    tgen = get_topogen()
    router = tgen.gears["r1"]

    # Get the router's log directory where fpm_test.data is written
    fpm_data_file = os.path.join(router.gearlogdir, "fpm_test.data")

    def dump_fpm_listener_data():
        """Send SIGUSR1 to fpm_listener to dump its data"""
        pid_file = os.path.join(router.gearlogdir, "fpm_listener.pid")
        try:
            with open(pid_file, "r") as f:
                pid = f.read().strip()
            router.run(f"kill -SIGUSR1 {pid}")
            return True
        except FileNotFoundError:
            return False

    def check_specific_route(prefix):
        """Check if a specific route prefix exists in the FPM dump file"""
        # Read directly from the host filesystem
        try:
            with open(fpm_data_file, "r") as f:
                content = f.read()
                return content.count(prefix)
        except FileNotFoundError:
            return 0

    # Let's check added routes
    router_count = 1
    router.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
        ip address 10.10.10.10 peer 10.10.10.11/24
        """
    )

    def check_r1_connected_routes():
        if not dump_fpm_listener_data():
            return 0

        def check_route():
            return check_specific_route("10.10.10.0/24")

        success, result = topotest.run_and_expect(
            check_route, router_count, count=30, wait=0.5
        )
        return result if success else 0

    def check_r1_local_routes():
        if not dump_fpm_listener_data():
            return 0

        def check_route():
            return check_specific_route("10.10.10.10/32")

        success, result = topotest.run_and_expect(
            check_route, router_count, count=30, wait=0.5
        )
        return result if success else 0

    success, result = topotest.run_and_expect(
        check_r1_connected_routes, router_count, count=30, wait=1
    )
    assert success, f"Failed to find {result} connected routes"
    success, result = topotest.run_and_expect(
        check_r1_local_routes, router_count, count=30, wait=1
    )
    assert success, f"Failed to find {result} local routes"

    # Let's check removed routes
    router_count = 0
    router.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
        no ip address 10.10.10.10 peer 10.10.10.11/24
        """
    )

    success, result = topotest.run_and_expect(
        check_r1_connected_routes, router_count, count=30, wait=1
    )
    assert success, f"Failed to find {result} connected routes"
    success, result = topotest.run_and_expect(
        check_r1_local_routes, router_count, count=30, wait=1
    )
    assert success, f"Failed to find {result} local routes"


def _get_nhg_for_prefix(router, prefix):
    """
    Helper: return (nhg_id, nhg_data) for a given route prefix string,
    or (None, None) if not found.
    """
    route_info = router.vtysh_cmd("show ip route {} json".format(prefix))
    try:
        route_json = json.loads(route_info)
    except json.JSONDecodeError:
        return None, None

    for pfx, routes in route_json.items():
        if pfx == prefix:
            nhg_id = routes[0].get("nexthopGroupId")
            if nhg_id is None:
                return None, None
            nhg_info = router.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
            try:
                nhg_json = json.loads(nhg_info)
                return nhg_id, nhg_json.get(str(nhg_id))
            except json.JSONDecodeError:
                return None, None
    return None, None


def _fpm_dump_path(router):
    return os.path.join(router.gearlogdir, "fpm_test.data")


def _fpm_listener_dump(router):
    """Send SIGUSR1 to fpm_listener so it rewrites its dump file."""
    pid_file = os.path.join(router.gearlogdir, "fpm_listener.pid")
    try:
        with open(pid_file, "r") as f:
            pid = f.read().strip()
        router.run("kill -SIGUSR1 {}".format(pid))
        return True
    except FileNotFoundError:
        return False


def _read_fpm_dump(router):
    try:
        with open(_fpm_dump_path(router), "r") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _fpm_dump_has_nhg(router, nhg_id):
    """
    Return True iff the fpm_listener dump file currently contains an entry
    for ``nhg_id``. The listener writes one line per live NHG of the form
    "  ID: <id>, Protocol: ..." (see sigusr1_handler in fpm_listener.c),
    and removes the entry when it receives the matching RTM_DELNEXTHOP.
    """
    if not _fpm_listener_dump(router):
        return False
    return "  ID: {},".format(nhg_id) in _read_fpm_dump(router)


def _check_nhg_fpm_and_not_kernel(router, prefix, route_type):
    """
    Assert that the NHG for ``prefix`` was received by the mock FPM
    listener and that the Linux kernel did NOT install it.

    The "received by FPM" half is verified by inspecting the fpm_listener
    dump file directly rather than relying on the in-zebra
    NEXTHOP_GROUP_FPM flag, which is only set by the FPM resync hash-walk
    (fpm_nhg_send_cb) and not by the runtime fpm_nl_enqueue() path that
    this test exercises.
    """

    last_seen = {"nhg_id": None, "nhg_data": None}

    def have_nhg_id():
        nhg_id, nhg_data = _get_nhg_for_prefix(router, prefix)
        last_seen["nhg_id"] = nhg_id
        last_seen["nhg_data"] = nhg_data
        return nhg_id is not None

    success, _ = topotest.run_and_expect(have_nhg_id, True, count=30, wait=1)
    nhg_id = last_seen["nhg_id"]
    assert (
        success and nhg_id is not None
    ), "{} route ({}) never picked up an NHG id in zebra. NHG data: {}".format(
        route_type, prefix, json.dumps(last_seen["nhg_data"], indent=2)
    )

    def check_nhg_in_fpm_dump():
        return _fpm_dump_has_nhg(router, nhg_id)

    success, _ = topotest.run_and_expect(check_nhg_in_fpm_dump, True, count=60, wait=1)
    assert success, (
        "{} route NHG ({}, id {}) was not received by the FPM listener.\n"
        "FPM dump tail:\n{}".format(
            route_type, prefix, nhg_id, _read_fpm_dump(router)[-2000:]
        )
    )

    def check_nhg_not_in_kernel():
        output = router.run("ip nexthop show")
        return "id {} ".format(nhg_id) not in output

    success, _ = topotest.run_and_expect(
        check_nhg_not_in_kernel, True, count=30, wait=1
    )
    assert success, (
        "{} route NHG ({}, id {}) was unexpectedly installed in the "
        "Linux kernel.".format(route_type, prefix, nhg_id)
    )


def test_fpm_system_route_nhg_sent_to_fpm_not_kernel():
    """
    Test that NHGs for system routes (connected, local, kernel) are forwarded
    to FPM but NOT installed in the kernel.
      - FPM listener receives the RTM_NEWNEXTHOP for the NHG (verified by
        inspecting the fpm_listener SIGUSR1 dump for the NHG id)
      - Kernel provider skips netlink programming (NHG absent from
        ``ip nexthop show``)

    Three sub-cases are verified:
      1. Connected route  (ZEBRA_ROUTE_CONNECT) - 172.16.1.0/24
      2. Local route      (ZEBRA_ROUTE_LOCAL)   - 172.16.1.1/32
      3. Kernel route     (ZEBRA_ROUTE_KERNEL)  - 172.16.2.0/24
    """

    tgen = get_topogen()
    router = tgen.gears["r1"]

    # Sub-case 1 & 2: connected + local routes
    router.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
        ip address 172.16.1.1/24
        """
    )

    _check_nhg_fpm_and_not_kernel(router, "172.16.1.0/24", "connected")
    _check_nhg_fpm_and_not_kernel(router, "172.16.1.1/32", "local")

    # Cleanup sub-case 1 & 2
    router.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
        no ip address 172.16.1.1/24
        """
    )

    # Sub-case 3: kernel route
    router.run("ip route add 172.16.2.0/24 dev r1-eth0")

    def kernel_route_visible():
        route_info = router.vtysh_cmd("show ip route 172.16.2.0/24 json")
        try:
            rj = json.loads(route_info)
            for pfx, routes in rj.items():
                if pfx == "172.16.2.0/24":
                    return routes[0].get("protocol") == "kernel"
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
        return False

    success, _ = topotest.run_and_expect(kernel_route_visible, True, count=30, wait=1)
    assert success, "Kernel route 172.16.2.0/24 did not appear in zebra RIB"

    _check_nhg_fpm_and_not_kernel(router, "172.16.2.0/24", "kernel")

    # Cleanup sub-case 3
    router.run("ip route del 172.16.2.0/24 dev r1-eth0")


def _get_route_nhg_id(router, prefix):
    """
    Return the nexthop group id for the route ``prefix``, or None if the
    route is not present.
    """
    output = router.vtysh_cmd("show ip route {} json".format(prefix))
    try:
        route_json = json.loads(output)
    except json.JSONDecodeError:
        return None

    for pfx, routes in route_json.items():
        if pfx == prefix and routes:
            return routes[0].get("nexthopGroupId")

    return None


def _get_nhg_tree(router, nhg_id):
    """
    Walk the nexthop group dependency tree rooted at ``nhg_id`` and return
    {nhg_id: nhg json object} as reported by vtysh.
    """
    tree = {}
    todo = [nhg_id]

    while todo:
        cur = todo.pop()
        if cur in tree:
            continue

        output = router.vtysh_cmd("show nexthop-group rib {} json".format(cur))
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            continue

        nhg = data.get(str(cur))
        if nhg is None:
            continue

        tree[cur] = nhg
        todo.extend(nhg.get("depends", []))

    return tree


def _get_fpm_resolved_via(router):
    """
    Dump the fpm_listener tables and return {nhg_id: resolved via id} for
    the nexthop groups received with a resolved-via attribute.
    """
    if not _fpm_listener_dump(router):
        return {}

    # Entries are not always newline-terminated (a group printed without
    # its nexthop list runs into the next entry), so parse them by
    # splitting on the entry marker instead of line by line.
    dump = _read_fpm_dump(router).split("=== Route Tree Dump ===")[0]

    resolved_via = {}
    for entry in re.split(r"(?=  ID: \d+,)", dump):
        nhg_id = re.match(r"  ID: (\d+),", entry)
        value = re.search(r"ResolvedVia: (\d+)", entry)
        if nhg_id and value:
            resolved_via[int(nhg_id.group(1))] = int(value.group(1))

    return resolved_via


def test_fpm_resolved_via_recursive_routes():
    """
    Check that the resolved-via information zebra sends down the FPM pipe
    matches what vtysh reports, for static routes that resolve recursively.

    The routes form a small resolution chain:
      - 10.200.10.0/24 is resolved via the connected route
      - 10.200.20.0/24 is resolved via 10.200.10.0/24
      - 10.200.30.0/24 is resolved via 10.200.20.0/24
    """
    tgen = get_topogen()
    router = tgen.gears["r1"]

    connected_prefix = "192.168.44.0/24"
    prefixes = ["10.200.10.0/24", "10.200.20.0/24", "10.200.30.0/24"]

    router.vtysh_cmd(
        """
        configure terminal
        ip route 10.200.10.0/24 192.168.44.2
        ip route 10.200.20.0/24 10.200.10.1
        ip route 10.200.30.0/24 10.200.20.1
        """
    )

    route_nhg_ids = {}

    def routes_resolved():
        for prefix in prefixes:
            output = router.vtysh_cmd("show ip route {} json".format(prefix))
            try:
                route_json = json.loads(output)
            except json.JSONDecodeError:
                return False

            routes = route_json.get(prefix)
            if not routes:
                return False

            nexthop_group_id = routes[0].get("nexthopGroupId")
            if nexthop_group_id is None:
                return False
            route_nhg_ids[prefix] = nexthop_group_id

            # The routes need to be resolved before the resolved-via
            # information is reported for their nexthops.
            if not any(
                "resolvedVia" in nexthop for nexthop in routes[0].get("nexthops", [])
            ):
                return False

        return True

    success, _ = topotest.run_and_expect(routes_resolved, True, count=30, wait=1)
    assert success, "Recursive static routes were not resolved: {}".format(
        route_nhg_ids
    )

    # Collect the nexthop groups used by the routes and the resolved-via
    # values vtysh reports for them.
    our_nhgs = {}
    vtysh_resolved_via = {}
    for prefix in prefixes:
        nhg_id = _get_route_nhg_id(router, prefix)
        if nhg_id is None:
            continue
        for cur_id, nhg in _get_nhg_tree(router, nhg_id).items():
            our_nhgs[cur_id] = nhg
            for nexthop in nhg.get("nexthops", []):
                if "resolvedVia" in nexthop:
                    vtysh_resolved_via.setdefault(cur_id, set()).add(
                        nexthop["resolvedVia"]
                    )

    # Nexthop groups without dependencies are sent to the FPM as singleton
    # nexthop messages, which carry the resolved-via attribute; groups with
    # dependencies (the recursive parents included) are sent as NHA_GROUP
    # messages, which cannot carry it.  Require every mapping that can be
    # observed on the FPM pipe, so an incomplete one fails the test.
    expected_resolved_via = {
        nhg_id: values
        for nhg_id, values in vtysh_resolved_via.items()
        if not our_nhgs[nhg_id].get("depends")
    }
    assert (
        expected_resolved_via
    ), "vtysh reports no resolved-via for singleton nexthop groups: " "{}".format(
        vtysh_resolved_via
    )

    # The first route's nexthop resolves via the connected route, so that
    # nexthop group id is what vtysh should report as the resolved-via.
    connected_nhg_id = _get_route_nhg_id(router, connected_prefix)
    assert connected_nhg_id is not None, "Connected route has no nexthop group id"
    expected_values = set().union(*expected_resolved_via.values())
    assert (
        connected_nhg_id in expected_values
    ), "vtysh did not report resolved-via {} for the routes: {}".format(
        connected_nhg_id, vtysh_resolved_via
    )

    # Wait until the FPM listener has received all of them over the FPM pipe.
    def fpm_has_expected_resolved_via():
        fpm_resolved_via = _get_fpm_resolved_via(router)
        for nhg_id, values in expected_resolved_via.items():
            if fpm_resolved_via.get(nhg_id) not in values:
                return False
        return True

    success, _ = topotest.run_and_expect(
        fpm_has_expected_resolved_via, True, count=30, wait=1
    )
    assert success, (
        "FPM pipe did not report the expected resolved-via mappings.\n"
        "Expected: {}\nFPM: {}\nFPM dump:\n{}".format(
            expected_resolved_via,
            _get_fpm_resolved_via(router),
            _read_fpm_dump(router)[-2000:],
        )
    )

    # The resolved-via value sent down the FPM pipe must match the value
    # vtysh reports for the same nexthop group.
    fpm_resolved_via = _get_fpm_resolved_via(router)
    for nhg_id, resolved_via in fpm_resolved_via.items():
        if nhg_id in vtysh_resolved_via:
            assert resolved_via in vtysh_resolved_via[nhg_id], (
                "FPM received resolved-via {} for NHG {}, but vtysh "
                "reports {}".format(resolved_via, nhg_id, vtysh_resolved_via[nhg_id])
            )

    # Cleanup
    router.vtysh_cmd(
        """
        configure terminal
        no ip route 10.200.10.0/24 192.168.44.2
        no ip route 10.200.20.0/24 10.200.10.1
        no ip route 10.200.30.0/24 10.200.20.1
        """
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
