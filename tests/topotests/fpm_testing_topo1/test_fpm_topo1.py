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


def _check_nhg_fpm_and_not_kernel(router, prefix, route_type):
    """
    Helper: assert that the NHG for prefix has been sent to FPM
    while skipping kernel programming.
    """

    def check_nhg_sent_to_fpm():
        nhg_id, nhg_data = _get_nhg_for_prefix(router, prefix)
        if nhg_id is None or nhg_data is None:
            return False
        return nhg_data.get("fpm", False) is True

    success, result = topotest.run_and_expect(
        check_nhg_sent_to_fpm, True, count=60, wait=1
    )
    assert success, (
        "{} route NHG ({}) was not sent to FPM "
        "(NEXTHOP_GROUP_FPM flag not set). NHG data: {}".format(
            route_type, prefix, result
        )
    )

    def check_nhg_not_in_kernel():
        nhg_id, _ = _get_nhg_for_prefix(router, prefix)
        if nhg_id is None:
            return False
        output = router.run("ip nexthop show")
        return "id {} ".format(nhg_id) not in output

    success, _ = topotest.run_and_expect(
        check_nhg_not_in_kernel, True, count=30, wait=1
    )
    assert (
        success
    ), "{} route NHG ({}) was unexpectedly installed in the Linux kernel.".format(
        route_type, prefix
    )


def test_fpm_system_route_nhg_sent_to_fpm_not_kernel():
    """
    Test that NHGs for system routes (connected, local, kernel) are forwarded
    to FPM but NOT installed in the kernel.
      - FPM provider receives and sends the NHG  (NEXTHOP_GROUP_FPM flag set)
      - Kernel provider skips netlink programming (NHG absent from kernel)

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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
