#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test zebra-native VRF route import.
"""

import functools
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    """Build a single-router topology."""
    tgen.add_router("r1")
    for idx in range(4):
        switch = tgen.add_switch(f"s{idx}")
        switch.add_link(tgen.gears["r1"], f"r1-eth{idx}")


def setup_module(mod):
    """Set up the pytest environment."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    for vrf, table in (("red", 10), ("blue", 20)):
        r1.cmd_raises(f"ip link add {vrf} type vrf table {table}")
        r1.cmd_raises(f"ip link set {vrf} up")

    for ifname, vrf, addr in (
        ("r1-eth0", "red", "192.0.2.1/24"),
        ("r1-eth1", "red", "192.0.3.1/24"),
        ("r1-eth2", "blue", "192.0.2.1/24"),
        ("r1-eth3", "blue", "192.0.3.1/24"),
    ):
        r1.cmd_raises(f"ip link set {ifname} master {vrf}")
        r1.cmd_raises(f"ip address add {addr} dev {ifname}")
        r1.cmd_raises(f"ip link set {ifname} up")

    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        [
            (TopoRouter.RD_ZEBRA, None),
            (TopoRouter.RD_STATIC, None),
        ],
    )
    tgen.start_router()


def teardown_module(_mod):
    """Tear down the pytest environment."""
    tgen = get_topogen()
    tgen.stop_topology()


def _vtysh_config(router, config):
    output = router.vtysh_cmd(config)
    assert "% Unknown command" not in output, output
    assert "% Ambiguous command" not in output, output
    assert "% Command incomplete" not in output, output
    assert "% Configuration failed" not in output, output
    assert "% Can't" not in output, output
    assert "% Malformed" not in output, output
    return output


def _vtysh_config_fail(router, config):
    output = router.vtysh_cmd(config)
    assert "% Unknown command" not in output, output
    assert "% Ambiguous command" not in output, output
    assert "% Command incomplete" not in output, output
    assert "% Configuration failed" in output, output
    return output


def _route_check(router, show_cmd, prefix, protocol, blackhole=True, present=True):
    output = router.vtysh_cmd(f"{show_cmd} {prefix} json", isjson=True)

    if not present:
        if prefix in output and output[prefix] is not None:
            return f"Route {prefix} unexpectedly present in {show_cmd}: {output}"
        return None

    routes = output.get(prefix)
    if not routes:
        return f"Route {prefix} missing from {show_cmd}: {output}"

    for route in routes:
        if route.get("protocol") != protocol:
            continue
        if not blackhole:
            return None
        nexthops = route.get("nexthops", [])
        if any(nexthop.get("blackhole") for nexthop in nexthops):
            return None

    return f"Route {prefix} did not match protocol {protocol}: {output}"


def _wait_route(router, show_cmd, prefix, protocol, blackhole=True, present=True):
    test_func = functools.partial(
        _route_check, router, show_cmd, prefix, protocol, blackhole, present
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def _nexthop_group_check(
    router,
    show_cmd,
    prefix,
    protocol,
    nexthops,
    active_required=True,
    interface_required=True,
):
    output = router.vtysh_cmd(f"{show_cmd} {prefix} json", isjson=True)
    routes = output.get(prefix)
    if not routes:
        return f"Route {prefix} missing from {show_cmd}: {output}"

    route_nexthops = []
    for route in routes:
        if route.get("protocol") == protocol:
            route_nexthops.extend(route.get("nexthops", []))

    if not route_nexthops:
        return f"Route {prefix} did not match protocol {protocol}: {output}"

    actual = {nexthop.get("ip") for nexthop in route_nexthops}
    if actual != set(nexthops):
        return f"Route {prefix} has wrong nexthops {actual}: {output}"

    if active_required:
        inactive = [nexthop for nexthop in route_nexthops if not nexthop.get("active")]
        if inactive:
            return f"Route {prefix} has inactive nexthops {inactive}: {output}"

    if not interface_required:
        with_interfaces = [
            nexthop for nexthop in route_nexthops if nexthop.get("interfaceName")
        ]
        if with_interfaces:
            return f"Route {prefix} kept source interfaces {with_interfaces}: {output}"

    return None


def _wait_nexthop_group(
    router,
    show_cmd,
    prefix,
    protocol,
    nexthops,
    active_required=True,
    interface_required=True,
):
    test_func = functools.partial(
        _nexthop_group_check,
        router,
        show_cmd,
        prefix,
        protocol,
        nexthops,
        active_required,
        interface_required,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def _check_show_running(router, present=None, absent=None):
    showrun = router.vtysh_cmd("show running-config")

    for line in present or []:
        if line not in showrun:
            return f"Missing '{line}' in show running-config:\n{showrun}"

    for line in absent or []:
        if line in showrun:
            return f"Unexpected '{line}' in show running-config:\n{showrun}"

    return None


def _wait_show_running(router, present=None, absent=None):
    test_func = functools.partial(_check_show_running, router, present, absent)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, result


def test_zebra_vrf_import():
    """Verify VRF import, route-map filtering, NHG copy, and removal."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Reject self-import configuration")
    output = _vtysh_config_fail(
        r1,
        """
        configure terminal
         vrf red
          ip import-vrf red
        """,
    )
    assert "source VRF must be different from destination VRF" in output, output
    _wait_show_running(r1, absent=["ip import-vrf red"])

    step("Configure source routes and import red into blue")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf red
          ip route 10.10.10.0/24 blackhole
          ip route 10.10.20.0/24 blackhole
          ipv6 route 2001:db8:10::/64 blackhole
         exit-vrf
         vrf blue
          ip import-vrf red
          ipv6 import-vrf red
        """,
    )

    step("Verify source static routes")
    _wait_route(r1, "show ip route vrf red", "10.10.10.0/24", "static")
    _wait_route(r1, "show ip route vrf red", "10.10.20.0/24", "static")
    _wait_route(r1, "show ipv6 route vrf red", "2001:db8:10::/64", "static")

    step("Verify imported IPv4 and IPv6 routes")
    _wait_route(r1, "show ip route vrf blue", "10.10.10.0/24", "vrf-import")
    _wait_route(r1, "show ip route vrf blue", "10.10.20.0/24", "vrf-import")
    _wait_route(r1, "show ipv6 route vrf blue", "2001:db8:10::/64", "vrf-import")

    step("Verify nexthop-group import copies all source nexthops")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf red
          ip route 10.10.30.0/24 192.0.2.2 r1-eth0 onlink
          ip route 10.10.30.0/24 192.0.3.2 r1-eth1 onlink
        """,
    )
    ecmp_nexthops = ["192.0.2.2", "192.0.3.2"]
    _wait_nexthop_group(
        r1, "show ip route vrf red", "10.10.30.0/24", "static", ecmp_nexthops
    )
    _wait_nexthop_group(
        r1,
        "show ip route vrf blue",
        "10.10.30.0/24",
        "vrf-import",
        ecmp_nexthops,
        active_required=False,
        interface_required=False,
    )

    output = r1.vtysh_cmd("show ip route vrf blue 10.10.10.0/24")
    assert 'Known via "vrf-import[red]"' in output, output

    _wait_show_running(
        r1,
        present=["ip import-vrf red", "ipv6 import-vrf red"],
    )

    step("Verify imported routes track source route deletion")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf red
          no ip route 10.10.10.0/24 blackhole
        """,
    )
    _wait_route(
        r1,
        "show ip route vrf blue",
        "10.10.10.0/24",
        "vrf-import",
        present=False,
    )

    _vtysh_config(
        r1,
        """
        configure terminal
         vrf red
          ip route 10.10.10.0/24 blackhole
        """,
    )
    _wait_route(r1, "show ip route vrf blue", "10.10.10.0/24", "vrf-import")

    step("Apply a route-map that only imports 10.10.20.0/24")
    _vtysh_config(
        r1,
        """
        configure terminal
         ip prefix-list IMPORT-20 permit 10.10.20.0/24
         route-map IMPORT-ONLY-20 permit 10
          match ip address prefix-list IMPORT-20
         exit
         vrf blue
          ip import-vrf red route-map IMPORT-ONLY-20
        """,
    )
    _wait_route(
        r1,
        "show ip route vrf blue",
        "10.10.10.0/24",
        "vrf-import",
        present=False,
    )
    _wait_route(r1, "show ip route vrf blue", "10.10.20.0/24", "vrf-import")
    _wait_show_running(r1, present=["ip import-vrf red route-map IMPORT-ONLY-20"])

    step("Remove the route-map and verify both IPv4 source routes are imported")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          ip import-vrf red
        """,
    )
    _wait_route(r1, "show ip route vrf blue", "10.10.10.0/24", "vrf-import")
    _wait_route(r1, "show ip route vrf blue", "10.10.20.0/24", "vrf-import")
    _wait_show_running(
        r1,
        present=["ip import-vrf red"],
        absent=["ip import-vrf red route-map IMPORT-ONLY-20"],
    )

    step("Remove import configuration and verify imported routes are removed")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          no ip import-vrf red
          no ipv6 import-vrf red
        """,
    )
    _wait_route(
        r1,
        "show ip route vrf blue",
        "10.10.10.0/24",
        "vrf-import",
        present=False,
    )
    _wait_route(
        r1,
        "show ip route vrf blue",
        "10.10.20.0/24",
        "vrf-import",
        present=False,
    )
    _wait_route(
        r1,
        "show ip route vrf blue",
        "10.10.30.0/24",
        "vrf-import",
        present=False,
    )
    _wait_route(
        r1,
        "show ipv6 route vrf blue",
        "2001:db8:10::/64",
        "vrf-import",
        present=False,
    )
    _wait_show_running(
        r1,
        absent=["ip import-vrf red", "ipv6 import-vrf red"],
    )


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
