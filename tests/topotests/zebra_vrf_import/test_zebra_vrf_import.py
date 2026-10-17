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

    # Addresses live in frr.conf: Router.start() flushes addresses configured
    # from the shell. The two VRFs are deliberately on disjoint subnets, so
    # nexthops copied from red cannot resolve against a connected route in
    # blue, while blue's own subnets are rewrite targets that can.
    for ifname, vrf in (
        ("r1-eth0", "red"),
        ("r1-eth1", "red"),
        ("r1-eth2", "blue"),
        ("r1-eth3", "blue"),
    ):
        r1.cmd_raises(f"ip link set {ifname} master {vrf}")
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


def _distance_check(router, show_cmd, prefix, protocol, distance):
    output = router.vtysh_cmd(f"{show_cmd} {prefix} json", isjson=True)
    routes = output.get(prefix)
    if not routes:
        return f"Route {prefix} missing from {show_cmd}: {output}"

    for route in routes:
        if route.get("protocol") != protocol:
            continue
        if route.get("distance") != distance:
            return f"Route {prefix} has distance {route.get('distance')}: {output}"
        return None

    return f"Route {prefix} did not match protocol {protocol}: {output}"


def _wait_distance(router, show_cmd, prefix, protocol, distance):
    test_func = functools.partial(
        _distance_check, router, show_cmd, prefix, protocol, distance
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def _selected_check(router, show_cmd, prefix, protocol):
    output = router.vtysh_cmd(f"{show_cmd} {prefix} json", isjson=True)
    routes = output.get(prefix)
    if not routes:
        return f"Route {prefix} missing from {show_cmd}: {output}"

    selected = [route for route in routes if route.get("selected")]
    if len(selected) != 1 or selected[0].get("protocol") != protocol:
        return f"Route {prefix} is not selected from {protocol}: {output}"

    return None


def _wait_selected(router, show_cmd, prefix, protocol):
    test_func = functools.partial(_selected_check, router, show_cmd, prefix, protocol)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def _nexthop_group_check(
    router,
    show_cmd,
    prefix,
    protocol,
    nexthops,
    active=True,
    interface_required=True,
    resolvers=None,
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

    # Recursively resolved nexthops are listed next to the ones the route was
    # created with, so only the latter are compared against the expectation.
    own = [nexthop for nexthop in route_nexthops if not nexthop.get("resolver")]
    resolved = [nexthop for nexthop in route_nexthops if nexthop.get("resolver")]

    actual = {nexthop.get("ip") for nexthop in own}
    if actual != set(nexthops):
        return f"Route {prefix} has wrong nexthops {actual}: {output}"

    if active is True:
        inactive = [nexthop for nexthop in own if not nexthop.get("active")]
        if inactive:
            return f"Route {prefix} has inactive nexthops {inactive}: {output}"
    elif active is False:
        still_active = [nexthop for nexthop in own if nexthop.get("active")]
        if still_active:
            return f"Route {prefix} has active nexthops {still_active}: {output}"

    if not interface_required:
        with_interfaces = [nexthop for nexthop in own if nexthop.get("interfaceName")]
        if with_interfaces:
            return f"Route {prefix} kept source interfaces {with_interfaces}: {output}"

    if resolvers is not None:
        actual_resolvers = {nexthop.get("ip") for nexthop in resolved}
        if actual_resolvers != set(resolvers):
            return f"Route {prefix} has wrong resolvers {actual_resolvers}: {output}"

    return None


def _wait_nexthop_group(
    router,
    show_cmd,
    prefix,
    protocol,
    nexthops,
    active=True,
    interface_required=True,
    resolvers=None,
):
    test_func = functools.partial(
        _nexthop_group_check,
        router,
        show_cmd,
        prefix,
        protocol,
        nexthops,
        active,
        interface_required,
        resolvers,
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
    """Verify VRF import, route-map filter and rewrite, NHG copy, and removal."""
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
        active=False,
        interface_required=False,
        resolvers=[],
    )

    step("Import a kernel route, whose source protocol allows no recursion")
    r1.cmd_raises("ip route add 10.10.40.0/24 via 192.0.2.2 dev r1-eth0 table 10")
    _wait_nexthop_group(
        r1, "show ip route vrf red", "10.10.40.0/24", "kernel", ["192.0.2.2"]
    )
    _wait_nexthop_group(
        r1,
        "show ip route vrf blue",
        "10.10.40.0/24",
        "vrf-import",
        ["192.0.2.2"],
        active=False,
        interface_required=False,
        resolvers=[],
    )

    step("Verify imported nexthops resolve recursively in the destination VRF")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          ip route 192.0.2.0/24 198.51.100.2
          ip route 192.0.3.0/24 203.0.113.2
        """,
    )
    _wait_nexthop_group(
        r1,
        "show ip route vrf blue",
        "10.10.30.0/24",
        "vrf-import",
        ecmp_nexthops,
        interface_required=False,
        resolvers=["198.51.100.2", "203.0.113.2"],
    )
    _wait_nexthop_group(
        r1,
        "show ip route vrf blue",
        "10.10.40.0/24",
        "vrf-import",
        ["192.0.2.2"],
        interface_required=False,
        resolvers=["198.51.100.2"],
    )
    r1.cmd_raises("ip route del 10.10.40.0/24 table 10")
    _wait_route(
        r1,
        "show ip route vrf blue",
        "10.10.40.0/24",
        "vrf-import",
        present=False,
    )

    step("Verify imported nexthops go inactive again when the resolver is gone")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          no ip route 192.0.2.0/24 198.51.100.2
          no ip route 192.0.3.0/24 203.0.113.2
        """,
    )
    _wait_nexthop_group(
        r1,
        "show ip route vrf blue",
        "10.10.30.0/24",
        "vrf-import",
        ecmp_nexthops,
        active=False,
        interface_required=False,
        resolvers=[],
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

    step("Verify imported routes do not inherit the source distance")
    # The source route is a static route at distance 1, which would outrank
    # most of what blue can learn itself if it were carried over.
    _wait_distance(r1, "show ip route vrf red", "10.10.10.0/24", "static", 1)
    _wait_distance(r1, "show ip route vrf blue", "10.10.10.0/24", "vrf-import", 15)
    _wait_distance(
        r1, "show ipv6 route vrf blue", "2001:db8:10::/64", "vrf-import", 15
    )

    step("Verify the import distance decides against the destination VRF's own route")
    # A competing static route at distance 100 sits between the default import
    # distance and the one configured below, so only the import distance can
    # decide which of the two is selected.
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          ip route 10.10.10.0/24 blackhole 100
        """,
    )
    _wait_selected(r1, "show ip route vrf blue", "10.10.10.0/24", "vrf-import")

    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          ip import-vrf red distance 201
        """,
    )
    _wait_distance(r1, "show ip route vrf blue", "10.10.20.0/24", "vrf-import", 201)
    _wait_selected(r1, "show ip route vrf blue", "10.10.10.0/24", "static")
    _wait_show_running(r1, present=["ip import-vrf red distance 201"])

    step("Restore the default import distance")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          ip import-vrf red
          no ip route 10.10.10.0/24 blackhole 100
        """,
    )
    _wait_distance(r1, "show ip route vrf blue", "10.10.10.0/24", "vrf-import", 15)
    _wait_show_running(
        r1,
        present=["ip import-vrf red"],
        absent=["ip import-vrf red distance 201"],
    )

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

    step("Drop a copy whose source route stops matching the route-map")
    # The route-map verdict can flip without any configuration change, so a
    # source route that stays selected but is no longer permitted has to lose
    # its copy. 10.10.50.0/24 is matched on its first nexthop, which changes
    # when the preferred one is withdrawn.
    _vtysh_config(
        r1,
        """
        configure terminal
         ip prefix-list IMPORT-VIA-ETH0 permit 192.0.2.2/32
         route-map IMPORT-VIA-ETH0 permit 10
          match ip next-hop prefix-list IMPORT-VIA-ETH0
         exit
         vrf red
          ip route 10.10.50.0/24 192.0.2.2 r1-eth0 onlink
          ip route 10.10.50.0/24 192.0.3.2 r1-eth1 onlink
         exit-vrf
         vrf blue
          ip import-vrf red route-map IMPORT-VIA-ETH0
        """,
    )
    _wait_route(
        r1, "show ip route vrf blue", "10.10.50.0/24", "vrf-import", blackhole=False
    )

    _vtysh_config(
        r1,
        """
        configure terminal
         vrf red
          no ip route 10.10.50.0/24 192.0.2.2 r1-eth0 onlink
        """,
    )
    _wait_nexthop_group(
        r1, "show ip route vrf red", "10.10.50.0/24", "static", ["192.0.3.2"]
    )
    _wait_route(
        r1, "show ip route vrf blue", "10.10.50.0/24", "vrf-import", present=False
    )

    step("Restore the unfiltered import")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf red
          no ip route 10.10.50.0/24 192.0.3.2 r1-eth1 onlink
         exit-vrf
         vrf blue
          ip import-vrf red
        """,
    )
    _wait_route(r1, "show ip route vrf blue", "10.10.10.0/24", "vrf-import")
    _wait_route(
        r1, "show ip route vrf blue", "10.10.50.0/24", "vrf-import", present=False
    )

    step("Rewrite imported IPv4 nexthops with a route-map")
    _vtysh_config(
        r1,
        """
        configure terminal
         route-map IMPORT-REWRITE-V4 permit 10
          set ip next-hop 198.51.100.2
         exit
         vrf blue
          ip import-vrf red route-map IMPORT-REWRITE-V4
        """,
    )
    # The rewritten nexthop replaces the copied ones and, unlike them, lies in
    # a subnet connected in blue, so it resolves without a helper route. A
    # connected match resolves in place rather than recursively, which is why
    # no resolver shows up next to it.
    _wait_nexthop_group(
        r1,
        "show ip route vrf blue",
        "10.10.30.0/24",
        "vrf-import",
        ["198.51.100.2"],
        resolvers=[],
    )
    # The source route is a blackhole, so only the rewrite can give the
    # imported route a nexthop that resolves at all.
    _wait_nexthop_group(
        r1,
        "show ip route vrf blue",
        "10.10.10.0/24",
        "vrf-import",
        ["198.51.100.2"],
        resolvers=[],
    )
    _wait_show_running(r1, present=["ip import-vrf red route-map IMPORT-REWRITE-V4"])

    step("Rewrite imported IPv6 nexthops with a route-map")
    # "set ipv6 next-hop local" only accepts link-local addresses, so the
    # rewritten nexthop resolves against blue's fe80::/64 connected route
    # rather than against any configured subnet.
    _vtysh_config(
        r1,
        """
        configure terminal
         route-map IMPORT-REWRITE-V6 permit 10
          set ipv6 next-hop local fe80::2
         exit
         vrf blue
          ipv6 import-vrf red route-map IMPORT-REWRITE-V6
        """,
    )
    _wait_nexthop_group(
        r1,
        "show ipv6 route vrf blue",
        "2001:db8:10::/64",
        "vrf-import",
        ["fe80::2"],
        resolvers=[],
    )
    _wait_show_running(r1, present=["ipv6 import-vrf red route-map IMPORT-REWRITE-V6"])

    step("Reject a rewrite whose address family differs from the import")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          ip import-vrf red route-map IMPORT-REWRITE-V6
        """,
    )
    for prefix in ("10.10.10.0/24", "10.10.20.0/24", "10.10.30.0/24"):
        _wait_route(
            r1,
            "show ip route vrf blue",
            prefix,
            "vrf-import",
            present=False,
        )

    step("Drop the rewrite route-maps and verify the copied nexthops return")
    _vtysh_config(
        r1,
        """
        configure terminal
         vrf blue
          ip import-vrf red
          ipv6 import-vrf red
        """,
    )
    _wait_nexthop_group(
        r1,
        "show ip route vrf blue",
        "10.10.30.0/24",
        "vrf-import",
        ecmp_nexthops,
        active=False,
        interface_required=False,
        resolvers=[],
    )
    _wait_route(r1, "show ip route vrf blue", "10.10.10.0/24", "vrf-import")
    _wait_route(r1, "show ip route vrf blue", "10.10.20.0/24", "vrf-import")
    _wait_route(r1, "show ipv6 route vrf blue", "2001:db8:10::/64", "vrf-import")

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
