#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_nhg_reuse_deleted_intf.py
#

"""
When an upper level protocol re-sends a route without a nexthop whose
interface went down, zebra keeps the route on its old nexthop group, with
that nexthop marked inactive, so that the group does not change when the
interface comes back up.

This must not happen for a nexthop whose interface or vrf has been deleted,
or whose interface moved to another vrf: such a nexthop can never become
active again, and keeping the old nexthop group left it in the route for
good, even after it was removed from the configuration
(https://github.com/FRRouting/frr/issues/24012).
"""

import json
import os
import re
import sys
from functools import partial
from time import sleep

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


def build_topo(tgen):
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    vrfs = ["vrfA", "rtvrfX", "rtvrfY", "rtvrfZ", "rtvrfM", "rtvrfN"]
    for table, vrf in enumerate(vrfs, 100):
        r1.net.add_l3vrf(vrf, table)
    ifnames = ["ifX", "ifY", "ifZ", "ifM", "ifA", "ifB", "ifC", "ifD", "ifE", "ifF"]
    for ifname in ifnames:
        r1.net.add_loop(ifname)
    for ifname, vrf in [
        ("ifX", "rtvrfX"),
        ("ifY", "rtvrfY"),
        ("ifZ", "rtvrfZ"),
        ("ifM", "rtvrfM"),
    ]:
        r1.net.attach_iface_to_l3vrf(ifname, vrf)

    r1.load_frr_config()
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def get_static_route(router, prefix, vrf=None):
    vrf_str = " vrf {}".format(vrf) if vrf else ""
    output = json.loads(
        router.vtysh_cmd("show ip route{} {} json".format(vrf_str, prefix))
    )
    routes = [r for r in output.get(prefix, []) if r.get("protocol") == "static"]
    if len(routes) != 1:
        return None

    return routes[0]


def check_nexthops(router, prefix, expected, vrf=None):
    """
    Check that the static route to prefix has exactly the nexthops listed in
    expected, as (gateway, interface name, active) tuples.
    """
    route = get_static_route(router, prefix, vrf)
    if route is None:
        return "Expected a single static route to {}".format(prefix)

    nexthops = sorted(
        (nh.get("ip", ""), nh.get("interfaceName", ""), nh.get("active", False))
        for nh in route.get("nexthops", [])
    )
    if nexthops != sorted(expected):
        return "{}: expected nexthops {}, got {}".format(
            prefix, sorted(expected), nexthops
        )

    return None


def expect_nexthops(router, prefix, expected, vrf=None):
    test_func = partial(check_nexthops, router, prefix, expected, vrf)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def check_nhg_id(router, prefix, nhg_id):
    route = get_static_route(router, prefix)
    if route is None:
        return "Expected a single static route to {}".format(prefix)
    if route.get("nexthopGroupId") != nhg_id:
        return "{}: expected nexthop group {}, got {}".format(
            prefix, nhg_id, route.get("nexthopGroupId")
        )

    return None


def expect_nhg_id(router, prefix, nhg_id):
    test_func = partial(check_nhg_id, router, prefix, nhg_id)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def check_kernel(router, prefix, present, absent, vrf=None):
    vrf_str = " vrf {}".format(vrf) if vrf else ""
    output = router.run("ip -4 route show{} {}".format(vrf_str, prefix))
    for gateway in present:
        if gateway not in output:
            return "{} not via {} in the kernel:\n{}".format(prefix, gateway, output)
    for gateway in absent:
        if gateway in output:
            return "{} still via {} in the kernel:\n{}".format(prefix, gateway, output)

    return None


def expect_kernel(router, prefix, present, absent, vrf=None):
    test_func = partial(check_kernel, router, prefix, present, absent, vrf)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def check_interface(router, ifname, deleted=False, vrf=None):
    "Check whether zebra has handled the deletion, or vrf move, of ifname"
    output = json.loads(router.vtysh_cmd("show interface {} json".format(ifname)))
    intf = output.get(ifname)
    if deleted:
        if intf is not None and not intf.get("pseudoInterface", False):
            return "{} is still known to zebra".format(ifname)
    elif intf is None or intf.get("vrfName") != vrf:
        return "{} is not in vrf {} in zebra: {}".format(ifname, vrf, intf)

    return None


def expect_interface(router, ifname, deleted=False, vrf=None):
    test_func = partial(check_interface, router, ifname, deleted, vrf)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def kernel_nhg_available(router):
    return re.search(r"Kernel NHG\s+Available", router.vtysh_cmd("show zebra"))


def get_route_updates_skipped(router):
    output = router.vtysh_cmd("show zebra dplane detailed")
    match = re.search(r"Route updates skipped:\s+(\d+)", output)
    assert match, "No route updates skipped counter in:\n{}".format(output)

    return int(match.group(1))


def settled_route_updates_skipped(router):
    """
    Return the route updates skipped counter once it stopped moving, so that
    late updates triggered by a previous step are not mistaken for the next
    one.
    """
    previous = get_route_updates_skipped(router)
    for _ in range(30):
        sleep(2)
        current = get_route_updates_skipped(router)
        if current == previous:
            return current
        previous = current

    assert False, "Route updates skipped kept changing"


def expect_route_updates_skipped_above(router, value):
    """
    Wait for zebra to skip a route update because the route kept its
    nexthop group: this tells the update re-sent by staticd was processed.
    """

    def _check():
        skipped = get_route_updates_skipped(router)
        if skipped <= value:
            return "Route updates skipped is still {}".format(skipped)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result


def test_nexthop_vrf_and_interface_deleted():
    "Remove a nexthop after its interface and its nexthop-vrf were deleted"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Both onlink nexthops of 10.9.9.9/32 in vrfA are active")
    expect_nexthops(
        r1,
        "10.9.9.9/32",
        [("10.200.1.3", "ifX", True), ("10.200.1.252", "ifY", True)],
        "vrfA",
    )

    step("Delete ifY, then rtvrfY")
    r1.net.del_iface("ifY")
    r1.net.del_iface("rtvrfY")

    step("Only the nexthop via ifX is left in zebra")
    expect_nexthops(r1, "10.9.9.9/32", [("10.200.1.3", "ifX", True)], "vrfA")

    step("Remove the nexthop via ifY from the configuration")
    r1.vtysh_cmd(
        """
        configure terminal
         no ip route 10.9.9.9/32 10.200.1.252 ifY vrf vrfA nexthop-vrf rtvrfY onlink
        """
    )

    step("Still only the nexthop via ifX, in zebra and in the kernel")
    expect_nexthops(r1, "10.9.9.9/32", [("10.200.1.3", "ifX", True)], "vrfA")
    expect_kernel(r1, "10.9.9.9/32", ["10.200.1.3"], ["10.200.1.252"], "vrfA")


def test_nexthop_vrf_deleted():
    "Remove a nexthop after its nexthop-vrf was deleted, its interface is kept"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Both onlink nexthops of 10.9.9.10/32 in vrfA are active")
    expect_nexthops(
        r1,
        "10.9.9.10/32",
        [("10.200.1.3", "ifX", True), ("10.200.3.252", "ifZ", True)],
        "vrfA",
    )

    step("Delete rtvrfZ, ifZ is moved to the default vrf")
    r1.net.del_iface("rtvrfZ")

    step("Only the nexthop via ifX is left in zebra")
    expect_nexthops(r1, "10.9.9.10/32", [("10.200.1.3", "ifX", True)], "vrfA")

    step("Remove the nexthop via ifZ from the configuration")
    r1.vtysh_cmd(
        """
        configure terminal
         no ip route 10.9.9.10/32 10.200.3.252 ifZ vrf vrfA nexthop-vrf rtvrfZ onlink
        """
    )

    step("Still only the nexthop via ifX, in zebra and in the kernel")
    expect_nexthops(r1, "10.9.9.10/32", [("10.200.1.3", "ifX", True)], "vrfA")
    expect_kernel(r1, "10.9.9.10/32", ["10.200.1.3"], ["10.200.3.252"], "vrfA")


def test_nexthop_interface_moved_vrf():
    "Remove a nexthop after its interface moved to another vrf"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Both onlink nexthops of 10.9.9.11/32 in vrfA are active")
    expect_nexthops(
        r1,
        "10.9.9.11/32",
        [("10.200.1.3", "ifX", True), ("10.200.4.252", "ifM", True)],
        "vrfA",
    )

    # Shut ifM first: the kernel does not cycle a down interface when moving
    # it, so its nexthop is inactive whenever the route is re-sent.
    step("Shut ifM, its nexthop is inactive")
    r1.run("ip link set dev ifM down")
    expect_nexthops(
        r1,
        "10.9.9.11/32",
        [("10.200.1.3", "ifX", True), ("10.200.4.252", "ifM", False)],
        "vrfA",
    )

    step("Move ifM from rtvrfM to rtvrfN")
    r1.net.attach_iface_to_l3vrf("ifM", "rtvrfN")
    expect_interface(r1, "ifM", vrf="rtvrfN")

    step("Remove the nexthop via ifM from the configuration")
    r1.vtysh_cmd(
        """
        configure terminal
         no ip route 10.9.9.11/32 10.200.4.252 ifM vrf vrfA nexthop-vrf rtvrfM onlink
        """
    )

    step("Only the nexthop via ifX is left, in zebra and in the kernel")
    expect_nexthops(r1, "10.9.9.11/32", [("10.200.1.3", "ifX", True)], "vrfA")
    expect_kernel(r1, "10.9.9.11/32", ["10.200.1.3"], ["10.200.4.252"], "vrfA")


def test_interface_deleted():
    "Remove nexthops after their interface was deleted"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # The nexthops via ifB sort last in the first two routes and first in
    # the other two, so both ends of the nexthop group comparison are used.
    kept = {
        "10.8.8.8/32": ("192.168.10.2", "ifA"),
        "10.7.7.7/32": ("192.168.10.2", "ifA"),
        "10.5.5.5/32": ("192.168.50.2", "ifE"),
        "10.4.4.4/32": ("192.168.50.2", "ifE"),
    }

    step("Both nexthops of {} are active".format(", ".join(kept)))
    for prefix, (gateway, ifname) in kept.items():
        expect_nexthops(
            r1, prefix, [(gateway, ifname, True), ("192.168.20.2", "ifB", True)]
        )

    step("Delete ifB")
    r1.net.del_iface("ifB")
    expect_interface(r1, "ifB", deleted=True)

    step("Remove the nexthops via ifB from the configuration")
    r1.vtysh_cmd(
        """
        configure terminal
         no ip route 10.8.8.8/32 192.168.20.2 ifB
         no ip route 10.7.7.7/32 192.168.20.2
         no ip route 10.5.5.5/32 192.168.20.2 ifB
         no ip route 10.4.4.4/32 192.168.20.2
        """
    )

    step("Only the other nexthops are left, in zebra and in the kernel")
    for prefix, (gateway, ifname) in kept.items():
        expect_nexthops(r1, prefix, [(gateway, ifname, True)])
        expect_kernel(r1, prefix, [gateway], ["192.168.20.2"])


def test_interface_recreated():
    "A nexthop re-sent via a recreated interface does not keep the old one"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    if not kernel_nhg_available(r1):
        pytest.skip("kernel nexthop groups are not available")

    prefix = "10.3.3.3/32"

    step("Both nexthops of {} are active".format(prefix))
    expect_nexthops(
        r1, prefix, [("192.168.10.2", "ifA", True), ("192.168.60.2", "ifF", True)]
    )
    nhg_id = get_static_route(r1, prefix)["nexthopGroupId"]

    step("Shut ifF: the route keeps its nexthop group, ifF inactive in it")
    skipped = settled_route_updates_skipped(r1)
    r1.run("ip link set dev ifF down")
    expect_route_updates_skipped_above(r1, skipped)
    expect_nexthops(
        r1, prefix, [("192.168.10.2", "ifA", True), ("192.168.60.2", "ifF", False)]
    )
    expect_nhg_id(r1, prefix, nhg_id)
    settled_route_updates_skipped(r1)

    step("Delete ifF: nothing is re-sent, the route keeps its nexthop group")
    r1.net.del_iface("ifF")
    expect_interface(r1, "ifF", deleted=True)
    settled_route_updates_skipped(r1)
    expect_nhg_id(r1, prefix, nhg_id)

    step("Create ifF again, down: the route uses the nexthop via the new ifF")
    r1.run("ip link add ifF type dummy")
    expect_nexthops(
        r1, prefix, [("192.168.10.2", "ifA", True), ("192.168.60.2", "ifF", False)]
    )

    step("Bring the new ifF up: both nexthops are active")
    r1.run("ip link set dev ifF up")
    expect_nexthops(
        r1, prefix, [("192.168.10.2", "ifA", True), ("192.168.60.2", "ifF", True)]
    )


def test_interface_down_keeps_nhg():
    "A nexthop whose interface is only down still keeps the nexthop group"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    if not kernel_nhg_available(r1):
        pytest.skip("kernel nexthop groups are not available")

    prefix = "10.6.6.6/32"
    nexthops = {"ifC": "192.168.30.2", "ifD": "192.168.40.2"}

    step("Both nexthops of {} are active".format(prefix))
    expect_nexthops(r1, prefix, [(gw, ifname, True) for ifname, gw in nexthops.items()])
    nhg_id = get_static_route(r1, prefix)["nexthopGroupId"]

    # ifC's nexthop sorts first, ifD's last
    for down in ["ifC", "ifD"]:
        step("Shut {}: its nexthop is inactive, the nexthop group is kept".format(down))
        skipped = settled_route_updates_skipped(r1)
        r1.run("ip link set dev {} down".format(down))
        expect_route_updates_skipped_above(r1, skipped)
        expect_nexthops(
            r1,
            prefix,
            [(gw, ifname, ifname != down) for ifname, gw in nexthops.items()],
        )
        expect_nhg_id(r1, prefix, nhg_id)

        step("Bring {} back up: both nexthops active, same nexthop group".format(down))
        skipped = settled_route_updates_skipped(r1)
        r1.run("ip link set dev {} up".format(down))
        expect_route_updates_skipped_above(r1, skipped)
        expect_nexthops(
            r1, prefix, [(gw, ifname, True) for ifname, gw in nexthops.items()]
        )
        expect_nhg_id(r1, prefix, nhg_id)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
