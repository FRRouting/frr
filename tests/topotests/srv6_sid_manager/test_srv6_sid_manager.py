#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by Carmine Scarpitta <cscarpit@cisco.com>
#

"""
test_srv6_sid_manager.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+             +---------+
         |         |                     |         |             |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |eth-dst2     |   DST2  |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |-------------+ 9.9.9.5 |
         |         |eth-rt5       eth-rt4|         |      eth-rt5|         |
         +---------+                     +---------+             +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
                              |eth-dst (.1)
                              |
                              |10.0.10.0/24
                              |
                              |eth-rt6 (.2)
                         +---------+
                         |         |
                         |   DST   |
                         | 9.9.9.2 |
                         |         |
                         +---------+

"""

import functools
import ipaddress
import json
import os
import re
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    create_interface_in_kernel,
    required_linux_kernel_version,
    shutdown_bringup_interface_in_kernel,
    step,
)
from lib.checkping import check_ping

pytestmark = [
    pytest.mark.bgpd,
    pytest.mark.isisd,
    pytest.mark.sharpd,
    pytest.mark.staticd,
]


def build_topo(tgen):
    """Build function"""

    # Define FRR Routers
    tgen.add_router("rt1")
    tgen.add_router("rt2")
    tgen.add_router("rt3")
    tgen.add_router("rt4")
    tgen.add_router("rt5")
    tgen.add_router("rt6")
    tgen.add_router("dst")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("ce5")
    tgen.add_router("ce6")
    tgen.add_router("ce7")
    tgen.add_router("dst2")

    # Define connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-1")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-2")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-dst")
    switch.add_link(tgen.gears["dst"], nodeif="eth-rt6")

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-dst2")
    switch.add_link(tgen.gears["dst2"], nodeif="eth-rt5")

    tgen.add_link(tgen.gears["ce1"], tgen.gears["rt1"], "eth-rt1", "eth-ce1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["rt6"], "eth-rt6", "eth-ce2")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["rt1"], "eth-rt1", "eth-ce3")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["rt6"], "eth-rt6", "eth-ce4")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["rt1"], "eth-rt1", "eth-ce5")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["rt6"], "eth-rt6", "eth-ce6")
    tgen.add_link(tgen.gears["ce7"], tgen.gears["rt5"], "eth-rt5", "eth-ce7")

    tgen.gears["rt1"].run("ip link add vrf10 type vrf table 10")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["rt1"].tgen,
        tgen.gears["rt1"].name,
        "vrf10",
        True,
    )
    tgen.gears["rt1"].run("ip link add vrf20 type vrf table 20")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["rt1"].tgen,
        tgen.gears["rt1"].name,
        "vrf20",
        True,
    )
    tgen.gears["rt1"].run("ip link set eth-ce1 master vrf10")
    tgen.gears["rt1"].run("ip link set eth-ce3 master vrf10")
    tgen.gears["rt1"].run("ip link set eth-ce5 master vrf20")

    tgen.gears["rt5"].run("ip link add vrf10 type vrf table 10")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["rt5"].tgen,
        tgen.gears["rt5"].name,
        "vrf10",
        True,
    )
    tgen.gears["rt5"].run("ip link set eth-dst2 master vrf10")
    tgen.gears["rt5"].run("ip link add vrf20 type vrf table 20")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["rt5"].tgen,
        tgen.gears["rt5"].name,
        "vrf20",
        True,
    )
    tgen.gears["rt5"].run("ip link set eth-ce7 master vrf20")

    tgen.gears["rt6"].run("ip link add vrf10 type vrf table 10")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["rt6"].tgen,
        tgen.gears["rt6"].name,
        "vrf10",
        True,
    )
    tgen.gears["rt6"].run("ip link add vrf20 type vrf table 20")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["rt6"].tgen,
        tgen.gears["rt6"].name,
        "vrf20",
        True,
    )
    tgen.gears["rt6"].run("ip link set eth-ce2 master vrf10")
    tgen.gears["rt6"].run("ip link set eth-ce4 master vrf20")
    tgen.gears["rt6"].run("ip link set eth-ce6 master vrf20")

    # Add dummy interface for SRv6
    create_interface_in_kernel(
        tgen,
        "rt1",
        "sr0",
        "2001:db8::1",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt2",
        "sr0",
        "2001:db8::2",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt3",
        "sr0",
        "2001:db8::3",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt4",
        "sr0",
        "2001:db8::4",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt5",
        "sr0",
        "2001:db8::5",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt6",
        "sr0",
        "2001:db8::6",
        netmask="128",
        create=True,
    )


def setup_module(mod):
    """Sets up the pytest environment"""
    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")

    # Verify if kernel requirements are satisfied
    result = required_linux_kernel_version("4.10")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # Build the topology
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra and isis configuration files
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        if rname == "rt1":
            router.load_config(TopoRouter.RD_STATIC)
        if os.path.exists("{}/sharpd.conf".format(rname)):
            router.load_config(
                TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
            )

    # Start routers
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"

    # Teardown the topology
    tgen = get_topogen()
    tgen.stop_topology()


router_compare_json_output = functools.partial(
    topotest.router_compare_json_output, count=120, wait=0.5, CWD=CWD
)


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_rib(name, cmd, expected_file):
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    func = functools.partial(_check, name, cmd, expected_file)
    success, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


#
# Step 1
#
# Test initial network convergence
#
def test_isis_adjacencies():
    logger.info("Test: check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4():
    logger.info("Test: verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "show_ip_route.ref"
        )


def test_rib_ipv6():
    logger.info("Test: verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(rname, "show ipv6 route json", "show_ipv6_route.ref")


def test_srv6_locator():
    logger.info("Test: verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "show_srv6_locator_table.ref",
        )


def test_vpn_rib():
    check_rib("rt1", "show bgp ipv6 vpn json", "rt1/vpnv6_rib.ref")
    check_rib("rt6", "show bgp ipv6 vpn json", "rt6/vpnv6_rib.ref")
    check_rib("rt1", "show ipv6 route vrf vrf10 json", "rt1/vrf10_rib.ref")
    check_rib("rt1", "show ipv6 route vrf vrf20 json", "rt1/vrf20_rib.ref")
    check_rib("rt6", "show ipv6 route vrf vrf10 json", "rt6/vrf10_rib.ref")
    check_rib("rt6", "show ipv6 route vrf vrf20 json", "rt6/vrf20_rib.ref")
    check_rib("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
    check_rib("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")
    check_rib("ce3", "show ipv6 route json", "ce3/ipv6_rib.json")
    check_rib("ce4", "show ipv6 route json", "ce4/ipv6_rib.json")
    check_rib("ce5", "show ipv6 route json", "ce5/ipv6_rib.json")
    check_rib("ce6", "show ipv6 route json", "ce6/ipv6_rib.json")


def test_ping():
    logger.info("Test: verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Setup encap route on rt1, decap route on rt2
    # tgen.gears["rt1"].vtysh_cmd("sharp install seg6-routes fc00:0:9::1 nexthop-seg6 2001:db8:1::2 encap fc00:0:2:6:fe00:: 1")
    tgen.gears["rt1"].cmd(
        "ip -6 r a fc00:0:9::1/128 encap seg6 mode encap segs fc00:0:2:6:fe00:: via 2001:db8:1::2"
    )
    # tgen.gears["rt6"].vtysh_cmd("sharp install seg6local-routes fc00:0:f00d:: nexthop-seg6local eth-dst End_DT6 254 1")
    tgen.gears["rt6"].cmd("ip -6 r a fc00:0:9::1/128 via 2001:db8:10::2 vrf vrf10")
    tgen.gears["dst"].cmd("ip -6 r a 2001:db8:1::1/128 via 2001:db8:10::1")

    # Try to ping dst from rt1
    check_ping("rt1", "fc00:0:9::1", True, 10, 1)


def test_usid_lib_ranges():
    """Verify uSID LIB ranges reject a start greater than the end."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    format_context = """configure terminal
segment-routing
srv6
formats
format usid-f3216
"""

    output = router.vtysh_cmd(
        format_context + "local-id-block explicit start 201 end 200\n"
    )
    assert "Explicit LIB start (201) cannot be greater than end (200)" in output

    output = router.vtysh_cmd(
        format_context + "wide-local-id-block start 401 end 400\n"
    )
    assert "Wide LIB start (401) cannot be greater than end (400)" in output

    output = router.vtysh_cmd("write terminal")
    assert "local-id-block explicit start 201 end 200" not in output
    assert "wide-local-id-block start 401 end 400" not in output


USID_F4816_CONTEXT = """configure terminal
segment-routing
srv6
formats
format usid-f4816
"""


def test_usid_wide_lib_explicit_range():
    """
    Verify an Explicit Wide LIB start below the Wide LIB start is reported
    rather than refused.

    The Explicit Wide LIB is the tail of the Wide LIB and has no end of its
    own. The Wide LIB is an array indexed by the offset of a SID function from
    the Wide LIB start, so a function below that start would index outside the
    array; the allocation paths clamp the Explicit Wide LIB start to keep the
    index in bounds. The commands themselves keep whatever they are given,
    because the two ranges are saved as separate config lines and replayed one
    at a time.

    Use usid-f4816, which no locator in this topology is attached to, so
    moving its ranges around does not disturb the allocated SIDs.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]

    # An Explicit Wide LIB start below the Wide LIB start is kept, and the
    # start it takes effect at is reported
    output = router.vtysh_cmd(
        USID_F4816_CONTEXT + "wide-local-id-block explicit start 0\n"
    )
    assert (
        "Explicit Wide LIB start (0) is below the Wide LIB start (65520), "
        "the Explicit Wide LIB starts at 65520" in output
    )
    assert "wide-local-id-block explicit start 0" in router.vtysh_cmd("write terminal")

    router.vtysh_cmd(USID_F4816_CONTEXT + "no wide-local-id-block explicit\n")

    # The Wide LIB can move above the Explicit Wide LIB start
    output = router.vtysh_cmd(
        USID_F4816_CONTEXT + "wide-local-id-block start 100000 end 100010\n"
    )
    assert (
        "Explicit Wide LIB start (65527) is below the Wide LIB start (100000), "
        "the Explicit Wide LIB starts at 100000" in output
    )

    # Resetting the Explicit Wide LIB cannot fail because of the Wide LIB
    output = router.vtysh_cmd(USID_F4816_CONTEXT + "no wide-local-id-block explicit\n")
    assert (
        "Explicit Wide LIB start (65527) is below the Wide LIB start (100000), "
        "the Explicit Wide LIB starts at 100000" in output
    )

    # Nor can resetting the Wide LIB fail because of the Explicit Wide LIB
    router.vtysh_cmd(
        USID_F4816_CONTEXT
        + """wide-local-id-block start 100 end 200
wide-local-id-block explicit start 150
"""
    )
    output = router.vtysh_cmd(USID_F4816_CONTEXT + "no wide-local-id-block\n")
    assert (
        "Explicit Wide LIB start (150) is below the Wide LIB start (65520), "
        "the Explicit Wide LIB starts at 65520" in output
    )

    router.vtysh_cmd(
        USID_F4816_CONTEXT
        + """no wide-local-id-block
no wide-local-id-block explicit
"""
    )

    output = router.vtysh_cmd("write terminal")
    assert "wide-local-id-block" not in output


def _check_srv6_sid_lifecycle(
    rt1,
    rt6,
    sid,
    expected_present,
    expected_allocation_mode="explicit",
    expected_clients=("bgp",),
):
    """Check SID allocation, local installation, and remote VPN propagation."""
    try:
        sid_output = json.loads(
            rt1.vtysh_cmd("show segment-routing srv6 sid {} json".format(sid))
        )
        rt1_routes = json.loads(rt1.vtysh_cmd("show ipv6 route json"))
        rt6_vrf_routes = json.loads(rt6.vtysh_cmd("show ipv6 route vrf vrf10 json"))
        rt6_vpn_routes = json.loads(rt6.vtysh_cmd("show bgp ipv6 vpn json"))
    except json.JSONDecodeError as error:
        return "Failed to decode SID lifecycle command output: {}".format(error)

    sid_info = sid_output.get(sid)
    if bool(sid_info) != expected_present:
        return "SID {} allocation presence is {}, expected {}".format(
            sid, bool(sid_info), expected_present
        )
    if sid_info and sid_info.get("allocationMode") != expected_allocation_mode:
        return "SID {} has allocation mode {}, expected {}".format(
            sid, sid_info.get("allocationMode"), expected_allocation_mode
        )
    if sid_info:
        clients = {client["protocol"] for client in sid_info.get("clients", [])}
        missing_clients = set(expected_clients) - clients
        if missing_clients:
            return "SID {} is missing clients {}".format(
                sid, ", ".join(sorted(missing_clients))
            )

    sid_routes = [
        route
        for prefix, routes in rt1_routes.items()
        if prefix.rsplit("/", 1)[0] == sid
        for route in routes
    ]
    if bool(sid_routes) != expected_present:
        return "SID {} local RIB route presence is {}, expected {}".format(
            sid, bool(sid_routes), expected_present
        )
    installed_sid_route = any(
        route.get("selected")
        and route.get("installed")
        and any(
            nexthop.get("interfaceName") == "vrf10"
            and nexthop.get("seg6local", {}).get("action") == "uDT6"
            for nexthop in route.get("nexthops", [])
        )
        for route in sid_routes
    )
    if installed_sid_route != expected_present:
        return "SID {} local RIB installation is {}, expected {}".format(
            sid, installed_sid_route, expected_present
        )

    vrf_route = rt6_vrf_routes.get("2001:1::/64", [])
    if bool(vrf_route) != expected_present:
        return "rt6 VRF route 2001:1::/64 presence is {}, expected {}".format(
            bool(vrf_route), expected_present
        )
    if expected_present and not any(
        route.get("selected")
        and route.get("installed")
        and route.get("protocol") == "bgp"
        and any(
            nexthop.get("seg6", {}).get("segs") == sid
            for nexthop in route.get("nexthops", [])
        )
        for route in vrf_route
    ):
        return "rt6 VRF route 2001:1::/64 is not installed with SID {}".format(sid)

    route_distinguishers = rt6_vpn_routes.get("routes", {}).get(
        "routeDistinguishers", {}
    )
    vpn_route_present = any(
        "2001:1::/64" in routes for routes in route_distinguishers.values()
    )
    if vpn_route_present != expected_present:
        return "rt6 BGP VPN route 2001:1::/64 presence is {}, expected {}".format(
            vpn_route_present, expected_present
        )

    return None


def _dynamic_sids_from_range(router, sid_start, sid_end):
    """Check that BGP and IS-IS have dynamic SIDs from the requested range."""
    try:
        sids = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
    except json.JSONDecodeError as error:
        return "show segment-routing srv6 sid json: {}".format(error)

    protocols = set()
    for sid, info in sids.items():
        if info.get("allocationMode") != "dynamic":
            continue

        sid_func = int.from_bytes(ipaddress.IPv6Address(sid).packed[6:8], "big")
        if not sid_start <= sid_func < sid_end:
            continue

        protocols.update(client["protocol"] for client in info.get("clients", []))

    missing = {"bgp", "isis"} - protocols
    if missing:
        return "No dynamic SID from range {}-{} for {}".format(
            sid_start, sid_end - 1, ", ".join(sorted(missing))
        )

    return None


def _dynamic_sid_for_client(router, protocol, sid_start, sid_end):
    """Return a client's dynamic SID from the requested uSID LIB range."""
    sids = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
    for sid, info in sids.items():
        if info.get("allocationMode") != "dynamic":
            continue

        sid_func = int.from_bytes(ipaddress.IPv6Address(sid).packed[6:8], "big")
        if not sid_start <= sid_func < sid_end:
            continue

        if any(client["protocol"] == protocol for client in info.get("clients", [])):
            return sid

    return None


def test_dynamic_sid_range_and_static_sid_configuration():
    """
    Change the dynamic range and verify BGP and IS-IS allocate from it. Configure
    an explicit SID in staticd and verify BGP gets the same SID, i.e., the SID
    is shared between BGP and staticd. Restore the original configuration and
    verify the default SID is allocated, installed, and advertised.
    """
    tgen = get_topogen()

    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]
    rt6 = tgen.gears["rt6"]
    start = 57600
    explicit_start = 65024
    format_context = """configure terminal
segment-routing
srv6
formats
format usid-f3216
"""

    step(
        "Change the dynamic SID range and verify BGP and IS-IS allocate from it",
        reset=True,
    )
    router.vtysh_cmd(format_context + "local-id-block start 57600\n")
    router.vtysh_cmd(
        """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
no sid vpn export 65024
"""
    )
    router.vtysh_cmd(
        """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
sid vpn export auto
"""
    )

    check_dynamic_sids = functools.partial(
        _dynamic_sids_from_range, router, start, explicit_start
    )
    _, result = topotest.run_and_expect(check_dynamic_sids, None, count=30, wait=1)
    assert (
        result is None
    ), "BGP and IS-IS did not allocate dynamic SIDs from range {}-{}: {}".format(
        start, explicit_start - 1, result
    )

    bgp_dynamic_sid = _dynamic_sid_for_client(router, "bgp", start, explicit_start)
    assert (
        bgp_dynamic_sid is not None
    ), "BGP did not receive a dynamic SID from range {}-{}".format(
        start, explicit_start - 1
    )
    check_lifecycle = functools.partial(
        _check_srv6_sid_lifecycle,
        router,
        rt6,
        bgp_dynamic_sid,
        True,
        "dynamic",
    )
    _, result = topotest.run_and_expect(check_lifecycle, None, count=30, wait=1)
    assert (
        result is None
    ), "BGP dynamic SID {} was not installed and advertised correctly: {}".format(
        bgp_dynamic_sid, result
    )
    check_ping("ce2", "2001:1::2", True, 10, 1)

    step(
        "Configure an explicit SID in staticd and verify BGP gets the same SID, "
        "shared between BGP and staticd"
    )
    sid = "fc00:0:1:fe10::"
    router.vtysh_cmd(
        """configure terminal
segment-routing
srv6
static-sids
sid fc00:0:1:fe10::/64 locator loc1 behavior uDT6 vrf vrf10
"""
    )

    check_lifecycle = functools.partial(
        _check_srv6_sid_lifecycle,
        router,
        rt6,
        sid,
        True,
        expected_clients=("bgp", "static"),
    )
    _, result = topotest.run_and_expect(check_lifecycle, None, count=30, wait=1)
    assert result is None, "Expected BGP and staticd to use SID {}: {}".format(
        sid, result
    )
    check_ping("ce2", "2001:1::2", True, 10, 1)

    step(
        "Restore the default SID settings and verify the default SID is allocated, "
        "installed, and advertised"
    )
    router.vtysh_cmd(
        """configure terminal
segment-routing
srv6
static-sids
no sid fc00:0:1:fe10::/64
"""
    )
    router.vtysh_cmd(format_context + "no local-id-block\n")
    router.vtysh_cmd(
        """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
no sid vpn export auto
"""
    )
    router.vtysh_cmd(
        """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
sid vpn export 65024
"""
    )

    output = router.vtysh_cmd("write terminal")
    assert (
        "local-id-block start 57600" not in output
    ), "The non-default dynamic SID range was not removed from the configuration"
    assert (
        "sid vpn export auto" not in output
    ), "BGP automatic VPN SID export was not removed from the configuration"
    assert (
        "sid vpn export 65024" in output
    ), "The default explicit VPN SID export was not restored"
    assert (
        "sid fc00:0:1:fe10::/64" not in output
    ), "The test SID configured in staticd was not removed"

    default_sid = "fc00:0:1:fe00::"
    check_lifecycle = functools.partial(
        _check_srv6_sid_lifecycle, router, rt6, default_sid, True
    )
    _, result = topotest.run_and_expect(check_lifecycle, None, count=30, wait=1)
    assert (
        result is None
    ), "Default SID {} was not allocated, installed, and advertised: {}".format(
        default_sid, result
    )
    check_ping("ce2", "2001:1::2", True, 10, 1)


def test_explicit_sid_range_change_lifecycle():
    """
    Move the explicit range so the SID falls outside it and verify withdrawal, then
    restore the default range and verify allocation, installation, and advertisement.
    """
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rt1 = tgen.gears["rt1"]
    rt6 = tgen.gears["rt6"]
    sid = "fc00:0:1:fe00::"
    format_context = """configure terminal
segment-routing
srv6
formats
format usid-f3216
"""

    step(
        "Check the default configuration and verify the explicit SID is allocated, "
        "installed, and advertised",
        reset=True,
    )
    check_lifecycle = functools.partial(_check_srv6_sid_lifecycle, rt1, rt6, sid, True)
    _, result = topotest.run_and_expect(check_lifecycle, None, count=30, wait=1)
    assert result is None, (
        "Default explicit SID {} was not allocated, installed, and advertised: "
        "{}".format(sid, result)
    )
    check_ping("ce2", "2001:1::2", True, 10, 1)
    check_ping("ce1", "2001:2::2", True, 10, 1)

    step(
        "Exclude the configured SID from the explicit range and verify it is "
        "withdrawn"
    )
    rt1.vtysh_cmd(format_context + "local-id-block explicit start 513 end 767\n")

    check_lifecycle = functools.partial(_check_srv6_sid_lifecycle, rt1, rt6, sid, False)
    _, result = topotest.run_and_expect(check_lifecycle, None, count=30, wait=1)
    assert result is None, (
        "SID {} remained allocated, installed, or advertised outside the explicit "
        "range: {}".format(sid, result)
    )
    check_ping("ce2", "2001:1::2", False, 10, 1)
    check_ping("ce1", "2001:2::2", False, 10, 1)

    step(
        "Restore the default explicit range and verify the SID is allocated, "
        "installed, and advertised again"
    )
    rt1.vtysh_cmd(format_context + "no local-id-block explicit\n")

    check_lifecycle = functools.partial(_check_srv6_sid_lifecycle, rt1, rt6, sid, True)
    _, result = topotest.run_and_expect(check_lifecycle, None, count=30, wait=1)
    assert result is None, (
        "SID {} was not reallocated, installed, and advertised after range "
        "restoration: {}".format(sid, result)
    )
    check_ping("ce2", "2001:1::2", True, 10, 1)
    check_ping("ce1", "2001:2::2", True, 10, 1)


BGP_VRF10_CONTEXT = """configure terminal
router bgp 1 vrf vrf10
address-family ipv6 unicast
"""


def _check_sid_allocated(router, sid, expected_present):
    """Check whether zebra has the SID allocated."""
    try:
        sid_output = json.loads(
            router.vtysh_cmd("show segment-routing srv6 sid {} json".format(sid))
        )
    except json.JSONDecodeError as error:
        return "show segment-routing srv6 sid {} json: {}".format(sid, error)

    present = bool(sid_output.get(sid))
    if present != expected_present:
        return "SID {} allocation presence is {}, expected {}".format(
            sid, present, expected_present
        )

    return None


def _export_vpn_sid(router, sid_func):
    """Export the SID with this function from vrf10 to the VPN."""
    router.vtysh_cmd(BGP_VRF10_CONTEXT + "sid vpn export {}\n".format(sid_func))


def _unexport_vpn_sid(router, sid_func):
    """Stop exporting the SID with this function from vrf10 to the VPN."""
    router.vtysh_cmd(BGP_VRF10_CONTEXT + "no sid vpn export {}\n".format(sid_func))


def test_usid_wide_lib_explicit_sid_allocation():
    """
    Verify SID allocation stays inside the Wide LIB when the Explicit Wide LIB
    starts below it.

    The Wide LIB is an array indexed by the offset of a SID function from the
    Wide LIB start, so a function below that start would index outside the
    array. The commands keep an Explicit Wide LIB start below the Wide LIB
    start, which leaves the clamp in the allocation and release paths as the
    only thing keeping the index in bounds.

    Use usid-f3216, the format of the locator SIDs are allocated from, so that
    the allocation and release paths are reached at all.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rt1 = tgen.gears["rt1"]
    format_context = """configure terminal
segment-routing
srv6
formats
format usid-f3216
"""
    default_sid = "fc00:0:1:fe00::"
    # The Explicit Wide LIB is configured at 65520 but the Wide LIB starts at
    # 65524, so the Explicit Wide LIB takes effect at 65524
    below_start_sid = "fc00:0:1:fff0::"
    start_sid = "fc00:0:1:fff4::"

    step("Configure an Explicit Wide LIB start below the Wide LIB start", reset=True)
    output = rt1.vtysh_cmd(
        format_context
        + """wide-local-id-block explicit start 65520
wide-local-id-block start 65524 end 65527
"""
    )
    assert (
        "Explicit Wide LIB start (65520) is below the Wide LIB start (65524), "
        "the Explicit Wide LIB starts at 65524" in output
    )

    check_default = functools.partial(_check_sid_allocated, rt1, default_sid, True)
    _, result = topotest.run_and_expect(check_default, None, count=30, wait=1)
    assert result is None, "The default SID was not reallocated: {}".format(result)

    step("Verify a SID below the Wide LIB start is not allocated")
    _unexport_vpn_sid(rt1, 65024)
    _export_vpn_sid(rt1, 65520)

    # Ask for a SID at the Wide LIB start afterwards. zebra handles the two
    # requests in order, so once this one is allocated the one below the start
    # has been handled as well.
    _unexport_vpn_sid(rt1, 65520)
    _export_vpn_sid(rt1, 65524)

    check_start = functools.partial(_check_sid_allocated, rt1, start_sid, True)
    _, result = topotest.run_and_expect(check_start, None, count=30, wait=1)
    assert result is None, "SID {} was not allocated: {}".format(start_sid, result)

    result = _check_sid_allocated(rt1, below_start_sid, False)
    assert result is None, "SID {} was allocated below the Wide LIB start: {}".format(
        below_start_sid, result
    )

    step("Verify the SID at the Wide LIB start is released and allocated again")
    _unexport_vpn_sid(rt1, 65524)

    check_released = functools.partial(_check_sid_allocated, rt1, start_sid, False)
    _, result = topotest.run_and_expect(check_released, None, count=30, wait=1)
    assert result is None, "SID {} was not released: {}".format(start_sid, result)

    _export_vpn_sid(rt1, 65524)

    _, result = topotest.run_and_expect(check_start, None, count=30, wait=1)
    assert result is None, "SID {} was not reallocated: {}".format(start_sid, result)

    step("Restore the default ranges and the default exported SID")
    _unexport_vpn_sid(rt1, 65524)
    _export_vpn_sid(rt1, 65024)
    rt1.vtysh_cmd(
        format_context
        + """no wide-local-id-block
no wide-local-id-block explicit
"""
    )

    _, result = topotest.run_and_expect(check_default, None, count=30, wait=1)
    assert result is None, "The default SID was not restored: {}".format(result)


def check_wide_lib_config_after_zebra_restart(router, expected):
    """
    Save the running configuration, restart zebra so it reads it back, and
    assert that every line in `expected` is in the running configuration
    again.
    """
    saved = router.vtysh_cmd("write terminal")
    for line in expected:
        assert line in saved, "'{}' was not saved".format(line)

    router.vtysh_cmd("write memory")
    router.killDaemons(["zebra"])
    router.startDaemons(["zebra"])

    def _zebra_read_config():
        return "locator loc1" in router.vtysh_cmd("show running-config")

    _, result = topotest.run_and_expect(_zebra_read_config, True, count=30, wait=1)
    assert result is True, "zebra did not read its configuration after a restart"

    output = router.vtysh_cmd("show running-config")
    for line in expected:
        assert line in output, "'{}' was lost when zebra re-read it".format(line)


def test_usid_wide_lib_config_survives_zebra_restart():
    """
    Verify saved Wide LIB ranges are still there after zebra re-reads them.

    zebra saves the Wide LIB and the Explicit Wide LIB as separate config
    lines and replays them one at a time, so a command that validated one
    range against the other's current value would reject a saved line whose
    sibling is still at its default, and the range would silently fall back to
    its default.

    Both a Wide LIB above the default Explicit Wide LIB start and a Wide LIB
    below the defaults are covered, so that emitting the two lines in a
    different order cannot fix one and break the other.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["rt1"]

    # A Wide LIB above the default Explicit Wide LIB start of 65527
    router.vtysh_cmd(
        USID_F4816_CONTEXT
        + """wide-local-id-block explicit start 100005
wide-local-id-block start 100000 end 100010
"""
    )
    check_wide_lib_config_after_zebra_restart(
        router,
        [
            "wide-local-id-block start 100000 end 100010",
            "wide-local-id-block explicit start 100005",
        ],
    )

    # A Wide LIB below the defaults, which breaks instead if the Explicit Wide
    # LIB is replayed first
    router.vtysh_cmd(
        USID_F4816_CONTEXT
        + """no wide-local-id-block
no wide-local-id-block explicit
wide-local-id-block start 100 end 200
wide-local-id-block explicit start 150
"""
    )
    check_wide_lib_config_after_zebra_restart(
        router,
        [
            "wide-local-id-block start 100 end 200",
            "wide-local-id-block explicit start 150",
        ],
    )

    router.vtysh_cmd(
        USID_F4816_CONTEXT
        + """no wide-local-id-block
no wide-local-id-block explicit
"""
    )


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
