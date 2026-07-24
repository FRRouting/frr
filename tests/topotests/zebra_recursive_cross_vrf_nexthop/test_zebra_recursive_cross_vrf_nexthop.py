#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Nexthop AI
#               Srinivasan Koona Lokabiraman
#
"""
Test recursive static route resolution across VRFs.

When a route resolves recursively through an intermediate route whose
nexthop is in a different VRF, the final resolved nexthop must carry
the egress interface VRF, not the outer route VRF.

Two directions are tested with separate functions:

- default_to_blue: outer route in default VRF, egress on r1-eth0 (vrf-blue)
- blue_to_default: outer route in vrf-blue, egress on r1-eth1 (default VRF)

Address plan (see r1/frr.conf): default uses 1/2/3 (outer/intermediate/
direct); vrf-blue uses 4/5/6. IPv6 mirrors this on db8:1:: and db8:4::.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

VRF_BLUE = "vrf-blue"
VRF_DEFAULT = "default"

DEFAULT_TO_BLUE = {
    4: {
        "prefix_recursive": "2.2.2.2/32",
        "prefix_direct": "3.3.3.3/32",
        "recursive_nh": "1.1.1.1",
        "resolved_nh": "10.1.2.2",
        "ifname": "r1-eth0",
        "egress_vrf": VRF_BLUE,
        "route_json": "show ip route {} json",
        "route_text": "show ip route {}",
    },
    6: {
        "prefix_recursive": "2001:db8:1::2/128",
        "prefix_direct": "2001:db8:1::3/128",
        "recursive_nh": "2001:db8:1::1",
        "resolved_nh": "2001:db8:2::2",
        "ifname": "r1-eth0",
        "egress_vrf": VRF_BLUE,
        "route_json": "show ipv6 route {} json",
        "route_text": "show ipv6 route {}",
    },
}

BLUE_TO_DEFAULT = {
    4: {
        "prefix_recursive": "5.5.5.5/32",
        "prefix_direct": "6.6.6.6/32",
        "recursive_nh": "4.4.4.4",
        "resolved_nh": "10.2.2.2",
        "ifname": "r1-eth1",
        "egress_vrf": VRF_DEFAULT,
        "route_vrf": VRF_BLUE,
        "route_json": "show ip route vrf {} {} json",
        "route_text": "show ip route vrf {} {}",
    },
    6: {
        "prefix_recursive": "2001:db8:4::5/128",
        "prefix_direct": "2001:db8:4::6/128",
        "recursive_nh": "2001:db8:4::4",
        "resolved_nh": "2001:db8:3::2",
        "ifname": "r1-eth1",
        "egress_vrf": VRF_DEFAULT,
        "route_vrf": VRF_BLUE,
        "route_json": "show ipv6 route vrf {} {} json",
        "route_text": "show ipv6 route vrf {} {}",
    },
}


def build_topo(tgen):
    """Single router with two interfaces, each on its own munet switch."""
    tgen.add_router("r1")
    switch1 = tgen.add_switch("s1")
    switch1.add_link(tgen.gears["r1"])
    switch2 = tgen.add_switch("s2")
    switch2.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.net.add_l3vrf(VRF_BLUE, 100)
    r1.net.attach_iface_to_l3vrf("r1-eth0", VRF_BLUE)

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _route_cmd(params, prefix, kind):
    if "route_vrf" in params:
        return params[kind].format(params["route_vrf"], prefix)
    return params[kind].format(prefix)


def _collect_nexthops(route_json, prefix):
    if prefix not in route_json:
        return None, "{} not in RIB".format(prefix)

    nexthops = []
    for entry in route_json[prefix]:
        nexthops.extend(entry.get("nexthops", []))

    if not nexthops:
        return None, "no nexthops for {}".format(prefix)

    return nexthops, None


def _find_nexthop(nexthops, ip):
    return [nh for nh in nexthops if nh.get("ip") == ip]


def _expect_check(check_fn):
    """Poll check_fn until it returns None or time out."""
    _, result = topotest.run_and_expect(check_fn, None, count=30, wait=1)
    assert result is None, result


def _check_recursive_resolved_nexthop_vrf(r1, params):
    """Verify a two-hop static route via show route JSON.

    The outer prefix (params["prefix_recursive"]) must resolve through an
    intermediate nexthop (params["recursive_nh"], marked recursive) to a
    leaf nexthop (params["resolved_nh"]) on params["ifname"] in
    params["egress_vrf"]. The outer route VRF and egress VRF always differ
    in this topology.

    Returns an error string, or None on success.
    """
    prefix = params["prefix_recursive"]
    cmd = _route_cmd(params, prefix, "route_json")
    output = r1.vtysh_cmd(cmd)
    logger.info("%s: %s", cmd, output)
    route = json.loads(output)

    nexthops, err = _collect_nexthops(route, prefix)
    if err:
        return err

    recursive = _find_nexthop(nexthops, params["recursive_nh"])
    if not recursive:
        return "missing recursive nexthop {}".format(params["recursive_nh"])
    if not recursive[0].get("recursive", False):
        return "nexthop {} is not marked recursive".format(params["recursive_nh"])

    resolved = _find_nexthop(nexthops, params["resolved_nh"])
    if not resolved:
        return "missing resolved nexthop {}".format(params["resolved_nh"])

    nh = resolved[0]
    if not nh.get("active", False):
        return "resolved nexthop {} is not active".format(params["resolved_nh"])
    if nh.get("interfaceName") != params["ifname"]:
        return "expected interface {}, got {}".format(
            params["ifname"], nh.get("interfaceName")
        )
    if nh.get("vrf") != params["egress_vrf"]:
        return "expected vrf {} on resolved nexthop, got {!r}".format(
            params["egress_vrf"], nh.get("vrf")
        )
    return None


def _check_recursive_show_route_text(r1, params):
    """Verify show route text for the recursive outer prefix.

    Confirms the resolved gateway and a (vrf NAME) tag for the egress
    interface VRF appear in CLI output. Returns an error string, or None.
    """
    prefix = params["prefix_recursive"]
    cmd = _route_cmd(params, prefix, "route_text")
    output = r1.vtysh_cmd(cmd)
    logger.info("%s:\n%s", cmd, output)
    if prefix not in output:
        return "prefix not shown"
    if params["resolved_nh"] not in output:
        return "resolved nexthop {} not shown".format(params["resolved_nh"])
    if "(vrf {})".format(params["egress_vrf"]) not in output:
        return "missing (vrf {}) indicator".format(params["egress_vrf"])
    return None


def _check_direct_cross_vrf_nexthop_vrf(r1, params):
    """Verify a direct nexthop-vrf static route via show route JSON.

    The direct prefix (params["prefix_direct"]) must be active with
    params["resolved_nh"] on params["ifname"] in params["egress_vrf"].
    Control case: direct cross-VRF statics worked before the recursive fix
    and should still expose the egress VRF on the nexthop. Returns an error
    string, or None on success.
    """
    prefix = params["prefix_direct"]
    cmd = _route_cmd(params, prefix, "route_json")
    output = r1.vtysh_cmd(cmd)
    logger.info("%s: %s", cmd, output)
    route = json.loads(output)

    nexthops, err = _collect_nexthops(route, prefix)
    if err:
        return err

    matches = _find_nexthop(nexthops, params["resolved_nh"])
    if not matches:
        return "missing nexthop {}".format(params["resolved_nh"])

    nh = matches[0]
    if not nh.get("active", False):
        return "nexthop {} is not active".format(params["resolved_nh"])
    if nh.get("interfaceName") != params["ifname"]:
        return "expected interface {}, got {}".format(
            params["ifname"], nh.get("interfaceName")
        )
    if nh.get("vrf") != params["egress_vrf"]:
        return "expected vrf {} on direct nexthop, got {!r}".format(
            params["egress_vrf"], nh.get("vrf")
        )
    return None


@pytest.mark.parametrize("ip_version", [4, 6])
def test_recursive_cross_vrf_resolved_nexthop_vrf_default_to_blue(ip_version):
    """Recursive default -> vrf-blue route exposes egress VRF on resolved NH."""
    params = DEFAULT_TO_BLUE[ip_version]
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Check recursive default -> vrf-blue resolved nexthop (IPv{})".format(ip_version))
    _expect_check(lambda: _check_recursive_resolved_nexthop_vrf(r1, params))


@pytest.mark.parametrize("ip_version", [4, 6])
def test_recursive_cross_vrf_resolved_nexthop_vrf_blue_to_default(ip_version):
    """Recursive vrf-blue -> default route exposes egress VRF on resolved NH."""
    params = BLUE_TO_DEFAULT[ip_version]
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Check recursive vrf-blue -> default resolved nexthop (IPv{})".format(ip_version))
    _expect_check(lambda: _check_recursive_resolved_nexthop_vrf(r1, params))


@pytest.mark.parametrize("ip_version", [4, 6])
def test_recursive_cross_vrf_show_route_text_default_to_blue(ip_version):
    """CLI shows (vrf vrf-blue) for recursive default -> vrf-blue route."""
    params = DEFAULT_TO_BLUE[ip_version]
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Check show route text for default -> vrf-blue (IPv{})".format(ip_version))
    _expect_check(lambda: _check_recursive_show_route_text(r1, params))


@pytest.mark.parametrize("ip_version", [4, 6])
def test_recursive_cross_vrf_show_route_text_blue_to_default(ip_version):
    """CLI shows (vrf default) for recursive vrf-blue -> default route."""
    params = BLUE_TO_DEFAULT[ip_version]
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Check show route text for vrf-blue -> default (IPv{})".format(ip_version))
    _expect_check(lambda: _check_recursive_show_route_text(r1, params))


@pytest.mark.parametrize("ip_version", [4, 6])
def test_direct_cross_vrf_nexthop_vrf_default_to_blue(ip_version):
    """Direct default -> vrf-blue route exposes vrf-blue on the nexthop."""
    params = DEFAULT_TO_BLUE[ip_version]
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Check direct default -> vrf-blue cross-VRF route (IPv{})".format(ip_version))
    _expect_check(lambda: _check_direct_cross_vrf_nexthop_vrf(r1, params))


@pytest.mark.parametrize("ip_version", [4, 6])
def test_direct_cross_vrf_nexthop_vrf_blue_to_default(ip_version):
    """Direct vrf-blue -> default route exposes default on the nexthop."""
    params = BLUE_TO_DEFAULT[ip_version]
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Check direct vrf-blue -> default cross-VRF route (IPv{})".format(ip_version))
    _expect_check(lambda: _check_direct_cross_vrf_nexthop_vrf(r1, params))


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
