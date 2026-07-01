#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by Carmine Scarpitta
#
# Test SRv6 L3 EVPN Type-5 (RT-5) route advertisement and forwarding.
#
# Two PE routers (r1, r2) run iBGP over IPv6 with l2vpn evpn address-family.
# Each PE has two VRFs (vrf10, vrf20) with SRv6 locators.  CE routers attach
# to the VRFs and originate connected prefixes.
#
# The test verifies:
#   - IPv4/IPv6 VPN RIBs contain the routes used for EVPN RT-5 advertisement
#   - EVPN RT-5 routes appear in the l2vpn evpn table on both PEs
#   - VRF routes are properly imported from EVPN
#   - CE-to-CE reachability within the same VRF works end-to-end
#   - CE-to-CE reachability across different VRFs is blocked
#   - Deleting/re-creating the SRv6 locator via zebra withdraws/restores routes
#   - Unsetting/re-setting the SRv6 locator in BGP withdraws/restores routes

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import bgp_vpn_router_json_cmp_exact_filter
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("ce5")
    tgen.add_router("ce6")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
    tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["r2"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["r1"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["r2"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["r1"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["r2"], "eth0", "eth3")


def setup_module(mod):
    result = required_linux_kernel_version("5.14")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        if os.path.exists("{}/{}/setup.sh".format(CWD, rname)):
            router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link set eth1 master vrf10")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.gears["r2"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r2"].run("ip link set vrf20 up")
    tgen.gears["r2"].run("ip link set eth1 master vrf10")
    tgen.gears["r2"].run("ip link set eth2 master vrf20")
    tgen.gears["r2"].run("ip link set eth3 master vrf20")
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


def check_rib(name, cmd, expected_file, count=15, wait=1):
    def _check(router, cmd, expected):
        logger.info("polling")
        output = json.loads(router.vtysh_cmd(cmd))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    router = tgen.gears[name]
    expected = open_json_file("{}/{}".format(CWD, expected_file))
    if "show bgp ipv4 vpn" in cmd or "show bgp ipv6 vpn" in cmd:
        func = functools.partial(
            bgp_vpn_router_json_cmp_exact_filter, router, cmd, expected
        )
    else:
        func = functools.partial(_check, router, cmd, expected)
    _, result = topotest.run_and_expect(func, None, count, wait)
    assert result is None, "Failed"


def check_vpn_ribs(expected_suffix=""):
    suffix = "_{}".format(expected_suffix) if expected_suffix else ""
    check_rib(
        "r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib{}.json".format(suffix)
    )
    check_rib(
        "r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib{}.json".format(suffix)
    )
    check_rib(
        "r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib{}.json".format(suffix)
    )
    check_rib(
        "r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib{}.json".format(suffix)
    )


def test_rib():
    """Verify EVPN RT-5 routes and VRF route tables on both PEs."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_rib("r1", "show bgp l2vpn evpn json", "r1/evpn_rib.json", 10, 1)
    check_rib("r2", "show bgp l2vpn evpn json", "r2/evpn_rib.json", 10, 1)

    check_vpn_ribs()

    check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10v4_rib.json")
    check_rib("r1", "show ip route vrf vrf20 json", "r1/vrf20v4_rib.json")
    check_rib("r2", "show ip route vrf vrf10 json", "r2/vrf10v4_rib.json")
    check_rib("r2", "show ip route vrf vrf20 json", "r2/vrf20v4_rib.json")

    check_rib("r1", "show ipv6 route vrf vrf10 json", "r1/vrf10v6_rib.json")
    check_rib("r1", "show ipv6 route vrf vrf20 json", "r1/vrf20v6_rib.json")
    check_rib("r2", "show ipv6 route vrf vrf10 json", "r2/vrf10v6_rib.json")
    check_rib("r2", "show ipv6 route vrf vrf20 json", "r2/vrf20v6_rib.json")

    check_rib("ce1", "show ip route json", "ce1/ip_rib.json")
    check_rib("ce2", "show ip route json", "ce2/ip_rib.json")
    check_rib("ce3", "show ip route json", "ce3/ip_rib.json")
    check_rib("ce4", "show ip route json", "ce4/ip_rib.json")
    check_rib("ce5", "show ip route json", "ce5/ip_rib.json")
    check_rib("ce6", "show ip route json", "ce6/ip_rib.json")

    check_rib("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
    check_rib("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")
    check_rib("ce3", "show ipv6 route json", "ce3/ipv6_rib.json")
    check_rib("ce4", "show ipv6 route json", "ce4/ipv6_rib.json")
    check_rib("ce5", "show ipv6 route json", "ce5/ipv6_rib.json")
    check_rib("ce6", "show ipv6 route json", "ce6/ipv6_rib.json")


def test_ping():
    """Verify CE-to-CE reachability within the same VRF (and isolation across VRFs)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # ce1 (r1/vrf10) reaches ce2 (r2/vrf10) and ce3 (r1/vrf10)
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "192.168.3.2", True, 10, 0.5)
    # ce1 cannot reach vrf20 CEs
    check_ping("ce1", "192.168.4.2", False, 10, 0.5)
    check_ping("ce1", "192.168.5.2", False, 10, 0.5)
    check_ping("ce1", "192.168.6.2", False, 10, 0.5)

    # ce4 (r2/vrf20) reaches ce5 (r1/vrf20) and ce6 (r2/vrf20)
    check_ping("ce4", "192.168.5.2", True, 10, 0.5)
    check_ping("ce4", "192.168.6.2", True, 10, 0.5)
    # ce4 cannot reach vrf10 CEs
    check_ping("ce4", "192.168.1.2", False, 10, 0.5)
    check_ping("ce4", "192.168.2.2", False, 10, 0.5)
    check_ping("ce4", "192.168.3.2", False, 10, 0.5)

    # IPv6
    check_ping("ce1", "2001:2::2", True, 10, 1)
    check_ping("ce1", "2001:3::2", True, 10, 1)
    check_ping("ce1", "2001:4::2", False, 10, 1)
    check_ping("ce1", "2001:5::2", False, 10, 1)
    check_ping("ce1", "2001:6::2", False, 10, 1)

    check_ping("ce4", "2001:5::2", True, 10, 1)
    check_ping("ce4", "2001:6::2", True, 10, 1)
    check_ping("ce4", "2001:1::2", False, 10, 1)
    check_ping("ce4", "2001:2::2", False, 10, 1)
    check_ping("ce4", "2001:3::2", False, 10, 1)


def test_locator_delete():
    """Deleting the SRv6 locator in zebra should withdraw EVPN RT-5 routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            no locator loc1
        """
    )
    check_vpn_ribs("locator_zebra_deleted")
    check_rib(
        "r1", "show bgp l2vpn evpn json", "r1/evpn_rib_locator_zebra_deleted.json"
    )
    check_rib(
        "r2", "show bgp l2vpn evpn json", "r2/evpn_rib_locator_zebra_deleted.json"
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)


def test_locator_recreate():
    """Re-creating the SRv6 locator should restore EVPN RT-5 routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix 2001:db8:1:1::/64
        """
    )
    check_vpn_ribs("locator_recreated")
    check_rib(
        "r1", "show bgp l2vpn evpn json", "r1/evpn_rib_locator_recreated.json"
    )
    check_rib(
        "r2", "show bgp l2vpn evpn json", "r2/evpn_rib_locator_recreated.json"
    )
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)


def test_bgp_locator_unset():
    """Unsetting the SRv6 locator in BGP should withdraw EVPN RT-5 routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          segment-routing srv6
           no locator loc1
        """
    )
    check_vpn_ribs("locator_deleted")
    check_rib(
        "r1", "show bgp l2vpn evpn json", "r1/evpn_rib_locator_deleted.json"
    )
    check_rib(
        "r2", "show bgp l2vpn evpn json", "r2/evpn_rib_locator_deleted.json"
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)


def test_bgp_locator_reset():
    """Re-setting the SRv6 locator in BGP should restore EVPN RT-5 routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          segment-routing srv6
           locator loc1
        """
    )
    check_vpn_ribs("locator_recreated")
    check_rib(
        "r1", "show bgp l2vpn evpn json", "r1/evpn_rib_locator_recreated.json"
    )
    check_rib(
        "r2", "show bgp l2vpn evpn json", "r2/evpn_rib_locator_recreated.json"
    )
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
