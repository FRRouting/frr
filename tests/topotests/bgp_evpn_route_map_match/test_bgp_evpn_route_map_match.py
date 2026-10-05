#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if route-map match by EVPN route-type and next-hop works.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


def setup_module(mod):
    topodef = {"s1": ("c1", "r1"), "s2": ("r1", "r2"), "s3": ("r2", "c2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    tgen.net["r1"].cmd(
        """
ip link add vxlan10 type vxlan id 10 dstport 4789 local 10.10.10.1 nolearning
ip link add name br10 type bridge
ip link set dev vxlan10 master br10
ip link set dev r1-eth0 master br10
ip link set up dev br10
ip link set up dev vxlan10"""
    )

    tgen.net["r2"].cmd(
        """
ip link add vxlan10 type vxlan id 10 dstport 4789 local 10.10.10.2 nolearning
ip link add name br10 type bridge
ip link set dev vxlan10 master br10
ip link set dev r2-eth1 master br10
ip link set up dev br10
ip link set up dev vxlan10"""
    )

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_evpn_route_map_match_route_type5():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp l2vpn evpn neighbor 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.1:1": {
                    "[5]:[0]:[32]:[10.10.10.10]": {
                        "valid": True,
                    }
                },
            },
            "totalPrefixCounter": 1,
        }
        return topotest.json_cmp(output, expected)

    logger.info("Check route type-5 filtering")
    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Filtered EVPN routes should not be advertised"


def test_bgp_evpn_route_map_match_route_type2():
    tgen = get_topogen()

    # Change to L2VNI
    for machine in [tgen.gears["r1"], tgen.gears["r2"]]:
        machine.vtysh_cmd("configure terminal\nno vni 10")

    def _check_l2vni():
        for machine in [tgen.gears["r1"], tgen.gears["r2"]]:
            output = json.loads(machine.vtysh_cmd("show evpn vni json"))

            expected = {"10": {"vni": 10, "type": "L2"}}
            return topotest.json_cmp(output, expected)

    logger.info("Check L2VNI setup")
    test_func = functools.partial(_check_l2vni)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "L2VNI setup failed."

    c2_mac = (
        tgen.gears["c2"]
        .cmd(r"ip link show c2-eth0 | awk '/link\/ether/ {print $2}'")
        .rstrip()
    )
    tgen.gears["r1"].vtysh_cmd(
        "\n".join(
            [
                "configure",
                "route-map rt2 deny 30",
                "match mac address %s" % c2_mac,
                "exit",
                "router bgp 65001",
                "address-family l2vpn evpn",
                "neighbor 192.168.1.2 route-map rt2 in",
            ]
        )
    )

    def _check_filter_mac():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show bgp l2vpn evpn neighbors 192.168.1.2 advertised-routes json"
            )
        )

        if (
            output["advertisedRoutes"]
            .get("10.10.10.2:2", {})
            .get("[2]:[0]:[48]:[%s]" % c2_mac)
        ):
            return False

        return True

    logger.info("check mac filter in, on c2 interface: %s" % c2_mac)
    test_func = functools.partial(_check_filter_mac)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result is True, "%s is not filtered" % c2_mac

    tgen.gears["r1"].vtysh_cmd(
        "\n".join(
            [
                "configure",
                "route-map rt2 deny 30",
                "no match mac address %s" % c2_mac,
                "match evpn route-type macip" "exit",
                "router bgp 65001",
                "address-family l2vpn evpn",
                "neighbor 192.168.1.2 route-map rt2 out",
            ]
        )
    )

    def _check_filter_type2():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show bgp l2vpn evpn neighbors 192.168.1.2 advertised-routes json"
            )
        )

        if output["totalPrefixCounter"] == 0:
            return True

        return False

    logger.info("check route type-2 filter out")
    test_func = functools.partial(_check_filter_type2)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result is True, "EVPN routes type-2 are not filtered."


# The EVPN routes r1 receives from r2 have r2's VTEP as next-hop.
def _apply_in(r1, route_map):
    r1.vtysh_cmd(
        "\n".join(
            [
                "configure",
                "router bgp 65001",
                "address-family l2vpn evpn",
                "neighbor 192.168.1.2 route-map %s in" % route_map,
                "end",
                "clear bgp l2vpn evpn 192.168.1.2 soft in",
            ]
        )
    )


def _check_received(r1, accepted):
    output = json.loads(r1.vtysh_cmd("show bgp l2vpn evpn summary json"))
    received = output.get("peers", {}).get("192.168.1.2", {}).get("pfxRcd")
    if received is None:
        return False
    return received > 0 if accepted else received == 0


def test_bgp_evpn_route_map_match_next_hop():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "\n".join(
            [
                "configure",
                "ip prefix-list nh-r2 seq 5 permit 10.10.10.2/32",
                "access-list nh-r2-acl seq 5 permit 10.10.10.2/32",
                "route-map nh-all permit 10",
                "exit",
                "route-map nh-pl deny 10",
                "match ip next-hop prefix-list nh-r2",
                "exit",
                "route-map nh-pl permit 20",
                "exit",
                "route-map nh-acl permit 10",
                "match ip next-hop nh-r2-acl",
            ]
        )
    )

    logger.info("Check EVPN routes are received from r2 without filtering")
    _apply_in(r1, "nh-all")
    test_func = functools.partial(_check_received, r1, True)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result is True, "No EVPN routes received from r2"

    logger.info("Check match ip next-hop prefix-list on EVPN routes")
    _apply_in(r1, "nh-pl")
    test_func = functools.partial(_check_received, r1, False)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result is True, "EVPN routes with next-hop 10.10.10.2 are not denied"

    logger.info("Check match ip next-hop access-list on EVPN routes")
    _apply_in(r1, "nh-acl")
    test_func = functools.partial(_check_received, r1, True)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result is True, "EVPN routes with next-hop 10.10.10.2 are not permitted"


def test_bgp_evpn_route_map_match_ipv6_next_hop():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Move r2 to an IPv6 VTEP: its EVPN routes get an IPv6 next-hop.
    tgen.net["r2"].cmd(
        """
ip -6 addr add 2001:db8::2/128 dev lo
ip link del vxlan10
ip link add vxlan10 type vxlan id 10 dstport 4789 local 2001:db8::2 nolearning
ip link set dev vxlan10 master br10
ip link set up dev vxlan10"""
    )

    r1.vtysh_cmd(
        "\n".join(
            [
                "configure",
                "ipv6 prefix-list nh6-r2 seq 5 permit 2001:db8::2/128",
                "ipv6 access-list nh6-r2-acl seq 5 permit 2001:db8::2/128",
                "route-map nh6-pl deny 10",
                "match ipv6 next-hop prefix-list nh6-r2",
                "exit",
                "route-map nh6-pl permit 20",
                "exit",
                "route-map nh6-acl permit 10",
                "match ipv6 next-hop nh6-r2-acl",
            ]
        )
    )

    def _check_ipv6_next_hop():
        return "2001:db8::2" in r1.vtysh_cmd("show bgp l2vpn evpn")

    logger.info("Check EVPN routes from r2 have an IPv6 next-hop")
    _apply_in(r1, "nh-all")
    _, result = topotest.run_and_expect(_check_ipv6_next_hop, True, count=60, wait=1)
    assert result is True, "No EVPN routes with next-hop 2001:db8::2 from r2"

    logger.info("Check match ipv6 next-hop prefix-list on EVPN routes")
    _apply_in(r1, "nh6-pl")
    test_func = functools.partial(_check_received, r1, False)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result is True, "EVPN routes with next-hop 2001:db8::2 are not denied"

    logger.info("Check match ipv6 next-hop access-list on EVPN routes")
    _apply_in(r1, "nh6-acl")
    test_func = functools.partial(_check_received, r1, True)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert result is True, "EVPN routes with next-hop 2001:db8::2 are not permitted"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
