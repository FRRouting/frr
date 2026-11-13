#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright (c) 2025 Tuetuopay <tuetuopay@me.com>

"""
Test if route-map set for EVPN fields works.
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
from lib.topogen import TopoRouter, Topogen, get_topogen
from lib.topolog import logger

# L2VNIs on r1: VNI -> (subnet prefix, host MAC). Each has one host,
# advertised as RT-2 MAC+IP route, and its subnet is advertised as RT-5.
L2VNIS = {
    20: ("192.168.20", "02:00:00:00:20:05"),
    30: ("192.168.30", "02:00:00:00:30:05"),
}
RT5_PREFIXES = ["10.10.10.10/32"] + ["{}.0/24".format(n) for n, _ in L2VNIS.values()]


def host_ip(vni):
    return "{}.5".format(L2VNIS[vni][0])


def rt2_macip(vni):
    return "[2]:[0]:[48]:[{}]:[32]:[{}]".format(L2VNIS[vni][1], host_ip(vni))


def rt2_mac_only(vni):
    return "[2]:[0]:[48]:[{}]".format(L2VNIS[vni][1])


def rt5(prefix):
    addr, plen = prefix.split("/")
    return "[5]:[0]:[{}]:[{}]".format(plen, addr)


def setup_module(mod):
    if not topotest.platform_has_evpn():
        pytest.skip("platform does not support EVPN")

    topodef = {"s1": ("c1", "r1"), "s2": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    tgen.net["r1"].cmd(
        """
ip link add br10 up type bridge
ip link add vxlan10 up master br10 type vxlan id 10 dstport 4789 local 10.0.0.2 nolearning
        """
    )
    # brN is the SVI of L2VNI N. Its address puts the host on a connected
    # subnet, so the static neighbor turns into an RT-2 MAC+IP route, and
    # r1/frr.conf redistributes the subnet as RT-5 route. These addresses
    # are also why r1/frr.conf pins the router-id.
    for vni, (net, mac) in L2VNIS.items():
        tgen.net["r1"].cmd(
            """
ip link add br{vni} up type bridge
ip link add vxlan{vni} up master br{vni} type vxlan id {vni} dstport 4789 local 10.0.0.2 nolearning
ip addr add {net}.1/24 dev br{vni}
ip link add host{vni} up master br{vni} type dummy
bridge fdb add {mac} dev host{vni} master static
ip neigh add {ip} lladdr {mac} dev br{vni}
            """.format(
                vni=vni, net=net, mac=mac, ip=host_ip(vni)
            )
        )
    tgen.net["r2"].cmd(
        """
ip link add br10 up type bridge
ip link add vxlan10 up master br10 type vxlan id 10 dstport 4789 local 10.0.0.3 nolearning
        """
    )

    for name, router in tgen.routers().items():
        router.load_frr_config()

    tgen.start_router()

    # The nexthop tests rewrite the next hop of r1's routes to addresses in
    # 10.20.0.0/24. Make them resolvable on r2, so the routes stay valid.
    # Added after start_router(), which flushes the link addresses and with
    # them any route via r2-eth0.
    tgen.net["r2"].cmd_raises("ip route add 10.20.0.0/24 via 10.0.0.2")


def teardown_module(mod):
    get_topogen().stop_topology()


def test_bgp_evpn_route_map_set_gateway_ip():
    tgen: Topogen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2: TopoRouter = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp l2vpn evpn all overlay json"))
        expected = {
            "10.0.0.2:1": {
                "[5]:[0]:[32]:[10.10.10.10]": {
                    "paths": [
                        {
                            "valid": True,
                            "overlay": {
                                "gw": "10.10.10.10",
                            },
                        },
                    ],
                },
            },
            "numPrefix": 9,
        }
        return topotest.json_cmp(output, expected)

    logger.info("Check route type-5 gateway-ip")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "EVPN Route with gateway-ip should be advertised"


def _r2_rt5_nexthops():
    """Installed next hops of r1's RT-5 route 10.10.10.10/32 on r2."""
    r2 = get_topogen().gears["r2"]
    out = r2.vtysh_cmd("show ip route 10.10.10.10/32 json", isjson=True)
    return sorted(
        nh.get("ip")
        for route in out.get("10.10.10.10/32", [])
        if route.get("installed")
        for nh in route.get("nexthops", [])
    )


def test_bgp_evpn_route_map_set_gateway_ip_removed():
    """
    r2 imports r1's RT-5 route with gateway IP 10.10.10.10, which does not
    resolve on r2, so the route is not installed. Once r1 stops setting the
    gateway IP, r2 must install the route via r1. Once r1 sets it again,
    r2 must remove it again.
    """
    tgen: Topogen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1: TopoRouter = tgen.gears["r1"]

    logger.info("Check the RT-5 route with gateway-ip is not installed")
    _, result = topotest.run_and_expect(_r2_rt5_nexthops, [], count=30, wait=1)
    assert result == [], "r2 installed the RT-5 route via {}".format(result)

    logger.info("Remove set-gw-ip on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64000
         address-family l2vpn evpn
          no neighbor 10.0.0.3 route-map set-gw-ip out
        """
    )
    _, result = topotest.run_and_expect(
        _r2_rt5_nexthops, ["10.0.0.2"], count=30, wait=1
    )
    assert result == ["10.0.0.2"], "r2 RT-5 route next hops: {}".format(result)

    logger.info("Put set-gw-ip back on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64000
         address-family l2vpn evpn
          neighbor 10.0.0.3 route-map set-gw-ip out
        """
    )
    _, result = topotest.run_and_expect(_r2_rt5_nexthops, [], count=30, wait=1)
    assert result == [], "r2 still installs the RT-5 route via {}".format(result)


def _evpn_paths(router, rd):
    """Map EVPN prefix -> list of (next hop, Router MACs) of valid paths in one RD."""
    out = router.vtysh_cmd("show bgp l2vpn evpn all overlay json", isjson=True)
    result = {}
    for prefix, route in out.get(rd, {}).items():
        if not isinstance(route, dict):
            continue
        for path in route.get("paths", []):
            if not path.get("valid"):
                continue
            rmac = path.get("overlay", {}).get("rmac")
            result.setdefault(prefix, []).append(
                (path.get("nexthop", {}).get("ip"), [rmac] if rmac else [])
            )
    return result


def _expect_paths(router, rd, expected):
    def check():
        paths = _evpn_paths(router, rd)
        return {p: paths.get(p) for p in expected}

    _, result = topotest.run_and_expect(check, expected, count=60, wait=1)
    assert result == expected, "{} RD {}: expected {}, got {}".format(
        router.name, rd, expected, result
    )


# These tests only check the rewrite as BGP sees it. A receiver cannot
# honor different RMACs behind one next hop: Linux resolves the next hop
# through a single neighbor entry (VTEP IP -> one MAC on the L3 SVI), and
# zebra keeps one RMAC per VTEP. On each update zebra replaces the RMAC,
# removes the previous RMAC and its FDB entry, and logs
# EC_ZEBRA_EVPN_RMAC_CONFLICT, so the last route processed wins for all
# routes via that VTEP. Distinct RMACs need distinct next hops.
def _check_route_map_set(
    router,
    apply_cmd,
    revert_cmd,
    rmac_rt2=None,
    nh_rt2=None,
    rmac_rt5=None,
    nh_rt5=None,
):
    """
    Configure route-map set-evpn on router with apply_cmd, with a set
    action for each given value. Check that r2 sees the given values on
    all RT-2 and RT-5 routes and the original values everywhere else.
    Then undo it with revert_cmd and check that the original values are
    back. MAC-only RT-2 routes carry no RMAC unless the route-map sets one.
    """
    tgen: Topogen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1: TopoRouter = tgen.gears["r1"]
    r2: TopoRouter = tgen.gears["r2"]
    rd_rt5 = "10.0.0.2:1"
    rd_rt2 = {
        vni: r1.vtysh_cmd("show bgp l2vpn evpn vni {} json".format(vni), isjson=True)[
            "rd"
        ]
        for vni in L2VNIS
    }
    r1_rmac = r1.vtysh_cmd("show evpn vni 10 json", isjson=True)["routerMac"]
    r1_nh = "10.0.0.2"

    def expect(rmac2, nh2, mac_only_rmac, rmac5, nh5):
        for vni, rd in rd_rt2.items():
            _expect_paths(
                r2,
                rd,
                {
                    rt2_macip(vni): [(nh2, [rmac2])],
                    rt2_mac_only(vni): [
                        (nh2, [mac_only_rmac] if mac_only_rmac else [])
                    ],
                },
            )
        _expect_paths(r2, rd_rt5, {rt5(p): [(nh5, [rmac5])] for p in RT5_PREFIXES})

    def sets(rmac, nh):
        lines = []
        if rmac:
            lines.append(" set extcommunity evpn rmac {}".format(rmac))
        if nh:
            lines.append(" set ip next-hop {}".format(nh))
        return "\n".join(lines)

    logger.info("Check the original next hop and RMAC")
    expect(r1_rmac, r1_nh, None, r1_rmac, r1_nh)

    logger.info("Apply route-map set-evpn on %s: %s", router.name, apply_cmd)
    router.vtysh_cmd(
        """
        configure terminal
        route-map set-evpn permit 10
         match evpn route-type macip
        {sets_rt2}
        route-map set-evpn permit 20
         match evpn route-type prefix
        {sets_rt5}
        route-map set-evpn permit 30
        router bgp 64000
         address-family l2vpn evpn
          {apply_cmd}
        """.format(
            sets_rt2=sets(rmac_rt2, nh_rt2),
            sets_rt5=sets(rmac_rt5, nh_rt5),
            apply_cmd=apply_cmd,
        )
    )
    expect(
        rmac_rt2 or r1_rmac,
        nh_rt2 or r1_nh,
        rmac_rt2,
        rmac_rt5 or r1_rmac,
        nh_rt5 or r1_nh,
    )

    logger.info("Revert route-map set-evpn on %s: %s", router.name, revert_cmd)
    router.vtysh_cmd(
        """
        configure terminal
        router bgp 64000
         address-family l2vpn evpn
          {revert_cmd}
        no route-map set-evpn
        """.format(
            revert_cmd=revert_cmd
        )
    )
    expect(r1_rmac, r1_nh, None, r1_rmac, r1_nh)


# r1 already sends to r2 with route-map set-gw-ip. The outbound tests swap
# it for set-evpn and put set-gw-ip back afterwards.
OUT_ON_R1 = {
    "apply_cmd": "neighbor 10.0.0.3 route-map set-evpn out",
    "revert_cmd": "neighbor 10.0.0.3 route-map set-gw-ip out",
}
IN_ON_R2 = {
    "apply_cmd": "neighbor 10.0.0.2 route-map set-evpn in",
    "revert_cmd": "no neighbor 10.0.0.2 route-map set-evpn in",
}


def test_bgp_evpn_route_map_set_rmac_out():
    """Override the RMAC of all RT-2 and RT-5 routes, outbound on r1."""
    _check_route_map_set(
        get_topogen().gears["r1"],
        rmac_rt2="02:22:00:00:00:01",
        rmac_rt5="02:55:00:00:00:01",
        **OUT_ON_R1
    )


def test_bgp_evpn_route_map_set_rmac_in():
    """Override the RMAC of all RT-2 and RT-5 routes, inbound on r2."""
    _check_route_map_set(
        get_topogen().gears["r2"],
        rmac_rt2="02:22:00:00:00:02",
        rmac_rt5="02:55:00:00:00:02",
        **IN_ON_R2
    )


def test_bgp_evpn_route_map_set_nexthop_out():
    """Override the next hop of all RT-2 and RT-5 routes, outbound on r1."""
    _check_route_map_set(
        get_topogen().gears["r1"], nh_rt2="10.20.0.21", nh_rt5="10.20.0.51", **OUT_ON_R1
    )


def test_bgp_evpn_route_map_set_nexthop_in():
    """Override the next hop of all RT-2 and RT-5 routes, inbound on r2."""
    _check_route_map_set(
        get_topogen().gears["r2"], nh_rt2="10.20.0.22", nh_rt5="10.20.0.52", **IN_ON_R2
    )


def _r2_installed():
    """r2's zebra and kernel state for routes from r1 in L3VNI 10."""
    r2 = get_topogen().gears["r2"]
    rmacs = r2.vtysh_cmd("show evpn rmac vni 10 json", isjson=True)
    nhs = r2.vtysh_cmd("show evpn next-hops vni 10 json", isjson=True)
    neigh = json.loads(r2.cmd("ip -j neigh show dev br10") or "[]")
    fdb = json.loads(r2.cmd("bridge -j fdb show dev vxlan10") or "[]")
    routes = {}
    for prefix in ["{}/32".format(host_ip(v)) for v in L2VNIS] + RT5_PREFIXES:
        out = r2.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
        routes[prefix] = sorted(
            nh.get("ip")
            for route in out.get(prefix, [])
            if route.get("installed")
            for nh in route.get("nexthops", [])
        )
    return {
        "zebra rmac": {
            m: e.get("vtepIp") for m, e in rmacs.items() if isinstance(e, dict)
        },
        "zebra next-hops": {
            ip: e.get("routerMac") for ip, e in nhs.items() if isinstance(e, dict)
        },
        "kernel neigh": {n["dst"]: n.get("lladdr") for n in neigh},
        "kernel fdb": {f["mac"]: f["dst"] for f in fdb if "dst" in f},
        "routes": routes,
    }


def _expect_installed(what, expected):
    _, result = topotest.run_and_expect(_r2_installed, expected, count=30, wait=1)
    assert result == expected, "r2 {}: expected {}, got {}".format(
        what, expected, result
    )


def test_bgp_evpn_route_map_set_rmac_nexthop_install():
    """
    Give the routes of each L2VNI, its RT-2 host route and the RT-5 route
    of its subnet, their own RMAC and next hop, outbound on r1. 10.10.10.10
    keeps r1's own values. All routes are in the same L3VNI, so r2 gets
    several next hops with different RMACs behind one L3VNI. That is the
    normal case of several remote VTEPs in one L3VNI, here produced by a
    route-map. r2 must install one RMAC per next hop in zebra and in the
    kernel, and route each prefix via its own next hop.
    """
    tgen: Topogen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1: TopoRouter = tgen.gears["r1"]
    r1_rmac = r1.vtysh_cmd("show evpn vni 10 json", isjson=True)["routerMac"]
    r1_nh = "10.0.0.2"
    # VNI -> (RMAC, next hop) for its RT-2 and RT-5 routes
    pairs = {
        20: ("02:20:00:00:00:01", "10.20.0.20"),
        30: ("02:30:00:00:00:01", "10.20.0.30"),
    }

    def state(pairs, rt5_installed=True):
        all_pairs = dict(pairs.values())
        all_pairs[r1_rmac] = r1_nh
        routes = {"10.10.10.10/32": [r1_nh] if rt5_installed else []}
        for vni, (net, _) in L2VNIS.items():
            nh = pairs.get(vni, (r1_rmac, r1_nh))[1]
            routes["{}/32".format(host_ip(vni))] = [nh]
            routes["{}.0/24".format(net)] = [nh] if rt5_installed else []
        return {
            "zebra rmac": all_pairs,
            "zebra next-hops": {nh: m for m, nh in all_pairs.items()},
            "kernel neigh": {nh: m for m, nh in all_pairs.items()},
            "kernel fdb": all_pairs,
            "routes": routes,
        }

    logger.info("Remove set-gw-ip on r1, so r2 installs the RT-5 routes")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64000
         address-family l2vpn evpn
          no neighbor 10.0.0.3 route-map set-gw-ip out
        """
    )
    _expect_installed("install with r1's own values", state({}))

    logger.info("Apply route-map set-evpn-vni on r1")
    cfg = ["configure terminal"]
    for vni, (rmac, nh) in pairs.items():
        cfg += [
            "ip prefix-list vni{}-subnet permit {}.0/24".format(vni, L2VNIS[vni][0]),
            "route-map set-evpn-vni permit {}".format(vni),
            " match evpn route-type macip",
            " match evpn vni {}".format(vni),
            " set extcommunity evpn rmac {}".format(rmac),
            " set ip next-hop {}".format(nh),
            "route-map set-evpn-vni permit {}".format(vni + 1),
            " match evpn route-type prefix",
            " match ip address prefix-list vni{}-subnet".format(vni),
            " set extcommunity evpn rmac {}".format(rmac),
            " set ip next-hop {}".format(nh),
        ]
    cfg += [
        "route-map set-evpn-vni permit 100",
        "router bgp 64000",
        " address-family l2vpn evpn",
        "  neighbor 10.0.0.3 route-map set-evpn-vni out",
    ]
    r1.vtysh_cmd("\n".join(cfg))
    _expect_installed("install with a pair per L2VNI", state(pairs))

    logger.info("Remove route-map set-evpn-vni on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64000
         address-family l2vpn evpn
          no neighbor 10.0.0.3 route-map set-evpn-vni out
        no route-map set-evpn-vni
        no ip prefix-list vni20-subnet
        no ip prefix-list vni30-subnet
        """
    )
    _expect_installed("install with r1's own values", state({}))

    logger.info("Put set-gw-ip back on r1, its RT-5 routes do not resolve on r2")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 64000
         address-family l2vpn evpn
          neighbor 10.0.0.3 route-map set-gw-ip out
        """
    )
    _expect_installed("install with set-gw-ip", state({}, rt5_installed=False))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
