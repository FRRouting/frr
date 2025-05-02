#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 Tuetuopay <tuetuopay@me.com>

"""
Tests if AddPath works for EVPN.

Here, we have two routers c1 and c2 announcing the same destination to a router r1. r1 exports the
received prefixes as EVPN type-5 routes, with the nexthop as the gateway-ip.
Using addpath, r2 should receive all paths to the destination instead of only the best one. Paths
are reflected by rr that acts as a route-reflector.
R3 will serve as an injector for the type-2 routes corresponding to c1/c2. FRR will not resolve
locally attached overlay index, so this is only a "means to an end".

Here we test:
- export using r1
- import using r2
- passthrough using rr

Topology:
                                       ┌────────┐
                                       │        │
                                       │   rr   │
                                       │        │  ┌────────┐
                        10.0.0.0/31    └───┬────┘  │        │
       ┌───────────────┐                   │    ┌──┤   r2   │
       │               │                   │    │  │        │
       │ c1 / AS 64000 ├──┐                ├────┘  └────────┘
       │               │  │    ┌────────┐  │       ┌────────┐
       └───────────────┘  └────┤        │  │       │        │
                               │   r1   ├──┴───────┤   r3   │
       ┌───────────────┐  ┌────┤        │          │        │
       │               │  │    └────────┘          └────────┘
       │ c2 / AS 64000 ├──┘             10.0.0.8/29
       │               │
       └───────────────┘
                        10.0.0.2/31
          AS 64000                          AS 64001
"""

import functools
import json
import os
import sys
import pytest
from typing import Optional

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import TopoRouter, Topogen, get_topogen
from lib.topolog import logger
from lib.topotest import json_cmp_result


def setup_module(mod):
    topodef = {"s1": ("c1", "r1"), "s2": ("c2", "r1"), "s3": ("r1", "r2", "r3", "rr")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    # L3 SVI only
    tgen.net["r1"].cmd("""
        ip link add vrf100 up type vrf table 100
        ip link add br100 up master vrf100 type bridge
        ip link add vxlan100 up master br100 type vxlan id 100 dstport 4789 local 10.0.0.10 nolearning
        ip link set r1-eth0 master vrf100
        ip link set r1-eth1 master vrf100
    """)
    # L3 + L2 SVIs
    tgen.net["r2"].cmd("""
        ip link add vrf100 up type vrf table 100
        ip link add br100 up master vrf100 type bridge
        ip link add vxlan100 up master br100 type vxlan id 100 dstport 4789 local 10.0.0.11 nolearning
        ip link add br10 up master vrf100 type bridge
        ip link add vxlan10 up master br10 type vxlan id 10 dstport 4789 local 10.0.0.11 nolearning
        ip addr add 10.0.0.1/31 dev br10
        ip addr add 10.0.0.3/31 dev br10
    """)
    # L2 SVI only
    tgen.net["r3"].cmd("""
        ip link add vrf100 up type vrf table 100
        ip link add br10 up master vrf100 type bridge
        ip link add vxlan10 up master br10 type vxlan id 10 dstport 4789 local 10.0.0.12 nolearning
        ip link add dummy-c1 up master br10 type dummy
        ip link add dummy-c2 up master br10 type dummy
        ip addr add 10.0.0.1/31 dev br10
        ip addr add 10.0.0.3/31 dev br10
        bridge fdb add 00:00:00:00:00:c1 dev dummy-c1 master static
        bridge fdb add 00:00:00:00:00:c2 dev dummy-c2 master static
        ip neigh add 10.0.0.0 dev br10 lladdr 00:00:00:00:00:c1
        ip neigh add 10.0.0.2 dev br10 lladdr 00:00:00:00:00:c2
    """)
        # ip link add br100 up master vrf100 type bridge
        # ip link add vxlan100 up master br100 type vxlan id 100 dstport 4789 local 10.0.0.12 nolearning

    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{name}/frr.conf"))
    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _converge_fn(router: TopoRouter, command: str, expected: dict):
    def _converge() -> Optional[json_cmp_result]:
        output: str = router.vtysh_cmd(command)
        return topotest.json_cmp(json.loads(output), expected)
    return functools.partial(_converge)


EXPECTED_R1_IPV4_BASELINE = {
    "routes": {
        "10.0.0.0/24": [
            {
                "aspath": {"string": "64000"},
                "valid": True,
                "multipath": True,
                "nexthops": [{"ip": "10.0.0.0"}],
            },
            {
                "aspath": {"string": "64000"},
                "valid": True,
                "multipath": True,
                "nexthops": [{"ip": "10.0.0.2"}],
            },
        ],
    },
    "totalRoutes": 1,
    "totalPaths": 2,
}
EXPECTED_R2_IPV4_BASELINE = {
    "routes": {
        "10.0.0.0/24": [
            {
                "importedFrom": "10.0.0.10:1",
                "aspath": {"string": "64000"},
                "valid": True,
                "multipath": True,
                "nexthops": [{"ip": "10.0.0.0"}],
            },
            {
                "aspath": {"string": "64000"},
                "valid": True,
                "multipath": True,
                "nexthops": [{"ip": "10.0.0.2"}],
            },
        ],
    },
    "totalRoutes": 1,
    "totalPaths": 2,
}


def _ensure_baseline(tgen: Topogen):
    logger.info("Check IPv4 routes on R2")
    expected = EXPECTED_R2_IPV4_BASELINE
    f = _converge_fn(tgen.gears["r2"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Multipath routes should be in overlay VRF"


def test_bgp_evpn_rt5_addpath_basic():
    """
    Basic test for the simple case. Tests taht routes are there, with expected parameters and such.
    """

    tgen: Topogen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check IPv4 routes on R1")
    expected = EXPECTED_R1_IPV4_BASELINE
    f = _converge_fn(tgen.gears["r1"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Multipath routes should be in overlay VRF"

    logger.info("Check EVPN routes on R1")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.0",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "local": True,
                            "multipath": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.2",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "local": True,
                            "multipath": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 2,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Multipath routes should be exported to EVPN"

    logger.info("Check EVPN routes on RR")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.0",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "multipath": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.2",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "multipath": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 2,
    }
    f = _converge_fn(tgen.gears["rr"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "All EVPN paths should be present in RR"

    logger.info("Check EVPN routes on R2")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.0",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "multipath": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.2",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "multipath": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 2,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "All EVPN paths should be present in R2"

    logger.info("Check IPv4 routes on R2")
    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "importedFrom": "10.0.0.10:1",
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "multipath": True,
                    "nexthops": [{"ip": "10.0.0.0"}],
                },
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "multipath": True,
                    "nexthops": [{"ip": "10.0.0.2"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 2,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Multipath routes should be imported in overlay VRF"

    logger.info("Check FIB on R2")
    expected = {
        "10.0.0.0/24":[
            {
                "selected": True,
                "installed": True,
                "nexthops":[
                    {"fib": True, "ip": "10.0.0.0", "interfaceName": "br10", "active":True},
                    {"fib": True, "ip": "10.0.0.2", "interfaceName": "br10", "active":True},
                ],
            },
        ],
    }
    f = _converge_fn(tgen.gears["r2"], "show ip route vrf vrf100 10.0.0.0/24 json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Multipath routes should be installed in FIB"


def test_bgp_evpn_rt5_addpath_withdraw():
    """
    Tests if a withdrawn route is properly un-exported from EVPN, and re-advertised back.
    This allows us to know the basic mechanism of propagation works across the RR, so we only need
    to test the edge routers in other, more complex tests.
    """

    tgen: Topogen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _ensure_baseline(tgen)

    logger.info("Withdrawing path through C1")
    c1: TopoRouter = tgen.gears["c1"]
    c1.vtysh_cmd("""
        conf
        router bgp 64000
         address-family ipv4 unicast
          no network 10.0.0.0/24
    """)

    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.2"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Route through C1 should be absent from overlay VRF"

    logger.info("Check EVPN routes on R1")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.2",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "local": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C1 should be withdrawn from EVPN"

    logger.info("Check EVPN routes on RR")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.2",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 1,
    }
    f = _converge_fn(tgen.gears["rr"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C1 should be absent from EVPN on the RR"

    logger.info("Check EVPN routes on R2")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.2",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 1,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C1 should be absent from R2"

    logger.info("Check IPv4 routes on R2")
    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.2"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 1,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C1 should be un-imported in R2"

    logger.info("Adding back path through C1")
    c1.vtysh_cmd("""
        conf
        router bgp 64000
         address-family ipv4 unicast
          network 10.0.0.0/24
    """)

    # ensure it is propagated back
    test_bgp_evpn_rt5_addpath_basic()


def test_bgp_evpn_rt5_addpath_transitions():
    """
    Tests a change in the advertise strategy between gateway-ip (so with addpath), and without
    overlay-index (so without addpath).
    Ensures the multipath routes are properly cleaned up, and properly advertised back.
    """

    tgen: Topogen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _ensure_baseline(tgen)

    logger.info("Switching to bestpath advertisement")
    r1: TopoRouter = tgen.gears["r1"]
    r1.vtysh_cmd("""
        conf
        router bgp 64001 vrf vrf100
         address-family l2vpn evpn
          advertise ipv4 unicast
    """)

    logger.info("Check IPv4 routes on R1")
    expected = EXPECTED_R1_IPV4_BASELINE
    f = _converge_fn(tgen.gears["r1"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Multipath routes should be in overlay VRF"

    logger.info("Check EVPN routes on R1")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "local": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Only the best path should be kept in R1"

    logger.info("Check EVPN routes on R1")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Only the best path should be kept in R2"

    logger.info("Check IPv4 routes on R2")
    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.10"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 1,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Route should go through R1 now"

    logger.info("Switching back to gateway-ip")
    r1.vtysh_cmd("""
        conf
        router bg 64001 vrf vrf100
         address-family l2vpn evpn
          advertise ipv4 unicast gateway-ip
    """)

    # ensure we go back to the original state
    test_bgp_evpn_rt5_addpath_basic()


def test_bgp_evpn_rt5_addpath_route_map():
    """
    Tests that route-map addition and removal properly works, especially for route filtering and
    modification.
    """

    tgen: Topogen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _ensure_baseline(tgen)

    logger.info("Adding drop route-map")
    r1: TopoRouter = tgen.gears["r1"]
    r1.vtysh_cmd("""
        conf
        route-map drop-c2 deny 10
         match ip next-hop address 10.0.0.2
        route-map drop-c2 permit 20
        router bgp 64001 vrf vrf100
         address-family l2vpn evpn
          advertise ipv4 unicast gateway-ip route-map drop-c2
    """)

    logger.info("Check IPv4 routes on R1")
    expected = EXPECTED_R1_IPV4_BASELINE
    f = _converge_fn(tgen.gears["r1"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "R1 overlay shoud still have both paths"

    logger.info("Check EVPN routes on R1")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.0",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "local": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C2 should be withdrawn from EVPN"

    logger.info("Check IPv4 routes on R2")
    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.0"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 1,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C2 should be un-imported in R2"

    logger.info("Changing for a preference update route-map")
    r1.vtysh_cmd("""
        conf
        no route-map drop-c2
        route-map set-pref permit 10
         match ip next-hop address 10.0.0.0
         set local-pref 50
        route-map set-pref permit 20
        router bgp 64001 vrf vrf100
         address-family l2vpn evpn
          advertise ipv4 unicast gateway-ip route-map set-pref
    """)

    logger.info("Check IPv4 routes on R1")
    expected = EXPECTED_R1_IPV4_BASELINE
    f = _converge_fn(tgen.gears["r1"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "R1 overlay shoud still have both paths"

    logger.info("Check EVPN routes on R1")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "gatewayIP": "10.0.0.2",
                            "valid": True,
                            "local": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                            "bestpath": {"overall": True, "selectionReason": "Local Pref"},
                        },
                    ],
                    [
                        {
                            "gatewayIP": "10.0.0.0",
                            "local": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                            "locPrf": 50,
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 2,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "All paths, including non-best should be in EVPN"

    logger.info("Check EVPN routes on RR")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "gatewayIP": "10.0.0.2",
                            "valid": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                            "bestpath": {"overall": True, "selectionReason": "Local Pref"},
                        },
                    ],
                    [
                        {
                            "gatewayIP": "10.0.0.0",
                            "nexthops": [{"ip": "10.0.0.10"}],
                            "locPrf": 50,
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 2,
    }
    f = _converge_fn(tgen.gears["rr"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "All paths, including non-best should be transmitted in EVPN"

    logger.info("Check EVPN routes on R2")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "gatewayIP": "10.0.0.2",
                            "valid": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                            "bestpath": {"overall": True, "selectionReason": "Local Pref"},
                        },
                    ],
                    [
                        {
                            "gatewayIP": "10.0.0.0",
                            "nexthops": [{"ip": "10.0.0.10"}],
                            "locPrf": 50,
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 2,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "All paths, including non-best should be transmitted in EVPN"

    logger.info("Check IPv4 routes on R2")
    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "importedFrom": "10.0.0.10:1",
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.2"}],
                    "locPrf": 100,
                    "bestpath": {"overall": True, "selectionReason": "Local Pref"},
                },
                {
                    "importedFrom": "10.0.0.10:1",
                    "nexthops": [{"ip": "10.0.0.0"}],
                    "locPrf": 50,
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 2,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "All paths, including non-best, should be imported in overlay VRF"

    logger.info("Cleaning up")
    r1.vtysh_cmd("""
        conf
        no route-map set-pref
        router bgp 64001 vrf vrf100
         address-family l2vpn evpn
          advertise ipv4 unicast gateway-ip
    """)
    _ensure_baseline(tgen)


def test_bgp_evpn_rt5_addpath_session_down():
    """
    Ensures that no issues arise from a session going down, either shut or down.
    """

    tgen: Topogen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _ensure_baseline(tgen)

    logger.info("Admin shutdown of the session with C1")
    r1: TopoRouter = tgen.gears["r1"]
    r1.vtysh_cmd("""
        conf
        router bgp 64001 vrf vrf100
         neighbor 10.0.0.0 shutdown
    """)

    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.2"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Route through C1 should be absent from overlay VRF"

    logger.info("Check EVPN routes on R1")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.2",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "local": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C1 should be withdrawn from EVPN"

    logger.info("Check IPv4 routes on R2")
    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.2"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 1,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C1 should be un-imported in R2"

    logger.info("Restore session to C1")
    r1.vtysh_cmd("""
        conf
        router bgp 64001 vrf vrf100
         no neighbor 10.0.0.0 shutdown
    """)
    _ensure_baseline(tgen)

    logger.info("Break session with C1")
    c1: TopoRouter = tgen.gears["c1"]
    c1.vtysh_cmd("""
        conf
        router bgp 64000
         neighbor 10.0.0.1 shutdown
    """)

    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.2"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Route through C1 should be absent from overlay VRF"

    logger.info("Check EVPN routes on R1")
    expected = {
        "10.0.0.10:1": {
            "[5]:[0]:[24]:[10.0.0.0]": {
                "paths": [
                    [
                        {
                            "vni": "100",
                            "gatewayIP": "10.0.0.2",
                            "aspath": {"string": "64000"},
                            "valid": True,
                            "local": True,
                            "nexthops": [{"ip": "10.0.0.10"}],
                        },
                    ],
                ],
            },
        },
        "numPrefix": 1,
        "numPaths": 1,
    }
    f = _converge_fn(tgen.gears["r1"], "show bgp l2vpn evpn route detail type prefix json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C1 should be withdrawn from EVPN"

    logger.info("Check IPv4 routes on R2")
    expected = {
        "routes": {
            "10.0.0.0/24": [
                {
                    "aspath": {"string": "64000"},
                    "valid": True,
                    "nexthops": [{"ip": "10.0.0.2"}],
                },
            ],
        },
        "totalRoutes": 1,
        "totalPaths": 1,
    }
    f = _converge_fn(tgen.gears["r2"], "show bgp vrf vrf100 ipv4 unicast detail json", expected)
    _, result = topotest.run_and_expect(f, None, count=60, wait=1)
    assert result is None, "Path through C1 should be un-imported in R2"

    logger.info("Restore session with C1")
    c1.vtysh_cmd("""
        conf
        router bgp 64000
         no neighbor 10.0.0.1 shutdown
    """)
    _ensure_baseline(tgen)
