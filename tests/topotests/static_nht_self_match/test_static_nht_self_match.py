#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Nvidia Inc.
# Donald Sharp
#

"""
staticd nexthop tracking must not resolve a gateway over the static route
that uses that gateway.

dummy5 is 11.11.0.1/16, so the connected cover is 11.11.0.0/16.  The static
route 11.11.0.0/24 uses 11.11.0.2, which is inside that cover and also inside
the static prefix.  NHT for 11.11.0.2 has to stay on the connected route.
Resolving it over 11.11.0.0/24 moves the registration off the connected prefix,
so shutting dummy5 never tells staticd the gateway is gone and the static
route stays installed against an inactive nexthop.

A gateway in another VRF is not that self-match. 12.12.0.2 is covered in
vrf_a by static 12.12.0.0/24, whose only nexthop is 12.12.0.2 resolved in
vrf_b. NHT for 12.12.0.2 in vrf_a has to use that route, and 1.1.1.0/24 via
12.12.0.2 in vrf_a has to install.

An import check is not a host registration. sharp watch import 192.168.0.5/24
is stored as 192.168.0.0/24. A kernel route 192.168.0.0/24 via 192.168.0.0,
covered by connected 192.168.0.0/16, must resolve that import check. Treating
the gateway as the tracked address walks up to the connected /16.
"""

import os
import sys
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.staticd, pytest.mark.sharpd]


def build_topo(tgen):
    "Single router. The covering connected route is on a dummy interface."
    tgen.add_router("r1")


def setup_module(mod):
    "Create the dummies and VRFs, then start FRR from the integrated config."
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.net.add_l3vrf("vrf_a", 100)
    r1.net.add_l3vrf("vrf_b", 200)
    r1.run("ip link add dummy5 type dummy")
    r1.run("ip link set dummy5 up")
    # interface IFNAME vrf NAME does not enslave on the l3mdev backend.
    # The connected cover has to be in vrf_b before FRR adds the address.
    r1.run("ip link add dummy_b type dummy")
    r1.net.attach_iface_to_l3vrf("dummy_b", "vrf_b")
    r1.run("ip link set dummy_b up")
    r1.run("ip link add dummy_c type dummy")
    r1.run("ip link set dummy_c up")

    for router in tgen.routers().values():
        router.load_frr_config(extra_daemons=["sharpd"])

    tgen.start_router()


def teardown_module(mod):
    "Stop the topology."
    tgen = get_topogen()
    tgen.stop_topology()


def _expect_json(router, cmd, expected, description):
    test_func = functools.partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "{}:\n{}".format(description, result)


def test_static_nht_self_match():
    """
    NHT for 11.11.0.2 follows the connected /16, clears when dummy5 goes
    down, and is learned again when dummy5 comes back.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    connected = {
        "11.11.0.0/16": [
            {
                "protocol": "connected",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "directlyConnected": True,
                        "interfaceName": "dummy5",
                        "active": True,
                    }
                ],
            }
        ]
    }
    static_up = {
        "11.11.0.0/24": [
            {
                "protocol": "static",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "fib": True,
                        "ip": "11.11.0.2",
                        "afi": "ipv4",
                        "interfaceName": "dummy5",
                        "active": True,
                    }
                ],
            }
        ]
    }
    nht_connected = {
        "default": {
            "ipv4": {
                "11.11.0.2": {
                    "resolutions": [
                        {
                            "clientList": [
                                {
                                    "protocol": "static",
                                    "filtered": False,
                                }
                            ],
                            "resolvedProtocol": "connected",
                            "prefix": "11.11.0.0/16",
                            "nexthops": [
                                {
                                    "directlyConnected": True,
                                    "interfaceName": "dummy5",
                                    "active": True,
                                }
                            ],
                        }
                    ]
                }
            }
        }
    }
    static_gone = {
        "11.11.0.0/24": None,
    }
    connected_gone = {
        "11.11.0.0/16": None,
    }
    nht_unresolved = {
        "default": {
            "ipv4": {
                "11.11.0.2": {
                    "resolutions": [
                        {
                            "unresolved": True,
                            "resolvedProtocol": None,
                            "prefix": None,
                            "clientList": [
                                {
                                    "protocol": "static",
                                }
                            ],
                        }
                    ]
                }
            }
        }
    }

    step("Static 11.11.0.0/24 is installed and NHT uses the connected /16")
    _expect_json(
        r1,
        "show ip route json",
        connected,
        "Connected cover 11.11.0.0/16 is not installed on dummy5",
    )
    _expect_json(
        r1,
        "show ip route 11.11.0.0/24 json",
        static_up,
        "Static 11.11.0.0/24 via 11.11.0.2 is not installed",
    )
    _expect_json(
        r1,
        "show ip nht json",
        nht_connected,
        "11.11.0.2 is not resolved over connected 11.11.0.0/16",
    )

    step("Shut dummy5; NHT must go unresolved and staticd must withdraw the route")
    r1.vtysh_cmd(
        """
        configure terminal
        interface dummy5
         shutdown
        """
    )
    _expect_json(
        r1,
        "show ip route json",
        connected_gone,
        "Connected 11.11.0.0/16 still present after dummy5 shutdown",
    )
    _expect_json(
        r1,
        "show ip nht json",
        nht_unresolved,
        "11.11.0.2 stayed resolved after dummy5 shutdown",
    )
    _expect_json(
        r1,
        "show ip route 11.11.0.0/24 json",
        static_gone,
        "Static 11.11.0.0/24 was left installed after its cover went down",
    )

    step("Bring dummy5 back; NHT and the static route must recover")
    r1.vtysh_cmd(
        """
        configure terminal
        interface dummy5
         no shutdown
        """
    )
    _expect_json(
        r1,
        "show ip route json",
        connected,
        "Connected cover 11.11.0.0/16 did not return",
    )
    _expect_json(
        r1,
        "show ip nht json",
        nht_connected,
        "11.11.0.2 did not resolve over connected 11.11.0.0/16 again",
    )
    _expect_json(
        r1,
        "show ip route 11.11.0.0/24 json",
        static_up,
        "Static 11.11.0.0/24 was not reinstalled",
    )


def test_static_nht_cross_vrf_resolution():
    """
    NHT in vrf_a resolves 12.12.0.2 over static 12.12.0.0/24 even though
    that route's gateway is 12.12.0.2, because the gateway VRF is vrf_b.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    connected_b = {
        "12.12.0.0/16": [
            {
                "protocol": "connected",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "directlyConnected": True,
                        "interfaceName": "dummy_b",
                        "active": True,
                    }
                ],
            }
        ]
    }
    cover_a = {
        "12.12.0.0/24": [
            {
                "protocol": "static",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "fib": True,
                        "ip": "12.12.0.2",
                        "afi": "ipv4",
                        "interfaceName": "dummy_b",
                        "vrf": "vrf_b",
                        "active": True,
                    }
                ],
            }
        ]
    }
    nht_b = {
        "vrf_b": {
            "ipv4": {
                "12.12.0.2": {
                    "resolutions": [
                        {
                            "clientList": [
                                {
                                    "protocol": "static",
                                    "filtered": False,
                                }
                            ],
                            "resolvedProtocol": "connected",
                            "prefix": "12.12.0.0/16",
                            "nexthops": [
                                {
                                    "directlyConnected": True,
                                    "interfaceName": "dummy_b",
                                    "active": True,
                                }
                            ],
                        }
                    ]
                }
            }
        }
    }
    nht_a = {
        "vrf_a": {
            "ipv4": {
                "12.12.0.2": {
                    "resolutions": [
                        {
                            "clientList": [
                                {
                                    "protocol": "static",
                                    "filtered": False,
                                }
                            ],
                            "resolvedProtocol": "static",
                            "prefix": "12.12.0.0/24",
                            "nexthops": [
                                {
                                    "ip": "12.12.0.2",
                                    "vrf": "vrf_b",
                                    "active": True,
                                }
                            ],
                        }
                    ]
                }
            }
        }
    }
    dependent_a = {
        "1.1.1.0/24": [
            {
                "protocol": "static",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "ip": "12.12.0.2",
                        "afi": "ipv4",
                        "active": True,
                    }
                ],
            }
        ]
    }

    step("Cross-VRF cover is installed and NHT in vrf_b uses connected 12.12.0.0/16")
    _expect_json(
        r1,
        "show ip route vrf vrf_b json",
        connected_b,
        "Connected cover 12.12.0.0/16 is not installed on dummy_b",
    )
    _expect_json(
        r1,
        "show ip route vrf vrf_a 12.12.0.0/24 json",
        cover_a,
        "Static 12.12.0.0/24 via 12.12.0.2 nexthop-vrf vrf_b is not installed",
    )
    _expect_json(
        r1,
        "show ip nht vrf vrf_b json",
        nht_b,
        "12.12.0.2 in vrf_b is not resolved over connected 12.12.0.0/16",
    )

    step("NHT in vrf_a must resolve over that cross-VRF static route")
    _expect_json(
        r1,
        "show ip nht vrf vrf_a json",
        nht_a,
        "12.12.0.2 in vrf_a was not resolved over static 12.12.0.0/24",
    )
    _expect_json(
        r1,
        "show ip route vrf vrf_a 1.1.1.0/24 json",
        dependent_a,
        "Static 1.1.1.0/24 via 12.12.0.2 in vrf_a is not installed",
    )


def test_import_check_network_address_gateway():
    """
    Import check 192.168.0.5/24 is masked to 192.168.0.0/24. Its resolution
    is the kernel /24 whose gateway is that network address, not the
    covering connected /16.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    connected = {
        "192.168.0.0/16": [
            {
                "protocol": "connected",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "directlyConnected": True,
                        "interfaceName": "dummy_c",
                        "active": True,
                    }
                ],
            }
        ]
    }
    kernel_route = {
        "192.168.0.0/24": [
            {
                "protocol": "kernel",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "ip": "192.168.0.0",
                        "afi": "ipv4",
                        "interfaceName": "dummy_c",
                        "active": True,
                    }
                ],
            }
        ]
    }
    # show ip nht json keys the registration by address. The /24 import is
    # stored as 192.168.0.0 after apply_mask().
    nht_import = {
        "default": {
            "ipv4": {
                "192.168.0.0": {
                    "resolutions": [
                        {
                            "clientList": [
                                {
                                    "protocol": "sharp",
                                    "filtered": False,
                                }
                            ],
                            "resolvedProtocol": "kernel",
                            "prefix": "192.168.0.0/24",
                            "nexthops": [
                                {
                                    "ip": "192.168.0.0",
                                    "interfaceName": "dummy_c",
                                    "active": True,
                                }
                            ],
                        }
                    ]
                }
            }
        }
    }

    step("Connected 192.168.0.0/16 covers a kernel /24 via its network address")
    _expect_json(
        r1,
        "show ip route json",
        connected,
        "Connected cover 192.168.0.0/16 is not installed on dummy_c",
    )
    r1.run("ip route add 192.168.0.0/24 via 192.168.0.0 dev dummy_c")
    _expect_json(
        r1,
        "show ip route 192.168.0.0/24 json",
        kernel_route,
        "Kernel 192.168.0.0/24 via 192.168.0.0 is not installed",
    )

    step("Import check must resolve over that kernel /24")
    r1.vtysh_cmd("sharp watch import 192.168.0.5/24")
    _expect_json(
        r1,
        "show ip nht json",
        nht_import,
        "Import 192.168.0.5/24 was not resolved over kernel 192.168.0.0/24",
    )


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", "-v", __file__]))
