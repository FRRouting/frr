#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Proxmox Server Solutions GmbH
#                    Gabriel Goller
#

"""Test IPv4 unnumbered IS-IS on a three-router broadcast LAN.

All three routers share one switch, with no point-to-point circuits and no
IPv4 addresses on their LAN interfaces. IS-IS must borrow loopback addresses,
elect a DIS, and install usable onlink nexthops for both peers on the same
interface.
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.checkping import check_ping
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    """Connect r1, r2, and r3 to a single broadcast domain."""
    switch = tgen.add_switch("s1")
    for index in range(1, 4):
        router = tgen.add_router("r{}".format(index))
        switch.add_link(router, nodeif="r{}-eth0".format(index))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def loopback_address(rname):
    return "10.254.0.{}".format(rname[1:])


def check_router_json(router, command, expected):
    """Wait for asynchronous adjacency/SPF/RIB updates."""
    compare = functools.partial(topotest.router_json_cmp, router, command, expected)
    _, diff = topotest.run_and_expect(compare, None, count=120, wait=0.5)
    assert diff is None, "{}: {} mismatch:\n{}".format(router.name, command, diff)


def test_isis_lan_adjacencies():
    """Both peers must be Up on one unnumbered LAN, with r1 as DIS."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        interface = "{}-eth0".format(rname)
        addresses = json.loads(
            router.cmd("ip -json address show dev {}".format(interface))
        )
        ipv4 = [a for a in addresses[0]["addr_info"] if a["family"] == "inet"]
        assert ipv4 == [], "{} is not unnumbered".format(interface)

        expected = {
            "areas": [
                {
                    "area": "1",
                    "circuits": [
                        {
                            "interface": {
                                "name": interface,
                                "state": "Up",
                                "type": "lan",
                                "levels": [
                                    {
                                        "level": "L2",
                                        "active-neighbors": 2,
                                        "lan": {
                                            "is-dis": "yes" if rname == "r1" else "no"
                                        },
                                    }
                                ],
                            }
                        }
                    ],
                }
            ]
        }
        check_router_json(router, "show isis interface detail json", expected)

        # Query each peer separately: the broadcast neighbor JSON otherwise
        # reports multiple adjacencies in the same circuit object.
        for peer in tgen.routers():
            if peer == rname:
                continue
            expected = {
                "areas": [
                    {
                        "area": "1",
                        "circuits": [
                            {
                                "adj": peer,
                                "interface": {"name": interface, "state": "Up"},
                                "level": 2,
                            }
                        ],
                    }
                ]
            }
            check_router_json(
                router, "show isis neighbor {} json".format(peer), expected
            )


def test_isis_routes():
    """Install distinct peer loopback nexthops on the same LAN interface."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        expected = {}
        expected_linux = []
        for peer in tgen.routers():
            if peer == rname:
                continue
            address = loopback_address(peer)
            prefix = "{}/32".format(address)
            expected[prefix] = [
                {
                    "protocol": "isis",
                    "selected": True,
                    "nexthops": [
                        {
                            "ip": address,
                            "interfaceName": "{}-eth0".format(rname),
                            "active": True,
                            "fib": True,
                        }
                    ],
                }
            ]
            expected_linux.append(
                {
                    "dst": address,
                    "gateway": address,
                    "dev": "{}-eth0".format(rname),
                    "protocol": "isis",
                    "flags": ["onlink"],
                }
            )

        check_router_json(router, "show ip route json", expected)

        def compare_linux_routes():
            routes = json.loads(router.cmd("ip -json route"))
            # Kernels with nexthop objects may nest a single nexthop.
            normalized = []
            for route in routes:
                nexthops = route.get("nexthops", [])
                if len(nexthops) == 1:
                    route = {**route, **nexthops[0]}
                    del route["nexthops"]
                normalized.append(route)
            return topotest.json_cmp(normalized, expected_linux)

        _, diff = topotest.run_and_expect(compare_linux_routes, None, count=30, wait=1)
        assert diff is None, "{}: kernel routes mismatch:\n{}".format(rname, diff)


def test_isis_forwarding():
    """Verify bidirectional forwarding to both peers using borrowed addresses."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in tgen.routers():
        for peer in tgen.routers():
            if peer == rname:
                continue
            address = loopback_address(peer)
            source = loopback_address(rname)
            check_ping(rname, address, True, count=10, wait=1, source_addr=source)


def test_isis_numbered_transition():
    """Refresh ONLINK in both directions without changing the peer nexthops."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]
    peers = ["r2", "r3"]
    expected = {
        "{}/32".format(loopback_address(peer)): [
            {
                "protocol": "isis",
                "selected": True,
                "nexthops": [
                    {
                        "ip": loopback_address(peer),
                        "interfaceName": "r1-eth0",
                        "active": True,
                        "fib": True,
                    }
                ],
            }
        ]
        for peer in peers
    }
    check_router_json(router, "show ip route json", expected)

    # Number only r1: r2/r3 keep advertising the same loopback nexthops.
    # A connected prefix covering those gateways makes them reachable without
    # ONLINK; one that does not cover them must keep ONLINK.
    steps = [
        ("10.254.0.254/24", True, False),
        ("10.254.0.254/24", False, True),
        ("192.0.2.1/24", True, True),
        ("192.0.2.1/24", False, True),
    ]
    for address, add, onlink in steps:
        router.vtysh_cmd(
            "configure terminal\ninterface r1-eth0\n{}ip address {}".format(
                "" if add else "no ", address
            )
        )
        expected_linux = [
            {
                "dst": loopback_address(peer),
                "gateway": loopback_address(peer),
                "dev": "r1-eth0",
                "protocol": "isis",
                "onlink": onlink,
            }
            for peer in peers
        ]

        def compare_linux_routes():
            routes = json.loads(router.cmd("ip -json route"))
            normalized = []
            for route in routes:
                nexthops = route.get("nexthops", [])
                if len(nexthops) == 1:
                    route = {**route, **nexthops[0]}
                    del route["nexthops"]
                # Compare a boolean so absence of ONLINK is checked as well.
                route["onlink"] = "onlink" in route.get("flags", [])
                normalized.append(route)
            return topotest.json_cmp(normalized, expected_linux)

        _, diff = topotest.run_and_expect(compare_linux_routes, None, count=30, wait=1)
        assert diff is None, "{} {}: kernel routes mismatch:\n{}".format(
            "add" if add else "del", address, diff
        )
        check_router_json(router, "show ip route json", expected)
        for peer in peers:
            check_ping(
                "r1",
                loopback_address(peer),
                True,
                count=10,
                wait=1,
                source_addr=loopback_address("r1"),
            )


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
