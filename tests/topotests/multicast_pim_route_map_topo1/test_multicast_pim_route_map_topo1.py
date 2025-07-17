#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_pim_route_map_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_multicast_pim_route_map_topo1.py: Test the FRR PIM multicast route map.
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd, pytest.mark.pimd]


def build_topo(tgen):
    """
              +----+     +----+
    dummy <-> | r1 | <-> | r2 |
              +----+     +----+
                           ^
              +----+       |
    dummy <-> | r3 | <-----+
              +----+
    """

    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.gears["r1"].load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.gears["r2"].load_frr_config(os.path.join(CWD, "r2/frr.conf"))
    tgen.gears["r3"].load_frr_config(os.path.join(CWD, "r3/frr.conf"))
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def expect_ospf_routes(router, command, expected):
    tgen = get_topogen()

    test_func = partial(topotest.router_json_cmp, tgen.gears[router], command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f'"{router}" convergence failure'


def test_ospf_convergence():
    "Check for OSPF convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_ospf_routes('r1', 'show ip route ospf json', {
        '10.254.254.2/32': [],
        '192.168.100.0/24': [],
        '192.168.101.0/24': [],
        '192.168.201.0/24': [],
    })
    expect_ospf_routes('r1', 'show ipv6 route ospf6 json', {
        '2001:db8:100::/64': [],
        '2001:db8:101::/64': [],
        '2001:db8:201::/64': [],
        '2001:db8:ffff::2/128': [],
    })

    expect_ospf_routes('r2', 'show ip route ospf json', {
        '192.168.100.0/24': [],
        '192.168.101.0/24': [],
        '192.168.200.0/24': [],
        '192.168.201.0/24': [],
    })
    expect_ospf_routes('r2', 'show ipv6 route ospf6 json', {
        '2001:db8:100::/64': [],
        '2001:db8:101::/64': [],
        '2001:db8:200::/64': [],
        '2001:db8:201::/64': [],
    })

    expect_ospf_routes('r3', 'show ip route ospf json', {
        '10.254.254.2/32': [],
        '192.168.100.0/24': [],
        '192.168.101.0/24': [],
        '192.168.200.0/24': [],
    })
    expect_ospf_routes('r3', 'show ipv6 route ospf6 json', {
        '2001:db8:100::/64': [],
        '2001:db8:101::/64': [],
        '2001:db8:200::/64': [],
        '2001:db8:ffff::2/128': [],
    })


def expect_pim_state(router, interface, source, group, exists=True, expected=None):
    "Check if PIM state exists in router"
    if exists:
        logger.info(f"Waiting for PIM state SG({source}, {group}) in {router} interface {interface}")
        expected = {
            interface: {
                group: {
                    source: {
                        "protocolPim": 1,
                    }
                }
            }
        }
    else:
        logger.info(f"Waiting for PIM state SG({source}, {group}) not in {router} interface {interface}")

    tgen = get_topogen()
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip pim join json",
        expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = f'"{router}" convergence failure'
    assert result is None, assertmsg


def test_pim_route_map():
    "Test PIM route map filtering"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd("""
    configure terminal
    interface r1-eth1
     ip igmp join 225.0.0.1
     ip igmp join 225.0.0.2
     ip igmp join 225.0.0.3
     ip igmp join 225.0.0.100
     ip igmp join 225.0.0.200
     ip igmp join 232.0.1.1 192.168.101.10
     ip igmp join 232.0.1.1 192.168.101.11
    """)

    tgen.gears["r3"].vtysh_cmd("""
    configure terminal
    interface r3-eth1
     ip igmp join 225.0.0.200
    """)

    pim_states = [
        {
            "interface": "r2-eth0",
            "group": "225.0.0.1",
            "source": "*",
            "exists": True,
        },
        {
            "interface": "r2-eth0",
            "group": "225.0.0.2",
            "source": "*",
            "exists": True,
        },
        {
            "interface": "r2-eth0",
            "group": "225.0.0.3",
            "source": "*",
            "exists": False,
            "expected": {
                "r2-eth0": {
                    "225.0.0.3": None
                }
            }
        },
        {
            "interface": "r2-eth0",
            "group": "225.0.0.100",
            "source": "*",
            "exists": True,
        },
        {
            "interface": "r2-eth0",
            "group": "232.0.1.1",
            "source": "192.168.101.10",
            "exists": True,
        },
        {
            "interface": "r2-eth0",
            "group": "232.0.1.1",
            "source": "192.168.101.11",
            "exists": False,
            "expected": {
                "r2-eth0": {
                    "232.0.1.1": {
                        "192.168.101.11": None
                    }
                }
            }
        },
        {
            "interface": "r2-eth0",
            "group": "225.0.0.200",
            "source": "*",
            "exists": False,
            "expected": {
                "r2-eth0": {
                    "225.0.0.200": None
                }
            }
        },
        {
            "interface": "r2-eth1",
            "group": "225.0.0.200",
            "source": "*",
            "exists": True,
        },
    ]
    for state in pim_states:
        expect_pim_state("r2", state["interface"], state["source"], state["group"], state["exists"], state.get("expected"))


def expect_pim6_state(router, interface, source, group, exists=True, expected=None):
    "Check if PIMv6 state exists in router"
    if exists:
        logger.info(f"Waiting for PIMv6 state SG({source}, {group}) in {router} interface {interface}")
        expected = {
            interface: {
                group: {
                    source: {
                        "protocolPim": 1,
                    }
                }
            }
        }
    else:
        logger.info(f"Waiting for PIMv6 state SG({source}, {group}) not in {router} interface {interface}")

    tgen = get_topogen()
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ipv6 pim join json",
        expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=360, wait=1)
    assertmsg = f'"{router}" convergence failure'
    assert result is None, assertmsg


def test_pim6_route_map():
    "Test PIMv6 route map filtering"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd("""
    configure terminal
    interface r1-eth1
     ipv6 mld join ff05::100
     ipv6 mld join ff05::200
     ipv6 mld join ff05::300
     ipv6 mld join ff05::1000
     ipv6 mld join ff05::2000
     ipv6 mld join ff35::100 2001:db8:101::100
     ipv6 mld join ff35::100 2001:db8:101::200
    """)

    tgen.gears["r3"].vtysh_cmd("""
    configure terminal
    interface r3-eth1
     ipv6 mld join ff05::2000
    """)

    pim_states = [
        {
            "interface": "r2-eth0",
            "group": "ff05::100",
            "source": "*",
            "exists": True,
        },
        {
            "interface": "r2-eth0",
            "group": "ff05::200",
            "source": "*",
            "exists": True,
        },
        {
            "interface": "r2-eth0",
            "group": "ff05::300",
            "source": "*",
            "exists": False,
            "expected": {
                "r2-eth0": {
                    "ff05::300": None
                }
            }
        },
        {
            "interface": "r2-eth0",
            "group": "ff05::1000",
            "source": "*",
            "exists": True,
        },
        {
            "interface": "r2-eth0",
            "group": "ff35::100",
            "source": "2001:db8:101::100",
            "exists": True,
        },
        {
            "interface": "r2-eth0",
            "group": "ff35::100",
            "source": "2001:db8:101::200",
            "exists": False,
            "expected": {
                "r2-eth0": {
                    "ff35::100": {
                        "2001:db8:101::200": None
                    }
                }
            }
        },
        {
            "interface": "r2-eth0",
            "group": "ff05::2000",
            "source": "*",
            "exists": False,
            "expected": {
                "r2-eth0": {
                    "ff05::2000": None
                }
            }
        },
        {
            "interface": "r2-eth1",
            "group": "ff05::2000",
            "source": "*",
            "exists": True,
        },
    ]
    for state in pim_states:
        expect_pim6_state("r2", state["interface"], state["source"], state["group"], state["exists"], state.get("expected"))


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
