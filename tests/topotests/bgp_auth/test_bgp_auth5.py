#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 by
# NVIDIA CORPORATION ("NVIDIA"). All rights reserved.
#
#

"""
test_bgp_auth5.py: Test BGP Md5 Authentication - VRF Prefix Peers Order

Topology:
    +------------------+     +------------------+
    |       r1         |     |       r2         |
    |              blue|-----|blue              |
    |                  |     |                  |
    |   default vrf    |     |                  |
    +------------------+     +------------------+
           |
           |
    +------------------+
    |   default vrf    |
    |                  |
    |       r3         |
    +------------------+

"""
# pylint: disable=C0413
import os
import platform
import sys

import pytest
from lib import common_config, topotest
from lib.common_config import (
    step,
)
from bgp_auth_common import check_neigh_state
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))


def build_topo(tgen):
    tgen.add_router("R1")
    tgen.add_router("R2")
    tgen.add_router("R3")

    tgen.add_link(tgen.gears["R1"], tgen.gears["R2"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R3"])


def setup_module(mod):
    """Sets up the pytest environment"""
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    # blue vrf
    r1.cmd_raises("ip link add blue type vrf table 1001")
    r1.cmd_raises("ip link set up dev blue")
    r2.cmd_raises("ip link add blue type vrf table 1001")
    r2.cmd_raises("ip link set up dev blue")

    r1.cmd_raises("ip link set R1-eth0 master blue")
    r2.cmd_raises("ip link set R2-eth0 master blue")

    r1.cmd_raises("ip link set up dev  R1-eth0")
    r2.cmd_raises("ip link set up dev  R2-eth0")

    r1.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")
    r2.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")
    r3.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr_dynamic_peers_vrf.conf".format(rname))
        )

    # After copying the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def verify_peer_states(r1, r2, r3, expected_states):
    """Verify BGP peer states across all routers and VRFs"""
    for router, peer_ip, state, vrf in expected_states:
        check_neigh_state(router, peer_ip, state, vrf)


def test_bgp_dynamic_peer_establish_vrf_order(tgen):
    """

    Test steps:
    1. Configure bgp listen range on R1 in blue VRF
    2. Configure R2(blue) and R3(default) to establish bgp session with R1
    3. Verify session between R1 and R2 is established
    4. Configure bgp listen range on R1 in default VRF
    5. Verify session (blue, R1, R2) and (default, R1, R3) is established
    """

    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    # Step 2: Verify peers are established in VRF blue
    step("Verify peers are established in VRF blue")
    bgp_peer_states = [
        # R2 peer states,
        (r2, "192.168.1.1", "Established", "blue"),
        # R1 peer states
        (r1, "192.168.1.2", "Established", "blue"),
    ]
    verify_peer_states(r1, r2, r3, bgp_peer_states)

    # Step 3: Configure peers in default VRF
    step("Configure peers in default vrf")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
        bgp router-id 10.0.1.1
        neighbor fabric_pg1 peer-group
        neighbor fabric_pg1 remote-as internal
        neighbor fabric_pg1 bfd 3 300 300
        neighbor fabric_pg1 password default123
        neighbor fabric_pg1 advertisement-interval 0
        neighbor fabric_pg1 timers 1 3
        neighbor fabric_pg1 timers connect 3
        neighbor fabric_pg1 capability extended-nexthop
        bgp listen limit 500
        bgp listen range 192.168.2.0/24 peer-group fabric_pg1
    """
    )

    # Step 4: Verify peers are established in all VRFs
    step("Verify peers are established in all VRFs")
    bgp_peer_states = [
        # R2 peer states,
        (r2, "192.168.1.1", "Established", "blue"),
        # R3 peer states
        (r3, "192.168.2.1", "Established", "default"),
        # R1 peer states
        (r1, "192.168.1.2", "Established", "blue"),
        (r1, "192.168.2.2", "Established", "default"),
    ]
    verify_peer_states(r1, r2, r3, bgp_peer_states)


def test_memory_leak(tgen):
    """Run the memory leak test and report results."""
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
