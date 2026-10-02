#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_auth.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_bgp_auth.py: Test BGP Md5 Authentication

                             +------+
                    +--------|      |--------+
                    | +------|  R1  |------+ |
                    | | -----|      |----+ | |
                    | | |    +------+    | | |
                    | | |                | | |
                   +------+            +------+
                   |      |------------|      |
                   |  R2  |------------|  R3  |
                   |      |------------|      |
                   +------+            +------+


setup is 3 routers with 3 links between each each link in a different vrf
Default, blue and red respectively
Tests check various fiddling with passwords and checking that the peer
establishment is as expected and passwords are not leaked across sockets
for bgp instances
"""
# pylint: disable=C0413

import os
import platform
import sys

import pytest
from lib import topotest
from lib.common_config import (
    create_interface_in_kernel,
    reset_with_new_configs,
    save_initial_config_on_routers,
    shutdown_bringup_interface_in_kernel,
)
from bgp_auth_common import (
    check_vrf_peer_change_passwords,
    check_all_peers_established,
    check_vrf_peer_remove_passwords,
)
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]

CWD = os.path.dirname(os.path.realpath(__file__))


def build_topo(tgen):
    tgen.add_router("R1")
    tgen.add_router("R2")
    tgen.add_router("R3")

    tgen.add_link(tgen.gears["R1"], tgen.gears["R2"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R2"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R2"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R2"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R2"])
    tgen.add_link(tgen.gears["R1"], tgen.gears["R3"])
    tgen.add_link(tgen.gears["R2"], tgen.gears["R3"])


def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    r1 = tgen.gears["R1"]
    r2 = tgen.gears["R2"]
    r3 = tgen.gears["R3"]

    # blue vrf
    r1.cmd_raises("ip link add blue type vrf table 1001")
    shutdown_bringup_interface_in_kernel(r1.tgen, r1.name, "blue", True)
    r2.cmd_raises("ip link add blue type vrf table 1001")
    shutdown_bringup_interface_in_kernel(r2.tgen, r2.name, "blue", True)
    r3.cmd_raises("ip link add blue type vrf table 1001")
    shutdown_bringup_interface_in_kernel(r3.tgen, r3.name, "blue", True)

    create_interface_in_kernel(tgen, "R1", "lo1", vrf="blue")
    create_interface_in_kernel(tgen, "R2", "lo1", vrf="blue")
    create_interface_in_kernel(tgen, "R3", "lo1", vrf="blue")

    r1.cmd_raises("ip link set R1-eth2 master blue")
    r1.cmd_raises("ip link set R1-eth3 master blue")
    r2.cmd_raises("ip link set R2-eth2 master blue")
    r2.cmd_raises("ip link set R2-eth3 master blue")
    r3.cmd_raises("ip link set R3-eth2 master blue")
    r3.cmd_raises("ip link set R3-eth3 master blue")

    shutdown_bringup_interface_in_kernel(r1.tgen, r1.name, "R1-eth2", True)
    shutdown_bringup_interface_in_kernel(r1.tgen, r1.name, "R1-eth3", True)
    shutdown_bringup_interface_in_kernel(r2.tgen, r2.name, "R2-eth2", True)
    shutdown_bringup_interface_in_kernel(r2.tgen, r2.name, "R2-eth3", True)
    shutdown_bringup_interface_in_kernel(r3.tgen, r3.name, "R3-eth2", True)
    shutdown_bringup_interface_in_kernel(r3.tgen, r3.name, "R3-eth3", True)

    # red vrf
    r1.cmd_raises("ip link add red type vrf table 1002")
    shutdown_bringup_interface_in_kernel(r1.tgen, r1.name, "red", True)
    r2.cmd_raises("ip link add red type vrf table 1002")
    shutdown_bringup_interface_in_kernel(r2.tgen, r2.name, "red", True)
    r3.cmd_raises("ip link add red type vrf table 1002")
    shutdown_bringup_interface_in_kernel(r3.tgen, r3.name, "red", True)

    create_interface_in_kernel(tgen, "R1", "lo2", vrf="red")
    create_interface_in_kernel(tgen, "R2", "lo2", vrf="red")
    create_interface_in_kernel(tgen, "R3", "lo2", vrf="red")

    r1.cmd_raises("ip link set R1-eth4 master red")
    r1.cmd_raises("ip link set R1-eth5 master red")
    r2.cmd_raises("ip link set R2-eth4 master red")
    r2.cmd_raises("ip link set R2-eth5 master red")
    r3.cmd_raises("ip link set R3-eth4 master red")
    r3.cmd_raises("ip link set R3-eth5 master red")

    shutdown_bringup_interface_in_kernel(r1.tgen, r1.name, "R1-eth4", True)
    shutdown_bringup_interface_in_kernel(r1.tgen, r1.name, "R1-eth5", True)
    shutdown_bringup_interface_in_kernel(r2.tgen, r2.name, "R2-eth4", True)
    shutdown_bringup_interface_in_kernel(r2.tgen, r2.name, "R2-eth5", True)
    shutdown_bringup_interface_in_kernel(r3.tgen, r3.name, "R3-eth4", True)
    shutdown_bringup_interface_in_kernel(r3.tgen, r3.name, "R3-eth5", True)

    r1.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")
    r2.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")
    r3.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept=1")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for router in router_list.values():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_OSPF, "")
        router.load_config(TopoRouter.RD_BGP, "")

    # After copying the configurations, this function loads configured daemons.
    tgen.start_router()

    # Save the initial router config. reset_config_on_routers will return to this config.
    save_initial_config_on_routers(tgen)


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_prefix_peer_change_passwords(tgen):
    "selecively change passwords checkig state with prefix config"

    # only supported in kernel > 5.3
    if topotest.version_cmp(platform.release(), "5.3") < 0:
        return

    reset_with_new_configs(tgen, "bgpd_prefix.conf", "ospfd.conf")
    check_vrf_peer_change_passwords(prefix="yes")


def test_vrf_peer_established(tgen):
    "default vrf 3 peers same password with VRF config"

    # clean routers and load vrf config
    reset_with_new_configs(tgen, "bgpd_vrf.conf", "ospfd_vrf.conf")
    check_all_peers_established("blue")


def test_vrf_peer_remove_passwords(tgen):
    "selectively remove passwords checking state with VRF config"

    reset_with_new_configs(tgen, "bgpd_vrf.conf", "ospfd_vrf.conf")
    check_vrf_peer_remove_passwords(vrf="blue")


def test_vrf_peer_change_passwords(tgen):
    "selectively change passwords checking state with VRF config"

    reset_with_new_configs(tgen, "bgpd_vrf.conf", "ospfd_vrf.conf")
    check_vrf_peer_change_passwords(vrf="blue")


def test_memory_leak(tgen):
    "Run the memory leak test and report results."
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
