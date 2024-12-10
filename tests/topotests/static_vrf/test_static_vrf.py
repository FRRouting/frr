#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2024 NFWare Inc.
#
# noqa: E501
#
"""
Test static route functionality
"""

import ipaddress

import pytest
from lib.topogen import Topogen
from lib.common_config import retry

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",), "s2": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Setup VRF red
        router.net.add_l3vrf("red", 10)
        router.net.attach_iface_to_l3vrf(rname + "-eth0", "red")
        # Setup VRF blue
        router.net.add_l3vrf("blue", 20)
        router.net.attach_iface_to_l3vrf(rname + "-eth1", "blue")
        # Load configuration
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@retry(retry_timeout=1, initial_wait=0.1)
def check_kernel(r1, prefix, nexthops, vrf, expected_p=True, expected_nh=True):
    vrfstr = f" vrf {vrf}" if vrf else ""

    net = ipaddress.ip_network(prefix)
    if net.version == 6:
        kernel = r1.run(f"ip -6 route show{vrfstr} {prefix}")
    else:
        kernel = r1.run(f"ip -4 route show{vrfstr} {prefix}")

    if expected_p:
        assert prefix in kernel, f"Failed to find \n'{prefix}'\n in \n'{kernel:.1920}'"
    else:
        assert (
            prefix not in kernel
        ), f"Failed found \n'{prefix}'\n in \n'{kernel:.1920}'"

    if not expected_p:
        return

    for nh in nexthops:
        if expected_nh:
            assert f"{nh}" in kernel, f"Failed to find \n'{nh}'\n in \n'{kernel:.1920}'"
        else:
            assert (
                f"{nh}" not in kernel
            ), f"Failed found \n'{nh}'\n in \n'{kernel:.1920}'"


def test_static_vrf(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Check initial configuration
    check_kernel(r1, "198.51.100.1", ["192.0.2.2", "192.0.2.130"], None)
    check_kernel(r1, "198.51.100.2", ["r1-eth0", "r1-eth1"], None)
    check_kernel(r1, "203.0.113.1", ["192.0.2.130"], "red")
    check_kernel(r1, "203.0.113.2", ["r1-eth1"], "red")
    check_kernel(r1, "203.0.113.129", ["192.0.2.2"], "blue")
    check_kernel(r1, "203.0.113.130", ["r1-eth0"], "blue")

    # Delete VRF red
    r1.net.del_iface("red")

    # Check that "red" nexthops are removed, "blue" nexthops are still there
    check_kernel(r1, "198.51.100.1", ["192.0.2.2"], None, expected_nh=False)
    check_kernel(r1, "198.51.100.1", ["192.0.2.130"], None)
    check_kernel(r1, "198.51.100.2", ["r1-eth0"], None, expected_nh=False)
    check_kernel(r1, "198.51.100.2", ["r1-eth1"], None)
    check_kernel(r1, "203.0.113.129", ["192.0.2.2"], "blue", expected_p=False)
    check_kernel(r1, "203.0.113.130", ["r1-eth0"], "blue", expected_p=False)

    # Delete VRF blue
    r1.net.del_iface("blue")

    # Check that "blue" nexthops are removed
    check_kernel(r1, "198.51.100.1", ["192.0.2.130"], None, expected_p=False)
    check_kernel(r1, "198.51.100.2", ["r1-eth1"], None, expected_p=False)

    # Add VRF red back, attach "eth0" to it
    r1.net.add_l3vrf("red", 10)
    r1.net.attach_iface_to_l3vrf("r1-eth0", "red")

    # Check that "red" nexthops are restored
    check_kernel(r1, "198.51.100.1", ["192.0.2.2"], None)
    check_kernel(r1, "198.51.100.2", ["r1-eth0"], None)

    # Add VRF blue back, attach "eth1" to it
    r1.net.add_l3vrf("blue", 20)
    r1.net.attach_iface_to_l3vrf("r1-eth1", "blue")

    # Check that everything is restored
    check_kernel(r1, "198.51.100.1", ["192.0.2.2", "192.0.2.130"], None)
    check_kernel(r1, "198.51.100.2", ["r1-eth0", "r1-eth1"], None)
    check_kernel(r1, "203.0.113.1", ["192.0.2.130"], "red")
    check_kernel(r1, "203.0.113.2", ["r1-eth1"], "red")
    check_kernel(r1, "203.0.113.129", ["192.0.2.2"], "blue")
    check_kernel(r1, "203.0.113.130", ["r1-eth0"], "blue")
