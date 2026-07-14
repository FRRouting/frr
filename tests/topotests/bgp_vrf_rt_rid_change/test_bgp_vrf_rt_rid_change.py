#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Verify that a configured VPN export RT survives a BGP router-ID change."""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

PREFIX = "198.51.100.1/32"


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.cmd_raises("ip link add RED type vrf table 10")
    router.cmd_raises("ip link set RED up")
    router.cmd_raises("ip link add BLUE type vrf table 20")
    router.cmd_raises("ip link set BLUE up")
    router.load_frr_config()
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _check_blue_route(router):
    expected = {"routes": {PREFIX: [{"nhVrfName": "RED"}]}}
    return topotest.router_json_cmp(
        router, "show bgp vrf BLUE ipv4 unicast json", expected
    )


def test_export_rt_survives_router_id_change():
    """Changing the router ID must not derive the export RT from the RD."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    step("Verify BLUE imports RED's route using RT 65000:100")
    test_func = partial(_check_blue_route, router)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert success, f"Route was not imported before the router-ID change: {result}"

    step("Change RED's explicitly configured BGP router ID")
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65000 vrf RED
          bgp router-id 192.168.2.10
        """
    )

    step("Verify the configured export RT and imported route are preserved")
    running_config = router.vtysh_cmd("show running-config")
    assert "  rt vpn both 65000:100\n" in running_config, running_config

    success, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert success, f"Route disappeared after the router-ID change: {result}"


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
