#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2026 6WIND S.A.
#

"""
Check the BGP VPN networks of a default instance that was hidden at
deletion, then configured again.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.common_config import retry
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


@retry(retry_timeout=10)
def check_bgp_vpn_network(router, present):
    output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn json"))
    rds = output.get("routes", {}).get("routeDistinguishers", {})
    if present and "10.0.0.1/32" not in rds.get("1:1", {}):
        return "10.0.0.1/32 rd 1:1 not found: {}".format(output)
    if not present and "1:1" in rds:
        return "rd 1:1 still present: {}".format(output)
    return True


def test_bgp_vpn_network_installed():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_bgp_vpn_network(tgen.gears["r1"], True)
    assert result is True, result


def test_bgp_default_instance_hidden_reconfigured():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        """
        configure terminal
         no router bgp 65500
        """
    )
    result = check_bgp_vpn_network(r1, False)
    assert result is True, result

    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65500
          no bgp network import-check
          bgp network import-check
        """
    )
    assert not tgen.routers_have_failure(), tgen.errors


def test_bgp_vpn_network_configured_again():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65500
          address-family ipv4 vpn
           network 10.0.0.1/32 rd 1:1 label 100
        """
    )
    result = check_bgp_vpn_network(r1, True)
    assert result is True, result


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
