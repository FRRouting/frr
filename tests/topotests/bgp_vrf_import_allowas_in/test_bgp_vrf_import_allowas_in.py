#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2026 6WIND
#

"""
Check that a VPN route with the AS of the target VRF in its AS path is
imported only with "allowas-in vpn import", up to the number of occurrences
set by "allowas-in vpn import count".

ce2 (AS 65100) --- r2 VRF-A (AS 65300) --> r2 (AS 65300)
                                                | eBGP VPNv4
                   r1 VRF-B (AS 65100) <-- r1 (AS 65200)

ce2 advertises 10.0.0.1/32, 10.0.0.3/32 and 10.0.0.4/32: their AS paths on
r1 contain the AS of VRF-B 1, 3 and 4 times. r2 VRF-A originates 10.0.0.2/32.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

CE2_AS_PATHS = {
    "10.0.0.1/32": "65300 65100",
    "10.0.0.3/32": "65300 65100 65100 65100",
    "10.0.0.4/32": "65300 65100 65100 65100 65100",
}


def build_topo(tgen):
    for rname in ["r1", "r2", "ce2"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["ce2"])


def setup_module(mod):
    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.run("ip link add VRF-B type vrf table 1002")
    r1.run("ip link set VRF-B up")

    r2 = tgen.gears["r2"]
    r2.run("ip link add VRF-A type vrf table 1001")
    r2.run("ip link set VRF-A up")
    r2.run("ip link set r2-eth1 master VRF-A")

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_vpn_route(prefix):
    def _check_vpn_route():
        r1 = get_topogen().gears["r1"]
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 vpn json"))
        expected = {
            "routes": {"routeDistinguishers": {"100:1": {prefix: [{"valid": True}]}}}
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_check_vpn_route, None, count=30, wait=1)
    assert result is None, "VPN {}: route not received".format(prefix)


def check_vrf_b_route(prefix, paths):
    def _check_vrf_b_route():
        r1 = get_topogen().gears["r1"]
        output = json.loads(
            r1.vtysh_cmd("show bgp vrf VRF-B ipv4 unicast {} json".format(prefix))
        )
        return topotest.json_cmp(output, {"paths": paths})

    _, result = topotest.run_and_expect(_check_vrf_b_route, None, count=30, wait=1)
    assert result is None, "VRF-B {}: unexpected route".format(prefix)


def configure_vrf_b(command):
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure
        router bgp 65100 vrf VRF-B
         address-family ipv4 unicast
          {}
        """.format(
            command
        )
    )


def test_bgp_vrf_import_loop_blocked():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for prefix in CE2_AS_PATHS:
        check_vpn_route(prefix)
        check_vrf_b_route(prefix, None)
    check_vrf_b_route("10.0.0.2/32", [{"valid": True}])


def test_bgp_vrf_import_allowas_in():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def check_vrf_b_imports(imported):
        for prefix, aspath in CE2_AS_PATHS.items():
            if prefix in imported:
                paths = [{"aspath": {"string": aspath}, "valid": True}]
            else:
                paths = None
            check_vrf_b_route(prefix, paths)

    def check_vrf_b_config(line, present=True):
        output = tgen.gears["r1"].vtysh_cmd("show running-config bgpd")
        lines = [config_line.strip() for config_line in output.splitlines()]
        assert (line in lines) == present, output

    try:
        # the count alone does not enable allowas-in
        configure_vrf_b("allowas-in vpn import count 1")
        check_vrf_b_config("allowas-in vpn import count 1")
        check_vrf_b_config("allowas-in vpn import", present=False)
        check_vrf_b_imports([])

        configure_vrf_b("allowas-in vpn import")
        check_vrf_b_config("allowas-in vpn import")
        check_vrf_b_imports(["10.0.0.1/32"])

        configure_vrf_b("allowas-in vpn import count 3")
        check_vrf_b_imports(["10.0.0.1/32", "10.0.0.3/32"])

        configure_vrf_b("allowas-in vpn import count 2")
        check_vrf_b_config("allowas-in vpn import count 2")
        check_vrf_b_imports(["10.0.0.1/32"])

        # 3 occurrences by default
        configure_vrf_b("no allowas-in vpn import count")
        check_vrf_b_config("allowas-in vpn import count 2", present=False)
        check_vrf_b_imports(["10.0.0.1/32", "10.0.0.3/32"])

        # the count is kept when allowas-in is disabled
        configure_vrf_b("allowas-in vpn import count 1")
        configure_vrf_b("no allowas-in vpn import")
        check_vrf_b_config("allowas-in vpn import", present=False)
        check_vrf_b_config("allowas-in vpn import count 1")
        check_vrf_b_imports([])
    finally:
        configure_vrf_b("no allowas-in vpn import")
        configure_vrf_b("no allowas-in vpn import count")

    check_vrf_b_imports([])
    check_vrf_b_route("10.0.0.2/32", [{"valid": True}])


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
