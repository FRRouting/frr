#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""

"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("pe1")
    tgen.add_router("rr1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["ce1"])
    switch.add_link(tgen.gears["pe1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["ce2"])
    switch.add_link(tgen.gears["pe1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["pe1"])
    switch.add_link(tgen.gears["rr1"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["pe1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["pe1"]
    rr1 = tgen.gears["rr1"]

    pe1.run("ip link add Customer type vrf table 1001")
    pe1.run("ip link set up dev Customer")
    pe1.run("ip link set pe1-eth0 master Customer")
    pe1.run("ip link add Service type vrf table 1002")
    pe1.run("ip link set up dev Service")
    pe1.run("ip link set pe1-eth1 master Service")
    pe1.run("ip link set pe1-eth3 master Customer")
    pe1.run("sysctl -w net.mpls.conf.pe1-eth2.input=1")
    rr1.run("sysctl -w net.mpls.conf.rr1-eth0.input=1")

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_LDP, os.path.join(CWD, "{}/ldpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_accept_own():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["pe1"]
    ce2 = tgen.gears["ce2"]

    step("Check if routes are not installed in PE1 from RR1 (due to ORIGINATOR_ID)")

    def _bgp_check_received_routes_due_originator_id():
        output = json.loads(pe1.vtysh_cmd("show bgp ipv4 vpn summary json"))
        expected = {"peers": {"10.10.10.101": {"pfxRcd": 0, "pfxSnt": 5}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_routes_due_originator_id)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Failed, received routes from RR1 regardless ORIGINATOR_ID"

    step("Enable ACCEPT_OWN for RR1")

    pe1.vtysh_cmd(
        """
    configure terminal
    router bgp 65001
     address-family ipv4 vpn
      neighbor 10.10.10.101 accept-own
    """
    )

    step("Check if we received routes due to ACCEPT_OWN from RR1")

    def _bgp_check_received_routes_with_modified_rts():
        output = json.loads(pe1.vtysh_cmd("show bgp ipv4 vpn summary json"))
        expected = {"peers": {"10.10.10.101": {"pfxRcd": 5, "pfxSnt": 5}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_routes_with_modified_rts)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "Failed, didn't receive routes from RR1 with ACCEPT_OWN enabled"

    step(
        "Check if 172.16.255.1/32 is imported into vrf Service due to modified RT list at RR1"
    )

    def _bgp_check_received_routes_with_changed_rts():
        output = json.loads(
            pe1.vtysh_cmd("show bgp vrf Service ipv4 unicast 172.16.255.1/32 json")
        )
        expected = {
            "paths": [
                {
                    "community": {"string": "65001:111"},
                    "extendedCommunity": {
                        "string": "RT:192.168.1.2:2 RT:192.168.2.2:2"
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_routes_with_changed_rts)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "Failed, routes are not imported from RR1 with modified RT list"

    step("Check if 192.0.2.0/24 is imported to vrf Service from vrf Customer")

    def _bgp_check_imported_local_routes_from_vrf_service():
        output = json.loads(
            pe1.vtysh_cmd("show ip route vrf Service 192.0.2.0/24 json")
        )
        expected = {
            "192.0.2.0/24": [
                {
                    "vrfName": "Service",
                    "table": 1002,
                    "installed": True,
                    "selected": True,
                    "nexthops": [
                        {
                            "fib": True,
                            "vrf": "Customer",
                            "active": True,
                        }
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_imported_local_routes_from_vrf_service)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "Failed, didn't import local route 192.0.2.0/24 from vrf Customer to vrf Service"

    step("Check if 172.16.255.1/32 is announced to CE2")

    def _bgp_check_received_routes_from_pe():
        output = json.loads(ce2.vtysh_cmd("show ip route 172.16.255.1/32 json"))
        expected = {
            "172.16.255.1/32": [
                {
                    "protocol": "bgp",
                    "installed": True,
                    "nexthops": [{"ip": "192.168.2.2"}],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_routes_from_pe)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Failed, didn't receive 172.16.255.1/32 from PE1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
