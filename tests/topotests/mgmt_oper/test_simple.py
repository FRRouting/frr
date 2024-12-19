#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
# noqa: E501
#
"""
Test static route functionality
"""
import pytest
from lib.topogen import Topogen
from oper import check_kernel_32, do_oper_test

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
        router.net.add_loop("lo-red")
        router.net.attach_iface_to_l3vrf("lo-red", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth1", "red")
        router.load_frr_config("frr-simple.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_oper_simple(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    query_results = [
        (
            # Non-key query with key specific selection
            '/frr-interface:lib/interface[name="r1-eth0"]/vrf',
            "simple-results/result-intf-eth0-vrf.json",
        ),
        # Test machines will have different sets of interfaces so the test results will
        # vary and need to be generated dynamically before this test is re-enabled
        # (
        #     # Key query on generic list
        #     "/frr-interface:lib/interface/name",
        #     "simple-results/result-intf-name.json",
        # ),
        (
            # Key query with key specific selection
            '/frr-interface:lib/interface[name="r1-eth0"]/name',
            "simple-results/result-intf-eth0-name.json",
        ),
        ("/frr-vrf:lib", "simple-results/result-lib.json"),
        ("/frr-vrf:lib/vrf", "simple-results/result-lib-vrf-nokey.json"),
        (
            '/frr-vrf:lib/vrf[name="default"]',
            "simple-results/result-lib-vrf-default.json",
        ),
        ('/frr-vrf:lib/vrf[name="red"]', "simple-results/result-lib-vrf-red.json"),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra',
            "simple-results/result-lib-vrf-zebra.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs',
            "simple-results/result-lib-vrf-zebra-ribs.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib',
            "simple-results/result-ribs-rib-nokeys.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]',
            "simple-results/result-ribs-rib-ipv4-unicast.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route',
            "simple-results/result-ribs-rib-route-nokey.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.1.0/24"]',
            "simple-results/result-ribs-rib-route-prefix.json",
        ),
        # Missing entry
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.0.0/24"]',
            "simple-results/result-empty.json",
        ),
        # Leaf reference
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
            'route[prefix="1.1.1.0/24"]/route-entry[protocol="connected"]/metric',
            "simple-results/result-singleton-metric.json",
        ),
        (
            '/frr-interface:lib/interface[name="r1-eth0"]',
            "simple-results/result-intf-eth0-with-config.json",
            "with-config",
        ),
        (
            '/frr-interface:lib/interface[name="r1-eth0"]',
            "simple-results/result-intf-eth0-only-config.json",
            "only-config",
        ),
        (
            "/frr-interface:lib/interface/description",
            "simple-results/result-intf-description.json",
            "with-config",
        ),
        (
            '/frr-interface:lib/interface[name="r1-eth0"]',
            "simple-results/result-intf-eth0-exact.json",
            "exact",
        ),
        (
            '/frr-interface:lib/interface[name="r1-eth0"]/description',
            "simple-results/result-intf-eth0-description-exact.json",
            "with-config exact",
        ),
        # Interface state
        (
            '/frr-interface:lib/interface[name="r1-eth0"]/state',
            "simple-results/result-intf-state.json",
        ),
        (
            '/frr-interface:lib/interface[name="r1-eth0"]/state/mtu',
            "simple-results/result-intf-state-mtu.json",
        ),
        # with-defaults
        (
            '/frr-interface:lib/interface[name="r1-eth0"]/frr-zebra:zebra/evpn-mh',
            "simple-results/result-intf-eth0-wd-explicit.json",
            "with-config exact",
        ),
        (
            '/frr-interface:lib/interface[name="r1-eth0"]/frr-zebra:zebra/evpn-mh',
            "simple-results/result-intf-eth0-wd-trim.json",
            "with-config exact with-defaults trim",
        ),
        (
            '/frr-interface:lib/interface[name="r1-eth0"]/frr-zebra:zebra/evpn-mh',
            "simple-results/result-intf-eth0-wd-all.json",
            "with-config exact with-defaults all",
        ),
        (
            '/frr-interface:lib/interface[name="r1-eth0"]/frr-zebra:zebra/evpn-mh',
            "simple-results/result-intf-eth0-wd-all-tag.json",
            "with-config exact with-defaults all-tag",
        ),
    ]

    r1 = tgen.gears["r1"].net
    check_kernel_32(r1, "11.11.11.11", 1, "")
    do_oper_test(tgen, query_results)


to_gen_new_results = """
scriptdir=~chopps/w/frr/tests/topotests/mgmt_oper
resdir=${scriptdir}/simple-results
vtysh -c 'show mgmt get-data /frr-vrf:lib'      > ${resdir}/result-lib.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf'  > ${resdir}/result-lib-vrf-nokey.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]'  > ${resdir}/result-lib-vrf-default.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="red"]'      > ${resdir}/result-lib-vrf-red.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra'          > ${resdir}/result-lib-vrf-zebra.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs'     > ${resdir}/result-lib-vrf-zebra-ribs.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib' > ${resdir}/result-ribs-rib-nokeys.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]' > ${resdir}/result-ribs-rib-ipv4-unicast.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route' > ${resdir}/result-ribs-rib-route-nokey.json

vtysh -c 'show mgmt get-data /frr-interface:lib/interface[name="r1-eth0"]/state' > ${resdir}/result-intf-state.json
vtysh -c 'show mgmt get-data /frr-interface:lib/interface[name="r1-eth0"]/state/mtu' > ${resdir}/result-intf-state-mtu.json

for f in ${resdir}/result-*; do
   sed -i -e 's/"uptime": ".*"/"uptime": "rubout"/;s/"id": [0-9][0-9]*/"id": "rubout"/' $f
   sed -i -e 's/"phy-address": ".*"/"phy-address": "rubout"/' $f
   sed -i -e 's/"if-index": [0-9][0-9]*/"if-index": "rubout"/' $f
   sed -i -e 's,"vrf": "[0-9]*","vrf": "rubout",' $f
done
"""  # noqa: 501

# Example commands:
# show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route[prefix="1.1.0.0/24"] # noqa: E501
# show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route[prefix="1.1.1.0/24"] # noqa: E501
