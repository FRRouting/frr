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
Test various query types
"""
import json
import logging

import pytest
from lib.common_config import step
from lib.topogen import Topogen
from oper import check_kernel_32

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
    """This test is useful for doing manual testing"""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    query_results = [
        # Non-key specific query with function filtering selector
        '/frr-interface:lib/interface[contains(name,"eth")]/vrf',
        # Non-key specific query with child value filtering selector
        '/frr-interface:lib/interface[vrf="red"]/vrf',
        '/frr-interface:lib/interface[./vrf="red"]/vrf',
        # Container query with function filtering selector
        '/frr-interface:lib/interface[contains(name,"eth")]/state',
        # Multi list elemenet with function filtering selector
        '/frr-interface:lib/interface[contains(name,"eth")]',
        #
        # Specific list entry after non-specific lists
        '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
        'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
        'route/route-entry[protocol="connected"]',
        # crashes: All specific until the end, then walk
        '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
        'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
        'route[prefix="1.1.1.0/24"]/route-entry[protocol="connected"]',
        # Does nothing: Root level query
        "//metric",
        # specific leaf after non-specific lists
        '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
        'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
        "route/route-entry/metric",
        # All specific until the end generic.
        '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
        'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
        'route[prefix="1.1.1.0/24"]/route-entry',
        # All specific until the penultimate generic with a specific leaf child.
        '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
        'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/'
        'route[prefix="1.1.1.0/24"]/route-entry/metric',
        # All generic until the end (middle) specific with unspecified
        # children below to walk.
        '/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route[prefix="1.1.1.0/24"]',
        # All generic until the end which is a specific leaf.
        "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/metric",
    ]
    # query_results = [
    #     '/frr-interface:lib/frr-interface:interface/frr-zebra:zebra/ip-addrs[frr-rt:address-family="frr-rt:ipv4"][prefix="1.1.1.1/24"]'
    # ]

    r1 = tgen.gears["r1"].net
    check_kernel_32(r1, "11.11.11.11", 1, "")

    step("Oper test start", reset=True)

    for qr in query_results:
        step(f"Perform query '{qr}'")
        try:
            output = r1.cmd_nostatus(f"vtysh -c 'show mgmt get-data {qr}'")
        except Exception as error:
            logging.error("Error sending query: %s: %s", qr, error)
            continue

        try:
            ojson = json.loads(output)
            logging.info("'%s': generates:\n%s", qr, ojson)
        except json.decoder.JSONDecodeError as error:
            logging.error("Error decoding json: %s\noutput:\n%s", error, output)
