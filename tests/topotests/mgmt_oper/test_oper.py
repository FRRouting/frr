#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
"""
Test static route functionality
"""

import ipaddress
import math
import time

import pytest
from lib.topogen import Topogen
from oper import check_kernel_32, do_oper_test

try:
    from deepdiff import DeepDiff as dd_json_cmp
except ImportError:
    dd_json_cmp = None

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",), "s2": ("r1",), "s3": ("r1",), "s4": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Setup VRF red
        router.net.add_l3vrf("red", 10)
        router.net.add_loop("lo-red")
        router.net.attach_iface_to_l3vrf("lo-red", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth2", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth3", "red")
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def get_ip_networks(super_prefix, count):
    count_log2 = math.log(count, 2)
    if count_log2 != int(count_log2):
        count_log2 = int(count_log2) + 1
    else:
        count_log2 = int(count_log2)
    network = ipaddress.ip_network(super_prefix)
    return tuple(network.subnets(count_log2))[0:count]


def test_oper(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    query_results = [
        ("/frr-vrf:lib", "oper-results/result-lib.json"),
        ("/frr-vrf:lib/vrf", "oper-results/result-lib-vrf-nokey.json"),
        (
            '/frr-vrf:lib/vrf[name="default"]',
            "oper-results/result-lib-vrf-default.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra',
            "oper-results/result-lib-vrf-zebra.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs',
            "oper-results/result-lib-vrf-zebra-ribs.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib',
            "oper-results/result-ribs-rib-nokeys.json",
        ),
        (
            '/frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/'
            'rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]',
            "oper-results/result-ribs-rib-ipv4-unicast.json",
        ),
    ]

    r1 = tgen.gears["r1"].net
    check_kernel_32(r1, "11.11.11.11", 1, "")
    check_kernel_32(r1, "12.12.12.12", 1, "")
    check_kernel_32(r1, "13.13.13.13", 1, "red")
    check_kernel_32(r1, "14.14.14.14", 1, "red")
    do_oper_test(tgen, query_results)


to_gen_new_results = """
scriptdir=~chopps/w/frr/tests/topotests/mgmt_oper
resdir=${scriptdir}/oper-results
vtysh -c 'show mgmt get-data /frr-vrf:lib'      > ${resdir}/result-lib.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf'  > ${resdir}/result-lib-vrf-nokey.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]'  > ${resdir}/result-lib-vrf-default.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="red"]'      > ${resdir}/result-lib-vrf-red.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra'          > ${resdir}/result-lib-vrf-zebra.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs'     > ${resdir}/result-lib-vrf-zebra-ribs.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib' > ${resdir}/result-ribs-rib-nokeys.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]' > ${resdir}/result-ribs-rib-ipv4-unicast.json
vtysh -c 'show mgmt get-data /frr-vrf:lib/vrf[name="default"]/frr-zebra:zebra/ribs/rib[afi-safi-name="frr-routing:ipv4-unicast"][table-id="254"]/route' > ${resdir}/result-ribs-rib-route-nokey.json

for f in ${resdir}/result-*; do
   sed -i -e 's/"uptime": ".*"/"uptime": "rubout"/;s/"id": [0-9][0-9]*/"id": "rubout"/' $f
   sed -i -e 's/"if-index": [0-9][0-9]*/"if-index": "rubout"/' $f
   sed -i -e 's,"vrf": "[0-9]*","vrf": "rubout",' $f
done
"""  # noqa: 501
# should not differ
# diff result-lib.json result-lib-vrf-nokey.json
# diff result-lib-vrf-zebra.json result-lib-vrf-zebra-ribs.json
