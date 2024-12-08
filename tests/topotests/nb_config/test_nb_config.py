# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# February 24 2024, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2024, LabN Consulting, L.L.C.
#
"""
Test Northbound Config Operations
"""
import json
import os

import pytest
from lib.topogen import Topogen
from lib.topotest import json_cmp

pytestmark = [pytest.mark.mgmtd]

CWD = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

<<<<<<< HEAD
    topodef = {
        "s1": ("r1",)
    }
=======
    topodef = {"s1": ("r1",)}
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
<<<<<<< HEAD
    for rname, router in router_list.items():
=======
    for _, router in router_list.items():
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_access_list_config_ordering(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

<<<<<<< HEAD
    output = r1.vtysh_multicmd([
        "conf t",
        "access-list test seq 1 permit host 10.0.0.1"])
    output = r1.vtysh_cmd("show ip access-list test json")
    got = json.loads(output)
    expected = json.loads('{"ZEBRA":{"test":{"type":"Standard", "addressFamily":"IPv4", "rules":[{"sequenceNumber":1, "filterType":"permit", "address":"10.0.0.1", "mask":"0.0.0.0"}]}}}')
=======
    output = r1.vtysh_multicmd(
        ["conf t", "access-list test seq 1 permit host 10.0.0.1"]
    )
    output = r1.vtysh_cmd("show ip access-list test json")
    got = json.loads(output)
    expected = json.loads(
        '{"zebra":{"test":{"type":"Standard", "addressFamily":"IPv4", "rules":[{"sequenceNumber":1, "filterType":"permit", "address":"10.0.0.1", "mask":"0.0.0.0"}]}}}'
    )
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
    result = json_cmp(got, expected)
    assert result is None

    #
    # If the northbound mis-orders the create/delete then this test fails.
    # https://github.com/FRRouting/frr/pull/15423/commits/38b85e0c2bc555b8827dbd2cb6515b6febf548b4
    #
<<<<<<< HEAD
    output = r1.vtysh_multicmd([
        "conf t",
        "access-list test seq 1 permit 10.0.0.0/8"])
    output = r1.vtysh_cmd("show ip access-list test json")
    got = json.loads(output)
    expected = json.loads('{"ZEBRA":{"test":{"type":"Zebra", "addressFamily":"IPv4", "rules":[{"sequenceNumber":1, "filterType":"permit", "prefix":"10.0.0.0/8", "exact-match":false}]}}}')
=======
    output = r1.vtysh_multicmd(["conf t", "access-list test seq 1 permit 10.0.0.0/8"])
    output = r1.vtysh_cmd("show ip access-list test json")
    got = json.loads(output)
    expected = json.loads(
        '{"zebra":{"test":{"type":"Zebra", "addressFamily":"IPv4", "rules":[{"sequenceNumber":1, "filterType":"permit", "prefix":"10.0.0.0/8", "exact-match":false}]}}}'
    )
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
    result = json_cmp(got, expected)
    assert result is None
