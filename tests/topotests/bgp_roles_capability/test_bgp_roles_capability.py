#!/usr/bin/python
# SPDX-License-Identifier: ISC
#
# test_bgp_roles_capability.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2022 by Eugene Bogomazov <eb@qrator.net>
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_bgp_roles_capability: test bgp roles negotiation
"""

import json
import os
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.bgpd]


topodef = {f"s{i}": ("r1", f"r{i}") for i in range(2, 7)}


@pytest.fixture(scope="module")
def tgen(request):
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_BGP, "bgpd.conf")
    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def find_neighbor_status(router, neighbor_ip):
    return json.loads(router.vtysh_cmd(f"show bgp neighbors {neighbor_ip} json"))[
        neighbor_ip
    ]


def check_role_mismatch(router, neighbor_ip):
    return is_role_mismatch(find_neighbor_status(router, neighbor_ip))


def is_role_mismatch(neighbor_status):
    return (
        neighbor_status["bgpState"] != "Established"
        and neighbor_status.get("lastErrorCodeSubcode") == "020B"  # <2, 11>
        and "Role Mismatch" in neighbor_status.get("lastNotificationReason", "")
    )


def check_session_established(router, neighbor_ip):
    neighbor_status = find_neighbor_status(router, neighbor_ip)
    return neighbor_status["bgpState"] == "Established"


def test_correct_pair(tgen):
    # provider-customer pair
    router = tgen.gears["r1"]
    neighbor_ip = "192.168.2.2"
    check_r2_established = functools.partial(
        check_session_established, router, neighbor_ip
    )
    success, _ = topotest.run_and_expect(check_r2_established, True, count=20, wait=3)
    assert success, "Session with r2 is not Established"

    neighbor_status = find_neighbor_status(router, neighbor_ip)
    assert neighbor_status["localRole"] == "provider"
    assert neighbor_status["remoteRole"] == "customer"
    assert (
        neighbor_status["neighborCapabilities"].get("role") == "advertisedAndReceived"
    )


def test_role_pair_mismatch(tgen):
    # provider-peer mistmatch
    router = tgen.gears["r3"]
    neighbor_ip = "192.168.3.1"
    check_r3_mismatch = functools.partial(check_role_mismatch, router, neighbor_ip)
    success, _ = topotest.run_and_expect(check_r3_mismatch, True, count=20, wait=3)
    assert success, "Session between r1 and r3 was not correctly closed"


def test_single_role_advertising(tgen):
    # provider-undefined pair; we set role
    router = tgen.gears["r1"]
    neighbor_ip = "192.168.4.2"
    check_r4_established = functools.partial(
        check_session_established, router, neighbor_ip
    )
    success, _ = topotest.run_and_expect(check_r4_established, True, count=20, wait=3)
    assert success, "Session with r4 is not Established"

    neighbor_status = find_neighbor_status(router, neighbor_ip)
    assert neighbor_status["localRole"] == "provider"
    assert neighbor_status["remoteRole"] == "undefined"
    assert neighbor_status["neighborCapabilities"].get("role") == "advertised"


def test_single_role_receiving(tgen):
    # provider-undefined pair; we receive role
    router = tgen.gears["r4"]
    neighbor_ip = "192.168.4.1"
    check_r1_established = functools.partial(
        check_session_established, router, neighbor_ip
    )
    success, _ = topotest.run_and_expect(check_r1_established, True, count=20, wait=3)
    assert success, "Session with r1 is not Established"

    neighbor_status = find_neighbor_status(router, neighbor_ip)
    assert neighbor_status["localRole"] == "undefined"
    assert neighbor_status["remoteRole"] == "provider"
    assert neighbor_status["neighborCapabilities"].get("role") == "received"


def test_role_strict_mode(tgen):
    # provider-undefined pair with strict-mode
    router = tgen.gears["r5"]
    neighbor_ip = "192.168.5.1"
    check_r5_mismatch = functools.partial(check_role_mismatch, router, neighbor_ip)
    success, _ = topotest.run_and_expect(check_r5_mismatch, True, count=20, wait=3)
    assert success, "Session between r1 and r5 was not correctly closed"


def test_correct_pair_peer_group(tgen):
    # provider-customer pair (using peer-groups)
    router = tgen.gears["r1"]
    neighbor_ip = "192.168.6.2"
    check_r6_established = functools.partial(
        check_session_established, router, neighbor_ip
    )
    success, _ = topotest.run_and_expect(check_r6_established, True, count=20, wait=3)
    assert success, "Session with r6 is not Established"

    neighbor_status = find_neighbor_status(router, neighbor_ip)
    assert neighbor_status["localRole"] == "provider"
    assert neighbor_status["remoteRole"] == "customer"
    assert (
        neighbor_status["neighborCapabilities"].get("role") == "advertisedAndReceived"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
