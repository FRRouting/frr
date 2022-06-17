#!/usr/bin/python
#
# test_bgp_roles_capability.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2022 by Eugene Bogomazov <eb@qrator.net>
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp_roles_capability: test bgp roles negotiation
"""

import json
import os
import sys
import functools
import pytest
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


topodef = {f"s{i}": ("r1", f"r{i}") for i in range(2, 6)}


@pytest.fixture(scope="module")
def tgen(request):
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_BGP, "bgpd.conf")
    tgen.start_router()
    time.sleep(1)
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def is_role_mismatch(neighbor_status):
    return (
        neighbor_status["bgpState"] != "Established"
        and neighbor_status.get("lastErrorCodeSubcode") == "020B"  # <2, 11>
        and "Role Mismatch" in neighbor_status.get("lastNotificationReason", "")
    )


def test_correct_pair(tgen):
    # provider-customer pair
    neighbor_ip = "192.168.2.2"
    neighbor_status = json.loads(
        tgen.gears["r1"].vtysh_cmd(f"show bgp neighbors {neighbor_ip} json")
    )[neighbor_ip]
    assert neighbor_status["localRole"] == "provider"
    assert neighbor_status["neighRole"] == "customer"
    assert neighbor_status["bgpState"] == "Established"
    assert (
        neighbor_status["neighborCapabilities"].get("role") == "advertisedAndReceived"
    )


def test_role_pair_mismatch(tgen):
    # provider-peer mistmatch
    neighbor_ip = "192.168.3.2"
    neighbor_status = json.loads(
        tgen.gears["r1"].vtysh_cmd(f"show bgp neighbors {neighbor_ip} json")
    )[neighbor_ip]
    assert is_role_mismatch(neighbor_status)


def test_single_role_advertising(tgen):
    # provider-undefine pair; we set role
    neighbor_ip = "192.168.4.2"
    neighbor_status = json.loads(
        tgen.gears["r1"].vtysh_cmd(f"show bgp neighbors {neighbor_ip} json")
    )[neighbor_ip]
    assert neighbor_status["localRole"] == "provider"
    assert neighbor_status["neighRole"] == "undefine"
    assert neighbor_status["bgpState"] == "Established"
    assert neighbor_status["neighborCapabilities"].get("role") == "advertised"


def test_single_role_receiving(tgen):
    # provider-undefine pair; we receive role
    neighbor_ip = "192.168.4.1"
    neighbor_status = json.loads(
        tgen.gears["r4"].vtysh_cmd(f"show bgp neighbors {neighbor_ip} json")
    )[neighbor_ip]
    assert neighbor_status["localRole"] == "undefine"
    assert neighbor_status["neighRole"] == "provider"
    assert neighbor_status["bgpState"] == "Established"
    assert neighbor_status["neighborCapabilities"].get("role") == "received"


def test_role_strict_mode(tgen):
    # provider-undefine pair bur strict-mode was set
    neighbor_ip = "192.168.5.2"
    neighbor_status = json.loads(
        tgen.gears["r1"].vtysh_cmd(f"show bgp neighbors {neighbor_ip} json")
    )
    assert is_role_mismatch(neighbor_status[neighbor_ip])


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
