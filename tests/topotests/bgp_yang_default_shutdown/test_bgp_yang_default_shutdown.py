#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test P1-01 (A1-01, B4-23): bgp default shutdown must not shut down neighbors
defined before it in a startup / vtysh -f batch, and must shut down neighbors
created after it.
"""

import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(r1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_default_shutdown_does_not_shut_boot_neighbors():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    summary = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
    peers = summary.get("peers", {})
    assert "192.0.2.2" in peers
    assert not peers["192.0.2.2"].get("adminShutDown", False), (
        "Boot neighbor defined before bgp default shutdown was shut down"
    )
    assert peers["192.0.2.2"].get("state") != "Idle (Admin)"

    run = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.2 shutdown" not in run
    assert "bgp default shutdown" in run


def test_default_shutdown_shuts_new_neighbors():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65001\n"
        "neighbor 192.0.2.3 remote-as 65002\n"
        "exit\n"
    )

    summary = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
    peers = summary.get("peers", {})
    assert "192.0.2.3" in peers
    assert peers["192.0.2.3"].get("state") == "Idle (Admin)", (
        "Neighbor added after bgp default shutdown was not shut down"
    )

    run = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.3 shutdown" in run


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
