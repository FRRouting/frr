#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
<<<<<<< HEAD
# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if peer-group works for numbered and unnumbered configurations.
=======
# Copyright (c) 2021-2024 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if various random settings with peer-group works for
numbered and unnumbered configurations.
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
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
<<<<<<< HEAD
from lib.topogen import Topogen, TopoRouter, get_topogen

=======
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
<<<<<<< HEAD
    for routern in range(1, 4):
=======
    for routern in range(1, 5):
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

<<<<<<< HEAD
=======
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

<<<<<<< HEAD
    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
=======
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_peer_group():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_peer_group_configured():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show ip bgp neighbor json"))
        expected = {
<<<<<<< HEAD
            "r1-eth0": {"peerGroup": "PG", "bgpState": "Established"},
            "192.168.255.3": {"peerGroup": "PG", "bgpState": "Established"},
=======
            "r1-eth0": {
                "peerGroup": "PG",
                "bgpState": "Established",
                "neighborCapabilities": {"gracefulRestart": "advertisedAndReceived"},
            },
            "192.168.255.3": {
                "peerGroup": "PG",
                "bgpState": "Established",
                "neighborCapabilities": {"gracefulRestart": "advertisedAndReceived"},
            },
            "192.168.251.2": {
                "peerGroup": "PG1",
                "bgpState": "Established",
                "neighborCapabilities": {"gracefulRestart": "received"},
            },
            "192.168.252.2": {
                "peerGroup": "PG2",
                "bgpState": "Established",
                "neighborCapabilities": {"gracefulRestart": "advertisedAndReceived"},
            },
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_configured)
<<<<<<< HEAD
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
=======
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    assert result is None, "Failed bgp convergence in r1"

    def _bgp_peer_group_check_advertised_routes():
        output = json.loads(
            tgen.gears["r3"].vtysh_cmd("show ip bgp neighbor PG advertised-routes json")
        )
        expected = {
            "advertisedRoutes": {
                "192.168.255.0/24": {
                    "valid": True,
                    "best": True,
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_check_advertised_routes)
<<<<<<< HEAD
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed checking advertised routes from r3"


=======
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed checking advertised routes from r3"


def test_show_running_remote_as_peer_group():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = (
        tgen.gears["r1"]
        .cmd(
            'vtysh -c "show running bgpd" | grep "^ neighbor 192.168.252.2 remote-as 65004"'
        )
        .rstrip()
    )
    assert (
        output == " neighbor 192.168.252.2 remote-as 65004"
    ), "192.168.252.2 remote-as is flushed"


def test_bgp_peer_group_remote_as_del_readd():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    logger.info("Remove bgp peer-group PG1 remote-as neighbor should be retained")
    r1.cmd(
        'vtysh -c "config t" -c "router bgp 65001" '
        + ' -c "no neighbor PG1 remote-as external" '
    )

    def _bgp_peer_group_remoteas_del():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.251.2": {"peerGroup": "PG1", "bgpState": "Active"},
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_remoteas_del)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed bgp convergence in r1"

    logger.info("Re-add bgp peer-group PG1 remote-as neighbor should be established")
    r1.cmd(
        'vtysh -c "config t" -c "router bgp 65001" '
        + ' -c "neighbor PG1 remote-as external" '
    )

    def _bgp_peer_group_remoteas_add():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.251.2": {"peerGroup": "PG1", "bgpState": "Established"},
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_remoteas_add)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed bgp convergence in r1"


>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
