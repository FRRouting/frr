#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Verify that a shared remote RMAC is reprogrammed when one VTEP changes it."""

import os
import platform
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

VTEP_A_IP = "10.0.0.10"
VTEP_B_IP = "10.0.0.11"
OBSERVER_IP = "10.0.0.12"
SHARED_RMAC = "44:38:39:42:42:01"
UPDATED_RMAC = "44:38:39:42:42:02"


def build_topo(tgen):
    for name in ("rr", "vtep_a", "vtep_b", "observer"):
        tgen.add_router(name)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rr"], nodeif="eth-rr")
    for name in ("vtep_a", "vtep_b", "observer"):
        switch.add_link(tgen.gears[name], nodeif="eth-rr")


def _configure_l3vni(router, local_ip, rmac):
    router.cmd_raises(
        """
ip link add vrf-101 type vrf table 101
ip link set dev vrf-101 up
ip link add loop101 type dummy
ip link set dev loop101 master vrf-101
ip link set dev loop101 up
ip link add bridge-101 type bridge stp_state 0
ip link set dev bridge-101 address {rmac}
ip link set dev bridge-101 master vrf-101
ip link set dev bridge-101 up
ip link add vxlan-101 type vxlan id 101 dstport 4789 dev eth-rr local {local_ip}
ip link set dev vxlan-101 master bridge-101
ip link set dev vxlan-101 up type bridge_slave learning off flood off mcast_flood off
""".format(rmac=rmac, local_ip=local_ip)
    )


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    if topotest.version_cmp(platform.release(), "4.18") < 0:
        tgen.stop_topology()
        pytest.skip("BGP EVPN L3VNI tests require kernel 4.18 or newer")

    for name, local_ip, rmac in (
        ("vtep_a", VTEP_A_IP, SHARED_RMAC),
        ("vtep_b", VTEP_B_IP, SHARED_RMAC),
        ("observer", OBSERVER_IP, "44:38:39:42:42:03"),
    ):
        _configure_l3vni(tgen.net[name], local_ip, rmac)

    for name, router in tgen.routers().items():
        logger.info("Loading router %s", name)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(name)))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _fdb_destinations(router, rmac):
    output = router.run("bridge fdb show")
    logger.info("%s bridge FDB:\n%s", router.name, output)
    destinations = []
    for line in output.splitlines():
        if rmac.lower() not in line.lower():
            continue
        match = re.search(r"\bdst\s+(\S+)", line)
        if match:
            destinations.append(match.group(1))
    return destinations


def _wait_for_fdb_destination(router, rmac, vtep_ip):
    check = lambda: (
        None
        if _fdb_destinations(router, rmac) == [vtep_ip]
        else "FDB entry not updated"
    )
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "{} on {} is not programmed to {}".format(
        rmac, router.name, vtep_ip
    )


def test_shared_rmac_fdb_moves_to_surviving_vtep():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    observer = tgen.gears["observer"]
    vtep_b = tgen.gears["vtep_b"]

    _wait_for_fdb_destination(observer, SHARED_RMAC, VTEP_A_IP)

    vtep_b.vtysh_cmd(
        """configure terminal
router bgp 65000 vrf vrf-101
address-family ipv4 unicast
network 10.0.101.2/32
end
"""
    )
    _wait_for_fdb_destination(observer, SHARED_RMAC, VTEP_B_IP)

    vtep_b.run("ip link set dev bridge-101 address {}".format(UPDATED_RMAC))

    _wait_for_fdb_destination(observer, SHARED_RMAC, VTEP_A_IP)
    _wait_for_fdb_destination(observer, UPDATED_RMAC, VTEP_B_IP)
