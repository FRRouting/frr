#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026, Cisco Systems, Inc.
# Nageswara Soma <nsoma@cisco.com>

"""
advertise-subnet has to reach zebra with a VNI it can decode.

Enabling advertise-subnet on a VNI makes bgpd send zebra a
ZEBRA_ADVERTISE_SUBNET carrying that VNI. Zebra looks the EVPN up by it
before turning the knob on, so the two sides have to agree on the width
of the field. When they do not, the lookup misses, zebra drops the
message, and the SVI subnet is never handed back to bgpd as a type-5
route.

The subnet is checked to be absent before the knob is set. That is what
makes the check afterwards a statement about advertise-subnet: the
connected prefix is not redistributed into the VRF's unicast table, so
'advertise ipv4 unicast' cannot originate it, and the peer does not
have advertise-subnet set either.
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

L2VNI = 100
L3VNI = 1000
VTEP_IP = {"r1": "10.100.0.1", "r2": "10.100.0.2"}
PEER_IP = {"r1": "10.0.1.2", "r2": "10.0.1.1"}
SVI_IP = {"r1": "192.168.50.1/24", "r2": "192.168.50.2/24"}
SVI_SUBNET = "192.168.50.0"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # L2VNI 100 on a bridge that doubles as the SVI, so the subnet the
    # test looks for is a connected prefix on it, plus L3VNI 1000 in
    # vrf-blue to give the VRF instance its RD.
    for name in ("r1", "r2"):
        node = tgen.net[name]
        node.cmd_raises("ip link add vrf-blue type vrf table 10")
        node.cmd_raises("ip link set dev vrf-blue up")

        node.cmd_raises(
            "ip link add vxlan%d type vxlan id %d dstport 4789 local %s"
            % (L2VNI, L2VNI, VTEP_IP[name])
        )
        node.cmd_raises("ip link add name br%d type bridge stp_state 0" % L2VNI)
        node.cmd_raises("ip link set dev vxlan%d master br%d" % (L2VNI, L2VNI))
        node.cmd_raises("ip addr add %s dev br%d" % (SVI_IP[name], L2VNI))
        node.cmd_raises("ip link set up dev br%d" % L2VNI)
        node.cmd_raises("ip link set up dev vxlan%d" % L2VNI)
        node.cmd_raises("ip link set dev br%d master vrf-blue" % L2VNI)

        node.cmd_raises(
            "ip link add vxlan%d type vxlan id %d dstport 4789 local %s"
            % (L3VNI, L3VNI, VTEP_IP[name])
        )
        node.cmd_raises("ip link add name br%d type bridge stp_state 0" % L3VNI)
        node.cmd_raises("ip link set dev vxlan%d master br%d" % (L3VNI, L3VNI))
        node.cmd_raises("ip link set up dev br%d" % L3VNI)
        node.cmd_raises("ip link set up dev vxlan%d" % L3VNI)
        node.cmd_raises("ip link set dev br%d master vrf-blue" % L3VNI)

        node.cmd_raises("sysctl -w net.ipv4.ip_forward=1")

    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _evpn_peer_established(router):
    data = router.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
    if not isinstance(data, dict):
        return "show bgp l2vpn evpn summary json returned %r" % (data,)
    peer = data.get("peers", {}).get(PEER_IP[router.name], {})
    if peer.get("state") != "Established":
        return "peer %s state %s" % (PEER_IP[router.name], peer.get("state"))
    return None


def _bgp_knows_vnis(router, vnis):
    """bgpd learns its VNIs from zebra, so this gates on the zapi session."""
    data = router.vtysh_cmd("show bgp l2vpn evpn vni json", isjson=True)
    if not isinstance(data, dict):
        return "show bgp l2vpn evpn vni json returned %r" % (data,)
    missing = [vni for vni in vnis if str(vni) not in data]
    if missing:
        return "bgpd is missing VNIs %s, has %s" % (
            missing,
            sorted(key for key in data if key.isdigit()),
        )
    return None


def _subnet_prefix(router, subnet):
    """The type-5 route covering subnet, or None if there is not one."""
    data = router.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)
    if not isinstance(data, dict):
        return None
    for routes in data.values():
        if not isinstance(routes, dict):
            continue
        for prefix in routes:
            if subnet in prefix:
                return prefix
    return None


def _has_subnet_prefix(router, subnet):
    if _subnet_prefix(router, subnet) is None:
        return "no type-5 route for %s" % subnet
    return None


def test_advertise_subnet_originates_type5_route():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    _, result = topotest.run_and_expect(
        lambda: _evpn_peer_established(router), None, count=40, wait=2
    )
    assert result is None, "EVPN session is not up on r1: %s" % result

    # Also waits out the zapi exchange, which advertise-subnet needs to
    # be up before it is set: bgp_zebra_advertise_subnet() drops the
    # message when the session is not ready and never re-sends it.
    _, result = topotest.run_and_expect(
        lambda: _bgp_knows_vnis(router, (L2VNI, L3VNI)), None, count=40, wait=2
    )
    assert result is None, "VNIs were not learned: %s" % result

    found = _subnet_prefix(router, SVI_SUBNET)
    assert found is None, "%s is already advertised as %s" % (SVI_SUBNET, found)

    logger.info("Enabling advertise-subnet on VNI %d", L2VNI)
    router.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          address-family l2vpn evpn
           vni %d
            advertise-subnet
        """
        % L2VNI
    )

    _, result = topotest.run_and_expect(
        lambda: _has_subnet_prefix(router, SVI_SUBNET), None, count=40, wait=2
    )
    assert result is None, "the SVI subnet was not originated: %s" % result
