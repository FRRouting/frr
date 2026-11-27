#!/usr/bin/env python
# SPDX-License-Identifier: ISC
"""Check EVPN VRF cleanup when Zebra shuts down with other VRFs present."""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib import topotest
from lib.evpn import evpn_verify_vni_state
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

VNI = 100
VTEP_IP = "198.51.100.1"


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.add_router("r1"))


@pytest.fixture
def topology(request):
    if not topotest.platform_has_vrf() or not topotest.platform_has_evpn():
        pytest.skip("VRF and EVPN support are required")

    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()
    request.addfinalizer(tgen.stop_topology)

    r1 = tgen.gears["r1"]
    r1.cmd_raises("ip link add underlay type vrf table 1001")
    r1.cmd_raises("ip link set dev underlay up")
    r1.cmd_raises("ip link set dev r1-eth0 master underlay")
    r1.cmd_raises("ip link set dev r1-eth0 up")

    r1.cmd_raises("ip link add evpn-dummy type dummy")
    r1.cmd_raises(f"ip addr add {VTEP_IP}/32 dev evpn-dummy")
    r1.cmd_raises("ip link set dev evpn-dummy up")
    r1.cmd_raises(
        f"ip link add vxlan{VNI} type vxlan id {VNI} local {VTEP_IP} "
        "dev evpn-dummy dstport 4789 nolearning"
    )
    r1.cmd_raises(f"ip link set dev vxlan{VNI} up")

    r1.load_frr_config(
        os.path.join(CWD, "frr.conf"),
        [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, None)],
    )
    tgen.start_router()
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000 vrf underlay\n"
        " bgp router-id 10.0.0.1\n"
        " no bgp default ipv4-unicast\n"
        " address-family l2vpn evpn\n"
        "  advertise-all-vni\n"
        " exit-address-family\n",
        raises=True,
    )

    _, result = topotest.run_and_expect(
        lambda: evpn_verify_vni_state(r1, [VNI]), None, count=30, wait=1
    )
    assert result is None, result

    yield tgen, r1


def test_shutdown_clears_evpn_vrf_before_other_vrf_interfaces(topology):
    tgen, r1 = topology

    assert not tgen.routers_have_failure(), tgen.errors
    assert r1.vtysh_cmd("show evpn vni 100 json", isjson=True).get("vni") == VNI

    try:
        # Keep BGP connected so it cannot withdraw advertise-all-vni first.
        r1.cmd_raises("kill -TERM $(cat /var/run/frr/zebra.pid)")

        _, stopped = topotest.run_and_expect(
            lambda: not any(name == "zebra" for name, _ in r1.net.listDaemons()),
            True,
            count=30,
            wait=1,
        )
        assert stopped, "Zebra did not stop"

        assert not topotest.checkAddressSanitizerError(
            "", r1.name, "zebra", tgen.logdir
        ), "Zebra shutdown triggered AddressSanitizer"
    finally:
        r1.report_memory_leaks(tgen.modname)
