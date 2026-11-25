#!/usr/bin/env python
# SPDX-License-Identifier: ISC
"""Deleting an EVPN owner must clean Zebra without disconnecting bgpd."""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib import topotest
from lib.common_config import (
    configure_interface_mac,
    create_address_on_interface,
    kill_router_daemons,
    shutdown_bringup_interface_in_kernel,
    start_router_daemons,
)
from lib.evpn import check_mac_in_fdb, evpn_verify_bgp_vni_state, evpn_zebra_mac_entry
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]
REMOTE_MAC = "02:00:00:00:02:02"
REMOTE_VTEP = "10.0.0.2"


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in ("r1", "r2"):
        switch.add_link(tgen.add_router(name))


def wait_for(check):
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, result


def configure_bgp(router, index, vrf_owner, vpn):
    peer = f"10.0.0.{3 - index}"
    owner = " vrf underlay" if vrf_owner else ""
    config = (
        "configure terminal\n"
        f"router bgp 65000{owner}\n"
        f" bgp router-id 10.0.0.{index}\n"
        " no bgp default ipv4-unicast\n"
        " no bgp network import-check\n"
        f" neighbor {peer} remote-as 65000\n"
        f" neighbor {peer} timers connect 1\n"
        " address-family l2vpn evpn\n"
        f"  neighbor {peer} activate\n"
        "  advertise-all-vni\n"
        "  advertise-svi-ip\n"
        " exit-address-family\n"
    )
    if vpn:
        config += f" address-family ipv4 vpn\n  neighbor {peer} activate\n"
        if index == 2:
            config += "  network 198.51.100.0/24 rd 65000:1 label 100\n"
    router.vtysh_cmd(config, raises=True)


@pytest.fixture
def topology(request):
    if not topotest.platform_has_vrf() or not topotest.platform_has_evpn():
        pytest.skip("VRF and EVPN support are required")
    vrf_owner, vpn = request.param
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()
    request.addfinalizer(tgen.stop_topology)
    for index, (name, router) in enumerate(tgen.routers().items(), 1):
        if vrf_owner:
            router.cmd_raises("ip link add underlay type vrf table 1001")
            shutdown_bringup_interface_in_kernel(tgen, name, "underlay", True)
            router.cmd_raises(f"ip link set {name}-eth0 master underlay")
        shutdown_bringup_interface_in_kernel(tgen, name, f"{name}-eth0", True)
        router.cmd_raises("ip link add br100 type bridge")
        assert (
            configure_interface_mac(
                tgen, {name: {"br100": f"02:00:00:00:0{index}:0{index}"}}
            )
            is True
        )
        create_address_on_interface(tgen, name, "br100", f"10.100.0.{index}/24")
        shutdown_bringup_interface_in_kernel(tgen, name, "br100", True)
        router.cmd_raises(
            f"ip link add vxlan100 type vxlan id 100 local 10.0.0.{index} "
            f"dev {name}-eth0 dstport 4789 nolearning"
        )
        router.cmd_raises("ip link set vxlan100 master br100")
        shutdown_bringup_interface_in_kernel(tgen, name, "vxlan100", True)
        router.load_frr_config(
            os.path.join(CWD, "frr.conf"),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, None)],
        )
    tgen.start_router()
    for index, router in enumerate(tgen.routers().values(), 1):
        owner = " vrf underlay" if vrf_owner else ""
        router.vtysh_cmd(
            "configure terminal\n"
            f"hostname {router.name}\n"
            f"interface {router.name}-eth0{owner}\n"
            f" ip address 10.0.0.{index}/24\n",
            raises=True,
        )
        configure_bgp(router, index, vrf_owner, vpn)
    yield tgen, vrf_owner, vpn


def installed(router):
    mac = evpn_zebra_mac_entry(router, 100, REMOTE_MAC)
    vni = router.vtysh_cmd("show evpn vni 100 json", isjson=True)
    if not mac or mac.get("type") != "remote":
        return f"Remote MAC not installed: {mac}; VNI: {vni}"
    if not any(vtep.get("ip") == REMOTE_VTEP for vtep in vni.get("remoteVteps", [])):
        return f"Remote VTEP not installed: {vni}"
    if not check_mac_in_fdb(router, REMOTE_MAC, "br100", "vxlan100", 0):
        return "Remote MAC not programmed in the kernel FDB"
    return None


def removed(router):
    mac = evpn_zebra_mac_entry(router, 100, REMOTE_MAC)
    vni = router.vtysh_cmd("show evpn vni 100 json", isjson=True)
    if mac or vni.get("remoteVteps"):
        return f"Stale Zebra EVPN state: mac={mac}, vni={vni}"
    # The existing self-FDB helper requires src_vni, which is absent for
    # traditional one-device-per-VNI VXLAN. Check MAC and flood entries.
    fdb = json.loads(router.run("bridge -j fdb show"))
    stale = [
        row
        for row in fdb
        if row.get("mac") == REMOTE_MAC or row.get("dst") == REMOTE_VTEP
    ]
    return f"Stale kernel FDB entries: {stale}" if stale else None


def async_bgp_clients(router):
    clients = router.vtysh_cmd("show zebra client json", isjson=True).get("bgp", [])
    return [client for client in clients if client["asynchronous"]]


def bgp_client(router):
    return [
        (client["fileDescriptor"], client["sessionId"])
        for client in async_bgp_clients(router)
    ]


def bgp_registered(router):
    clients = async_bgp_clients(router)
    if len(clients) != 1 or not clients[0]["connected"]["add"]:
        return "BGP has not registered for interfaces after the Zebra restart"
    return None


@pytest.mark.parametrize(
    "topology",
    [(False, False), (False, True), (True, False)],
    ids=("default", "default-hidden", "vrf"),
    indirect=True,
)
def test_evpn_instance_delete(topology):
    tgen, vrf_owner, vpn = topology
    assert not tgen.routers_have_failure(), tgen.errors
    r1 = tgen.gears["r1"]
    try:
        wait_for(lambda: installed(r1))
        if vpn:
            wait_for(
                lambda: None
                if r1.vtysh_cmd("show bgp ipv4 vpn json", isjson=True).get(
                    "totalRoutes", 0
                )
                else "VPN RIB is empty"
            )
        client = bgp_client(r1)
        assert len(client) == 1, client
        owner = " vrf underlay" if vrf_owner else ""
        r1.vtysh_cmd(f"configure terminal\nno router bgp 65000{owner}")
        assert "router bgp 65000" not in r1.vtysh_cmd("show running-config")
        routers = r1.vtysh_cmd("show bgp router json", isjson=True)
        assert routers.get("bgpInstanceCount") == int(vpn), routers
        assert (
            bgp_client(r1) == client
        ), "BGP's Zebra client changed during instance deletion"
        wait_for(lambda: removed(r1))
        assert bgp_client(r1) == client
        if vpn:
            error = kill_router_daemons(tgen, r1.name, ["zebra"])
            assert not error, error
            error = start_router_daemons(tgen, r1.name, ["zebra"])
            assert not error, error
            wait_for(lambda: bgp_registered(r1))
            evpn = r1.vtysh_cmd(
                "show evpn json", daemon="zebra", isjson=True, raises=True
            )
            assert not evpn, evpn

            configure_bgp(r1, 1, vrf_owner, vpn)
            wait_for(
                lambda: evpn_verify_bgp_vni_state(
                    r1, [100], expected_fields={"inKernel": "True"}
                )
            )
            wait_for(lambda: installed(r1))
            assert not tgen.routers_have_failure(), tgen.errors
    finally:
        tgen.report_memory_leaks()
