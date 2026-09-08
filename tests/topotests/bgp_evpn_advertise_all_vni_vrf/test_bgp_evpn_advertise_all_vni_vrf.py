#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Maxim Lotka
#

"""
Functional regression test for advertise-all-vni in a non-default
EVPN underlay VRF.

Topology::

    host1                                                  host2
192.168.100.1/24                                    192.168.100.2/24
      |                                                    |
   pe1-eth0                                             pe2-eth0
      |                                                    |
    br100                                                br100
      |                                                    |
  vxlan100 ========================================== vxlan100
      |                  L2VNI 100                         |
      |                                                    |
   pe1-eth1                                             pe2-eth1
 10.0.0.1/30                                          10.0.0.2/30
      +-------------- VRF "underlay" ----------------------+

Each PE also has a default BGP instance with EVPN disabled.

The EVPN BGP instance lives in VRF "underlay" and owns
advertise-all-vni.  This is the configuration that used to be rejected
solely because the default BGP instance existed.

The test verifies:

* default BGP and EVPN in the non-default VRF coexist;
* Zebra sees the connected non-default underlay;
* the two VTEPs are reachable through the underlay VRF;
* the EVPN BGP session establishes inside the underlay VRF;
* VNI 100 learns the remote VTEP;
* real host-to-host traffic crosses VXLAN;
* the remote host MAC is programmed in the VXLAN FDB;
* advertise-all-vni is still rejected in another BGP instance while
  EVPN is actually enabled in the underlay VRF.
"""

import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import required_linux_kernel_version
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

UNDERLAY_VRF = "underlay"
UNDERLAY_TABLE = 1001
UNDERLAY_AS = 65000

VNI = 100
BRIDGE = "br100"
VXLAN = "vxlan100"

PE_CONFIG = {
    "pe1": {
        "underlay_if": "pe1-eth1",
        "access_if": "pe1-eth0",
        "vtep_ip": "10.0.0.1",
        "vtep_prefix": "10.0.0.1/30",
        "peer_ip": "10.0.0.2",
    },
    "pe2": {
        "underlay_if": "pe2-eth1",
        "access_if": "pe2-eth0",
        "vtep_ip": "10.0.0.2",
        "vtep_prefix": "10.0.0.2/30",
        "peer_ip": "10.0.0.1",
    },
}

HOST_CONFIG = {
    "host1": {
        "ifname": "host1-eth0",
        "ip": "192.168.100.1/24",
        "peer_ip": "192.168.100.2",
        "mac": "02:00:00:00:01:01",
    },
    "host2": {
        "ifname": "host2-eth0",
        "ip": "192.168.100.2/24",
        "peer_ip": "192.168.100.1",
        "mac": "02:00:00:00:02:02",
    },
}


def build_topo(tgen):
    """Build two PEs, two access hosts and one shared underlay segment."""
    for name in ("pe1", "pe2", "host1", "host2"):
        tgen.add_router(name)

    access1 = tgen.add_switch("s-access1")
    access1.add_link(tgen.gears["host1"], nodeif="host1-eth0")
    access1.add_link(tgen.gears["pe1"], nodeif="pe1-eth0")

    underlay = tgen.add_switch("s-underlay")
    underlay.add_link(tgen.gears["pe1"], nodeif="pe1-eth1")
    underlay.add_link(tgen.gears["pe2"], nodeif="pe2-eth1")

    access2 = tgen.add_switch("s-access2")
    access2.add_link(tgen.gears["pe2"], nodeif="pe2-eth0")
    access2.add_link(tgen.gears["host2"], nodeif="host2-eth0")


def _prepare_underlay_linux(pe, config):
    """
    Create the Linux VRF before FRR starts.

    The IP address is configured by FRR from frr.conf so Zebra owns and
    observes the exact connected route used by BGP nexthop tracking.
    """
    underlay_if = config["underlay_if"]

    pe.run("sysctl -q -w net.ipv4.conf.all.rp_filter=0")
    pe.run("sysctl -q -w net.ipv4.conf.default.rp_filter=0")
    pe.run("sysctl -q -w net.ipv4.tcp_l3mdev_accept=0")

    pe.run(f"ip link add {UNDERLAY_VRF} type vrf table {UNDERLAY_TABLE}")
    pe.run(f"ip link set dev {UNDERLAY_VRF} up")

    pe.run(f"ip link set dev {underlay_if} master {UNDERLAY_VRF}")
    pe.run(f"ip link set dev {underlay_if} up")


def _setup_overlay_linux(pe, config):
    """Create a traditional one-device-per-VNI VXLAN bridge."""
    access_if = config["access_if"]
    underlay_if = config["underlay_if"]
    vtep_ip = config["vtep_ip"]

    pe.run(f"ip link add name {BRIDGE} type bridge stp_state 0")
    pe.run(f"ip link set dev {BRIDGE} up")

    pe.run(f"ip link set dev {access_if} master {BRIDGE}")
    pe.run(f"ip link set dev {access_if} up")

    pe.run(
        f"ip link add {VXLAN} type vxlan id {VNI} "
        f"local {vtep_ip} dev {underlay_if} "
        "dstport 4789 nolearning"
    )
    pe.run(f"ip link set dev {VXLAN} master {BRIDGE}")
    pe.run(f"bridge link set dev {VXLAN} learning off")
    pe.run(f"ip link set dev {VXLAN} up")


def _setup_host(host, config):
    ifname = config["ifname"]

    host.run(f"ip link set dev {ifname} down")
    host.run(f"ip addr flush dev {ifname}")
    host.run(f"ip link set dev {ifname} address {config['mac']}")
    host.run(f"ip addr add {config['ip']} dev {ifname}")
    host.run(f"ip link set dev {ifname} up")


def _disable_advertise_all_vni(pe):
    """Release the EVPN underlay owner before daemon shutdown."""
    pe.vtysh_cmd(
        "configure terminal\n"
        f"router bgp {UNDERLAY_AS} vrf {UNDERLAY_VRF}\n"
        " address-family l2vpn evpn\n"
        "  no advertise-all-vni\n"
        " exit-address-family\n"
        "exit\n"
    )


def _kernel_address_present(pe, ifname, address):
    output = pe.run(f"ip -4 -o addr show dev {ifname}")
    return address in output


def _wait_for_underlay_address(pe, config):
    """Wait until FRR/Zebra has installed the VTEP/underlay address."""
    success, _ = topotest.run_and_expect(
        lambda: _kernel_address_present(pe, config["underlay_if"], config["vtep_ip"]),
        True,
        count=20,
        wait=1,
    )

    if not success:
        running = pe.vtysh_cmd("show running-config")
        addresses = pe.run("ip -br -4 addr")
        raise RuntimeError(
            f"FRR did not install {config['vtep_prefix']} on "
            f"{config['underlay_if']}\n\n"
            f"=== running-config ===\n{running}\n"
            f"=== addresses ===\n{addresses}\n"
        )


def setup_module(mod):
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Linux kernel >= 5.15 is required")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The Linux VRF must exist before Zebra/bgpd start.
    for name, config in PE_CONFIG.items():
        _prepare_underlay_linux(tgen.gears[name], config)

    for name in PE_CONFIG:
        tgen.gears[name].load_frr_config(os.path.join(CWD, name, "frr.conf"))

    tgen.start_router()

    # VXLAN requires the local VTEP address to exist first.
    for name, config in PE_CONFIG.items():
        _wait_for_underlay_address(tgen.gears[name], config)

    for name, config in PE_CONFIG.items():
        _setup_overlay_linux(tgen.gears[name], config)

    for name, config in HOST_CONFIG.items():
        _setup_host(tgen.gears[name], config)


def teardown_module(mod):
    tgen = get_topogen()

    # Keep Linux VRF/VXLAN objects alive until FRR daemons have stopped.
    # Topogen removes the namespaces and interfaces afterwards.
    for name in PE_CONFIG:
        if name not in tgen.gears:
            continue

        try:
            _disable_advertise_all_vni(tgen.gears[name])
        except Exception:  # pylint: disable=W0718
            logger.exception("Failed to disable EVPN on %s", name)

    time.sleep(1)
    tgen.stop_topology()


def _routers_have_failure():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    return tgen


def _ping_succeeds(node, command):
    output = node.run(command)
    return "0% packet loss" in output


def _bgp_established(router, peer):
    output = router.vtysh_cmd(f"show bgp vrf {UNDERLAY_VRF} neighbors {peer}")
    return "BGP state = Established" in output


def _extract_vni_data(output):
    """Accept both direct and VNI-keyed JSON shapes used by show evpn vni."""
    if not isinstance(output, dict):
        return None

    if output.get("vni") in (VNI, str(VNI)):
        return output

    keyed = output.get(str(VNI))
    if isinstance(keyed, dict):
        return keyed

    vnis = output.get("vnis")
    if isinstance(vnis, list):
        for item in vnis:
            if not isinstance(item, dict):
                continue
            if item.get("vni") in (VNI, str(VNI)):
                return item

    return None


def _vni_has_remote_vtep(router, remote_vtep):
    output = router.vtysh_cmd(f"show evpn vni {VNI} json", isjson=True)
    data = _extract_vni_data(output)

    if data is None:
        return False

    remote_vteps = data.get("remoteVteps", [])

    for item in remote_vteps:
        if isinstance(item, str) and item == remote_vtep:
            return True

        if isinstance(item, dict):
            value = item.get("ip") or item.get("vtep") or item.get("remoteVtep")
            if value == remote_vtep:
                return True

    return False


def _remote_mac_in_fdb(router, mac, remote_vtep):
    output = router.run(f"bridge fdb show dev {VXLAN}")

    for line in output.splitlines():
        if mac.lower() not in line.lower():
            continue
        if f"dst {remote_vtep}" not in line:
            continue
        return True

    return False


def _diagnose_bgp_failure(pe, name, config):
    peer = config["peer_ip"]

    neighbor = pe.vtysh_cmd(f"show bgp vrf {UNDERLAY_VRF} neighbors {peer}")
    summary = pe.vtysh_cmd(f"show bgp vrf {UNDERLAY_VRF} summary")
    nht = pe.vtysh_cmd(f"show ip nht vrf {UNDERLAY_VRF} {peer}")
    zebra_routes = pe.vtysh_cmd(f"show ip route vrf {UNDERLAY_VRF}")

    kernel_routes = pe.run(f"ip -4 route show table {UNDERLAY_TABLE}")
    route_get = pe.run(f"ip -4 route get vrf {UNDERLAY_VRF} {peer} 2>&1")
    addresses = pe.run(
        "ip -br -4 addr; "
        f"ip -d link show {UNDERLAY_VRF}; "
        f"ip -d link show {config['underlay_if']}"
    )
    sockets = pe.run("ss -lntp | grep ':179' || true")
    sysctl = pe.run("sysctl net.ipv4.tcp_l3mdev_accept")

    pytest.fail(
        f"{name}: EVPN BGP peer {peer} did not establish\n\n"
        f"=== neighbor ===\n{neighbor}\n"
        f"=== summary ===\n{summary}\n"
        f"=== NHT ===\n{nht}\n"
        f"=== Zebra RIB ===\n{zebra_routes}\n"
        f"=== kernel table {UNDERLAY_TABLE} ===\n{kernel_routes}\n"
        f"=== kernel route-get ===\n{route_get}\n"
        f"=== addresses/interfaces ===\n{addresses}\n"
        f"=== TCP/179 ===\n{sockets}\n"
        f"=== tcp_l3mdev_accept ===\n{sysctl}\n"
    )


def test_default_bgp_and_non_default_evpn_config():
    """The original false-positive configuration must be accepted."""
    tgen = _routers_have_failure()

    for name in PE_CONFIG:
        running = tgen.gears[name].vtysh_cmd("show running-config")

        assert f"router bgp {UNDERLAY_AS}\n" in running
        assert f"router bgp {UNDERLAY_AS} vrf {UNDERLAY_VRF}" in running
        assert running.count("advertise-all-vni") == 1


def test_underlay_vrf_and_vtep_reachability():
    """The directly connected VTEPs must work inside the non-default VRF."""
    tgen = _routers_have_failure()

    for name, config in PE_CONFIG.items():
        pe = tgen.gears[name]

        zebra_routes = pe.vtysh_cmd(f"show ip route vrf {UNDERLAY_VRF}")

        assert "10.0.0.0/30" in zebra_routes, (
            f"{name}: connected underlay route is missing from Zebra:\n"
            f"{zebra_routes}"
        )

        command = (
            f"ip vrf exec {UNDERLAY_VRF} "
            f"ping -c 1 -W 1 -I {config['vtep_ip']} "
            f"{config['peer_ip']}"
        )
        success, last = topotest.run_and_expect(
            lambda pe=pe, command=command: _ping_succeeds(pe, command),
            True,
            count=20,
            wait=1,
        )

        assert success, f"{name}: peer VTEP is unreachable: {last}"


def test_evpn_bgp_session_in_underlay_vrf():
    """The EVPN peers must establish inside the non-default VRF."""
    tgen = _routers_have_failure()

    for name, config in PE_CONFIG.items():
        pe = tgen.gears[name]
        peer = config["peer_ip"]

        success, _ = topotest.run_and_expect(
            lambda pe=pe, peer=peer: _bgp_established(pe, peer),
            True,
            count=30,
            wait=1,
        )

        if not success:
            _diagnose_bgp_failure(pe, name, config)


def test_evpn_vni_discovers_remote_vtep():
    """EVPN Type-3 processing must populate the remote VTEP for VNI 100."""
    tgen = _routers_have_failure()

    for name, config in PE_CONFIG.items():
        pe = tgen.gears[name]
        remote_vtep = config["peer_ip"]

        success, last = topotest.run_and_expect(
            lambda pe=pe, remote_vtep=remote_vtep: _vni_has_remote_vtep(
                pe, remote_vtep
            ),
            True,
            count=30,
            wait=1,
        )

        if not success:
            output = pe.vtysh_cmd(f"show evpn vni {VNI} json")
            pytest.fail(
                f"{name}: VNI {VNI} did not learn remote VTEP "
                f"{remote_vtep}: {last}\n\n"
                f"=== show evpn vni {VNI} json ===\n{output}"
            )


def test_evpn_vxlan_moves_host_traffic():
    """Real L2 host traffic must cross the EVPN-programmed VXLAN tunnel."""
    tgen = _routers_have_failure()
    host1 = tgen.gears["host1"]
    host2 = tgen.gears["host2"]

    # Repeated ping generates ARP and gives EVPN time to advertise/program
    # host MAC state before the assertion is evaluated.
    success, last = topotest.run_and_expect(
        lambda: _ping_succeeds(
            host1,
            f"ping -c 2 -W 1 {HOST_CONFIG['host1']['peer_ip']}",
        ),
        True,
        count=30,
        wait=1,
    )
    assert success, f"host1 -> host2 VXLAN ping failed: {last}"

    success, last = topotest.run_and_expect(
        lambda: _ping_succeeds(
            host2,
            f"ping -c 2 -W 1 {HOST_CONFIG['host2']['peer_ip']}",
        ),
        True,
        count=20,
        wait=1,
    )
    assert success, f"host2 -> host1 VXLAN ping failed: {last}"


def test_remote_host_macs_are_programmed_in_vxlan_fdb():
    """Zebra must program remote host MACs with the correct VTEP destination."""
    tgen = _routers_have_failure()

    checks = (
        (
            "pe1",
            HOST_CONFIG["host2"]["mac"],
            PE_CONFIG["pe1"]["peer_ip"],
        ),
        (
            "pe2",
            HOST_CONFIG["host1"]["mac"],
            PE_CONFIG["pe2"]["peer_ip"],
        ),
    )

    for name, mac, remote_vtep in checks:
        pe = tgen.gears[name]

        success, last = topotest.run_and_expect(
            lambda pe=pe, mac=mac, remote_vtep=remote_vtep: _remote_mac_in_fdb(
                pe, mac, remote_vtep
            ),
            True,
            count=20,
            wait=1,
        )

        if not success:
            fdb = pe.run(f"bridge fdb show dev {VXLAN}")
            pytest.fail(
                f"{name}: remote MAC {mac} was not programmed via "
                f"VTEP {remote_vtep}: {last}\n\n"
                f"=== FDB ===\n{fdb}"
            )


def test_other_bgp_instance_cannot_take_evpn_ownership():
    """Mutual exclusion must remain when EVPN is actually enabled elsewhere."""
    tgen = _routers_have_failure()

    for name in PE_CONFIG:
        pe = tgen.gears[name]

        output = pe.vtysh_cmd(
            "configure terminal\n"
            f"router bgp {UNDERLAY_AS}\n"
            " address-family l2vpn evpn\n"
            "  advertise-all-vni\n"
            " exit-address-family\n"
            "exit\n"
        )

        assert "Please unconfigure EVPN" in output, (
            f"{name}: default BGP unexpectedly took EVPN ownership:\n" f"{output}"
        )


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", os.path.basename(__file__)] + sys.argv[1:]))
