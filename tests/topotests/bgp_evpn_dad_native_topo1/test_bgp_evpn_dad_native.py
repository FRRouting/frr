#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Exercise EVPN duplicate-address freeze and clear with a native VLAN-aware
bridge/VXLAN layout matching the SSIM NOS-agnostic DAD test.
"""

import os
import sys
import time
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.checkping import check_ping
from lib.common_config import required_linux_kernel_version
from lib.evpn import evpn_verify_vni_remote_vteps
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

TOR1 = "tor-11"
TOR2 = "tor-21"
HOST1 = "host-111"
HOST2 = "host-211"

TOR_UNDERLAY_IF = "swp1"
TOR_ACCESS_IF = "swp2"
HOST_IF = "swp1"
BRIDGE = "br_default"
VLAN_IF = "vlan111"
VXLAN_IF = "vxlan48"

VLAN = 111
VNI = 1000111
TEST_IP4 = "60.1.1.100"
TEST_IP6 = "2060:1:1:1::100"
LOCAL_MAC = "aa:11:aa:aa:aa:aa"
REMOTE_MAC = "aa:21:aa:aa:aa:aa"
SNOOPER = os.path.join(CWD, "dad_snooper.py")
PYTHON = sys.executable


def build_topo(tgen):
    "Build function"

    tgen.add_router(TOR1)
    tgen.add_router(TOR2)
    tgen.add_router(HOST1)
    tgen.add_router(HOST2)

    switch = tgen.add_switch("s-underlay")
    switch.add_link(tgen.gears[TOR1], nodeif=TOR_UNDERLAY_IF)
    switch.add_link(tgen.gears[TOR2], nodeif=TOR_UNDERLAY_IF)

    switch = tgen.add_switch("s-{}".format(HOST1))
    switch.add_link(tgen.gears[TOR1], nodeif=TOR_ACCESS_IF)
    switch.add_link(tgen.gears[HOST1], nodeif=HOST_IF)

    switch = tgen.add_switch("s-{}".format(HOST2))
    switch.add_link(tgen.gears[TOR2], nodeif=TOR_ACCESS_IF)
    switch.add_link(tgen.gears[HOST2], nodeif=HOST_IF)


def _setup_tor(router, local_vtep, underlay_cidr, peer_vtep, peer_underlay, svi4, svi6):
    router.run("ip link set dev {} up".format(TOR_UNDERLAY_IF))
    router.run("ip link set dev {} up".format(TOR_ACCESS_IF))
    router.run("ip addr add {} dev {}".format(underlay_cidr, TOR_UNDERLAY_IF))
    router.run("ip addr add {}/32 dev lo".format(local_vtep))
    router.run("ip route replace {}/32 via {}".format(peer_vtep, peer_underlay))

    for dev in (VLAN_IF, VXLAN_IF, BRIDGE):
        router.run("ip link set dev {} down 2>/dev/null || true".format(dev))
        router.run("ip link del {} 2>/dev/null || true".format(dev))

    router.run("ip link add name {} type bridge stp_state 0".format(BRIDGE))
    router.run("ip link set dev {} type bridge vlan_filtering 1".format(BRIDGE))
    router.run("ip link set dev {} type bridge ageing_time 18000".format(BRIDGE))
    router.run("ip link set dev {} up".format(BRIDGE))
    router.run("bridge vlan add vid {} dev {} self".format(VLAN, BRIDGE))

    router.run(
        "ip link add {} type vxlan dstport 4789 local {} "
        "nolearning external ttl 64 ageing 18000".format(VXLAN_IF, local_vtep)
    )
    router.run("ip link set dev {} master {}".format(VXLAN_IF, BRIDGE))
    router.run("bridge link set dev {} vlan_tunnel on".format(VXLAN_IF))
    router.run("bridge link set dev {} neigh_suppress on".format(VXLAN_IF))
    router.run("bridge link set dev {} learning off".format(VXLAN_IF))
    router.run("bridge vlan add dev {} vid {}".format(VXLAN_IF, VLAN))
    router.run(
        "bridge vlan add dev {} vid {} tunnel_info id {}".format(
            VXLAN_IF, VLAN, VNI
        )
    )
    router.run("ip link set dev {} up".format(VXLAN_IF))

    router.run(
        "ip link add link {} name {} type vlan id {} protocol 802.1q".format(
            BRIDGE, VLAN_IF, VLAN
        )
    )
    router.run("/sbin/sysctl -w net.ipv6.conf.{}.accept_dad=0".format(VLAN_IF))
    router.run("/sbin/sysctl -w net.ipv6.conf.{}.dad_transmits=0".format(VLAN_IF))
    router.run("ip addr add {} dev {}".format(svi4, VLAN_IF))
    router.run("ip addr add {} dev {}".format(svi6, VLAN_IF))
    router.run("ip link set dev {} up".format(VLAN_IF))
    router.run("/sbin/sysctl -w net.ipv4.conf.{}.arp_accept=1".format(VLAN_IF))

    router.run("ip link set dev {} master {}".format(TOR_ACCESS_IF, BRIDGE))
    router.run(
        "bridge vlan del vid 1 dev {} 2>/dev/null || true".format(TOR_ACCESS_IF)
    )
    router.run(
        "bridge vlan del vid 1 untagged pvid dev {} 2>/dev/null || true".format(
            TOR_ACCESS_IF
        )
    )
    router.run("bridge vlan add vid {} dev {}".format(VLAN, TOR_ACCESS_IF))
    router.run(
        "bridge vlan add vid {} pvid untagged dev {}".format(VLAN, TOR_ACCESS_IF)
    )


def _setup_host(host):
    host.run("ip link set dev {} up".format(HOST_IF))
    host.run("/sbin/sysctl -w net.ipv6.conf.all.accept_dad=0")
    host.run("/sbin/sysctl -w net.ipv6.conf.default.accept_dad=0")
    host.run("/sbin/sysctl -w net.ipv6.conf.{}.accept_dad=0".format(HOST_IF))
    host.run("/sbin/sysctl -w net.ipv6.conf.{}.dad_transmits=0".format(HOST_IF))


def setup_module(mod):
    "Sets up the pytest environment"

    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >= 5.15")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _setup_tor(
        tgen.gears[TOR1],
        "10.0.0.11",
        "10.0.0.1/30",
        "10.0.0.21",
        "10.0.0.2",
        "60.1.1.11/24",
        "2060:1:1:1::11/64",
    )
    _setup_tor(
        tgen.gears[TOR2],
        "10.0.0.21",
        "10.0.0.2/30",
        "10.0.0.11",
        "10.0.0.1",
        "60.1.1.21/24",
        "2060:1:1:1::21/64",
    )
    _setup_host(tgen.gears[HOST1])
    _setup_host(tgen.gears[HOST2])

    for rname in (TOR1, TOR2):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()
    if tgen is not None:
        for host in (HOST1, HOST2):
            if host in tgen.gears:
                _stop_snooper(tgen.gears[host])
        tgen.stop_topology()


def _configure_evpn_dad(router, enable):
    if enable:
        cmd = """
configure terminal
router bgp 65000
 address-family l2vpn evpn
  dup-addr-detection max-moves 4 time 100
  dup-addr-detection freeze permanent
end
"""
    else:
        cmd = """
configure terminal
router bgp 65000
 address-family l2vpn evpn
  no dup-addr-detection
end
"""

    output = router.vtysh_cmd(cmd) or ""
    assert "% Unknown command" not in output
    assert "% Invalid input" not in output


def _evpn_peer_established(router, peer):
    output = router.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
    if not isinstance(output, dict):
        return "{}: no EVPN summary JSON: {}".format(router.name, output)

    state = output.get("peers", {}).get(peer, {}).get("state")
    if state != "Established":
        return "{}: peer {} state is {}".format(router.name, peer, state)

    return None


def _wait_evpn_peer(router, peer):
    test_func = partial(_evpn_peer_established, router, peer)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def _wait_vni_remote_vtep(router, remote_vtep):
    test_func = partial(evpn_verify_vni_remote_vteps, router, [VNI], [remote_vtep])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def _start_snooper(host, mac):
    _stop_snooper(host)
    host.run(
        "{} {} --interface {} --mac {} --ip4 {} --ip6 {} "
        "--no-unsolicited-na "
        ">>dad_snooper.log 2>&1 &".format(
            PYTHON, SNOOPER, HOST_IF, mac, TEST_IP4, TEST_IP6
        )
    )
    time.sleep(1)
    test_func = partial(_snooper_running, host)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, result


def _stop_snooper(host):
    host.run(
        "pkill -f '[d]ad_snooper.py .*--interface {}' 2>/dev/null || true".format(
            HOST_IF
        )
    )
    host.run("ip link set dev {} promisc off 2>/dev/null || true".format(HOST_IF))


def _snooper_running(host):
    output = host.run("pgrep -f '[d]ad_snooper.py .*--interface {}'".format(HOST_IF))
    if not output.strip():
        return "{}: dad_snooper.py is not running".format(host.name)
    return None


def _activate_host_on_tor(tor, mac):
    output = tor.run("bridge fdb replace {} dev {} master".format(mac, TOR_ACCESS_IF))
    assert "RTNETLINK answers" not in output, output

    output = tor.run(
        "ip neigh replace {} lladdr {} dev {} nud reachable".format(
            TEST_IP4, mac, VLAN_IF
        )
    )
    assert "RTNETLINK answers" not in output, output

    output = tor.run(
        "ip -6 neigh replace {} lladdr {} dev {} nud reachable".format(
            TEST_IP6, mac, VLAN_IF
        )
    )
    assert "RTNETLINK answers" not in output, output


def _withdraw_host_from_tor(tor, mac):
    tor.run("ip neigh del {} dev {} 2>/dev/null || true".format(TEST_IP4, VLAN_IF))
    tor.run("ip -6 neigh del {} dev {} 2>/dev/null || true".format(TEST_IP6, VLAN_IF))
    tor.run(
        "bridge fdb del {} dev {} master 2>/dev/null || true".format(
            mac, TOR_ACCESS_IF
        )
    )
    tor.run(
        "bridge fdb del {} dev {} vlan {} master 2>/dev/null || true".format(
            mac, TOR_ACCESS_IF, VLAN
        )
    )


def _simulate_dad_moves(remote_tor, remote_host, local_tor, local_host):
    _stop_snooper(remote_host)
    _stop_snooper(local_host)
    _withdraw_host_from_tor(remote_tor, REMOTE_MAC)
    _withdraw_host_from_tor(local_tor, LOCAL_MAC)

    # Initial placement behind the remote VTEP. The first local learn below
    # must see this remote entry so DAD starts counting the move sequence.
    _start_snooper(remote_host, REMOTE_MAC)
    _activate_host_on_tor(remote_tor, REMOTE_MAC)
    _wait_evpn_neigh_state(local_tor, TEST_IP4, "remote", REMOTE_MAC, False)
    _wait_evpn_neigh_state(local_tor, TEST_IP6, "remote", REMOTE_MAC, False)

    # Move 1: stop remote host replies, but keep the remote route visible so
    # the remote-to-local transition increments DAD.
    _stop_snooper(remote_host)
    _start_snooper(local_host, LOCAL_MAC)
    _activate_host_on_tor(local_tor, LOCAL_MAC)
    _wait_evpn_neigh_state(local_tor, TEST_IP4, "local", LOCAL_MAC, False, 1)
    _wait_evpn_neigh_state(local_tor, TEST_IP6, "local", LOCAL_MAC, False, 1)
    logger.info("EVPN DAD move number 1")


    # Stop the local host replies before moving back to the remote side.
    # The TOR state remains until a later withdraw; stopping snooper alone
    # does not generate an EVPN delete.
    _stop_snooper(local_host)
    _start_snooper(remote_host, REMOTE_MAC)
    _activate_host_on_tor(remote_tor, REMOTE_MAC)
    _wait_evpn_neigh_state(local_tor, TEST_IP4, "remote", REMOTE_MAC, False, 2)
    _wait_evpn_neigh_state(local_tor, TEST_IP6, "remote", REMOTE_MAC, False, 2)
    logger.info("EVPN DAD move number 2")

    # Keep the remote TOR's stale MAC-IP route while learning local again.
    # Withdrawing it here resets DAD accounting and move 4 will not freeze.
    _stop_snooper(remote_host)
    _start_snooper(local_host, LOCAL_MAC)
    _activate_host_on_tor(local_tor, LOCAL_MAC)
    _wait_evpn_neigh_state(local_tor, TEST_IP4, "local", LOCAL_MAC, False, 3)
    _wait_evpn_neigh_state(local_tor, TEST_IP6, "local", LOCAL_MAC, False, 3)
    logger.info("EVPN DAD move number 3")

    # Keep the local kernel entry in place; the final remote add should freeze
    # in EVPN while the kernel still has the newer local MAC.
    _stop_snooper(local_host)
    _start_snooper(remote_host, REMOTE_MAC)
    _activate_host_on_tor(remote_tor, REMOTE_MAC)
    _wait_evpn_neigh_state(local_tor, TEST_IP4, "remote", REMOTE_MAC, True, 4)
    _wait_evpn_neigh_state(local_tor, TEST_IP6, "remote", REMOTE_MAC, True, 4)
    logger.info("EVPN DAD move number 4")


def _log_state(label, *routers):
    logger.info("=== %s ===", label)
    for router in routers:
        logger.info(
            "%s ip neigh ipv4:\n%s",
            router.name,
            router.run("ip neigh show dev {}".format(VLAN_IF)),
        )
        logger.info(
            "%s ip neigh ipv6:\n%s",
            router.name,
            router.run("ip -6 neigh show dev {}".format(VLAN_IF)),
        )
        logger.info("%s bridge fdb:\n%s", router.name, router.run("bridge fdb show"))
        logger.info(
            "%s evpn arp-cache:\n%s",
            router.name,
            router.vtysh_cmd("show evpn arp-cache vni {}".format(VNI)),
        )
        logger.info(
            "%s evpn mac:\n%s",
            router.name,
            router.vtysh_cmd("show evpn mac vni {}".format(VNI)),
        )


def _evpn_neigh_state_matches(
    router,
    ip,
    expected_type,
    expected_mac,
    expected_duplicate=None,
    min_detection_count=None,
):
    state = router.vtysh_cmd(
        "show evpn arp-cache vni {} ip {} json".format(VNI, ip), isjson=True
    )
    if not isinstance(state, dict) or not state:
        return "{} expected EVPN neighbor {}, got {}".format(router.name, ip, state)

    if state.get("type") != expected_type:
        return "{} neighbor {} expected type {}, got {}".format(
            router.name, ip, expected_type, state
        )

    if state.get("mac") != expected_mac:
        return "{} neighbor {} expected MAC {}, got {}".format(
            router.name, ip, expected_mac, state
        )

    if expected_duplicate is not None and state.get("isDuplicate") != expected_duplicate:
        return "{} neighbor {} expected duplicate {}, got {}".format(
            router.name, ip, expected_duplicate, state
        )

    if min_detection_count is not None and state.get("detectionCount", 0) < min_detection_count:
        return "{} neighbor {} expected detection count at least {}, got {}".format(
            router.name, ip, min_detection_count, state
        )

    return None


def _wait_evpn_neigh_state(
    router,
    ip,
    expected_type,
    expected_mac,
    expected_duplicate=None,
    min_detection_count=None,
    count=45,
):
    test_func = partial(
        _evpn_neigh_state_matches,
        router,
        ip,
        expected_type,
        expected_mac,
        expected_duplicate,
        min_detection_count,
    )
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    assert result is None, result


def _kernel_neigh_matches(node, ip, mac):
    output = node.run("ip neigh show {} dev {}".format(ip, VLAN_IF)).lower()
    if mac.lower() not in output:
        return "{} neighbor {} expected MAC {}, got {}".format(node.name, ip, mac, output)
    return None


def _wait_kernel_neigh(node, ip, mac):
    test_func = partial(_kernel_neigh_matches, node, ip, mac)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_dad_remote_mac_del_keeps_local_kernel_mac():
    """
    Verify a DAD-frozen remote MAC-IP delete does not remove a newer
    local kernel neighbor for the same IP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor11 = tgen.gears[TOR1]
    tor21 = tgen.gears[TOR2]
    host111 = tgen.gears[HOST1]
    host211 = tgen.gears[HOST2]

    check_ping(TOR1, "10.0.0.2", True, 10, 1)
    check_ping(TOR2, "10.0.0.1", True, 10, 1)
    _wait_evpn_peer(tor11, "10.0.0.2")
    _wait_evpn_peer(tor21, "10.0.0.1")
    _wait_vni_remote_vtep(tor11, "10.0.0.21")
    _wait_vni_remote_vtep(tor21, "10.0.0.11")

    _configure_evpn_dad(tor11, True)
    _configure_evpn_dad(tor21, True)

    try:
        tor11.vtysh_cmd("clear evpn dup-addr vni all")
        tor21.vtysh_cmd("clear evpn dup-addr vni all")
        tor11.run("ip neigh flush dev {}".format(VLAN_IF))
        tor21.run("ip neigh flush dev {}".format(VLAN_IF))

        _simulate_dad_moves(tor21, host211, tor11, host111)
        _log_state("after move sequence", tor11, tor21)

        _wait_evpn_neigh_state(tor11, TEST_IP4, "remote", REMOTE_MAC, True, 4)
        _wait_evpn_neigh_state(tor11, TEST_IP6, "remote", REMOTE_MAC, True, 4)
        _wait_kernel_neigh(tor11, TEST_IP4, LOCAL_MAC)
        _wait_kernel_neigh(tor11, TEST_IP6, LOCAL_MAC)

        _wait_evpn_neigh_state(tor21, TEST_IP4, "local", REMOTE_MAC, False)
        _wait_evpn_neigh_state(tor21, TEST_IP6, "local", REMOTE_MAC, False)
        _wait_kernel_neigh(tor21, TEST_IP4, REMOTE_MAC)
        _wait_kernel_neigh(tor21, TEST_IP6, REMOTE_MAC)

        _stop_snooper(host211)
        _withdraw_host_from_tor(tor21, REMOTE_MAC)

        _wait_kernel_neigh(tor11, TEST_IP4, LOCAL_MAC)
        _wait_kernel_neigh(tor11, TEST_IP6, LOCAL_MAC)
        _wait_evpn_neigh_state(tor11, TEST_IP4, "local", LOCAL_MAC, False)
        _wait_evpn_neigh_state(tor11, TEST_IP6, "local", LOCAL_MAC, False)
    finally:
        _stop_snooper(host111)
        _stop_snooper(host211)
        _configure_evpn_dad(tor11, False)
        _configure_evpn_dad(tor21, False)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
