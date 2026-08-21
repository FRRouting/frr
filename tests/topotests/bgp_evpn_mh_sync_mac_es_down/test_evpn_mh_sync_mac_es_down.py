#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_mh_sync_mac_es_down.py
#
# Regression test for zebra sync MAC NHG FDB uninstall when a local ES
# bond is oper-down with evpn mh redirect-off (slow-failover path).
#

import json
import os
import platform
import subprocess
import sys
from functools import partial

import pytest

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn, pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

tor_ips = {
    "torm11": "192.168.100.15",
    "torm12": "192.168.100.16",
}

svi_ips = {
    "torm11": "45.0.0.2",
    "torm12": "45.0.0.3",
}

host_es_map = {
    "hostd11": "03:44:38:39:ff:ff:01:00:00:01",
    "hostd12": "03:44:38:39:ff:ff:01:00:00:02",
}


def build_topo(tgen):
    """Rack-1 EVPN MH topology (subset of bgp_evpn_mh)."""
    for r in ("spine1", "spine2", "leaf1", "leaf2", "torm11", "torm12"):
        tgen.add_router(r)
    for h in ("hostd11", "hostd12"):
        tgen.add_router(h)

    links = [
        ("spine1", "leaf1", "sw1"),
        ("spine1", "leaf2", "sw2"),
        ("spine2", "leaf1", "sw3"),
        ("spine2", "leaf2", "sw4"),
        ("leaf1", "torm11", "sw5"),
        ("leaf1", "torm12", "sw6"),
        ("leaf2", "torm11", "sw7"),
        ("leaf2", "torm12", "sw8"),
        ("torm11", "hostd11", "sw9"),
        ("torm11", "hostd12", "sw10"),
        ("torm12", "hostd11", "sw11"),
        ("torm12", "hostd12", "sw12"),
    ]
    for a, b, swname in links:
        switch = tgen.add_switch(swname)
        switch.add_link(tgen.gears[a])
        switch.add_link(tgen.gears[b])


def config_bond(node, bond_name, bond_members, bond_ad_sys_mac, br):
    node.run("ip link add dev %s type bond mode 802.3ad" % bond_name)
    node.run("ip link set dev %s type bond lacp_rate 1" % bond_name)
    node.run("ip link set dev %s type bond miimon 100" % bond_name)
    node.run("ip link set dev %s type bond xmit_hash_policy layer3+4" % bond_name)
    node.run("ip link set dev %s type bond min_links 1" % bond_name)
    node.run(
        "ip link set dev %s type bond ad_actor_system %s" % (bond_name, bond_ad_sys_mac)
    )

    for bond_member in bond_members:
        node.run("ip link set dev %s down" % bond_member)
        node.run("ip link set dev %s master %s" % (bond_member, bond_name))
        node.run("ip link set dev %s up" % bond_member)

    node.run("ip link set dev %s up" % bond_name)

    if br:
        node.run(" ip link set dev %s master bridge" % bond_name)
        node.run("/sbin/bridge link set dev %s priority 8" % bond_name)
        node.run("/sbin/bridge vlan del vid 1 dev %s" % bond_name)
        node.run("/sbin/bridge vlan del vid 1 untagged pvid dev %s" % bond_name)
        node.run("/sbin/bridge vlan add vid 1000 dev %s" % bond_name)
        node.run("/sbin/bridge vlan add vid 1000 untagged pvid dev %s" % bond_name)


def config_mcast_tunnel_termination_device(node):
    node.run("ip link add dev ipmr-lo type dummy")
    node.run("ip link set dev ipmr-lo mtu 16000")
    node.run("ip link set dev ipmr-lo mode dormant")
    node.run("ip link set dev ipmr-lo up")


def config_bridge(node):
    node.run("ip link add dev bridge type bridge stp_state 0")
    node.run("ip link set dev bridge type bridge vlan_filtering 1")
    node.run("ip link set dev bridge mtu 9216")
    node.run("ip link set dev bridge type bridge ageing_time 1800")
    node.run("ip link set dev bridge type bridge mcast_snooping 0")
    node.run("ip link set dev bridge type bridge vlan_stats_enabled 1")
    node.run("ip link set dev bridge up")
    node.run("/sbin/bridge vlan add vid 1000 dev bridge self")


def config_vxlan(node, node_ip):
    node.run("ip link add dev vx-1000 type vxlan id 1000 dstport 4789")
    node.run("ip link set dev vx-1000 type vxlan nolearning")
    node.run("ip link set dev vx-1000 type vxlan local %s" % node_ip)
    node.run("ip link set dev vx-1000 type vxlan ttl 64")
    node.run("ip link set dev vx-1000 mtu 9152")
    node.run("ip link set dev vx-1000 type vxlan dev ipmr-lo group 239.1.1.100")
    node.run("ip link set dev vx-1000 up")

    node.run("ip link set dev vx-1000 master bridge")
    node.run("/sbin/bridge link set dev vx-1000 neigh_suppress on")
    node.run("/sbin/bridge link set dev vx-1000 learning off")
    node.run("/sbin/bridge link set dev vx-1000 priority 8")
    node.run("/sbin/bridge vlan del vid 1 dev vx-1000")
    node.run("/sbin/bridge vlan del vid 1 untagged pvid dev vx-1000")
    node.run("/sbin/bridge vlan add vid 1000 dev vx-1000")
    node.run("/sbin/bridge vlan add vid 1000 untagged pvid dev vx-1000")


def config_svi(node, svi_pip):
    node.run("ip link add link bridge name vlan1000 type vlan id 1000 protocol 802.1q")
    node.run("ip addr add %s/24 dev vlan1000" % svi_pip)
    node.run("ip link set dev vlan1000 up")
    node.run("/sbin/sysctl net.ipv4.conf.vlan1000.arp_accept=1")
    node.run("ip link add link vlan1000 name vlan1000-v0 type macvlan mode private")
    node.run("/sbin/sysctl net.ipv6.conf.vlan1000-v0.accept_dad=0")
    node.run("/sbin/sysctl net.ipv6.conf.vlan1000-v0.dad_transmits=0")
    node.run("ip link set dev vlan1000-v0 address 00:00:5e:00:01:01")
    node.run("ip link set dev vlan1000-v0 up")
    node.run("ip addr add 45.0.0.1/24 dev vlan1000-v0")


def config_tor(tor_name, tor, tor_ip, svi_pip):
    config_mcast_tunnel_termination_device(tor)
    config_bridge(tor)
    config_vxlan(tor, tor_ip)

    sys_mac = "44:38:39:ff:ff:01"
    config_bond(tor, "hostbond1", [tor_name + "-eth2"], sys_mac, "bridge")
    config_bond(tor, "hostbond2", [tor_name + "-eth3"], sys_mac, "bridge")
    config_svi(tor, svi_pip)


def compute_host_ip_mac(host_name):
    host_id = host_name.split("hostd")[1]
    host_ip = "45.0.0." + host_id + "/24"
    host_mac = "00:00:00:00:00:" + host_id
    return host_ip, host_mac


def config_host(host_name, host):
    bond_members = [host_name + "-eth0", host_name + "-eth1"]
    config_bond(host, "torbond", bond_members, "00:00:00:00:00:00", None)

    host_ip, host_mac = compute_host_ip_mac(host_name)
    host.run("ip addr add %s dev %s" % (host_ip, "torbond"))
    host.run("ip link set dev %s address %s" % ("torbond", host_mac))


def ping_anycast_gw(tgen):
    python3_path = tgen.net.get_exec_path(["python3", "python"])
    script_path = os.path.abspath(os.path.join(CWD, "../lib/scapy_sendpkt.py"))
    intf = "torbond"
    ipaddr = "45.0.0.1"
    ping_cmd = [
        python3_path,
        script_path,
        "--imports=Ether,ARP",
        "--interface=" + intf,
        'Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="{}")'.format(ipaddr),
    ]
    for name in ("hostd11", "hostd12"):
        host = tgen.net.hosts[name]
        host.cmd_status(ping_cmd, warn=False, stderr=subprocess.STDOUT)


def check_mac(dut, vni, mac, m_type, esi, intf, ping_gw=False, tgen=None):
    if ping_gw:
        ping_anycast_gw(tgen)

    out = dut.vtysh_cmd("show evpn mac vni %d mac %s json" % (vni, mac))
    mac_js = json.loads(out)
    for _, info in mac_js.items():
        tmp_esi = info.get("esi", "")
        tmp_m_type = info.get("type", "")
        tmp_intf = info.get("intf", "") if tmp_m_type == "local" else ""
        if tmp_esi == esi and tmp_m_type == m_type and tmp_intf == intf:
            return None

    return "invalid vni %d mac %s expected esi %s type %s intf %s got %s" % (
        vni,
        mac,
        esi,
        m_type,
        intf,
        mac_js,
    )


def check_es_flag(dut, esi, flag, expect_present):
    es = json.loads(dut.vtysh_cmd("show evpn es %s json" % esi))
    if not es:
        return "esi %s not found" % esi

    flags = es.get("flags", [])
    present = flag in flags
    if expect_present and not present:
        return "ES %s missing flag %s (flags %s)" % (esi, flag, flags)
    if not expect_present and present:
        return "ES %s unexpected flag %s (flags %s)" % (esi, flag, flags)
    return None


def check_mac_on_dev(dut, dev, mac, expect_present):
    out = dut.run("bridge fdb show dev %s" % dev)
    present = mac.lower() in out.lower()
    if expect_present and not present:
        return "MAC %s missing on %s" % (mac, dev)
    if not expect_present and present:
        return "MAC %s unexpectedly present on %s: %s" % (mac, dev, out)
    return None


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.19") < 0:
        tgen.errors = "kernel 4.19 needed for multihoming tests"
        pytest.skip(tgen.errors)

    for tor_name in ("torm11", "torm12"):
        config_tor(
            tor_name,
            tgen.gears[tor_name],
            tor_ips[tor_name],
            svi_ips[tor_name],
        )

    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()

    for host_name in ("hostd11", "hostd12"):
        config_host(host_name, tgen.gears[host_name])


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_evpn_mh_sync_mac_nhg_oper_down():
    """
    With evpn mh redirect-off, ES oper-down moves a local static MAC from
    the access bond onto the VxLAN/NHG dataplane.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut = tgen.gears["torm12"]
    vni = 1000
    host = "hostd11"
    _, mac = compute_host_ip_mac(host)
    esi = host_es_map[host]

    for tor_name in ("torm11", "torm12"):
        tor = tgen.gears[tor_name]
        test_fn = partial(check_mac, tor, vni, mac, "local", esi, "hostbond1", True, tgen)
        _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
        assert result is None, '"{}" baseline MAC incorrect'.format(tor_name)

    test_fn = partial(check_es_flag, dut, esi, "operUp", True)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "ES not oper-up at baseline"

    test_fn = partial(check_mac_on_dev, dut, "hostbond1", mac, True)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "baseline hostbond1 FDB missing MAC"

    dut.run("ip link set dev hostbond1 down")

    test_fn = partial(check_es_flag, dut, esi, "operUp", False)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "ES still oper-up after bond down"

    test_fn = partial(check_es_flag, dut, esi, "nexthopGroupActive", True)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "ES NHG inactive after bond down"

    test_fn = partial(check_mac_on_dev, dut, "hostbond1", mac, False)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "hostbond1 FDB still has MAC after oper-down"

    test_fn = partial(check_mac_on_dev, dut, "vx-1000", mac, True)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "vx-1000 FDB missing MAC after oper-down"

    dut.run("ip link set dev hostbond1 up")

    test_fn = partial(check_es_flag, dut, esi, "operUp", True)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "ES not oper-up after bond up"


def _recreate_hostbond1(tor_name, tor):
    """Restore hostbond1 after destructive flush test for clean teardown."""
    sys_mac = "44:38:39:ff:ff:01"
    config_bond(tor, "hostbond1", [tor_name + "-eth2"], sys_mac, "bridge")


def test_evpn_mh_sync_mac_nhg_flush_on_bond_del():
    """
    When the access bond is deleted while the MAC is on the NHG dataplane,
    flush_local_mac must force-remove the NHG FDB entry (no orphan).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut = tgen.gears["torm12"]
    vni = 1000
    host = "hostd11"
    _, mac = compute_host_ip_mac(host)
    esi = host_es_map[host]

    test_fn = partial(check_mac, dut, vni, mac, "local", esi, "hostbond1", True, tgen)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "baseline MAC missing before flush test"

    dut.run("ip link set dev hostbond1 down")

    test_fn = partial(check_mac_on_dev, dut, "vx-1000", mac, True)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "NHG FDB not programmed after oper-down"

    dut.run("ip link del hostbond1")

    test_fn = partial(check_mac_on_dev, dut, "vx-1000", mac, False)
    _, result = topotest.run_and_expect(test_fn, None, count=30, wait=1)
    assert result is None, "orphaned NHG FDB on vx-1000 after bond delete"

    _recreate_hostbond1("torm12", dut)
