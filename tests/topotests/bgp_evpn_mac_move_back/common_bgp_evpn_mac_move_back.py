#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# common_bgp_evpn_mac_move_back.py
#
# Shared by the three bgp_evpn_mac_move_back tests, which differ only in how
# the PEs' bridges and VXLAN devices are built:
#
#   unaware  a VLAN-unaware bridge and a VXLAN device per VNI
#   aware    one VLAN-aware bridge, a VXLAN device per VNI (access VLANs)
#   svd      one VLAN-aware bridge and a single VXLAN device for all VNIs
#
#   host1 --- PE1 ---- PE2 --- host2      host1 and host2: VNI 100, the same
#                       |                 MAC and IP, one port up at a time
#                       +----- host3      host3: VNI 200, the same MAC, always up
#
# A MAC that moves to the other PE and back, make-before-break (the order a
# live migration produces: the MAC is learnt on the new port while the old
# PE still advertises it). When PE1 learns the MAC locally again, the bridge
# takes over its own entry, but the VXLAN device's own entry to PE2
# (NTF_SELF, extern_learn) stays. zebra used to read that entry back on every
# FDB re-read (a restart, a VNI rebuild, advertise-all-vni) as a remote learn
# and delete the local MAC: PE1 then advertised nothing for a host that was
# still behind its port, until the bridge entry happened to change.
#
# Besides the fix itself, the steps check that the delete zebra now sends for
# the VXLAN device's entry touches nothing else. The move back and the two
# leftover steps run `bridge monitor fdb` and require that the bridge's local
# entry on PE1's access port is never deleted. Every step checks that the same
# MAC in VNI 200 keeps its VXLAN entry to PE2 (on a single VXLAN device both
# entries live in one FDB, told apart by the source VNI).
#

import functools
import os

from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

MAC = "02:00:00:00:00:21"
HOST_IP = {
    "host1": "192.168.101.21",
    "host2": "192.168.101.21",
    "host3": "192.168.102.21",
}
PING_TARGET = {
    "host1": "192.168.101.99",
    "host2": "192.168.101.99",
    "host3": "192.168.102.99",
}
VNIS = {100: 10, 200: 20}  # VNI: access VLAN (VLAN-aware modes only)
VTEP = {"PE1": "10.100.0.1", "PE2": "10.100.0.2"}
# The access ports, and the VNI each belongs to
PORTS = {"PE1": {"PE1-eth1": 100}, "PE2": {"PE2-eth1": 100, "PE2-eth2": 200}}

MODE = None


def build_topo(tgen):
    for name in ("PE1", "PE2", "host1", "host2", "host3"):
        tgen.add_router(name)
    tgen.add_link(tgen.gears["PE1"], tgen.gears["PE2"], "PE1-eth0", "PE2-eth0")
    tgen.add_link(tgen.gears["PE1"], tgen.gears["host1"], "PE1-eth1", "host1-eth0")
    tgen.add_link(tgen.gears["PE2"], tgen.gears["host2"], "PE2-eth1", "host2-eth0")
    tgen.add_link(tgen.gears["PE2"], tgen.gears["host3"], "PE2-eth2", "host3-eth0")


def vxlan_dev(vni):
    return "vxlan0" if MODE == "svd" else f"vxlan{vni}"


def _setup_unaware(pe, name):
    for vni in VNIS:
        pe.cmd_raises(f"ip link add br{vni} type bridge stp_state 0")
        pe.cmd_raises(
            f"ip link add vxlan{vni} type vxlan id {vni} dstport 4789 local {VTEP[name]} nolearning"
        )
        pe.cmd_raises(f"ip link set dev vxlan{vni} master br{vni}")
        pe.cmd_raises(f"bridge link set dev vxlan{vni} neigh_suppress on learning off")
        pe.cmd_raises(f"ip link set up dev br{vni}")
        pe.cmd_raises(f"ip link set up dev vxlan{vni}")
    for port, vni in PORTS[name].items():
        pe.cmd_raises(f"ip link set dev {port} master br{vni}")


def _setup_vlan_aware_bridge(pe, name):
    pe.cmd_raises("ip link add br0 type bridge stp_state 0 vlan_filtering 1")
    for vid in VNIS.values():
        pe.cmd_raises(f"bridge vlan add vid {vid} dev br0 self")
    pe.cmd_raises("ip link set up dev br0")
    for port, vni in PORTS[name].items():
        pe.cmd_raises(f"ip link set dev {port} master br0")
        pe.cmd_raises(f"bridge vlan del vid 1 dev {port}")
        pe.cmd_raises(f"bridge vlan add vid {VNIS[vni]} pvid untagged dev {port}")


def _setup_aware(pe, name):
    _setup_vlan_aware_bridge(pe, name)
    for vni, vid in VNIS.items():
        pe.cmd_raises(
            f"ip link add vxlan{vni} type vxlan id {vni} dstport 4789 local {VTEP[name]} nolearning"
        )
        pe.cmd_raises(f"ip link set dev vxlan{vni} master br0")
        pe.cmd_raises(f"bridge vlan del vid 1 dev vxlan{vni}")
        pe.cmd_raises(f"bridge vlan add vid {vid} pvid untagged dev vxlan{vni}")
        pe.cmd_raises(f"bridge link set dev vxlan{vni} neigh_suppress on learning off")
        pe.cmd_raises(f"ip link set up dev vxlan{vni}")


def _setup_svd(pe, name):
    _setup_vlan_aware_bridge(pe, name)
    pe.cmd_raises(
        f"ip link add vxlan0 type vxlan dstport 4789 local {VTEP[name]} nolearning external"
    )
    pe.cmd_raises("ip link set dev vxlan0 master br0")
    pe.cmd_raises(
        "bridge link set dev vxlan0 vlan_tunnel on neigh_suppress on learning off"
    )
    pe.cmd_raises("bridge vlan del vid 1 dev vxlan0")
    for vni, vid in VNIS.items():
        pe.cmd_raises(f"bridge vlan add dev vxlan0 vid {vid}")
        pe.cmd_raises(f"bridge vlan add dev vxlan0 vid {vid} tunnel_info id {vni}")
    pe.cmd_raises("ip link set up dev vxlan0")


def setup(mod, mode, cwd):
    global MODE
    MODE = mode
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The bridges and vxlan devices are created here, after the topology's
    # veths, so the access ports have the lower ifindex and come first in an
    # FDB dump. The bug needs that order (the local entry read before the
    # vxlan device's leftover); in the other order the re-read steps pass
    # without the fix. Keep the vxlan devices created after the ports.
    setup_pe = {"unaware": _setup_unaware, "aware": _setup_aware, "svd": _setup_svd}[
        mode
    ]
    for name in ("PE1", "PE2"):
        setup_pe(tgen.net[name], name)
        # A bridge outside EVPN for FdbMonitor's sentinel entry
        pe = tgen.net[name]
        pe.cmd_raises("ip link add brmon type bridge")
        pe.cmd_raises("ip link add dmon type dummy")
        pe.cmd_raises("ip link set dev dmon master brmon")
        pe.cmd_raises("ip link set up dev brmon")
        pe.cmd_raises("ip link set up dev dmon")
    for host in ("host1", "host2", "host3"):
        h = tgen.net[host]
        h.cmd_raises(f"ip link set dev {host}-eth0 address {MAC}")
        h.cmd_raises(f"ip addr add {HOST_IP[host]}/24 dev {host}-eth0")
    # host2 starts away: its PE port is down
    tgen.net["PE2"].cmd_raises("ip link set dev PE2-eth1 down")

    for rname in ("PE1", "PE2"):
        logger.info(f"Loading config to router {rname}")
        tgen.gears[rname].load_frr_config(os.path.join(cwd, f"{rname}/frr.conf"))

    tgen.start_router()


def teardown(mod):
    get_topogen().stop_topology()


def talk(host):
    """Make the host send a frame (an ARP request) so its PE learns the MAC."""
    get_topogen().net[host].cmd(f"ping -c 2 -i 0.2 -W 1 {PING_TARGET[host]}")


def _zebra_mac(pe, vni):
    out = (
        get_topogen()
        .gears[pe]
        .vtysh_cmd(f"show evpn mac vni {vni} mac {MAC} json", isjson=True)
    )
    return (out or {}).get(MAC, {})


def _mac_is(pe, vni, type_, where=None):
    mac = _zebra_mac(pe, vni)
    if mac.get("type") != type_:
        return mac or "absent"
    if where and where not in (mac.get("intf"), mac.get("remoteVtep")):
        return mac
    return None


def wait(fn, what, count=30):
    ok, res = topotest.run_and_expect(fn, None, count=count, wait=1)
    assert ok, f"{what}: {res}"


def vxlan_entries(pe, vni, vtep):
    """The VXLAN device's own entries for MAC in this VNI to this VTEP."""
    dev = vxlan_dev(vni)
    fdb = get_topogen().gears[pe].cmd(f"bridge fdb show dev {dev}")
    entries = []
    for line in fdb.splitlines():
        if not line.startswith(MAC) or f"dst {vtep}" not in line:
            continue
        if MODE == "svd" and f"src_vni {vni} " not in line + " ":
            continue
        entries.append(line)
    return entries


def _bridge_local_entry(pe, port):
    fdb = get_topogen().gears[pe].cmd(f"bridge fdb show dev {port}")
    return [l for l in fdb.splitlines() if l.startswith(MAC) and "master" in l]


SENTINEL_MAC = "02:00:00:00:ff:01"


class FdbMonitor:
    """`bridge monitor fdb` on a PE for the duration of a step."""

    def __init__(self, pe, tag):
        tgen = get_topogen()
        self.pe = pe
        self.path = os.path.join(tgen.logdir, pe, f"fdb-monitor-{tag}.log")
        net = tgen.net[pe]
        self.pid = net.cmd(
            f"stdbuf -oL timeout 300 bridge monitor fdb > {self.path} 2>&1 & echo $!"
        ).strip()
        # The monitor starts in the background and misses every event until
        # it is subscribed, so re-add a sentinel entry on brmon (a bridge
        # zebra has no VNI for) until the monitor has reported it. The
        # assertions only look at MAC's lines.
        ok, _ = topotest.run_and_expect(self._sentinel_seen, True, count=30, wait=0.5)
        net.cmd(f"bridge fdb del {SENTINEL_MAC} dev dmon master static")
        if not ok:
            net.cmd(f"kill {self.pid}")
        assert ok, f"bridge monitor fdb on {pe} did not start: {self.path}"

    def _sentinel_seen(self):
        with open(self.path) as f:
            if any(l.startswith(SENTINEL_MAC) for l in f):
                return True
        net = get_topogen().net[self.pe]
        net.cmd(f"bridge fdb del {SENTINEL_MAC} dev dmon master static")
        net.cmd_raises(f"bridge fdb add {SENTINEL_MAC} dev dmon master static")
        return False

    def stop(self):
        get_topogen().net[self.pe].cmd(f"kill {self.pid}")
        with open(self.path) as f:
            return f.read().splitlines()


def assert_only_vxlan_entry_deleted(
    mon, vni200_untouched=True, pe="PE1", port="PE1-eth1"
):
    """
    During the step, the VXLAN device's entry for VNI 100 to PE2 was deleted
    (so the step did exercise the delete), the bridge's local entry on the
    access port never was, and, where nothing else explains it, neither was
    the MAC's VNI 200 entry.
    """
    lines = mon.stop()
    svd = " src_vni 100" if MODE == "svd" else ""
    want = f"Deleted {MAC} dev {vxlan_dev(100)} dst {VTEP['PE2']}{svd} self"
    assert any(l.startswith(want) for l in lines), f"'{want}' not seen: {lines}"
    deleted = [l for l in lines if l.startswith(f"Deleted {MAC} dev {port} ")]
    assert not deleted, f"bridge's local entry on {pe} {port} deleted: {deleted}"
    assert _bridge_local_entry(pe, port), f"no bridge entry for {MAC} on {pe} {port}"
    if vni200_untouched:
        dev200 = vxlan_dev(200)
        svd200 = " src_vni 200" if MODE == "svd" else ""
        gone = [
            l
            for l in lines
            if l.startswith(f"Deleted {MAC} dev {dev200} ")
            and (MODE != "svd" or svd200 in l or "vlan 20" in l)
        ]
        assert not gone, f"VNI 200 entry of {MAC} deleted: {gone}"


def assert_vni200_intact():
    """The same MAC in VNI 200 is still remote on PE1, with its VXLAN entry to PE2."""
    wait(
        functools.partial(_mac_is, "PE1", 200, "remote", VTEP["PE2"]),
        "PE1 VNI 200 remote",
        60,
    )
    wait(
        lambda: None if vxlan_entries("PE1", 200, VTEP["PE2"]) else "absent",
        "PE1 VNI 200 vxlan entry to PE2",
        60,
    )


def _reread(pe):
    """Make zebra re-read the kernel FDB, as a restart does."""
    r = get_topogen().gears[pe]
    asn = "10" + pe[-1]
    r.vtysh_cmd(
        f"conf\nrouter bgp {asn}\naddress-family l2vpn evpn\nno advertise-all-vni\n"
    )
    r.vtysh_cmd(
        f"conf\nrouter bgp {asn}\naddress-family l2vpn evpn\nadvertise-all-vni\n"
    )


def _plant_leftover():
    """The state a zebra without the fix leaves behind."""
    src_vni = " src_vni 100" if MODE == "svd" else ""
    get_topogen().net["PE1"].cmd_raises(
        f"bridge fdb replace {MAC} dev {vxlan_dev(100)} dst {VTEP['PE2']}{src_vni} "
        "self extern_learn dynamic"
    )


def _no_leftover(what):
    wait(lambda: vxlan_entries("PE1", 100, VTEP["PE2"]) or None, what)


def step_mac_home_on_pe1():
    talk("host1")
    talk("host3")
    wait(functools.partial(_mac_is, "PE1", 100, "local", "PE1-eth1"), "PE1 local")
    wait(functools.partial(_mac_is, "PE2", 100, "remote", VTEP["PE1"]), "PE2 remote")
    assert_vni200_intact()


def step_move_to_pe2_and_back():
    tgen = get_topogen()
    pe1, pe2 = tgen.net["PE1"], tgen.net["PE2"]
    # to PE2, make-before-break
    pe2.cmd_raises("ip link set dev PE2-eth1 up")
    talk("host2")
    pe1.cmd_raises("ip link set dev PE1-eth1 down")
    wait(functools.partial(_mac_is, "PE1", 100, "remote", VTEP["PE2"]), "PE1 remote")
    wait(
        lambda: None if vxlan_entries("PE1", 100, VTEP["PE2"]) else "absent",
        "PE1 vxlan entry to PE2 while the MAC is remote",
    )
    # and back, make-before-break; the monitor starts first, as host1 may
    # send (IPv6 ND) as soon as its link comes up
    mon = FdbMonitor("PE1", "move-back")
    pe1.cmd_raises("ip link set dev PE1-eth1 up")
    talk("host1")
    pe2.cmd_raises("ip link set dev PE2-eth1 down")
    wait(functools.partial(_mac_is, "PE1", 100, "local", "PE1-eth1"), "PE1 local again")
    wait(
        functools.partial(_mac_is, "PE2", 100, "remote", VTEP["PE1"]),
        "PE2 remote again",
    )
    _no_leftover("vxlan entry to PE2 left on PE1")
    assert_only_vxlan_entry_deleted(mon)
    assert_vni200_intact()


def step_fdb_reread_keeps_local_mac():
    _reread("PE1")
    wait(
        functools.partial(_mac_is, "PE1", 100, "local", "PE1-eth1"),
        "PE1 local after re-read",
    )
    wait(
        functools.partial(_mac_is, "PE2", 100, "remote", VTEP["PE1"]),
        "PE2 remote after re-read",
    )
    assert_vni200_intact()


def step_leftover_seen_live_is_removed():
    mon = FdbMonitor("PE1", "leftover-live")
    _plant_leftover()
    _no_leftover("leftover not removed")
    wait(
        functools.partial(_mac_is, "PE1", 100, "local", "PE1-eth1"),
        "PE1 local after leftover",
    )
    wait(
        functools.partial(_mac_is, "PE2", 100, "remote", VTEP["PE1"]),
        "PE2 remote after leftover",
    )
    assert_only_vxlan_entry_deleted(mon)
    assert_vni200_intact()


def step_leftover_across_restart():
    # The production case: the leftover is in the kernel when zebra starts
    tgen = get_topogen()
    mon = FdbMonitor("PE1", "leftover-restart")
    kill_router_daemons(tgen, "PE1", ["bgpd", "zebra"])
    _plant_leftover()
    assert vxlan_entries("PE1", 100, VTEP["PE2"]), "could not plant the leftover"
    start_router_daemons(tgen, "PE1", ["zebra", "bgpd"])
    talk("host1")
    wait(
        functools.partial(_mac_is, "PE1", 100, "local", "PE1-eth1"),
        "PE1 local after restart",
        60,
    )
    _no_leftover("leftover not removed after restart")
    wait(
        functools.partial(_mac_is, "PE2", 100, "remote", VTEP["PE1"]),
        "PE2 remote after restart",
        60,
    )
    # zebra's shutdown uninstalls the VNI 200 entry; assert_vni200_intact()
    # checks that it comes back
    assert_only_vxlan_entry_deleted(mon, vni200_untouched=False)
    assert_vni200_intact()
