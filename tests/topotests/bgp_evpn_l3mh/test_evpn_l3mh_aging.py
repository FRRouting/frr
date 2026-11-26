# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Cisco Systems, Inc.

from contextlib import ExitStack, contextmanager, nullcontext
import json
import subprocess

import pytest

import test_evpn_l3mh as l3mh
from l3mh_netlink import (
    NEIGH_ADD,
    NUD_FAILED,
    check_probe,
    check_static_fdb,
    observe_probe,
    watch_binding,
)
from test_evpn_l3mh_port_events import (
    PORT,
    PROTECTION,
    VID,
    events,
    setup_module,
    teardown_module,
)

pytestmark = l3mh.pytestmark

ARP_WIRE = """
import socket
import struct
import sys

iface, address, host_mac, target_mac, *opcode = sys.argv[1:]
host_mac = bytes.fromhex(host_mac.replace(":", ""))
address = socket.inet_aton(address)
eth_arp = 0x0806
operation = int(opcode[0]) if opcode else 2
header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(eth_arp)) as wire:
    wire.bind((iface, eth_arp))
    if target_mac:
        target = bytes.fromhex(target_mac.replace(":", ""))
        target_ip = socket.inet_aton("45.0.0.1")
    else:
        # Observe a unicast request for the synthetic MAC on this bond member.
        membership = struct.pack("=IHH8s", socket.if_nametoindex(iface), 1, 0, b"")
        wire.setsockopt(263, 1, membership)  # SOL_PACKET, PACKET_ADD_MEMBERSHIP
        wire.settimeout(20)
        print("ready", flush=True)
        while True:
            frame = wire.recv(2048)
            if frame[:6] == host_mac and frame[20:22] == b"\\0\\1" and frame[38:42] == address:
                target, target_ip = frame[22:28], frame[28:32]
                break
        assert sys.stdin.buffer.read(1) == b"y"
    target_hw = bytes(6) if operation == 1 else target
    wire.send(target + host_mac + struct.pack("!H", eth_arp) + header
              + host_mac + address + target_hw + target_ip)
"""

USE_NEIGHBOR = """
import socket
import sys

vrf, address = sys.argv[1:]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
with socket.socket(family, socket.SOCK_DGRAM) as traffic:
    traffic.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, vrf.encode() + b"\\0")
    traffic.sendto(b"neighbor use", (address, 9))
"""

ND_WIRE = """
import socket
import struct
import sys
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import Ether

member, ip, mac = sys.argv[1:]
eth_ipv6 = 0x86dd
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(eth_ipv6)) as wire:
    wire.bind((member, eth_ipv6))
    membership = struct.pack("=IHH8s", socket.if_nametoindex(member), 1, 0, b"")
    wire.setsockopt(263, 1, membership)  # SOL_PACKET, PACKET_ADD_MEMBERSHIP
    wire.settimeout(20)
    print("ready", flush=True)
    while True:
        frame = Ether(wire.recv(2048))
        if frame.dst == mac and ICMPv6ND_NS in frame and frame[ICMPv6ND_NS].tgt == ip:
            break
    assert sys.stdin.buffer.read(1) == b"y"
    reply = (
        Ether(src=mac, dst=frame.src)
        / IPv6(src=ip, dst=frame[IPv6].src, hlim=255)
        / ICMPv6ND_NA(tgt=ip, R=0, S=1, O=1)
        / ICMPv6NDOptDstLLAddr(lladdr=mac)
    )
    wire.send(bytes(reply))
"""


@contextmanager
def answer_nd_probe(entry, member):
    host = l3mh.get_topogen().gears["host1"]
    ip, mac, _ = entry
    with host.popen(
        ["python3", "-c", ND_WIRE, member, ip, mac],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as wire:
        try:
            assert wire.stdout.readline() == "ready\n", wire.stderr.read()
            yield
            _, error = wire.communicate("y", timeout=25)
            assert not wire.returncode, error
        finally:
            if wire.poll() is None:
                wire.terminate()


@pytest.mark.parametrize("events", ("ipv6",), indirect=True)
@pytest.mark.parametrize("protected", (False, True), ids=("unprotected", "protected"))
def test_nd_unicast_handoff_and_port_up_validation(events, protected):
    owner, peer, other = events.leaves
    if not protected:
        owner.vtysh_cmd(
            f"configure terminal\ninterface {PORT}\n no {PROTECTION}", raises=True
        )
    entry = events.binding(168)
    events.learn(owner, entry)
    events.settle()
    assert events.route(owner, entry)
    for leaf in (peer, other):
        events.status(entry, "PERMANENT", leaf)
        assert l3mh._mac_static_pinned(leaf, entry[1], VID)

    with answer_nd_probe(entry, "host1-eth1"):
        events.flap("down")
        detail = events.status(entry, "PERMANENT")
        assert detail["l3mhState"] == "handoff-wait", detail
        assert detail["timerState"] == "down-peering", detail
        assert events.pinned(entry) and events.route(owner, entry)
        for leaf in (peer, other):
            events.status(entry, "PROBE", leaf)
            assert not l3mh._mac_static_pinned(leaf, entry[1], VID)
            assert not events.route(leaf, entry, owner)
    events.settle()
    assert events.status(entry, "REACHABLE", peer)["l3mhState"] == "local-dynamic"
    assert events.route(peer, entry, owner) and not events.route(owner, entry)
    for leaf in (owner, other):
        detail = events.status(entry, "PERMANENT", leaf)
        assert detail["l3mhState"] == "peer-sync-protected", detail
        assert detail["peerOrigin"] == l3mh.LEAF_LO[peer.name], detail
        assert detail["timerState"] == "inactive", detail
        assert l3mh._mac_static_pinned(leaf, entry[1], VID)
    assert not events.route(other, entry, peer)

    with answer_nd_probe(entry, "host1-eth0"):
        events.flap("up")
        detail = events.status(entry, "PROBE")
        assert detail["l3mhState"] == "validation-pending", detail
        assert not events.pinned(entry) and not events.route(owner, entry)
    events.settle()
    assert events.status(entry, "REACHABLE")["l3mhState"] == "local-dynamic"
    assert events.route(owner, entry) and not events.pinned(entry)


def send_arp(leaf, entry, member, mac=None, request=False):
    host = l3mh.get_topogen().gears["host1"]
    host.cmd_raises(
        [
            "python3",
            "-c",
            ARP_WIRE,
            member,
            entry[0],
            mac or entry[1],
            "ff:ff:ff:ff:ff:ff"
            if request
            else l3mh._bridge_mac(l3mh.LEAF_LO[leaf.name]),
            "1" if request else "2",
        ]
    )


@pytest.mark.parametrize(
    "shared", (False, True), ids=("dynamic-mac", "shared-static-mac")
)
def test_real_unicast_reply_resolves_only_the_receiving_leaf(events, shared):
    owner, receiver, observer = events.leaves
    tgen = l3mh.get_topogen()
    host = tgen.gears["host1"]
    entry = events.binding(135)
    late = events.binding(139)
    sibling = events.binding(140, entry[1])
    companion = events.binding(156, entry[1])
    for binding in (entry, late):
        events.learn(owner, binding)
    events.settle()
    assert events.route(owner, entry)
    for leaf in (receiver, observer):
        events.status(entry, "PERMANENT", leaf)

    speaker = (
        l3mh._raw_evpn_peer(receiver, tgen.gears["leaf3"], sibling[1], sibling[0])
        if shared
        else nullcontext()
    )
    with speaker as send, host.popen(
        ["python3", "-c", ARP_WIRE, "host1-eth1", entry[0], entry[1], ""],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as wire:
        try:
            assert wire.stdout.readline() == "ready\n"
            if shared:
                send(f"announce 0 {l3mh.L3VNI}")
                events.settle()
                events.status(sibling, "PERMANENT", receiver)
            events.flap("down")
            for leaf in (receiver, observer):
                events.status(entry, "PROBE", leaf)
                assert not events.route(leaf, entry, owner)
            assert l3mh._mac_static_pinned(receiver, entry[1], VID) is shared
            if not shared:
                events.arp(receiver, companion)
            with check_static_fdb(receiver, entry) if shared else nullcontext():
                _, error = wire.communicate("y", timeout=25)
                assert not wire.returncode, error
                events.settle()
            assert events.route(receiver, entry)
            assert l3mh._mac_static_pinned(receiver, entry[1], VID) is shared
            if shared:
                events.status(sibling, "PERMANENT", receiver)
            else:
                events.status(companion, "REACHABLE", receiver)
                assert events.route(receiver, companion)
        finally:
            if wire.poll() is None:
                wire.terminate()

    if shared:
        l3mh._relearn_local_fdb(receiver, entry[1], leaves=events.leaves)
    events.settle()
    assert events.route(receiver, entry)
    events.status(entry, "REACHABLE", receiver)
    detail = events.status(entry, "PERMANENT", observer)
    assert detail.get("peerOrigin") == l3mh.LEAF_LO[receiver.name], detail
    assert not events.route(observer, entry, receiver)

    # A late reply on the other leg cannot change an installed permanent ARP.
    send_arp(observer, entry, "host1-eth2", mac="02:00:00:00:01:ff")
    events.settle()
    events.status(entry, "PERMANENT", observer)
    assert l3mh._mac_static_pinned(observer, entry[1], VID)
    assert not events.route(observer, entry, receiver)

    # A late reply can still learn once a failed probe has left a dynamic slot.
    events.status(late, "PROBE", receiver)
    events.arp(receiver, late, "failed")
    events.settle()
    assert not events.route(receiver, late)
    assert not l3mh._mac_static_pinned(receiver, late[1], VID)
    send_arp(receiver, late, "host1-eth1")
    events.settle()
    events.status(late, "REACHABLE", receiver)
    assert events.route(receiver, late)


@pytest.mark.parametrize(
    "events,fdb_start",
    (
        pytest.param("ipv4", "existing-fdb", id="existing-fdb"),
        pytest.param("ipv4", "missing-fdb", id="missing-fdb"),
        pytest.param("ipv4", "shared-static", id="shared-static"),
        ("ipv6", "existing-fdb"),
    ),
    indirect=("events",),
)
def test_kernel_aging_and_fallback_during_ordinary_probe(events, fdb_start):
    owner, peer, _ = events.leaves
    aging, idle, static = (events.binding(i) for i in (136, 137, 138))
    idle_with_peer = events.binding(153)
    svi = f"vlan{VID}"
    sysctl = f"net.{events.family}.neigh.{svi}"
    delay = f"{sysctl}.delay_first_probe_time"
    original = owner.cmd_raises(f"sysctl -n {delay}").strip()
    try:
        # Hold DELAY until the explicit PROBE update.
        owner.cmd_raises(f"sysctl -qw {delay}=60")
        bridge = json.loads(owner.cmd_raises("ip -d -j link show dev br_default"))[0]
        reachable_ms = int(
            owner.cmd_raises(f"sysctl -n {sysctl}.base_reachable_time_ms")
        )
        # iproute2 reports the FDB timer in hundredths of a second. Linux
        # randomizes reachable time up to one and a half times the base.
        assert bridge["linkinfo"]["info_data"]["ageing_time"] * 10 > 1.5 * reachable_ms
        for entry in (aging, idle, idle_with_peer):
            events.learn(owner, entry)
        events.learn(peer, static)
        events.settle()
        events.status(aging, "REACHABLE")
        events.status(static, "PERMANENT")
        assert events.pinned(static)
        assert events.route(owner, aging) and events.route(owner, idle)
        assert aging[1] in owner.cmd_raises(f"bridge fdb show dev {PORT}")

        for entry in (aging, idle, idle_with_peer):
            events.arp(owner, entry, "stale")
            events.status(entry, "STALE")
        owner.cmd_raises(["python3", "-c", USE_NEIGHBOR, l3mh.VRF, aging[0]])
        events.status(aging, "DELAY")
        events.arp(owner, aging, "probe")
        events.status(aging, "PROBE")

        with check_probe(owner, aging):
            events.arp(peer, aging)
            events.arp(peer, idle_with_peer)
            l3mh._relearn_local_fdb(peer, aging[1], leaves=events.leaves)
            events.fdb(peer, idle_with_peer)
            events.settle()
        detail = events.status(aging, "PROBE")
        assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
        assert events.route(owner, aging) and events.route(peer, aging)
        detail = events.status(idle_with_peer, "STALE")
        assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
        assert events.route(owner, idle_with_peer)

        missing_fdb = fdb_start == "missing-fdb"
        if missing_fdb:
            for entry in (aging, idle_with_peer, idle):
                events.fdb(owner, entry, "del")
            events.settle()
            fdb = owner.cmd_raises(f"bridge fdb show dev {PORT}")
            assert idle[1] not in fdb and not events.route(owner, idle)
            assert not events.status(idle, "STALE").get("peerActive")
            for entry, state in ((aging, "PROBE"), (idle_with_peer, "STALE")):
                assert entry[1] not in fdb
                assert not events.route(owner, entry)
                assert events.route(peer, entry, owner)
                detail = events.status(entry, state)
                assert detail.get("peerActive"), detail

        siblings = ()
        if fdb_start == "shared-static":
            siblings = (
                events.binding(170, aging[1]),
                events.binding(171, idle_with_peer[1]),
            )
            for sibling in siblings:
                events.arp(peer, sibling)
            events.settle()
            for sibling in siblings:
                events.status(sibling, "PERMANENT")
                assert events.pinned(sibling) and events.route(peer, sibling)
            events.status(aging, "PROBE")
            events.status(idle_with_peer, "STALE")

        with ExitStack() as observers:
            for sibling in siblings:
                observers.enter_context(
                    check_static_fdb(owner, sibling, permanent_arp=True)
                )
            if missing_fdb:
                idle_changes = observers.enter_context(watch_binding(owner, idle))
            events.status(idle, "STALE")
            events.arp(owner, aging, "failed")
            # A kernel delete reports the same event to Zebra as idle GC.
            for entry in (idle, idle_with_peer):
                events.delete_arp(owner, entry)
            events.settle()
        detail = events.status(aging, "PERMANENT")
        assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
        assert events.pinned(aging) and not events.route(owner, aging)
        if missing_fdb:
            assert not any(fdb for fdb, _, _ in idle_changes), idle_changes
        for sibling in siblings:
            events.status(sibling, "PERMANENT")
            assert events.pinned(sibling) and events.route(peer, sibling)
        events.status(idle)
        assert not events.route(owner, idle)
        assert (
            idle[1] in owner.cmd_raises(f"bridge fdb show dev {PORT}")
        ) is not missing_fdb
        detail = events.status(idle_with_peer, "PERMANENT")
        assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
        assert events.pinned(idle_with_peer) and not events.route(owner, idle_with_peer)
        events.status(static, "PERMANENT")
        assert events.pinned(static) and events.route(peer, static)
    finally:
        owner.cmd_raises(f"sysctl -qw {delay}={original}")


@pytest.mark.parametrize(
    "trigger", ("rt1-withdrawal", "rt1-withdrawal-shared", "last-rt2-withdrawal")
)
def test_probe_failure_and_kernel_delete(events, trigger):
    owner, peer, _ = events.leaves
    retained = trigger != "last-rt2-withdrawal"
    shared = trigger == "rt1-withdrawal-shared"
    source, receiver = (owner, peer) if retained else (peer, owner)
    codes = {
        "rt1-withdrawal": 148,
        "rt1-withdrawal-shared": 157,
        "last-rt2-withdrawal": 141,
    }
    entry = events.binding(codes[trigger])
    sibling = events.binding(158, entry[1])
    events.learn(source, entry)
    events.settle()
    events.status(entry, "PERMANENT", receiver)
    # The sibling's RT-2 must stay usable independently of the failed link.
    speaker = (
        l3mh._raw_evpn_peer(
            receiver, l3mh.get_topogen().gears["leaf3"], sibling[1], sibling[0]
        )
        if shared
        else nullcontext()
    )
    with speaker as send:
        if shared:
            send(f"announce 0 {l3mh.L3VNI}")
            events.settle()
            events.status(sibling, "PERMANENT", receiver)
        with observe_probe(receiver, entry):
            if retained:
                owner.cmd_raises(f"ip link set dev {PORT} down")
            else:
                events.delete_arp(source, entry)
        events.status(entry, "PROBE", receiver)
        events.arp(receiver, entry, "failed")
        events.settle()
        events.status(entry, "FAILED", receiver)
        if shared:
            events.status(sibling, "PERMANENT", receiver)
        assert l3mh._mac_static_pinned(receiver, entry[1], VID) is shared
        assert (
            entry[1] in receiver.cmd_raises(f"bridge fdb show dev {PORT}")
        ) is shared
        assert not events.route(receiver, entry)
        assert bool(events.route(source, entry, receiver)) is retained
        events.delete_arp(receiver, entry)
        events.settle()
        events.status(entry, leaf=receiver)
        if shared:
            events.status(sibling, "PERMANENT", receiver)
            assert l3mh._mac_static_pinned(receiver, entry[1], VID)
        assert not events.route(receiver, entry)
        assert bool(events.route(source, entry, receiver)) is retained


def test_real_reply_during_ordinary_aging_keeps_or_restores_rt2(events):
    owner = events.owner
    keep, relearn = (events.binding(i) for i in (142, 143))
    for entry in (keep, relearn):
        events.learn(owner, entry)
    events.settle()
    version = l3mh._local_rt2_version(owner, keep[0])
    assert version is not None and events.route(owner, relearn)

    for entry in (keep, relearn):
        events.arp(owner, entry, "probe")
        events.status(entry, "PROBE")
    events.fdb(owner, relearn, "del")
    events.settle()
    assert not events.route(owner, relearn)
    assert l3mh._local_rt2_version(owner, keep[0]) == version

    for entry in (keep, relearn):
        send_arp(owner, entry, "host1-eth0")
    events.settle()
    for entry in (keep, relearn):
        events.status(entry, "REACHABLE")
        assert events.route(owner, entry)
    assert l3mh._local_rt2_version(owner, keep[0]) == version


@pytest.mark.parametrize("events", ("ipv4", "ipv6"), indirect=True)
def test_retained_port_up_probe_failure_and_kernel_delete(events):
    owner = events.owner
    entry = events.binding(162)
    events.learn(owner, entry)
    events.settle()
    events.flap("down")
    events.status(entry, "PERMANENT")
    assert events.pinned(entry) and events.route(owner, entry)
    with observe_probe(owner, entry):
        owner.cmd_raises(f"ip link set dev {PORT} up")
    events.status(entry, "PROBE")
    assert events.route(owner, entry)
    with watch_binding(owner, entry) as changes:
        events.arp(owner, entry, "failed")
        events.settle()
    assert (0, NEIGH_ADD, NUD_FAILED) in changes, changes
    assert not events.route(owner, entry)
    assert entry[1] not in owner.cmd_raises(f"bridge fdb show dev {PORT}")
    # The kernel may collect the failed entry before the readback.
    kernel = owner.cmd_raises(f"ip neigh show to {entry[0]} dev vlan{VID}").split()
    assert not kernel or "FAILED" in kernel, kernel
    owner.run(f"ip neigh del {entry[0]} dev vlan{VID} 2>/dev/null")
    events.settle()
    assert not events.status(entry).get("ip")
    assert not events.route(owner, entry)


@pytest.mark.parametrize("source", ("retained", "peer-backed"))
def test_port_up_validation_with_wire_replies(events, source):
    owner, peer, _ = events.leaves
    retained = source == "retained"
    shared, dynamic = (events.binding(i) for i in (149, 150))
    sibling = events.binding(151, shared[1])
    companion = events.binding(152, dynamic[1])
    entries = (shared, dynamic)
    for entry in entries:
        events.learn(owner if retained else peer, entry)
    events.settle()
    versions = {entry: l3mh._local_rt2_version(owner, entry[0]) for entry in entries}
    assert all((version is not None) is retained for version in versions.values())

    events.flap("down")
    for entry in entries:
        events.status(entry, "PERMANENT")
        assert events.pinned(entry)
    events.flap("up")
    for entry in entries:
        detail = events.status(entry, "PROBE")
        assert detail.get("timerState") == "inactive", detail
        assert bool(events.route(owner, entry)) is retained
        assert not events.pinned(entry)

    events.learn(peer, sibling)
    events.arp(owner, companion)
    events.settle()
    events.status(sibling, "PERMANENT")
    events.status(companion, "REACHABLE")
    assert events.pinned(shared) and not events.route(owner, companion)
    assert dynamic[1] not in owner.cmd_raises(f"bridge fdb show dev {PORT}")

    with check_static_fdb(owner, shared):
        for entry in entries:
            send_arp(owner, entry, "host1-eth0")
        events.settle()
    for entry in entries:
        detail = events.status(entry, "REACHABLE")
        assert detail.get("l3mhState") == "local-dynamic", detail
        assert events.route(owner, entry)
        if retained:
            assert l3mh._local_rt2_version(owner, entry[0]) == versions[entry]
        else:
            assert detail.get("peerOrigin") == l3mh.LEAF_LO[peer.name], detail
    assert events.pinned(shared) and not events.pinned(dynamic)
    assert dynamic[1] in owner.cmd_raises(f"bridge fdb show dev {PORT}")
    events.status(sibling, "PERMANENT")
    events.status(companion, "REACHABLE")
    assert events.route(owner, companion)
