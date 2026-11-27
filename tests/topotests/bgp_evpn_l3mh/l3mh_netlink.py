# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Cisco Systems, Inc.

from contextlib import contextmanager
import subprocess

NEIGH_ADD, NEIGH_DELETE = 28, 29
NUD_FAILED = 0x20
NUD_NOARP, NUD_PERMANENT = 0x40, 0x80
FDB_STATIC = NUD_NOARP | NUD_PERMANENT

WATCH_BINDING = """
import select
import socket
import struct
import sys

ip, mac, vlan, *probe = sys.argv[1:]
svi = socket.if_nametoindex(f"vlan{vlan}")
port = socket.if_nametoindex("hostbond1")
address_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
address = socket.inet_pton(address_family, ip)
mac = bytes.fromhex(mac.replace(":", ""))
tag = struct.pack("=H", int(vlan))
with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as netlink:
    netlink.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    netlink.bind((0, 4))  # RTMGRP_NEIGH
    netlink.setblocking(False)
    print("ready", flush=True)
    sources = [netlink] if probe else [netlink, sys.stdin]
    done = False
    while not done:
        ready, _, _ = select.select(sources, [], [])
        done = sys.stdin in ready
        # Drain notifications even if the stop signal arrived in the same poll.
        while True:
            try:
                messages = netlink.recv(65536)
            except BlockingIOError:
                break
            while len(messages) >= 28:
                length, kind = struct.unpack_from("=IH", messages)
                message, messages = messages[:length], messages[(length + 3) & ~3:]
                family, _, _, index, state = struct.unpack_from("=BBHiH", message, 16)
                if kind not in (28, 29):  # RTM_NEWNEIGH, RTM_DELNEIGH
                    continue
                neighbor = family == address_family and index == svi
                fdb = family == 7 and index == port  # AF_BRIDGE
                if not (neighbor or fdb):
                    continue
                attrs = message[28:]
                values = {}
                while len(attrs) >= 4:
                    size, key = struct.unpack_from("=HH", attrs)
                    assert size >= 4
                    values[key] = attrs[4:size]
                    attrs = attrs[(size + 3) & ~3:]
                if neighbor and values.get(1) == address:  # NDA_DST
                    if probe and kind == 28 and state == 16:  # NUD_PROBE
                        sys.exit(0)
                    if not probe:
                        print(0, kind, state)
                if not probe and fdb and values.get(2) == mac and values.get(5) == tag:
                    print(1, kind, state)  # NDA_LLADDR, NDA_VLAN
    assert sys.stdin.readline()
"""


@contextmanager
def watch_binding(leaf, entry, *, expect_probe=False):
    """Collect this binding's kernel IP neighbor and FDB events."""
    ip, mac, vid = entry
    args = ["python3", "-c", WATCH_BINDING, ip, mac, str(vid)]
    if expect_probe:
        args.append("probe")
    with leaf.popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as monitor:
        try:
            assert monitor.stdout.readline() == "ready\n"
            changes = []
            yield changes
            output, error = monitor.communicate(
                None if expect_probe else "done\n", timeout=10
            )
            assert monitor.returncode == 0, error
            changes.extend(
                tuple(map(int, line.split())) for line in output.splitlines()
            )
        finally:
            if monitor.poll() is None:
                monitor.terminate()


@contextmanager
def observe_probe(leaf, entry):
    """Observe the kernel probe started by the action in the context."""
    with watch_binding(leaf, entry, expect_probe=True):
        yield


@contextmanager
def check_fdb_delete(leaf, entry, deleted=False):
    with watch_binding(leaf, entry) as changes:
        yield
    assert any(fdb and op == NEIGH_DELETE for fdb, op, _ in changes) is deleted, (
        leaf.name,
        entry,
        changes,
    )


@contextmanager
def check_static_fdb(leaf, entry, *, permanent_arp=False):
    with watch_binding(leaf, entry) as changes:
        yield
    for fdb, op, state in changes:
        if fdb:
            assert op == NEIGH_ADD and state & FDB_STATIC, (leaf.name, entry, changes)
        elif permanent_arp:
            assert op == NEIGH_ADD and state == NUD_PERMANENT, (
                leaf.name,
                entry,
                changes,
            )


@contextmanager
def check_probe(leaf, entry):
    # The fixture keeps retransmits beyond this event window. A new neighbor
    # notification would reveal a replacement or a restart of this probe.
    with watch_binding(leaf, entry) as changes:
        yield
    assert not changes, (leaf.name, entry, changes)


def has_dynamic_fdb(leaf, entry):
    _, mac, vid = entry
    lines = leaf.cmd_raises(f"bridge fdb show dev hostbond1 vlan {vid}").splitlines()
    return any(
        fields[0] == mac and not {"static", "permanent"}.intersection(fields)
        for fields in (line.split() for line in lines)
        if fields
    )
