#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# ospf_rl_common.py
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
"""Shared helpers for the ospf_resource_limits topotest modules.

Topology (one per module): r1 (victim, DR) and r2 (legit Full peer and
frame injector) on one broadcast segment, area 0.0.0.0.  r2 injects raw
OSPF frames (spoofed source IPs, mapped to r2's MAC via permanent
neighbor entries on r1) while r1's real adjacency must stay Full.

The wire format of the injected frames is identical to the
runtime-confirmation script for this bug class (distinct one-way Hellos
for the neighbor table, distinct valid Type-5 LSAs for the LSDB, a rogue
DD master for ls_req, a rogue held in Exchange for MaxAge GC deferral).
"""

import json
import os
import shlex
import socket
import struct
import sys
import time

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

HELPER = os.path.join(CWD, "inject_ospf.py")

R1_IP = "10.222.20.1"
R2_IP = "10.222.20.2"
R1_RID = "10.255.20.1"
R2_RID = "10.255.20.2"

# Small quotas, applied at runtime; large enough to prove the tables
# grow below the cap and small enough to saturate quickly.
NBR_CAP = 9          # 1 real neighbor + 8 injected
MAX_LSA_CAP = 8
LS_REQ_CAP = 4
GRADES = (4, 8, 12)  # cumulative identities offered, as in the repro

LSA_ADV_RID = "10.255.20.240"
GC_ADV_RID = "10.255.20.241"
REQ_IP = "10.222.20.120"
REQ_RID = "10.255.20.120"
GC_IP = "10.222.20.130"
GC_RID = "10.255.20.130"
INVALID_IP = "10.222.20.99"
INVALID_RID = "10.255.20.99"
DD_BASE_SEQ = 0x00420000
GC_DD_SEQ = 0x00430000
GC_DELETE_TIMEOUT = 75
GC_BLOCKED_HOLD = 68
RECOVERY_TIMEOUT = 20


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="eth1")
    switch.add_link(tgen.gears["r2"], nodeif="eth1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# vtysh helpers (same JSON shapes as the runtime-confirmation script)
# ---------------------------------------------------------------------------


def vty_json(router, command):
    return json.loads(router.vtysh_cmd(command))


def neighbors(router):
    data = vty_json(router, "show ip ospf neighbor json")
    entries = []
    for router_id, values in data.get("neighbors", {}).items():
        for value in values:
            entries.append({"router_id": router_id, **value})
    return entries


def neighbor(router, router_id, source_ip):
    for entry in neighbors(router):
        if entry.get("router_id") == router_id and entry.get("ifaceAddress") == source_ip:
            return entry
    return None


def neighbor_state(entry):
    if entry is None:
        return "Absent"
    return entry.get("converged", entry.get("nbrState", "Unknown"))


def external_entries(router):
    return vty_json(router, "show ip ospf database external json").get(
        "asExternalLinkStates", [])


def external_entry(router, lsa_id):
    for entry in external_entries(router):
        if entry.get("linkStateId") == lsa_id:
            return entry
    return None


def maxage_map(router):
    return vty_json(router, "show ip ospf database max-age json").get(
        "maxAgeLinkStates", {})


def retransmit_total(router):
    return sum(
        entry.get("linkStateRetransmissionListCounter", 0) or 0
        for entry in neighbors(router)
    )


def find_key(value, key):
    "Depth-first search for key anywhere in a decoded JSON value."
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = find_key(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_key(child, key)
            if found is not None:
                return found
    return None


def wait_until(name, predicate, timeout, interval=0.5):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last is True:
            return True
        time.sleep(interval)
    raise AssertionError("timeout waiting for %s: last=%r" % (name, last))


def wait_retrans_quiet(router, quiet=3.0, timeout=30.0):
    "Wait until router has nothing on any retransmission list for `quiet` s."
    deadline = time.monotonic() + timeout
    changed = time.monotonic()
    last = None
    while time.monotonic() < deadline:
        current = retransmit_total(router)
        if current != last:
            last = current
            changed = time.monotonic()
        if last == 0 and time.monotonic() - changed >= quiet:
            return
        time.sleep(0.5)
    raise AssertionError("retransmission lists never went quiet: last=%r" % last)


def real_full():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    return (
        neighbor_state(neighbor(r1, R2_RID, R2_IP)) == "Full"
        and neighbor_state(neighbor(r2, R1_RID, R1_IP)) == "Full"
    )


def require_full(label):
    "Precondition: the real adjacency is Full both ways."
    assert real_full(), "real adjacency not Full at %s" % label


# ---------------------------------------------------------------------------
# injection helpers
# ---------------------------------------------------------------------------


def rogue_identity(index):
    return "10.222.20.%d" % (100 + index), "10.255.20.%d" % (100 + index)


class Injector:
    "Builds frame specs and runs the scapy helper on r2."

    def __init__(self, r2_mac, r1_mac):
        self.r2_mac = r2_mac
        self.r1_mac = r1_mac

    def inject(self, frames):
        r2 = get_topogen().gears["r2"]
        raw = r2.cmd_raises(
            "python3 %s --iface eth1 --frames %s"
            % (shlex.quote(HELPER), shlex.quote(json.dumps(frames)))
        )
        for line in reversed(raw.splitlines()):
            if line.startswith("SENT_JSON="):
                return json.loads(line.split("=", 1)[1])["count"]
        raise RuntimeError("inject helper produced no result: %s" % raw[-500:])

    def hello(self, at, src_ip, router_id, include_target=True, corrupt=False):
        return {
            "kind": "hello", "at": at, "src_ip": src_ip, "router_id": router_id,
            "include_target": include_target, "corrupt": corrupt,
            "multicast": True, "src_mac": self.r2_mac,
        }

    def dd(self, at, src_ip, router_id, seq, flags, headers=()):
        return {
            "kind": "dd", "at": at, "src_ip": src_ip, "router_id": router_id,
            "seq": seq, "flags": flags, "headers": list(headers),
            "multicast": False, "src_mac": self.r2_mac,
            "target_mac": self.r1_mac,
        }

    def lsu_external(self, at, src_ip, router_id, lsa_ids, adv_router, age=1):
        lsas = [
            {"id": lsa_id, "adv_router": adv_router, "age": age}
            for lsa_id in lsa_ids
        ]
        return {
            "kind": "lsu", "at": at, "src_ip": src_ip, "router_id": router_id,
            "lsas": lsas, "multicast": False, "src_mac": self.r2_mac,
            "target_mac": self.r1_mac,
        }

    def ack(self, at, src_ip, router_id, lsa_id, adv_router, age=3600):
        return {
            "kind": "ack", "at": at, "src_ip": src_ip, "router_id": router_id,
            "lsa": {"id": lsa_id, "adv_router": adv_router, "age": age},
            "multicast": False, "src_mac": self.r2_mac,
            "target_mac": self.r1_mac,
        }


def header_hex(lsa_id, adv_router):
    "20-byte Type-5 LSA header hex for DD injection (same LSA as inject_ospf)."
    body = (
        socket.inet_aton("255.255.255.0")
        + b"\x80\x00\x00\x14"
        + socket.inet_aton("0.0.0.0")
        + struct.pack("!I", 0)
    )
    lsa = bytearray(
        struct.pack(
            "!HBB4s4sIHH",
            1, 0x02, 5, socket.inet_aton(lsa_id),
            socket.inet_aton(adv_router), 0x80000001, 0, 36,
        )
        + body
    )
    return bytes(lsa[:20]).hex()


def make_injector():
    "Fixture body: MAC discovery plus permanent neighbor entries on r1."
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r2_mac = r2.cmd("cat /sys/class/net/eth1/address").strip()
    r1_mac = r1.cmd("cat /sys/class/net/eth1/address").strip()
    source_ips = [INVALID_IP, REQ_IP, GC_IP, "10.222.20.199"] + [
        rogue_identity(index)[0] for index in range(GRADES[-1])
    ]
    for source_ip in source_ips:
        r1.cmd_raises(
            "ip neigh replace %s lladdr %s dev eth1 nud permanent"
            % (source_ip, r2_mac)
        )
    return Injector(r2_mac, r1_mac)


def apply_limit(r1, command):
    "Apply a router ospf limit; return True iff the running ospfd kept it."
    r1.vtysh_cmd("configure terminal\nrouter ospf\n%s\nend" % command)
    running = r1.vtysh_cmd("show running-config")
    return command.split()[0] in running


def baseline(tgen):
    "Skip guard plus baseline Full/ping checks; returns (r1, r2, inj)."
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r1.expect_ospfv2_neighbor(R2_RID)
    tgen.gears["r2"].expect_ospfv2_neighbor(R1_RID)
    ping = r1.cmd("ping -c 2 -W 1 %s" % R2_IP)
    assert "2 received" in ping, "baseline ping failed: %s" % ping
    inj = make_injector()
    return r1, tgen.gears["r2"], inj
