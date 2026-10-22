#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_nssa_translator_phantom.py
# Part of NetDEF Topology Tests
#

"""
test_ospf_nssa_translator_phantom.py: NSSA translator election must ignore
phantom (unreachable) Router-LSAs.

RFC 3101 Section 3.1 restricts the Type-7 translator election to NSSA
border routers that are reachable over the NSSA.  ospfd's
ospf_abr_nssa_am_elected() instead scanned the raw Router-LSDB: it did not
skip MaxAge LSAs and did not check SPF reachability, so any attacker with
an adjacency inside the NSSA could inject a phantom Router-LSA (B-bit with
a higher router ID, or B-bit plus Nt) and make every real ABR believe it
lost the election.  All 7-to-5 translation then stopped and the NSSA's
external prefixes disappeared from the backbone.

Topology (mirrors the original reproducer):

            area 0.0.0.1 (NSSA)              area 0.0.0.0
   r1 (ASBR) -------------- r2 (ABR) -------------------- r3 (observer)
   redistribute connected   translate-candidate

The test:
  1. proves the baseline (Full adjacencies, elected translator, Type-7 to
     Type-5 translation, observer route) and its no-attack stability,
  2. runs the controls: a corrupt Fletcher checksum is rejected, and a
     valid high-RID Router-LSA without the B-bit is installed but does not
     touch the election,
  3. injects the phantom Router-LSAs (B-bit with the highest RID, then
     B-bit+Nt with a lower RID) and asserts the election, the existing
     Type-5, the observer route and the translation of a new prefix all
     survive,
  4. flushes the phantoms and verifies full recovery.
"""

import os
import re
import socket
import struct
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd]

NSSA_AREA = "0.0.0.1"
ASBR_RID = "10.255.9.1"
ABR_RID = "10.255.9.2"
OBSERVER_RID = "10.255.9.3"
ASBR_IP = "10.209.9.1"
ABR_NSSA_IP = "10.209.9.2"

CONTROL_RID = "10.255.255.253"
HIGH_RID = "10.255.255.254"
NT_RID = "10.0.0.9"

TARGET = "198.51.100.9"
TARGET_PREFIX = TARGET + "/32"
HIGH_PROBE = "198.51.100.109"
NT_PROBE = "198.51.100.110"
FINAL_PROBE = "198.51.100.111"

ROUTER_LSA_BORDER = 0x01
ROUTER_LSA_NT = 0x10
LSA_OPTIONS_NSSA = 0x08
HIGH_SEQ = 0x80001001
CONTROL_SEQ = 0x80002001
NT_SEQ = 0x80003001
MAX_AGE = 3600

SCAPY_SEND = r"""
import sys
from scapy.all import Ether, IP, Raw, sendp
iface, src_mac, dst_mac, src_ip, dst_ip, payload_hex = sys.argv[1:]
payload = bytes.fromhex(payload_hex)
frame = (Ether(src=src_mac, dst=dst_mac)
         / IP(src=src_ip, dst=dst_ip, proto=89, ttl=1)
         / Raw(payload))
sendp(frame, iface=iface, count=1, verbose=False)
print("sent=1")
"""


def build_topo(tgen):
    "Build function"
    for r in ("r1", "r2", "r3"):
        tgen.add_router(r)
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth0")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth0")
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth1")
    switch.add_link(tgen.gears["r3"], nodeif="r3-eth0")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for router in tgen.routers().values():
        router.load_frr_config()
    tgen.start_router()

    helper = os.path.join(tgen.logdir, "scapy_send.py")
    with open(helper, "w") as fp:
        fp.write(SCAPY_SEND)

    # Bound the MaxAge removal delay so phantom flushes complete quickly.
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nrouter ospf\nospf maxage-delay 5\nend"
    )


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


#
# State sampling helpers
#


def _find_lsa(value, ls_id, adv_router):
    if isinstance(value, dict):
        if (
            value.get("linkStateId") == ls_id
            and value.get("advertisingRouter") == adv_router
            and "lsaAge" in value
        ):
            return value
        for child in value.values():
            found = _find_lsa(child, ls_id, adv_router)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_lsa(child, ls_id, adv_router)
            if found is not None:
                return found
    return None


def _active(lsa):
    return lsa is not None and int(lsa["lsaAge"]) < MAX_AGE


def _type5(node, prefix=TARGET):
    "r2's translated Type-5 for prefix (advertised by the ABR)."
    data = (
        get_topogen()
        .gears[node]
        .vtysh_cmd("show ip ospf database external {} json".format(prefix), isjson=True)
    )
    return _find_lsa(data, prefix, ABR_RID)


def _type7(node, prefix=TARGET):
    "r1's Type-7 for prefix."
    data = (
        get_topogen()
        .gears[node]
        .vtysh_cmd(
            "show ip ospf database nssa-external {} json".format(prefix), isjson=True
        )
    )
    return _find_lsa(data, prefix, ASBR_RID)


def _phantom(node, rid):
    data = (
        get_topogen()
        .gears[node]
        .vtysh_cmd("show ip ospf database router {} json".format(rid), isjson=True)
    )
    return _find_lsa(data, rid, rid)


def _translator_elected():
    data = get_topogen().gears["r2"].vtysh_cmd("show ip ospf json", isjson=True)
    area = data.get("areas", {}).get(NSSA_AREA, {})
    return area.get("nssaTranslatorElected") is True


def _observer_route(prefix):
    out = get_topogen().gears["r3"].cmd("ip route show {}".format(prefix))
    return bool(out.strip())


def _neighbor_full(node, peer_rid):
    data = (
        get_topogen().gears[node].vtysh_cmd("show ip ospf neighbor json", isjson=True)
    )
    neighbors = data.get("neighbors", {}).get(peer_rid, [])
    return bool(neighbors) and neighbors[0].get("converged") == "Full"


def _full_adjacencies():
    return (
        _neighbor_full("r1", ABR_RID)
        and _neighbor_full("r2", ASBR_RID)
        and _neighbor_full("r2", OBSERVER_RID)
        and _neighbor_full("r3", ABR_RID)
    )


def _ls_update_input():
    data = (
        get_topogen()
        .gears["r2"]
        .vtysh_cmd("show ip ospf interface traffic json", isjson=True)
    )
    return data["r2-eth0"]["lsUpdIn"]


def _type5_seq():
    lsa = _type5("r2")
    return lsa["lsaSeqNumber"] if _active(lsa) else None


def _wait_type5_seq_stable():
    "Post-convergence re-origination settles: seq constant across 3 samples."
    last = None
    stable = 0
    for _ in range(30):
        seq = _type5_seq()
        if seq is not None and seq == last:
            stable += 1
            if stable >= 3:
                return seq
        else:
            stable = 0
        last = seq
        time.sleep(1)
    raise AssertionError("Type-5 sequence did not settle")


def _translation_baseline_ready():
    "None once the full baseline (adjacencies, election, translation, route) holds."
    if not _full_adjacencies():
        return "adjacencies not Full"
    if not _translator_elected():
        return "translator not elected"
    if not (_active(_type7("r1")) and _active(_type7("r2"))):
        return "Type-7 missing on r1/r2"
    type5 = _type5("r2")
    if not _active(type5):
        return "translated Type-5 missing on r2"
    if not type5.get("translatedFromType7"):
        return "Type-5 not marked translatedFromType7"
    if not _active(_type5("r3")):
        return "Type-5 missing on r3"
    if not _observer_route(TARGET_PREFIX):
        return "observer route missing"
    return None


def _translation_unchanged(baseline_seq):
    "None while election, Type-5 sequence, route and adjacencies all hold."
    if not _translator_elected():
        return "translator no longer elected"
    if _type5_seq() != baseline_seq:
        return "Type-5 sequence changed"
    if not (_active(_type5("r2")) and _active(_type5("r3"))):
        return "Type-5 no longer active"
    if not _observer_route(TARGET_PREFIX):
        return "observer route withdrawn"
    if not _full_adjacencies():
        return "adjacencies not Full"
    return None


#
# Raw packet construction (byte-identical to the original reproducer)
#


def _internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _fletcher_checksum(lsa):
    data = bytearray(lsa[2:])
    data[14:16] = b"\x00\x00"
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    x = ((len(data) - 14 - 1) * c0 - c1) % 255
    if x == 0:
        x = 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    return (x << 8) | y


def _make_router_lsa(rid, flags, sequence, age, corrupt_checksum=False):
    lsa = bytearray(
        struct.pack(
            "!HBB4s4sIHHBBH",
            age,
            LSA_OPTIONS_NSSA,
            1,
            socket.inet_aton(rid),
            socket.inet_aton(rid),
            sequence,
            0,
            24,
            flags,
            0,
            0,
        )
    )
    struct.pack_into("!H", lsa, 16, _fletcher_checksum(lsa))
    data = bytearray(lsa[2:])
    c0 = 0
    c1 = 0
    for value in data:
        c0 = (c0 + value) % 255
        c1 = (c1 + c0) % 255
    assert (c0, c1) == (0, 0), "generated Router-LSA checksum invalid"
    if corrupt_checksum:
        lsa[16] ^= 0x5A
    return bytes(lsa)


def _make_update(rid, flags, sequence, age=1, corrupt_checksum=False):
    lsa = _make_router_lsa(rid, flags, sequence, age, corrupt_checksum)
    packet = bytearray(
        struct.pack(
            "!BBH4s4sHH8sI",
            2,
            4,
            28 + len(lsa),
            socket.inet_aton(ASBR_RID),
            socket.inet_aton(NSSA_AREA),
            0,
            0,
            b"\x00" * 8,
            1,
        )
        + lsa
    )
    struct.pack_into("!H", packet, 12, _internet_checksum(bytes(packet)))
    assert _internet_checksum(bytes(packet)) == 0, "OSPF checksum invalid"
    return bytes(packet)


def _inject(label, rid, flags, sequence, age=1, corrupt_checksum=False):
    "Send one forged LSU from r1 to r2 and confirm the ABR received it."
    tgen = get_topogen()
    packet = _make_update(rid, flags, sequence, age, corrupt_checksum)
    macs = {}
    for node, ifname in (("r1", "r1-eth0"), ("r2", "r2-eth0")):
        out = tgen.gears[node].cmd_raises("ip -o link show dev {}".format(ifname))
        macs[node] = re.search(r"link/ether ([0-9a-f:]{17})", out).group(1)
    before = _ls_update_input()
    helper = os.path.join(tgen.logdir, "scapy_send.py")
    out = tgen.gears["r1"].cmd_raises(
        "python3 {} {} {} {} {} {} {}".format(
            helper,
            "r1-eth0",
            macs["r1"],
            macs["r2"],
            ASBR_IP,
            ABR_NSSA_IP,
            packet.hex(),
        )
    )
    assert "sent=1" in out, "scapy send failed for {}: {}".format(label, out)
    _, result = topotest.run_and_expect(
        lambda: None if _ls_update_input() > before else "no lsUpdIn increment",
        None,
        count=10,
        wait=1,
    )
    assert result is None, "{}: ABR did not receive the injected LSU".format(label)
    logger.info(
        "injected %s: rid=%s flags=0x%02x age=%d seq=0x%08x corrupt=%s",
        label,
        rid,
        flags,
        age,
        sequence,
        corrupt_checksum,
    )


def _flush_phantom(rid, flags, sequence):
    "Withdraw a phantom Router-LSA with a MaxAge copy of the same instance."
    _inject("flush_{}".format(rid), rid, flags, sequence, age=MAX_AGE)

    def _gone():
        return None if _phantom("r2", rid) is None else "phantom still in LSDB"

    _, result = topotest.run_and_expect(_gone, None, count=75, wait=1)
    assert result is None, "phantom {} was not flushed".format(rid)


def _expect_phantom_installed(rid, flags, sequence):
    "Wait until the forged Router-LSA sits in the ABR LSDB with the requested fields."

    def _installed():
        lsa = _phantom("r2", rid)
        if not _active(lsa):
            return "phantom not installed"
        if lsa["flags"] != flags:
            return "phantom flags {} != {}".format(lsa["flags"], flags)
        if lsa["lsaSeqNumber"].lower() != "{:x}".format(sequence):
            return "phantom seq {} != {:x}".format(lsa["lsaSeqNumber"], sequence)
        return None

    _, result = topotest.run_and_expect(_installed, None, count=15, wait=1)
    assert result is None, "phantom {} not installed as requested: {}".format(
        rid, result
    )


def _expect_election_intact(context):
    "The fixed behavior: the phantom must not depose the translator or the route."

    def _intact():
        elected = _translator_elected()
        type5_abr = _active(_type5("r2"))
        type5_obs = _active(_type5("r3"))
        route = _observer_route(TARGET_PREFIX)
        if elected and type5_abr and type5_obs and route:
            return None
        return (
            "{}: translator_elected={} type5_abr={} type5_obs={} route={}"
            " (phantom must not affect the election)".format(
                context, elected, type5_abr, type5_obs, route
            )
        )

    _, result = topotest.run_and_expect(_intact, None, count=30, wait=1)
    assert result is None, result


def _expect_new_translation(probe):
    "A brand-new prefix must still be translated 7->5 and routed (fixed behavior)."
    tgen = get_topogen()
    tgen.gears["r1"].cmd_raises("ip addr add {}/32 dev lo".format(probe))

    def _type7_ready():
        if _active(_type7("r1", probe)) and _active(_type7("r2", probe)):
            return None
        return "probe Type-7 not yet on r1/r2"

    _, result = topotest.run_and_expect(_type7_ready, None, count=20, wait=1)
    assert result is None, "probe {}/32: {}".format(probe, result)

    def _translated():
        if not _active(_type5("r2", probe)):
            return "translated Type-5 missing on r2"
        if not _active(_type5("r3", probe)):
            return "Type-5 missing on r3"
        if not _observer_route("{}/32".format(probe)):
            return "observer route missing"
        return None

    _, result = topotest.run_and_expect(_translated, None, count=20, wait=1)
    assert result is None, "probe {}/32 not translated: {}".format(probe, result)


#
# Tests
#


def test_baseline_translation():
    "Baseline: Full adjacencies, elected translator, 7->5 translation, observer route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _, result = topotest.run_and_expect(
        _translation_baseline_ready, None, count=90, wait=1
    )
    assert result is None, "baseline NSSA translation not established: {}".format(
        result
    )

    # No-attack control: the election, the Type-5 sequence, the observer
    # route and the adjacencies must be stable without any injected packet.
    baseline_seq = _wait_type5_seq_stable()
    for _ in range(5):
        time.sleep(1)
        assert (
            _translation_unchanged(baseline_seq) is None
        ), "no-attack control changed translator/Type-5/route state"


def test_control_invalid_checksum():
    "A high-RID B-bit Router-LSA with a corrupt checksum must be rejected."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    baseline_seq = _type5_seq()
    _inject(
        "invalid_checksum_high_rid",
        HIGH_RID,
        ROUTER_LSA_BORDER,
        HIGH_SEQ,
        corrupt_checksum=True,
    )
    time.sleep(2)
    assert (
        _phantom("r2", HIGH_RID) is None
    ), "corrupt-checksum Router-LSA was installed in the ABR LSDB"
    assert (
        _translation_unchanged(baseline_seq) is None
    ), "corrupt-checksum control changed the election"


def test_control_high_rid_without_b():
    "A valid high-RID Router-LSA without the B-bit must not affect the election."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    baseline_seq = _type5_seq()
    _inject("valid_high_rid_without_b", CONTROL_RID, 0, CONTROL_SEQ)
    _expect_phantom_installed(CONTROL_RID, 0, CONTROL_SEQ)
    time.sleep(8)
    assert _translator_elected(), "non-ABR high-RID LSA deposed the translator"
    assert _type5_seq() == baseline_seq, "Type-5 sequence changed"
    assert _active(_type5("r2")) and _active(_type5("r3"))
    assert _observer_route(TARGET_PREFIX)

    # Withdraw the control LSA again so later scenarios start clean.
    _flush_phantom(CONTROL_RID, 0, CONTROL_SEQ)


def test_attack_high_rid_b_bit():
    "B9: an unreachable B-bit phantom with the highest RID must not win."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _inject("high_rid_b_only", HIGH_RID, ROUTER_LSA_BORDER, HIGH_SEQ)
    _expect_phantom_installed(HIGH_RID, ROUTER_LSA_BORDER, HIGH_SEQ)

    _expect_election_intact("high-RID B-only phantom")
    _expect_new_translation(HIGH_PROBE)

    # Withdraw the phantom; translation must continue uninterrupted.
    _flush_phantom(HIGH_RID, ROUTER_LSA_BORDER, HIGH_SEQ)
    _expect_election_intact("after flushing the high-RID phantom")


def test_attack_b_nt_lower_rid():
    "B9: an unreachable B-bit+Nt phantom with a lower RID must not win."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _inject("b_nt_lower_rid", NT_RID, ROUTER_LSA_BORDER | ROUTER_LSA_NT, NT_SEQ)
    _expect_phantom_installed(NT_RID, ROUTER_LSA_BORDER | ROUTER_LSA_NT, NT_SEQ)

    _expect_election_intact("B+Nt lower-RID phantom")
    _expect_new_translation(NT_PROBE)

    _flush_phantom(NT_RID, ROUTER_LSA_BORDER | ROUTER_LSA_NT, NT_SEQ)
    _expect_election_intact("after flushing the B+Nt phantom")


def test_recovery_and_convergence():
    "With all phantoms gone the network is fully converged and translating."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rid, flags, seq in (
        (HIGH_RID, ROUTER_LSA_BORDER, HIGH_SEQ),
        (NT_RID, ROUTER_LSA_BORDER | ROUTER_LSA_NT, NT_SEQ),
        (CONTROL_RID, 0, CONTROL_SEQ),
    ):
        if _phantom("r2", rid) is not None:
            _flush_phantom(rid, flags, seq)

    assert _translator_elected(), "translator not elected after cleanup"
    assert _full_adjacencies(), "adjacencies not Full after cleanup"
    for r in ("r1", "r2", "r3"):
        assert (
            tgen.gears[r].cmd_raises("pidof ospfd").strip()
        ), "ospfd not running on {}".format(r)

    # A brand-new prefix translates end to end after the attacks.
    _expect_new_translation(FINAL_PROBE)

    # The original prefix is still translated and routed.
    assert _active(_type5("r2")) and _active(_type5("r3"))
    assert _observer_route(TARGET_PREFIX)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
