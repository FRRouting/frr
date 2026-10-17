#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test IS-IS generic cryptographic authentication with key chains (RFC 5310)
and Extended Sequence Numbers (RFC 7602).

    r1 --(p2p)-- r2 --(LAN)-- r3
                       |
                       +----- r4

Every router is level-1-2, authenticates its hellos with the "hello" key
chain, level-1 LSPs and SNPs with "area" and level-2 ones with "domain", and
verifies Extended Sequence Numbers on every link.
"""

import functools
import json
import os
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons, step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]

ROUTERS = ("r1", "r2", "r3", "r4")

EXPECTED_ADJACENCIES = {
    "r1": {("r1-eth0", "r2")},
    "r2": {("r2-eth0", "r1"), ("r2-eth1", "r3"), ("r2-eth1", "r4")},
    "r3": {("r3-eth0", "r2"), ("r3-eth0", "r4")},
    "r4": {("r4-eth0", "r2"), ("r4-eth0", "r3")},
}

KEY_STRINGS = {
    "hello": "hello-key-1",
    "area": "area-key-1",
    "domain": "domain-key-1-longer-than-a-sha-256-hash",
}

# The IS-IS PDU follows the 802.3 header and the LLC in a frame
PDU_OFFSET = 14 + 3

# PDU types (ISO 10589)
L2_LAN_IIH = 16
P2P_IIH = 17
L2_CSNP = 25


def build_topo(tgen):
    for router in ROUTERS:
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    for router in ("r2", "r3", "r4"):
        switch.add_link(tgen.gears[router])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _configure(router, *lines):
    router.vtysh_cmd("configure terminal\n" + "\n".join(lines))


def _lifetime(timestamp):
    """A key chain lifetime time: HH:MM:SS DAY MONTH YEAR, local time"""
    return time.strftime("%H:%M:%S %d %b %Y", time.localtime(timestamp))


def _wait(func, *args, count=60, wait=1):
    test_func = functools.partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert result is None, result


def _adjacencies(router):
    """{(interface, neighbor): levels} of the adjacencies that are Up"""
    # The JSON output has one object per circuit, so it cannot list several
    # LAN neighbors; read the table.
    rv = {}
    for line in router.vtysh_cmd("show isis neighbor").splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[3] != "Up" or not fields[2].isdigit():
            continue
        key = (fields[1], fields[0])
        rv[key] = rv.get(key, 0) | int(fields[2])
    return rv


def _check_adjacencies(router, expected):
    """Exactly the expected adjacencies are Up, at both levels."""
    expected = {key: 3 for key in expected}
    adjacencies = _adjacencies(router)
    if adjacencies != expected:
        return "{}: adjacencies Up {}, expected {}".format(
            router.name, adjacencies, expected
        )
    return None


def _check_adjacency(router, ifname, neighbor, up):
    if ((ifname, neighbor) in _adjacencies(router)) != up:
        return "{}: adjacency with {} on {} {}".format(
            router.name, neighbor, ifname, "down" if up else "still up"
        )
    return None


def _flaps(router):
    """{(interface, neighbor, level): adjacency flaps}"""
    rv = {}
    neighbor = key = None
    for line in router.vtysh_cmd("show isis neighbor detail").splitlines():
        m = re.match(r"^\s*(\S+)\s*$", line)
        if m and not line.strip().startswith("Area"):
            neighbor = m.group(1)
        m = re.match(r"\s*Interface: (\S+), Level: (\d)", line)
        if m:
            key = (m.group(1), neighbor, int(m.group(2)))
        m = re.match(r"\s*Adjacency flaps: (\d+)", line)
        if m:
            rv[key] = int(m.group(1))
    return rv


def _check_routes(router):
    """A route to the loopback of every other router."""
    routes = json.loads(router.vtysh_cmd("show ip route isis json"))
    missing = [
        "10.255.0.{}/32".format(other[1:])
        for other in ROUTERS
        if other != router.name and "10.255.0.{}/32".format(other[1:]) not in routes
    ]
    if missing:
        return "{}: no IS-IS route to {}".format(router.name, missing)
    return None


def _check_baseline():
    tgen = get_topogen()
    for name, expected in EXPECTED_ADJACENCIES.items():
        _wait(_check_adjacencies, tgen.gears[name], expected)
    for name in ROUTERS:
        _wait(_check_routes, tgen.gears[name])


def _lsps(router, level):
    """{LSP ID: LSP} of the database of router at level"""
    output = json.loads(router.vtysh_cmd("show isis database detail json"))
    rv = {}
    for area in output.get("areas", []):
        for lvl in area.get("levels", []):
            if lvl.get("id") == level:
                for lsp in lvl.get("lsps", []):
                    rv[lsp["lsp"]["id"]] = lsp
    return rv


def _check_lsp_key_ids(router, level, key_id):
    """Every LSP of every router, in the database of router, is signed with key_id."""
    lsps = _lsps(router, level)
    wrong = {
        lsp_id: lsp.get("authKeyId")
        for lsp_id, lsp in lsps.items()
        if lsp.get("authKeyId") != key_id
    }
    if len(lsps) < len(ROUTERS) or wrong:
        return "{}: level-{} LSPs not signed with Key ID {}: {} (of {})".format(
            router.name, level, key_id, wrong, list(lsps)
        )
    return None


def _seqno(router, lsp_id, level):
    lsp = _lsps(router, level).get(lsp_id)
    return int(lsp["seqNumber"], 16) if lsp else None


def _check_same_seqno(lsp_id, level, router, owner):
    seen, own = _seqno(router, lsp_id, level), _seqno(owner, lsp_id, level)
    if seen != own:
        return "{} level {}: seq {} on {}, {} on {}".format(
            lsp_id, level, seen, router.name, own, owner.name
        )
    return None


def _esn(router, ifname):
    """The Extended Sequence Number state of an interface"""
    output = json.loads(router.vtysh_cmd("show isis interface {} json".format(ifname)))
    for area in output["areas"]:
        for circuit in area["circuits"]:
            iface = circuit.get("interface", {})
            if iface.get("name") == ifname:
                return iface.get("extended-sequence-number")
    return None


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def test_adjacencies_and_routes():
    _skip_on_failure()

    step("Every adjacency comes up at both levels, and every route")
    _check_baseline()


def test_lsps_signed():
    _skip_on_failure()
    tgen = get_topogen()

    step("Every LSP is signed with Key ID 1, including those learned two hops away")
    for name in ROUTERS:
        for level in (1, 2):
            _wait(_check_lsp_key_ids, tgen.gears[name], level, 1)

    step("No LSP carries an Extended Sequence Number")
    for level in (1, 2):
        for lsp_id, lsp in _lsps(tgen.gears["r4"], level).items():
            assert "extendedSequenceNumber" not in lsp, (lsp_id, lsp)


def test_running_config():
    _skip_on_failure()
    r2 = get_topogen().gears["r2"]

    config = r2.vtysh_cmd("show running-config").splitlines()
    for line in (
        " isis password key-chain hello",
        " isis extended-sequence-number verify",
        " area-password key-chain area authenticate snp validate",
        " domain-password key-chain domain authenticate snp validate",
    ):
        assert line in config, "{!r} not in the running configuration".format(line)


def test_hello_key_mismatch():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r1 signs its hellos with another key string: the p2p adjacency goes down")
    _configure(r1, "key chain hello", "key 1", "key-string not-the-hello-key")
    _wait(_check_adjacency, r2, "r2-eth0", "r1", False)
    _wait(_check_adjacency, r1, "r1-eth0", "r2", False)

    step("The LAN adjacencies of r2 stay up")
    adjacencies = _adjacencies(r2)
    assert ("r2-eth1", "r3") in adjacencies and ("r2-eth1", "r4") in adjacencies

    step("The key string restored, the adjacency comes back")
    _configure(r1, "key chain hello", "key 1", "key-string " + KEY_STRINGS["hello"])
    _check_baseline()


def test_hello_unknown_key_id():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r1 signs its hellos with Key ID 9, which r2 does not have")
    _configure(
        r1,
        "key chain hello",
        "key 9",
        "key-string " + KEY_STRINGS["hello"],
        "cryptographic-algorithm hmac-sha-256",
        "exit",
        "no key 1",
    )
    _wait(_check_adjacency, r2, "r2-eth0", "r1", False)

    step("Key ID 1 back on r1, the adjacency comes back")
    _configure(
        r1,
        "key chain hello",
        "key 1",
        "key-string " + KEY_STRINGS["hello"],
        "cryptographic-algorithm hmac-sha-256",
        "exit",
        "no key 9",
    )
    _check_baseline()


def test_lsp_key_mismatch():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r4 = tgen.gears["r1"], tgen.gears["r4"]

    step("r4 signs its level-2 LSPs with another key: r1 keeps the last valid one")
    before = _seqno(r1, "r4.00-00", 2)
    _configure(r4, "key chain domain", "key 1", "key-string not-the-domain-key")

    def check():
        own, seen = _seqno(r4, "r4.00-00", 2), _seqno(r1, "r4.00-00", 2)
        if own > before and seen == before:
            return None
        return "r4.00-00 at level 2: {} on r4, {} on r1 (was {})".format(
            own, seen, before
        )

    _wait(check)

    step("r4's level-1 LSPs, signed with the area key chain, still reach r1")
    _configure(r4, "router isis 1", "set-overload-bit")
    _wait(_check_same_seqno, "r4.00-00", 1, r1, r4)
    _configure(r4, "router isis 1", "no set-overload-bit")

    step("The key string restored, r1 gets r4's current level-2 LSP")
    _configure(r4, "key chain domain", "key 1", "key-string " + KEY_STRINGS["domain"])
    _wait(_check_same_seqno, "r4.00-00", 2, r1, r4)
    _check_baseline()


def test_strict_rfc5310():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2, r4 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r4"]
    strict = "domain-password key-chain domain strict-rfc5310 authenticate snp validate"
    plain = "domain-password key-chain domain authenticate snp validate"
    assert 32 < len(KEY_STRINGS["domain"]) <= 64  # where RFC 5310 and HMAC differ

    step("r4 alone hashes its domain key as RFC 5310 does: r1 keeps r4's last LSP")
    before = _seqno(r1, "r4.00-00", 2)
    _configure(r4, "router isis 1", strict)

    def check():
        own, seen = _seqno(r4, "r4.00-00", 2), _seqno(r1, "r4.00-00", 2)
        if own > before and seen == before:
            return None
        return "r4.00-00 at level 2: {} on r4, {} on r1 (was {})".format(
            own, seen, before
        )

    _wait(check)

    step("With every router doing so, r1 gets r4's current LSP")
    for name in ROUTERS:
        _configure(tgen.gears[name], "router isis 1", strict)
    _wait(_check_same_seqno, "r4.00-00", 2, r1, r4)
    assert " " + strict in r2.vtysh_cmd("show running-config").splitlines()
    _check_baseline()

    step("The hello key is shorter than the hash: r1 hashing it alone changes nothing")
    flaps = _flaps(r2)
    _configure(r1, "interface r1-eth0", "isis password key-chain hello strict-rfc5310")
    time.sleep(6)  # twice the holding time
    assert _check_adjacency(r2, "r2-eth0", "r1", True) is None
    assert _flaps(r2) == flaps

    _configure(r1, "interface r1-eth0", "isis password key-chain hello")
    for name in ROUTERS:
        _configure(tgen.gears[name], "router isis 1", plain)
    _wait(_check_same_seqno, "r4.00-00", 2, r1, r4)
    _check_baseline()


def test_no_send_key():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    now = time.time()
    expired = "send-lifetime {} {}".format(_lifetime(now - 3600), _lifetime(now - 60))
    valid = "send-lifetime {} infinite".format(_lifetime(now - 3600))

    step("r1's only hello key stops being valid for sending: r1 sends no IIH")
    _configure(r1, "key chain hello", "key 1", expired)
    _wait(_check_adjacency, r2, "r2-eth0", "r1", False)
    assert not _capture(r1, "r1-eth0", r2, "r2-eth0", P2P_IIH, 4), "r1 sent an IIH"

    step("Valid again, the adjacency comes back")
    _configure(r1, "key chain hello", "key 1", valid)
    _check_baseline()

    step("r1's only domain key stops being valid for sending: r1 sends no L2 CSNP")
    _configure(r1, "key chain domain", "key 1", expired)
    assert not _capture(r1, "r1-eth0", r2, "r2-eth0", L2_CSNP, 12), "r1 sent a CSNP"
    _configure(r1, "key chain domain", "key 1", valid)
    _wait(_check_same_seqno, "r1.00-00", 2, r2, r1)
    _check_baseline()


def _mac(router, ifname):
    return router.cmd("cat /sys/class/net/{}/address".format(ifname)).strip()


def _capture(sender, sender_if, receiver, receiver_if, pdu_type, timeout=15):
    """A PDU of sender received by receiver, in hex"""
    return receiver.cmd(
        "python3 {}/pdu_replay.py capture {} {} {} {} || true".format(
            CWD, receiver_if, _mac(sender, sender_if), pdu_type, timeout
        )
    ).strip()


def _inject(sender, sender_if, receiver, receiver_if, pdu_type, args, marker):
    """
    Run pdu_replay.py args on sender, and check that receiver gets the frame
    it sends, which contains marker: a test that the frame changes nothing
    proves nothing otherwise.
    """
    seen = "{}/injected".format(receiver.gearlogdir)
    receiver.cmd(
        "python3 {}/pdu_replay.py capture {} {} {} 10 {} > {} 2>&1 < /dev/null &".format(
            CWD, receiver_if, _mac(sender, sender_if), pdu_type, marker, seen
        )
    )
    time.sleep(1)  # for the capture socket to be bound
    sender.cmd("python3 {}/pdu_replay.py {}".format(CWD, args))

    def check():
        return (
            None if receiver.cmd("cat " + seen).strip() else "injected PDU not received"
        )

    _wait(check, count=10)


def _replay(sender, sender_if, receiver, receiver_if, pdu_type):
    """Capture a PDU of sender at receiver, then send it again."""
    frame = _capture(sender, sender_if, receiver, receiver_if, pdu_type)
    assert frame, "no PDU of type {} from {}".format(pdu_type, sender.name)
    _inject(
        sender,
        sender_if,
        receiver,
        receiver_if,
        pdu_type,
        "send {} {}".format(sender_if, frame),
        frame,
    )


def _check_replay_drops(router, ifname, drops):
    esn = _esn(router, ifname)
    if esn["replay-drops"] != drops:
        return "{} {}: {} replayed PDUs dropped, expected {}".format(
            router.name, ifname, esn["replay-drops"], drops
        )
    return None


def test_esn_replayed_p2p_iih():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("A replayed p2p IIH from r1 is dropped by r2, which keeps the adjacency")
    drops = _esn(r2, "r2-eth0")["replay-drops"]
    _replay(r1, "r1-eth0", r2, "r2-eth0", P2P_IIH)
    _wait(_check_replay_drops, r2, "r2-eth0", drops + 1)
    assert _check_adjacency(r2, "r2-eth0", "r1", True) is None


def test_esn_replayed_lan_iih():
    _skip_on_failure()
    tgen = get_topogen()
    r2, r3, r4 = tgen.gears["r2"], tgen.gears["r3"], tgen.gears["r4"]

    step("A replayed level-2 LAN IIH from r3 is dropped by r2 and r4")
    drops2 = _esn(r2, "r2-eth1")["replay-drops"]
    drops4 = _esn(r4, "r4-eth0")["replay-drops"]
    _replay(r3, "r3-eth0", r2, "r2-eth1", L2_LAN_IIH)
    _wait(_check_replay_drops, r2, "r2-eth1", drops2 + 1)
    _wait(_check_replay_drops, r4, "r4-eth0", drops4 + 1)


def test_esn_replayed_csnp():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("A replayed level-2 CSNP from r1 is dropped by r2")
    drops = _esn(r2, "r2-eth0")["replay-drops"]
    _replay(r1, "r1-eth0", r2, "r2-eth0", L2_CSNP)
    _wait(_check_replay_drops, r2, "r2-eth0", drops + 1)


def test_esn_send_only_accepts_replay():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("Sending without verifying, r2 accepts the same replay")
    drops = _esn(r2, "r2-eth0")["replay-drops"]
    _configure(r2, "interface r2-eth0", "isis extended-sequence-number send")
    _replay(r1, "r1-eth0", r2, "r2-eth0", P2P_IIH)
    time.sleep(2)
    assert _esn(r2, "r2-eth0")["replay-drops"] == drops
    _configure(r2, "interface r2-eth0", "isis extended-sequence-number verify")
    assert _check_adjacency(r2, "r2-eth0", "r1", True) is None


def test_esn_forged_iih():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    frame = _capture(r1, "r1-eth0", r2, "r2-eth0", P2P_IIH)
    assert frame, "no IIH from r1"

    def forge(tlv):
        r1.cmd(
            "python3 {}/pdu_replay.py forge r1-eth0 {} {} {}".format(
                CWD, frame, KEY_STRINGS["hello"], tlv
            )
        )

    step("Re-signed with an unknown TLV added, r1's IIH is authentic, and replayed")
    esn = _esn(r2, "r2-eth0")
    forge("fa00")
    _wait(_check_replay_drops, r2, "r2-eth0", esn["replay-drops"] + 1)
    assert _esn(r2, "r2-eth0")["missing-drops"] == esn["missing-drops"]

    step("Re-signed with a second ESN TLV, or an empty one, it is invalid")
    forge("0b0c" + "00" * 7 + "7f" + "ff" * 4)
    forge("0b00")
    time.sleep(2)
    assert _esn(r2, "r2-eth0")["missing-drops"] == esn["missing-drops"] + 2
    assert _esn(r2, "r2-eth0")["replay-drops"] == esn["replay-drops"] + 1
    assert _check_adjacency(r2, "r2-eth0", "r1", True) is None


def _rewrite_esn(
    sender, sender_if, receiver, receiver_if, frame, session=2**64 - 1, packet=2**32 - 1
):
    """Send a captured PDU again with another ESN, the highest by default."""
    _inject(
        sender,
        sender_if,
        receiver,
        receiver_if,
        int(frame[2 * PDU_OFFSET + 8 : 2 * PDU_OFFSET + 10], 16) & 0x1F,
        "rewrite-esn {} {} {} {}".format(sender_if, frame, session, packet),
        "0b0c{:016x}{:08x}".format(session, packet),
    )


def test_esn_unvalidated_snp():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r2 stops validating level-2 SNPs, which anyone can then forge")
    _configure(
        r2,
        "router isis 1",
        "domain-password key-chain domain authenticate snp send-only",
    )
    frame = _capture(r1, "r1-eth0", r2, "r2-eth0", L2_CSNP)
    assert frame, "no CSNP from r1"
    esn = _esn(r2, "r2-eth0")

    step("A CSNP of r1 with the highest ESN does not make r2 drop the next ones")
    _rewrite_esn(r1, "r1-eth0", r2, "r2-eth0", frame)
    time.sleep(25)  # r1 sends a CSNP every 10s
    assert _esn(r2, "r2-eth0") == esn

    step("Nor does it remember that ESN once it validates SNPs again")
    # Right after a CSNP of r1, so that no other one comes before validating
    frame = _capture(r1, "r1-eth0", r2, "r2-eth0", L2_CSNP)
    _rewrite_esn(r1, "r1-eth0", r2, "r2-eth0", frame)
    _configure(
        r2,
        "router isis 1",
        "domain-password key-chain domain authenticate snp validate",
    )
    time.sleep(25)
    assert _esn(r2, "r2-eth0") == esn
    _check_baseline()


def test_esn_cleartext_iih():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r1 and r2 authenticate their hellos with a clear-text password")
    for router, ifname in ((r1, "r1-eth0"), (r2, "r2-eth0")):
        _configure(router, "interface " + ifname, "isis password clear hello-clear")
    _check_baseline()
    frame = _capture(r1, "r1-eth0", r2, "r2-eth0", P2P_IIH)
    assert frame, "no IIH from r1"
    esn, flaps = _esn(r2, "r2-eth0"), _flaps(r2)

    step(
        "An IIH of r1 with the highest ESN, password intact, does not block the next ones"
    )
    _rewrite_esn(r1, "r1-eth0", r2, "r2-eth0", frame)
    time.sleep(6)  # twice the holding time
    assert _check_adjacency(r2, "r2-eth0", "r1", True) is None
    assert _esn(r2, "r2-eth0") == esn
    assert _flaps(r2) == flaps

    step("Nor is an IIH with an invalid ESN dropped: its ESN is not checked at all")
    _rewrite_esn(r1, "r1-eth0", r2, "r2-eth0", frame, session=0)
    time.sleep(2)
    assert _esn(r2, "r2-eth0") == esn

    for router, ifname in ((r1, "r1-eth0"), (r2, "r2-eth0")):
        _configure(router, "interface " + ifname, "isis password key-chain hello")
    _check_baseline()


def test_esn_missing():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r1 stops sending ESNs: r2 verifies them, so it drops r1's IIHs")
    drops = _esn(r2, "r2-eth0")["missing-drops"]
    _configure(r1, "interface r1-eth0", "no isis extended-sequence-number")
    _wait(_check_adjacency, r2, "r2-eth0", "r1", False)
    assert _esn(r2, "r2-eth0")["missing-drops"] > drops

    step("r1 sends them again without verifying: the adjacency comes back")
    _configure(r1, "interface r1-eth0", "isis extended-sequence-number send")
    _wait(_check_adjacency, r2, "r2-eth0", "r1", True)
    _configure(r1, "interface r1-eth0", "isis extended-sequence-number verify")
    _check_baseline()


def test_esn_circuit_restart():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r1 restarts IS-IS on its link before r2's adjacency expires")
    drops = _esn(r2, "r2-eth0")["replay-drops"]
    _configure(
        r1,
        "interface r1-eth0",
        "no ip router isis 1",
        "ip router isis 1",
        "isis network point-to-point",
        "isis hello-interval 1",
        "isis hello-multiplier 3",
        "isis password key-chain hello",
        "isis extended-sequence-number verify",
    )

    step("r2 takes r1's hellos as new, not as replayed: the numbers kept increasing")
    _check_baseline()
    assert _esn(r2, "r2-eth0")["replay-drops"] == drops


def _restart_isisd(router):
    tgen = get_topogen()
    kill_router_daemons(tgen, router.name, ["isisd"])
    start_router_daemons(tgen, router.name, ["isisd"])


def test_esn_replay_after_adjacency_loss():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    frame = _capture(r1, "r1-eth0", r2, "r2-eth0", P2P_IIH)
    assert frame, "no IIH from r1"

    step("r1's isisd stops, and r2's adjacency with r1 times out")
    kill_router_daemons(tgen, "r1", ["isisd"])
    _wait(_check_adjacency, r2, "r2-eth0", "r1", False)
    drops = _esn(r2, "r2-eth0")["replay-drops"]

    step("A captured IIH of r1 does not bring it back: r2 still knows r1's ESNs")
    _inject(r1, "r1-eth0", r2, "r2-eth0", P2P_IIH, "send r1-eth0 " + frame, frame)
    _wait(_check_replay_drops, r2, "r2-eth0", drops + 1)
    assert _check_adjacency(r2, "r2-eth0", "r1", False) is None

    step("r1's isisd starts again, in a new session that r2 accepts")
    start_router_daemons(tgen, "r1", ["isisd"])
    _check_baseline()


def test_esn_session_across_restarts():
    _skip_on_failure()
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("The Extended Session Sequence Number grows with every isisd start")
    session = _esn(r1, "r1-eth0")["session"]
    _restart_isisd(r1)
    _check_baseline()
    assert _esn(r1, "r1-eth0")["session"] > session

    step("Without the state file, the clock keeps it growing")
    session = _esn(r1, "r1-eth0")["session"]
    r1.cmd("rm -f /var/lib/frr/isisd.json")
    _restart_isisd(r1)
    _check_baseline()
    assert _esn(r1, "r1-eth0")["session"] > session

    step("A session in the state file ahead of the clock is continued")
    session = int(time.time()) + 10**9
    kill_router_daemons(tgen, "r1", ["isisd"])
    r1.cmd(
        "echo '{}' > /var/lib/frr/isisd.json".format(
            json.dumps({"extended-session-sequence-numbers": {"1": session}})
        )
    )
    start_router_daemons(tgen, "r1", ["isisd"])
    _check_baseline()
    assert _esn(r1, "r1-eth0")["session"] == session + 1


def test_key_rollover_on_schedule():
    _skip_on_failure()
    tgen = get_topogen()
    start = int(time.time()) + 20

    step("Key ID 2 in every key chain sends from in 20s, when Key ID 1 stops")
    for name in ROUTERS:
        for chain, string in KEY_STRINGS.items():
            _configure(
                tgen.gears[name],
                "key chain " + chain,
                "key 2",
                "key-string {}-2".format(string),
                "cryptographic-algorithm hmac-sha-256",
                "send-lifetime {} infinite".format(_lifetime(start)),
                "exit",
                "key 1",
                "send-lifetime {} {}".format(
                    _lifetime(start - 3600), _lifetime(start - 1)
                ),
            )
    flaps = {name: _flaps(tgen.gears[name]) for name in ROUTERS}
    for name in ROUTERS:
        for level in (1, 2):
            assert _check_lsp_key_ids(tgen.gears[name], level, 1) is None

    step("Until then the adjacencies stay up")
    while time.time() < start:
        for name, expected in EXPECTED_ADJACENCIES.items():
            assert _check_adjacencies(tgen.gears[name], expected) is None
        time.sleep(1)

    step("Within seconds of the switch, every LSP is re-signed with Key ID 2")
    for name in ROUTERS:
        for level in (1, 2):
            _wait(_check_lsp_key_ids, tgen.gears[name], level, 2, count=15)

    step("No adjacency flapped")
    for name in ROUTERS:
        assert _flaps(tgen.gears[name]) == flaps[name], name
    _check_baseline()


def test_key_chain_change_resigns():
    _skip_on_failure()
    tgen = get_topogen()

    step("Key ID 3 added to the domain key chains, Key ID 2 then deleted")
    for name in ROUTERS:
        _configure(
            tgen.gears[name],
            "key chain domain",
            "key 3",
            "key-string {}-3".format(KEY_STRINGS["domain"]),
            "cryptographic-algorithm hmac-sha-256",
        )
    for name in ROUTERS:
        _configure(tgen.gears[name], "key chain domain", "no key 2")

    step("The level-2 LSPs are re-signed with Key ID 3 at once, not at their refresh")
    for name in ROUTERS:
        _wait(_check_lsp_key_ids, tgen.gears[name], 2, 3, count=20)
        assert _check_lsp_key_ids(tgen.gears[name], 1, 2) is None
    _check_baseline()


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
