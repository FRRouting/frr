#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test IS-IS generic cryptographic authentication with key chains (RFC 5310).

    r1 --(p2p)-- r2 --(LAN)-- r3
                       |
                       +----- r4

Every router is level-1-2 and authenticates its hellos with the "hello" key
chain, level-1 LSPs and SNPs with "area" and level-2 ones with "domain".
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
from lib.common_config import step
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

# PDU types (ISO 10589)
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


def _mac(ifname):
    """The MAC address of interface rN-ethM, set in setup_module()"""
    router, eth = re.match(r"r(\d+)-eth(\d+)$", ifname).groups()
    return "02:00:00:00:{:02x}:{:02x}".format(int(router), int(eth))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name, router in tgen.routers().items():
        for ifname in sorted({ifname for ifname, _ in EXPECTED_ADJACENCIES[name]}):
            router.cmd_raises("ip link set {} address {}".format(ifname, _mac(ifname)))
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


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


def _interface(router, ifname):
    """What show isis interface detail json gives ifname"""
    output = json.loads(router.vtysh_cmd("show isis interface detail json"))
    for area in output["areas"]:
        for circuit in area["circuits"]:
            interface = circuit.get("interface", {})
            if interface.get("name") == ifname:
                return interface
    return None


def _interface_auth(router, ifname):
    return _interface(router, ifname).get("authentication")


def _level_auth(router, level):
    """The authentication show isis summary json gives a level"""
    output = json.loads(router.vtysh_cmd("show isis summary json"))
    for lvl in output["vrfs"][0]["areas"][0]["levels"]:
        if lvl["id"] == level:
            return lvl["authentication"]
    return None


def _check_send_key(auth, key_chain, key_id):
    """auth signs with key_id of key_chain, or with no key if key_id is None"""
    expected = {"type": "key-chain", "key-chain": key_chain, "key-chain-exists": True}
    if key_id is not None:
        expected.update({"send-key-id": key_id, "send-algorithm": "hmac-sha-256"})
    actual = {key: auth.get(key) for key in expected}
    if actual != expected or (key_id is None and "send-key-id" in auth):
        return "authentication {}, expected {}".format(auth, expected)
    return None


def _check_neighbor_key_ids(router, key_id):
    """Every adjacency of router was last authenticated with key_id."""
    output = router.vtysh_cmd("show isis neighbor detail")
    adjacencies = output.count("Adjacency flaps:")
    signed = output.count("Authenticated with Key ID {}\n".format(key_id))
    if not adjacencies or signed != adjacencies:
        return "{}: {} of {} adjacencies authenticated with Key ID {}".format(
            router.name, signed, adjacencies, key_id
        )
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


def test_running_config():
    _skip_on_failure()
    r2 = get_topogen().gears["r2"]

    config = r2.vtysh_cmd("show running-config").splitlines()
    for line in (
        " isis password key-chain hello",
        " area-password key-chain area authenticate snp validate",
        " domain-password key-chain domain authenticate snp validate",
    ):
        assert line in config, "{!r} not in the running configuration".format(line)


def test_show_authentication():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("The interfaces show the key chain and the key signing their hellos")
    assert _check_send_key(_interface_auth(r1, "r1-eth0"), "hello", 1) is None
    assert "strict-rfc5310" in _interface_auth(r1, "r1-eth0")
    assert _interface_auth(r1, "lo") is None, "a passive interface sends no hello"
    assert (
        "    Authentication: key chain hello, sending with Key ID 1 (hmac-sha-256)\n"
        in r1.vtysh_cmd("show isis interface detail")
    )

    step("The levels show theirs, and how SNPs are authenticated")
    for level, key_chain in ((1, "area"), (2, "domain")):
        auth = _level_auth(r2, level)
        assert _check_send_key(auth, key_chain, 1) is None
        assert auth["snp"] == "validate", auth
    assert (
        "    Authentication: key chain domain, sending with Key ID 1 (hmac-sha-256),"
        " SNP authentication: validate\n" in r2.vtysh_cmd("show isis summary")
    )

    step("The neighbors show the Key ID of their last hello")
    for name in ROUTERS:
        _wait(_check_neighbor_key_ids, tgen.gears[name], 1)


def test_hello_key_mismatch():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r1 signs its hellos with another key string: the p2p adjacency goes down")
    failures = _interface_auth(r2, "r2-eth0")["failures"]
    r1.vtysh_cmd("""
        configure terminal
        key chain hello
         key 1
          key-string not-the-hello-key
        """)
    _wait(_check_adjacency, r2, "r2-eth0", "r1", False)
    _wait(_check_adjacency, r1, "r1-eth0", "r2", False)
    assert _interface_auth(r2, "r2-eth0")["failures"] > failures

    step("The LAN adjacencies of r2 stay up")
    adjacencies = _adjacencies(r2)
    assert ("r2-eth1", "r3") in adjacencies and ("r2-eth1", "r4") in adjacencies

    step("The key string restored, the adjacency comes back")
    r1.vtysh_cmd(f"""
        configure terminal
        key chain hello
         key 1
          key-string {KEY_STRINGS["hello"]}
        """)
    _check_baseline()


def test_hello_unknown_key_id():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("r1 signs its hellos with Key ID 9, which r2 does not have")
    r1.vtysh_cmd(f"""
        configure terminal
        key chain hello
         key 9
          key-string {KEY_STRINGS["hello"]}
          cryptographic-algorithm hmac-sha-256
         exit
         no key 1
        """)
    _wait(_check_adjacency, r2, "r2-eth0", "r1", False)

    step("Key ID 1 back on r1, the adjacency comes back")
    r1.vtysh_cmd(f"""
        configure terminal
        key chain hello
         key 1
          key-string {KEY_STRINGS["hello"]}
          cryptographic-algorithm hmac-sha-256
         exit
         no key 9
        """)
    _check_baseline()


def test_lsp_key_mismatch():
    _skip_on_failure()
    tgen = get_topogen()
    r1, r2, r4 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r4"]

    step("r4 signs its level-2 LSPs with another key: r1 keeps the last valid one")
    before = _seqno(r1, "r4.00-00", 2)
    failures = _level_auth(r2, 2)["failures"]
    r4.vtysh_cmd("""
        configure terminal
        key chain domain
         key 1
          key-string not-the-domain-key
        """)

    def check():
        own, seen = _seqno(r4, "r4.00-00", 2), _seqno(r1, "r4.00-00", 2)
        if own > before and seen == before:
            return None
        return "r4.00-00 at level 2: {} on r4, {} on r1 (was {})".format(
            own, seen, before
        )

    _wait(check)
    assert _level_auth(r2, 2)["failures"] > failures

    step("r4's level-1 LSPs, signed with the area key chain, still reach r1")
    r4.vtysh_cmd("""
        configure terminal
        router isis 1
         set-overload-bit
        """)
    _wait(_check_same_seqno, "r4.00-00", 1, r1, r4)
    r4.vtysh_cmd("""
        configure terminal
        router isis 1
         no set-overload-bit
        """)

    step("The key string restored, r1 gets r4's current level-2 LSP")
    r4.vtysh_cmd(f"""
        configure terminal
        key chain domain
         key 1
          key-string {KEY_STRINGS["domain"]}
        """)
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
    r4.vtysh_cmd(f"""
        configure terminal
        router isis 1
         {strict}
        """)

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
        tgen.gears[name].vtysh_cmd(f"""
            configure terminal
            router isis 1
             {strict}
            """)
    _wait(_check_same_seqno, "r4.00-00", 2, r1, r4)
    assert " " + strict in r2.vtysh_cmd("show running-config").splitlines()
    _check_baseline()

    step("The hello key is shorter than the hash: r1 hashing it alone changes nothing")
    flaps = _flaps(r2)
    r1.vtysh_cmd("""
        configure terminal
        interface r1-eth0
         isis password key-chain hello strict-rfc5310
        """)
    time.sleep(6)  # twice the holding time
    assert _check_adjacency(r2, "r2-eth0", "r1", True) is None
    assert _flaps(r2) == flaps

    r1.vtysh_cmd("""
        configure terminal
        interface r1-eth0
         isis password key-chain hello
        """)
    for name in ROUTERS:
        tgen.gears[name].vtysh_cmd(f"""
            configure terminal
            router isis 1
             {plain}
            """)
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
    r1.vtysh_cmd(f"""
        configure terminal
        key chain hello
         key 1
          {expired}
        """)
    _wait(_check_adjacency, r2, "r2-eth0", "r1", False)
    assert not _capture("r1-eth0", r2, "r2-eth0", P2P_IIH, 4), "r1 sent an IIH"
    assert _check_send_key(_interface_auth(r1, "r1-eth0"), "hello", None) is None
    assert (
        "    Authentication: key chain hello, no key valid for sending\n"
        in r1.vtysh_cmd("show isis interface detail")
    )

    step("Valid again, the adjacency comes back")
    r1.vtysh_cmd(f"""
        configure terminal
        key chain hello
         key 1
          {valid}
        """)
    _check_baseline()

    step("r1's only domain key stops being valid for sending: r1 sends no L2 CSNP")
    r1.vtysh_cmd(f"""
        configure terminal
        key chain domain
         key 1
          {expired}
        """)
    assert not _capture("r1-eth0", r2, "r2-eth0", L2_CSNP, 12), "r1 sent a CSNP"
    assert _check_send_key(_level_auth(r1, 2), "domain", None) is None
    r1.vtysh_cmd(f"""
        configure terminal
        key chain domain
         key 1
          {valid}
        """)
    _wait(_check_same_seqno, "r1.00-00", 2, r2, r1)
    _check_baseline()


def _capture(sender_if, receiver, receiver_if, pdu_type, timeout=15):
    """A PDU sent on sender_if received by receiver, in hex"""
    return receiver.cmd(
        "python3 {}/pdu_replay.py capture {} {} {} {} || true".format(
            CWD, receiver_if, _mac(sender_if), pdu_type, timeout
        )
    ).strip()


def test_key_rollover_on_schedule():
    _skip_on_failure()
    tgen = get_topogen()
    start = int(time.time()) + 20

    step("Key ID 2 in every key chain sends from in 20s, when Key ID 1 stops")
    for name in ROUTERS:
        for chain, string in KEY_STRINGS.items():
            tgen.gears[name].vtysh_cmd(f"""
                configure terminal
                key chain {chain}
                 key 2
                  key-string {string}-2
                  cryptographic-algorithm hmac-sha-256
                  send-lifetime {_lifetime(start)} infinite
                 exit
                 key 1
                  send-lifetime {_lifetime(start - 3600)} {_lifetime(start - 1)}
                """)
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

    step("Every router shows it sends with Key ID 2, and gets hellos signed with it")
    for name in ROUTERS:
        router = tgen.gears[name]
        for ifname, _ in EXPECTED_ADJACENCIES[name]:
            assert _check_send_key(_interface_auth(router, ifname), "hello", 2) is None
        for level, key_chain in ((1, "area"), (2, "domain")):
            assert _check_send_key(_level_auth(router, level), key_chain, 2) is None
        _wait(_check_neighbor_key_ids, router, 2, count=5)

    step("No adjacency flapped")
    for name in ROUTERS:
        assert _flaps(tgen.gears[name]) == flaps[name], name
    _check_baseline()


def test_key_chain_change_resigns():
    _skip_on_failure()
    tgen = get_topogen()

    step("Key ID 3 added to the domain key chains, Key ID 2 then deleted")
    for name in ROUTERS:
        tgen.gears[name].vtysh_cmd(f"""
            configure terminal
            key chain domain
             key 3
              key-string {KEY_STRINGS["domain"]}-3
              cryptographic-algorithm hmac-sha-256
            """)
    for name in ROUTERS:
        tgen.gears[name].vtysh_cmd("""
            configure terminal
            key chain domain
             no key 2
            """)

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
