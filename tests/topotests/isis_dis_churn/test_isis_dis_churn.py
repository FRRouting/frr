#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_dis_churn.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Bing Shui <bingshui@smail.nju.edu.cn>
#
"""
test_isis_dis_churn.py

A spoofed LAN hello must not steer a pseudonode LSP purge off the LAN.

isis_dr_commence() purges the LSP named by circuit->u.bc.l2_desig_is
to clean up after the previous DIS.  That record is fed by the LAN ID
(designated IS) field of LAN hellos, which carries no authentication:
process_lan_hello() used to accept whatever a DIS-marked adjacency
reported.  A spoofed hello could therefore poison the record with an
off-LAN identity, and the next legitimate DIS change purged that
off-LAN router's pseudonode LSP and flooded the purge through the
whole area, until the victim fought back with a newer sequence number.

Topology (level-2-only, area 49.0001):

    r2 ----+
    h1 ----+---- LAN1 ---- r1 ---- LAN2 ---- r4 (DIS, prio 127)
  injector        (DIS, prio 64)       r5
                          |
                          +---- p2p ---- r3 (observer)

h1 replays captured genuine hellos with edited priority / LAN ID
fields, unicast to r2.  The attack itself (priority 0 lets r2 win the
LAN1 election) is unauthenticated by design and still works; what must
not happen is r2 acting on a LAN ID that names no adjacency of its own
circuit.
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd]

INJECTOR = os.path.join(CWD, "isis_inject.py")

SYSID = {
    "r1": "000000000001",
    "r2": "000000000002",
    "r3": "000000000003",
    "r4": "000000000004",
    "r5": "000000000005",
}


def build_topo(tgen):
    "Build function"

    for rname in ["r1", "r2", "r3", "r4", "r5"]:
        tgen.add_router(rname)
    tgen.add_host("h1", "10.0.1.100/24", "via 10.0.1.1")

    lan1 = tgen.add_switch("lan1")
    lan1.add_link(tgen.gears["r1"], nodeif="eth-lan1")
    lan1.add_link(tgen.gears["r2"], nodeif="eth-lan1")
    lan1.add_link(tgen.gears["h1"], nodeif="eth0")

    lan2 = tgen.add_switch("lan2")
    lan2.add_link(tgen.gears["r1"], nodeif="eth-lan2")
    lan2.add_link(tgen.gears["r4"], nodeif="eth-lan2")
    lan2.add_link(tgen.gears["r5"], nodeif="eth-lan2")

    p2p = tgen.add_switch("p2p")
    p2p.add_link(tgen.gears["r1"], nodeif="eth-p2p")
    p2p.add_link(tgen.gears["r3"], nodeif="eth-p2p")


def setup_module(module):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    get_topogen().stop_topology()


def router_out(rname, command, isjson=False):
    return get_topogen().gears[rname].vtysh_cmd(command, isjson=isjson)


def vtysh_cfg(rname, *lines):
    args = " ".join('-c "{}"'.format(line) for line in ("conf t",) + lines)
    get_topogen().net[rname].cmd("vtysh {}".format(args))


def dotted(sysid):
    return "{}.{}.{}".format(sysid[0:4], sysid[4:8], sysid[8:12])


def adjacency_up(rname, peer):
    "True when rname has an Up adjacency to peer (hostname or sysid)."
    out = router_out(rname, "show isis neighbor")
    for line in out.splitlines():
        fields = line.split()
        if fields and fields[0] in (peer, dotted(SYSID[peer])) and "Up" in line:
            return True
    return False


def lsdb_map(rname):
    "Map normalized LSP id -> {seqno, holdtime} from rname's LSDB."

    def walk(value, out):
        if isinstance(value, dict):
            lsp = value.get("lsp")
            if isinstance(lsp, dict) and "id" in lsp and "seqNumber" in value:
                key = lsp["id"].replace(".", "").replace("-", "").lower()
                out[key] = {
                    "id": lsp["id"],
                    "seqno": int(value["seqNumber"], 16),
                    "holdtime": value.get("holdtime"),
                }
            for child in value.values():
                walk(child, out)
        elif isinstance(value, list):
            for child in value:
                walk(child, out)

    out = {}
    walk(router_out(rname, "show isis database json", isjson=True), out)
    return out


def pseudo_of(db, owner):
    "The owner's pseudonode LSP entry in an lsdb_map, or None."
    for key, entry in db.items():
        if key.startswith(SYSID[owner]):
            pseudo = key[12:14]
        elif key.startswith(owner):
            pseudo = key[len(owner):len(owner) + 2]
        else:
            continue
        if pseudo != "00":
            entry["pseudo"] = pseudo
            return entry
    return None


def lan_dis_state(rname):
    "Map interface -> {priority, is_dis} for broadcast circuits."

    def walk(value, out):
        if isinstance(value, dict):
            iface = value.get("interface")
            if isinstance(iface, dict) and "name" in iface:
                for level in iface.get("levels", []):
                    lan = level.get("lan")
                    if isinstance(lan, dict) and "is-dis" in lan:
                        out[iface["name"]] = {
                            "priority": lan.get("priority"),
                            "is_dis": lan.get("is-dis") == "yes",
                        }
            for child in value.values():
                walk(child, out)
        elif isinstance(value, list):
            for child in value:
                walk(child, out)

    out = {}
    walk(router_out(rname, "show isis interface detail json", isjson=True), out)
    return out


def wait_until(fn, timeout, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def wait_lsdb_stable(rname, timeout=20, gap=2):
    """
    Wait until rname's LSP sequence numbers stop changing.  A DIS
    change schedules a node-LSP regeneration (gen-interval 1s) that
    can land after the DIS state itself has settled; entries aging in
    or out of the LSDB are ignored.
    """

    def seqnos():
        return {key: entry["seqno"] for key, entry in lsdb_map(rname).items()}

    prev = seqnos()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(gap)
        cur = seqnos()
        if all(prev[key] == cur[key] for key in prev.keys() & cur.keys()):
            return True
        prev = cur
    return False


def templates_path():
    return os.path.join(get_topogen().logdir, "dis_churn_templates.json")


def templates():
    "Per-sysid {pdu, src_mac} templates sniffed on LAN1, captured once."
    cache = templates._cache
    if cache is None:
        path = templates_path()
        out = get_topogen().net["h1"].cmd(
            "python3 {} template eth0 {} 60".format(INJECTOR, path),
            timeout=120,
        )
        assert "TEMPLATE_DONE" in out, "template capture failed: {}".format(out)
        with open(path) as fp:
            cache = json.load(fp)
        templates._cache = cache
    return cache


templates._cache = None


def inject(src, dst, count, spacing, priority=None, dis=None):
    "Replay src's hello template to dst, COUNT times, with edits."
    templates()
    args = "python3 {} send eth0 {} {} {} {} {}".format(
        INJECTOR, templates_path(), SYSID[src], SYSID[dst], count, spacing
    )
    if priority is not None:
        args += " priority {}".format(priority)
    if dis is not None:
        args += " dis {}".format(dis)
    out = get_topogen().net["h1"].cmd(args, timeout=60)
    assert "SENT={}".format(count) in out, "injection failed: {}".format(out)


def require_r4_pseudo(rname):
    entry = pseudo_of(lsdb_map(rname), "r4")
    assert entry, "r4's pseudonode LSP missing from {}'s LSDB".format(rname)
    return entry


def alive(entry):
    "True while the LSP is not purged: holdtime is a positive int."
    return isinstance(entry["holdtime"], int) and entry["holdtime"] > 0


def test_wait_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def check():
        for rname, peer in (
            ("r1", "r2"), ("r2", "r1"), ("r1", "r4"),
            ("r4", "r1"), ("r1", "r5"), ("r1", "r3"), ("r3", "r1"),
        ):
            if not adjacency_up(rname, peer):
                return "{} has no adjacency to {}".format(rname, peer)
        if not lan_dis_state("r1").get("eth-lan1", {}).get("is_dis"):
            return "r1 is not DIS on eth-lan1"
        if not lan_dis_state("r4").get("eth-lan2", {}).get("is_dis"):
            return "r4 is not DIS on eth-lan2"
        db = lsdb_map("r1")
        if pseudo_of(db, "r1") is None:
            return "r1's pseudonode LSP not in r1's LSDB"
        if pseudo_of(db, "r4") is None:
            return "r4's pseudonode LSP not in r1's LSDB"
        return None

    _, result = topotest.run_and_expect(check, None, count=90, wait=1)
    assert result is None, "IS-IS did not converge:\n{}".format(result)

    capture = templates()
    assert set(capture) == {SYSID["r1"], SYSID["r2"]}


def test_legal_dis_change():
    """
    A priority-driven DIS change must still purge the old DIS's
    pseudonode LSP (the fix must not disable normal cleanup), and must
    never touch r4's pseudonode on the other LAN.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r4p = require_r4_pseudo("r1")
    seq0 = r4p["seqno"]

    logger.info("raise r2's LAN1 priority so it preempts r1")
    vtysh_cfg("r2", "interface eth-lan1", "isis priority 127")
    assert wait_until(
        lambda: lan_dis_state("r2").get("eth-lan1", {}).get("is_dis"), 20
    ), "r2 never became DIS after the priority change"
    assert wait_until(
        lambda: pseudo_of(lsdb_map("r1"), "r2") is not None, 20
    ), "r2's pseudonode LSP never reached r1"

    logger.info("restore r2's LAN1 priority so r1 wins again")
    vtysh_cfg("r2", "interface eth-lan1", "isis priority 10")
    assert wait_until(
        lambda: not lan_dis_state("r2").get("eth-lan1", {}).get("is_dis"), 20
    ), "r2 never resigned after the priority restore"

    r4p = require_r4_pseudo("r1")
    assert r4p["seqno"] == seq0 and alive(r4p), (
        "legal DIS change on LAN1 disturbed r4's pseudonode LSP:\n{}".format(r4p)
    )
    # The DIS event schedules a node-LSP regeneration; let it land
    # before the next test snapshots the LSDB.
    assert wait_lsdb_stable("r1", 20), "r1's LSDB never settled after the DIS change"


def test_repeat_identical_iih():
    """
    Replaying genuine hellos unchanged must produce no work: the
    reported LAN ID matches the recorded one, so there is no DIS
    event, no LSP regeneration and no SPF.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    before = lsdb_map("r1")
    r4p = require_r4_pseudo("r1")
    seq0 = r4p["seqno"]

    inject("r1", "r2", count=8, spacing=0.5)
    time.sleep(5)

    assert lan_dis_state("r1").get("eth-lan1", {}).get("is_dis"), (
        "r1 lost DIS from replayed identical hellos"
    )
    after = lsdb_map("r1")
    churned = sorted(
        key for key in before if key in after and before[key]["seqno"] != after[key]["seqno"]
    )
    assert not churned, "replayed identical hellos churned LSPs: {}".format(churned)
    r4p = require_r4_pseudo("r1")
    assert r4p["seqno"] == seq0 and alive(r4p), (
        "replayed identical hellos disturbed r4's pseudonode LSP:\n{}".format(r4p)
    )


def test_poisoned_desig_is_purge():
    """
    The attack: spoof r1's hellos with priority 0 so r2 wins the LAN1
    election, and LAN ID = r4's pseudonode, an identity that is not on
    LAN1 at all.  Unpatched, r2's isis_dr_commence() purges r4's
    pseudonode LSP and floods the purge into LAN2; r4 fights back and
    the LSP's sequence number moves.  Patched, process_lan_hello()
    rejects the bogus LAN ID and r4's pseudonode stays untouched.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r4p = require_r4_pseudo("r1")
    poison_dis = SYSID["r4"] + r4p["pseudo"]
    seq0 = {r: require_r4_pseudo(r)["seqno"] for r in ("r1", "r2", "r3")}
    # r2's win is transient (the next genuine r1 hello makes it resign
    # again), but its pseudonode LSP keeps a bumped seqno in r1's LSDB
    # for the zero-age lifetime, so the attack can be verified after
    # the fact.  A stale zero-age copy from an earlier test is the
    # baseline to beat.
    r2p0 = pseudo_of(lsdb_map("r1"), "r2")
    r2_seq0 = r2p0["seqno"] if r2p0 else 0

    logger.info("poison r2's designated-IS record with %s", poison_dis)
    inject("r1", "r2", count=12, spacing=0.5, priority=0, dis=poison_dis)

    def r2_won():
        if lan_dis_state("r2").get("eth-lan1", {}).get("is_dis"):
            return True
        entry = pseudo_of(lsdb_map("r1"), "r2")
        return entry is not None and entry["seqno"] > r2_seq0

    assert wait_until(r2_won, 20), "r2 never won the LAN1 election; attack did not run"

    disturbed = []
    deadline = time.time() + 20
    while time.time() < deadline:
        for rname in ("r1", "r2", "r3"):
            entry = pseudo_of(lsdb_map(rname), "r4")
            if entry is None or entry["seqno"] != seq0[rname] or not alive(entry):
                disturbed.append({rname: entry})
        time.sleep(0.5)

    assert not disturbed, (
        "off-LAN pseudonode LSP disturbed by a spoofed LAN ID:\n{}".format(
            json.dumps(disturbed, default=str, indent=1)
        )
    )
