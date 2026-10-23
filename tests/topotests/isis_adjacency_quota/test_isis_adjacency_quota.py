#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_isis_adjacency_quota.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Bing Shui <bingshui@smail.nju.edu.cn>
#
r"""
test_isis_adjacency_quota.py:

                 +---------+
                 |   r2    |  injector + legit peer
                 |         |
                 +---------+
                      |eth-r1
                      |
                      |eth-r2
                 +---------+
                 |   r1    |  victim (level-1-2)
                 |         |
                 +---------+
                      |eth-r3
                      |
                      |eth-r1
                 +---------+
                 |   r3    |  legit peer on a second circuit
                 |         |
                 +---------+

A LAN IIH that passes the area/protocol/auth checks makes
process_lan_hello() create an adjacency for every previously unseen
system ID (isis_new_adj), and nothing bounds circuit->u.bc.adjdb[]:
each entry pins an object, an expire timer and a linear-scan slot for
later IIHs.  ISO 10589 8.4.1.5 requires creating adjacency state for
received LAN IIHs but explicitly covers an adjacency database without
space (8.4.2: the new adjacency is ignored and counted as rejected).

This test checks that:
1. distinct system IDs create adjacencies (Initializing without the
   receiver's SNPA in the LAN Neighbours TLV, Up with it) and the Up
   count follows;
2. re-sending a known system ID does not create another adjacency;
3. IIHs failing the area/protocol/auth checks create nothing;
4. at most ISIS_MAX_LAN_ADJACENCIES (1024) adjacencies are kept per
   level on a broadcast circuit; excess creation attempts are dropped
   and counted;
5. the quota is per level and per circuit: an L1 IIH is still admitted
   after the L2 adjacency database is full, and the adjacency on the
   other circuit is untouched;
6. rejected system IDs are admitted again after the injected
   adjacencies expire (holdtime), and legitimate adjacencies and
   routes are intact after the drain.

Note: once the adjacency table outgrows the IIH MTU (~230 entries,
Initializing included), send_hello() fails isis_pack_tlvs() and
silently stops sending the LAN IIH (isis_pdu.c:2059-2063, no log),
dropping legitimate neighbours on that circuit until the table drains.
That is a distinct pre-existing defect, not covered here; the
saturation step therefore asserts only the quota behaviour, while
recovery after the drain is asserted in step 6.
"""

import json
import os
import re
import shlex
import sys
import time

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd]

HELPER = os.path.join(CWD, "inject_iih.py")

R1_SYSID = "000000000001"
AREA = "490001"
WRONG_AREA = "490009"
INJECT_SYSID_BASE = bytes.fromhex("02110000")  # + 2 counter bytes
INJECT_HOLDTIME = 120
INJECT_IPV4 = [10, 213, 12, 99]

N_INIT = 16
N_UP = 32
SAT_EXTRA = 8
# must match ISIS_MAX_LAN_ADJACENCIES in isisd/isis_constants.h
CAP = 1024
GC_TIMEOUT = 300


def build_topo(tgen):
    "Build function"

    for router in ["r1", "r2", "r3"]:
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r1")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r2")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r3")
    switch.add_link(tgen.gears["r3"], nodeif="eth-r1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def inject_sysid(index):
    return (INJECT_SYSID_BASE + index.to_bytes(2, "big")).hex()


def spec(index, holdtime=INJECT_HOLDTIME, with_neigh=False, r1_mac="",
         level=2, area=AREA, protocols="01cc", auth=None):
    entry = {
        "sysid": inject_sysid(index),
        "holdtime": holdtime,
        "level": level,
        "area": area,
        "protocols": protocols,
        "ipv4": INJECT_IPV4,
    }
    if with_neigh:
        entry["snpa_tlv"] = r1_mac.replace(":", "")
    if auth is not None:
        entry["auth"] = auth
    return entry


def inject(r2, frames, spacing=0.2):
    "Run the inject helper on r2; return the number of frames sent."
    raw = r2.cmd_raises(
        "python3 %s --iface eth-r1 --frames %s --spacing %s"
        % (shlex.quote(HELPER), shlex.quote(json.dumps(frames)), spacing)
    )
    for line in reversed(raw.splitlines()):
        if line.startswith("SENT_JSON="):
            return json.loads(line.split("=", 1)[1])["count"]
    raise RuntimeError("inject helper produced no result: %s" % raw[-500:])


def adj_rows(router):
    "Parse 'show isis neighbor' text into (interface, level, state) rows."
    # The JSON variant prints every adjacency of a circuit into one
    # object, so only the text output lists them all.
    raw = router.vtysh_cmd("show isis neighbor")
    rows = []
    for line in raw.splitlines():
        match = re.match(
            r"^\s*(\S+)\s+(\S+)\s+([12])\s+(Up|Initializing|Down)\s", line)
        if match:
            rows.append({
                "interface": match.group(2),
                "level": int(match.group(3)),
                "state": match.group(4),
            })
    return rows


def adj_count(router, iface=None, level=None):
    return sum(
        1 for row in adj_rows(router)
        if (iface is None or row["interface"] == iface)
        and (level is None or row["level"] == level)
    )


def circuit_counters(router, iface, level_str):
    """(active-neighbors, adjacencies-dropped) of one circuit/level.

    dropped is None when the running isisd has no such counter.
    """
    data = json.loads(router.vtysh_cmd("show isis interface detail json"))

    def walk(value):
        if isinstance(value, dict):
            if value.get("name") == iface and isinstance(value.get("levels"),
                                                         list):
                for entry in value["levels"]:
                    if isinstance(entry, dict) \
                            and entry.get("level") == level_str:
                        return entry.get("active-neighbors"), \
                            entry.get("adjacencies-dropped")
            for child in value.values():
                found = walk(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found is not None:
                    return found
        return None

    result = walk(data)
    if result is None:
        raise RuntimeError("no circuit json for %s" % iface)
    return result


def adjacency_up(router, peer):
    raw = router.vtysh_cmd("show isis neighbor detail")
    blocks = re.split(r"\n\s*\n", raw)
    return any(peer in block and "State: Up" in block for block in blocks)


def wait_adjacency_up(router, peer, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if adjacency_up(router, peer):
                return True
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(1)
    return False


def wait_adj_count(router, iface, level, wanted, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if adj_count(router, iface, level) == wanted:
                return True
        except (ValueError, json.JSONDecodeError):
            pass
        time.sleep(2)
    return False


def route_present(router, prefix):
    wanted = prefix + "/32"
    data = json.loads(router.vtysh_cmd("show isis route json"))

    def walk(value):
        if isinstance(value, dict):
            if value.get("prefix") == wanted:
                return True
            return any(walk(child) for child in value.values())
        if isinstance(value, list):
            return any(walk(child) for child in value)
        return False

    return walk(data)


def test_isis_adjacency_quota():
    "LAN IIH adjacency creation: protocol behaviour, controls, quota, GC."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Precondition: r1 has one Up adjacency per circuit.
    assert wait_adjacency_up(r1, "10.213.12.2"), "r1-r2 adjacency did not come up"
    assert wait_adjacency_up(r1, "10.213.13.3"), "r1-r3 adjacency did not come up"
    assert adj_count(r1, "eth-r2", 2) == 1
    assert adj_count(r1, "eth-r3", 2) == 1
    r1_mac = r1.cmd("cat /sys/class/net/eth-r2/address").strip()

    # 1a. Distinct system IDs without the receiver's SNPA in the LAN
    #     Neighbours TLV create Initializing adjacencies, not Up.
    assert inject(r2, [spec(i) for i in range(N_INIT)], spacing=0.05) == N_INIT
    assert adj_count(r1, "eth-r2", 2) == 1 + N_INIT
    assert sum(1 for row in adj_rows(r1)
               if row["interface"] == "eth-r2" and row["state"] == "Up") == 1
    assert circuit_counters(r1, "eth-r2", "L2")[0] == 1

    # 1b. With the receiver's SNPA in the LAN Neighbours TLV the new
    #     adjacencies go Up and the Up count follows.
    frames = [spec(i, with_neigh=True, r1_mac=r1_mac)
              for i in range(N_INIT, N_INIT + N_UP)]
    assert inject(r2, frames, spacing=0.05) == N_UP
    assert adj_count(r1, "eth-r2", 2) == 1 + N_INIT + N_UP
    assert circuit_counters(r1, "eth-r2", "L2")[0] == 1 + N_UP

    # 2. Re-sending a known system ID does not create another adjacency.
    assert inject(r2, [spec(0) for _ in range(8)], spacing=0.05) == 8
    assert adj_count(r1, "eth-r2", 2) == 1 + N_INIT + N_UP

    # 3a. Controls: no Area Addresses TLV / no Protocols Supported TLV /
    #     L1 IIH with a foreign area must not create adjacencies.
    assert inject(r2, [spec(900, area=None)], spacing=0.05) == 1
    assert inject(r2, [spec(901, protocols=None)], spacing=0.05) == 1
    assert inject(r2, [spec(902, level=1, area=WRONG_AREA)],
                  spacing=0.05) == 1
    assert adj_count(r1, "eth-r2", 2) == 1 + N_INIT + N_UP
    assert adj_count(r1, "eth-r2", 1) == 0

    # 3b. Auth control: with an MD5 password on r1's interface, an IIH
    #     with a cleartext auth TLV and one without auth are both
    #     rejected.  r2's own IIHs fail too; its adjacency recovers
    #     after the password is removed (protocol-normal flap).
    r1.vtysh_cmd(
        "configure terminal\ninterface eth-r2\nisis password md5 topofuzz\nend"
    )
    time.sleep(1)
    assert inject(r2, [spec(903, auth="01" + b"wrongpass".hex())],
                  spacing=0.05) == 1
    assert inject(r2, [spec(904, auth=None)], spacing=0.05) == 1
    r1.vtysh_cmd(
        "configure terminal\ninterface eth-r2\nno isis password\nend"
    )
    assert wait_adjacency_up(r1, "10.213.12.2", timeout=60), (
        "r2 adjacency did not recover after the auth control"
    )
    assert adj_count(r1, "eth-r2", 2) == 1 + N_INIT + N_UP
    assert adj_count(r1, "eth-r2", 1) == 0

    # 4. Saturation: more than CAP distinct system IDs.  The adjacency
    #    database must stop at CAP entries per level; the excess is
    #    dropped and counted.  The burst uses Initializing IIHs (no
    #    LAN Neighbours TLV): an Up list longer than the IIH MTU makes
    #    isis_pack_tlvs() fail the whole LAN IIH and send_hello()
    #    silently skips sending, dropping the legitimate neighbours —
    #    a distinct defect the quota does not claim to fix, so the
    #    quota assertions must not depend on it.  Established
    #    adjacencies (r2 on this circuit, r3 on the other) must be
    #    unaffected.
    before = adj_count(r1, "eth-r2", 2)
    dropped_before = circuit_counters(r1, "eth-r2", "L2")[1]
    frames = [spec(i) for i in range(2000, 2000 + CAP + SAT_EXTRA)]
    assert inject(r2, frames, spacing=0.02) == CAP + SAT_EXTRA
    expected_dropped = before + CAP + SAT_EXTRA - CAP
    assert adj_count(r1, "eth-r2", 2) == CAP, (
        "adjacency database not capped at %d: %d" % (CAP, adj_count(r1, "eth-r2", 2))
    )
    assert circuit_counters(r1, "eth-r2", "L2")[1] == \
        (dropped_before or 0) + expected_dropped, (
        "excess adjacencies not dropped and counted"
    )
    # NOTE: the fate of r2's adjacency at this point is not asserted:
    # once the table outgrows the IIH MTU (~230 entries incl.
    # Initializing), send_hello() silently stops the LAN IIH and the
    # neighbour drops — a distinct pre-existing defect (see the module
    # docstring).  Recovery after the drain is asserted in step 6c.

    # 5a. The quota is per circuit: r3's adjacency is untouched.
    assert adjacency_up(r1, "10.213.13.3")
    assert adj_count(r1, "eth-r3", 2) == 1

    # 5b. The quota is per level: a valid L1 IIH is still admitted.
    assert inject(r2, [spec(3000, level=1, with_neigh=True, r1_mac=r1_mac)],
                  spacing=0.05) == 1
    assert adj_count(r1, "eth-r2", 1) == 1
    assert circuit_counters(r1, "eth-r2", "L2")[1] == \
        (dropped_before or 0) + expected_dropped

    # 6a. After the injected adjacencies' holdtime expires, the
    #     database drains back to the legitimate one.
    assert wait_adj_count(r1, "eth-r2", 2, 1, GC_TIMEOUT), (
        "injected adjacencies not reclaimed after holdtime"
    )
    assert wait_adj_count(r1, "eth-r2", 1, 0, 60)

    # 6b. A fresh system ID is admitted again.
    assert inject(r2, [spec(4000)], spacing=0.05) == 1
    assert adj_count(r1, "eth-r2", 2) == 2

    # 6c. Legitimate adjacencies and routes are intact.  r2's
    #     adjacency re-forms a few seconds after the IIH resumes on
    #     the drained circuit, and its loopback route follows the
    #     adjacency, so poll instead of checking once.
    assert wait_adjacency_up(r1, "10.213.12.2", timeout=90), (
        "r2 adjacency did not recover after the drain"
    )
    assert adjacency_up(r1, "10.213.13.3")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if route_present(r1, "10.0.2.2") and route_present(r1, "10.0.3.3"):
            break
        time.sleep(3)
    assert route_present(r1, "10.0.2.2"), "r2 loopback route missing after the drain"
    assert route_present(r1, "10.0.3.3"), "r3 loopback route missing after the drain"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
