#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026

"""
test_isis_noncontiguous_mask.py:

        +---------+            +---------+            +---------+
        |   r2    | 10.0.12/24 |   r1    | 10.0.13/24 |   r3    |
        | origin  +------------+ target  +------------+ observer|
        +---------+            +---------+            +---------+

Test that old-style IPv4 Reachability TLVs (128/130) carrying a
non-contiguous netmask are not silently folded into a different prefix.

RFC 1195 section 3.10 encodes the IPv4 reachability information as an
address+mask pair; FRR stores it as a struct prefix, which can only
represent contiguous masks.  unpack_item_oldstyle_ip_reach() derived the
prefix length with ip_masklen() (leading one bits only) and process_N()
then apply_mask()ed the address to that length, so e.g.
10.0.2.0 + 255.0.255.0 was converted into 10.0.0.0/8 and installed as a
route.  A non-contiguous mask cannot be represented and the entry must
be skipped instead.

Trigger: a hand-crafted L2 LSP claiming r2's LSP id, carrying
  TLV 128: 10.0.2.0 + 255.0.255.0 (non-contiguous), 10.0.3.0 + /24 and
           0.0.0.0 + 0.0.0.0 (legal entries in the same TLV)
  TLV 130: 172.16.9.0 + 255.255.0.255 (non-contiguous)
is injected on r2-eth0.  r2's isisd is stopped after convergence while
the adjacency is inside its advertised holdtime (hello-multiplier 30),
so the originator cannot fight the forged copy back and the entry stays
in the LSDB for a stable observation window.  The target r1 must not
install the folded prefixes in its LSDB, IS-IS RIB, zebra or the kernel,
the downstream observer r3 must not learn them either, and the legal
entries of the same TLVs must be installed.  Controls: an invalid
Fletcher checksum is dropped before TLV unpacking and an older seqno is
ignored.  A final transition-mode case checks that new-style TLV 135
processing stays intact while the non-contiguous old-style entry is
still skipped.
"""

import functools
import json
import os
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

HELPER = os.path.join(CWD, "isis_ncm_send.py")

PEER_SYSID = "0000.0000.0002"
PEER_LSP_ID = "0000.0000.0002.00-00"
PEER_IF_ADDR = "10.0.12.2"
R1_SYSID = "0000.0000.0001"
PEER_LOOPBACK = "10.255.0.2/32"

BOGUS_FOLDED = "10.0.0.0/8"
BOGUS_FOLDED_EXT = "172.16.0.0/16"
LEGAL = "10.0.3.0/24"
DEFAULT = "0.0.0.0/0"
NEWSTYLE = "10.0.4.0/24"


def build_topo(tgen):
    """Build r2 - r1 - r3 chain."""
    for router in ("r1", "r2", "r3"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _find_lsp(value, sysid):
    if isinstance(value, dict):
        lsp = value.get("lsp")
        if isinstance(lsp, dict) and sysid in str(lsp.get("id", "")):
            return value
        for child in value.values():
            found = _find_lsp(child, sysid)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_lsp(child, sysid)
            if found is not None:
                return found
    return None


def _peer_lsp_seqno(router):
    data = router.vtysh_cmd("show isis database json", isjson=True)
    lsp = _find_lsp(data, PEER_SYSID)
    if lsp is None:
        return None
    return int(lsp["seqNumber"], 16)


def _adjacency_up(router, peer_ip):
    raw = router.vtysh_cmd("show isis neighbor detail")
    blocks = []
    current = None
    for line in raw.splitlines():
        if line.startswith(" ") and not line.startswith("    ") and line.strip():
            if current:
                blocks.append(current)
            current = line
        elif current is not None:
            current += "\n" + line
    if current:
        blocks.append(current)
    return any(peer_ip in block and "State: Up" in block for block in blocks)


def _adjacencies_up(r1, r3):
    if (
        _adjacency_up(r1, PEER_IF_ADDR)
        and _adjacency_up(r1, "10.0.13.3")
        and _adjacency_up(r3, "10.0.13.1")
    ):
        return None
    return "adjacencies not up yet"


def _isis_route_has(router, prefix):
    data = router.vtysh_cmd("show isis route json", isjson=True)
    return prefix in json.dumps(data)


def _zebra_route_has(router, prefix):
    data = router.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
    return prefix in data


def _kernel_route_has(router, prefix):
    return bool(router.run("ip route show {}".format(prefix)).strip())


def _lsdb_detail_has(router, needle):
    return needle in router.vtysh_cmd("show isis database detail")


def _isis_route_absent(router, prefix):
    if _isis_route_has(router, prefix):
        return "IS-IS route {} present on {}".format(prefix, router.name)
    return None


def _isis_route_present(router, prefix):
    if not _isis_route_has(router, prefix):
        return "IS-IS route {} absent on {}".format(prefix, router.name)
    return None


def _zebra_route_absent(router, prefix):
    if _zebra_route_has(router, prefix):
        return "zebra route {} present on {}".format(prefix, router.name)
    return None


def _kernel_route_absent(router, prefix):
    if _kernel_route_has(router, prefix):
        return "kernel route {} present on {}".format(prefix, router.name)
    return None


def _lsdb_entry_absent(router, needle):
    if _lsdb_detail_has(router, needle):
        return "LSDB detail on {} contains {}".format(router.name, needle)
    return None


def _expect(test_func, count=20, wait=0.5):
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert result is None, result


def _inject(r2, mode, seqno):
    out = r2.run(
        "python3 {} inject --iface r2-eth0 --lsp-id {} --neighbor-sysid {} "
        "--if-addr {} --mode {} --seqno {}".format(
            HELPER, PEER_LSP_ID, R1_SYSID, PEER_IF_ADDR, mode, seqno
        )
    )
    assert "SENT_JSON=" in out, out
    return json.loads(out.split("SENT_JSON=", 1)[1].splitlines()[0])


def test_convergence():
    """Adjacencies come up and no bogus prefix exists before the trigger."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    step("Wait for IS-IS adjacencies r1<->r2 and r1<->r3")
    _expect(functools.partial(_adjacencies_up, r1, r3), count=90, wait=1)

    step("Precondition: r1 has an IS-IS route to r2's loopback")
    _expect(functools.partial(_isis_route_present, r1, PEER_LOOPBACK))

    step("Precondition: bogus prefixes are absent everywhere")
    for router in (r1, r3):
        _expect(functools.partial(_isis_route_absent, router, BOGUS_FOLDED))
        _expect(functools.partial(_isis_route_absent, router, BOGUS_FOLDED_EXT))

    assert _peer_lsp_seqno(r1) is not None


def test_noncontiguous_mask_narrow():
    """TLV 128/130 with a non-contiguous netmask must not become routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Stop r2's isisd so the forged LSP cannot be fought back")
    r2.killDaemons(["isisd"])
    # The originator stays down for the rest of the module; keep the
    # per-test daemon health check from failing on the deliberate kill.
    r2.net.daemons["isisd"] = 0
    assert _adjacency_up(r1, PEER_IF_ADDR), "r1<->r2 adjacency dropped after isisd kill"

    # Read the seqno the target currently holds so the forged copy is
    # strictly newer; a stale value would make the injection an LSP_EQUAL
    # replay that the target legitimately ignores.
    seqno = _peer_lsp_seqno(r1) + 1
    step("Inject forged r2 LSP with non-contiguous masks in TLV 128/130")
    sent = _inject(r2, "nc_mask", seqno)
    wire = [
        (entry["prefix"], entry["mask"])
        for tlv in sent["tlvs"] if tlv["tlv"] == 128
        for entry in tlv["entries"]
    ]
    assert ("10.0.2.0", "255.0.255.0") in wire, wire
    wire_ext = [
        (entry["prefix"], entry["mask"])
        for tlv in sent["tlvs"] if tlv["tlv"] == 130
        for entry in tlv["entries"]
    ]
    assert ("172.16.9.0", "255.255.0.255") in wire_ext, wire_ext

    step("The forged LSP is accepted into the LSDB (seqno bump)")
    test_func = functools.partial(
        lambda: None
        if _peer_lsp_seqno(r1) == seqno
        else "peer LSP seqno is {}, expected {}".format(_peer_lsp_seqno(r1), seqno)
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assert result is None, result

    step("Legal entries of the same TLVs are installed on r1 and r3")
    for router in (r1, r3):
        _expect(functools.partial(_isis_route_present, router, LEGAL))
        _expect(functools.partial(_isis_route_present, router, DEFAULT))

    step("Folded prefixes must not reach the IS-IS RIB of r1 and r3")
    for router in (r1, r3):
        _expect(functools.partial(_isis_route_absent, router, BOGUS_FOLDED))
        _expect(functools.partial(_isis_route_absent, router, BOGUS_FOLDED_EXT))

    step("Folded prefixes must not reach zebra or the kernel of r1")
    _expect(functools.partial(_zebra_route_absent, r1, BOGUS_FOLDED))
    _expect(functools.partial(_zebra_route_absent, r1, BOGUS_FOLDED_EXT))
    _expect(functools.partial(_kernel_route_absent, r1, BOGUS_FOLDED))
    _expect(functools.partial(_kernel_route_absent, r1, BOGUS_FOLDED_EXT))

    step("The folded entry must not appear in the LSDB detail of r1")
    _expect(functools.partial(_lsdb_entry_absent, r1, "10.0.2.0/8"))


def test_invalid_checksum_control():
    """A corrupted Fletcher checksum is dropped before TLV unpacking."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    seqno_before = _peer_lsp_seqno(r1)
    step("Inject the same LSP with a corrupted checksum")
    _inject(r2, "invalid_cksum", seqno_before + 1)

    step("LSDB keeps the previous seqno and routes stay unchanged")
    time.sleep(2)
    assert _peer_lsp_seqno(r1) == seqno_before, "corrupted LSP changed the LSDB"
    assert _isis_route_has(r1, LEGAL), "legal route vanished after corrupted LSP"


def test_older_seqno_control():
    """A replay with an older seqno is ignored."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    seqno_before = _peer_lsp_seqno(r1)
    step("Inject the same LSP with an older seqno")
    _inject(r2, "older", max(seqno_before - 1, 1))

    step("LSDB keeps the current seqno and routes stay unchanged")
    time.sleep(2)
    assert _peer_lsp_seqno(r1) == seqno_before, "older LSP changed the LSDB"
    assert _isis_route_has(r1, LEGAL), "legal route vanished after older LSP"


def test_transition_newstyle():
    """In transition mode TLV 135 stays intact and the bad TLV 128 is skipped."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Switch r1 to metric-style transition")
    r1.vtysh_cmd("configure terminal\nrouter isis TEST\nmetric-style transition\nend")
    time.sleep(3)

    seqno = _peer_lsp_seqno(r1) + 1
    step("Inject LSP with new-style TLV 135 plus non-contiguous TLV 128")
    sent = _inject(r2, "transition", seqno)
    wire = [
        (entry["prefixlen"], entry["prefix"])
        for tlv in sent["tlvs"] if tlv["tlv"] == 135
        for entry in tlv["entries"]
    ]
    assert (24, "10.0.4") in wire, wire

    step("The forged LSP is accepted into the LSDB (seqno bump)")
    test_func = functools.partial(
        lambda: None
        if _peer_lsp_seqno(r1) == seqno
        else "peer LSP seqno is {}, expected {}".format(_peer_lsp_seqno(r1), seqno)
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assert result is None, result

    step("The new-style prefix reaches the IS-IS RIB, zebra and kernel of r1")
    _expect(functools.partial(_isis_route_present, r1, NEWSTYLE))
    _expect(functools.partial(_zebra_route_present, r1, NEWSTYLE))
    _expect(functools.partial(_kernel_route_present, r1, NEWSTYLE))

    step("The non-contiguous TLV 128 entry is still not folded anywhere")
    for router in (r1, r3):
        _expect(functools.partial(_isis_route_absent, router, BOGUS_FOLDED))

    step("The legal old-style entries of the same TLV are still installed")
    _expect(functools.partial(_isis_route_present, r1, LEGAL))
    _expect(functools.partial(_isis_route_present, r1, DEFAULT))

    step("The old TLV 130 entry is gone with the replaced LSP")
    _expect(functools.partial(_isis_route_absent, r1, BOGUS_FOLDED_EXT))


def _zebra_route_present(router, prefix):
    if not _zebra_route_has(router, prefix):
        return "zebra route {} absent on {}".format(prefix, router.name)
    return None


def _kernel_route_present(router, prefix):
    if not _kernel_route_has(router, prefix):
        return "kernel route {} absent on {}".format(prefix, router.name)
    return None


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
