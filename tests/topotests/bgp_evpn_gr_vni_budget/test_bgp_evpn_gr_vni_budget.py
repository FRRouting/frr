#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_evpn_gr_vni_budget.py
#
# Copyright (C) 2026 Johan Linder
#
# PE1 ---- PE2 (eBGP EVPN with graceful restart)
#
# Fifty shared L2VNIs carry 110 MACs each, plus an SVI on every second VNI.
# Ten PE2-only VNIs have no remote destinations, even during the first pass.
# The
# global EVPN table and per-VNI MAC/IP tables exceed the 10000-destination
# budget. Restart PE2's bgpd and check actual deferred-work accounting,
# including nonzero incoming counts, completed tables and the batch boundary.
# Verify the learned MACs and SVI neighbours in zebra and the kernel as well.

import functools
import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest  # noqa: E402
from lib.common_config import (  # noqa: E402
    kill_router_daemons,
    start_router_daemons,
)
from lib.topogen import Topogen, get_topogen  # noqa: E402
from lib.topolog import logger  # noqa: E402

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

PE = {"PE1": "1", "PE2": "2"}
VNIS = range(101, 151)
EMPTY_VNIS = range(151, 161)
MACS_PER_VNI = 110
BUDGET = 10000  # BGP_MAX_BEST_ROUTE_SELECT


def _mac(vni, index):
    return f"02:00:00:{vni:02x}:{index // 256:02x}:{index % 256:02x}"


def build_topo(tgen):
    for name in PE:
        tgen.add_router(name)
    tgen.add_link(tgen.gears["PE1"], tgen.gears["PE2"], "PE1-eth0", "PE2-eth0")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name, suf in PE.items():
        pe = tgen.net[name]
        vnis = list(VNIS) + (list(EMPTY_VNIS) if name == "PE2" else [])
        for vni in vnis:
            pe.cmd_raises(
                f"ip link add vxlan{vni} type vxlan id {vni} dstport 4789 "
                f"local 10.100.0.{suf} nolearning"
            )
            pe.cmd_raises(
                f"ip link add name br{vni} "
                f"address 02:11:00:00:{int(suf):02x}:{vni:02x} "
                "type bridge stp_state 0"
            )
            pe.cmd_raises(f"ip link set dev vxlan{vni} master br{vni}")
            pe.cmd_raises(f"ip link set up dev br{vni}")
            pe.cmd_raises(f"ip link set up dev vxlan{vni}")
        if name != "PE1":
            continue
        fdb = []
        for vni in VNIS:
            pe.cmd_raises(f"ip link add acc{vni} type dummy")
            pe.cmd_raises(f"ip link set dev acc{vni} master br{vni}")
            pe.cmd_raises(f"ip link set up dev acc{vni}")
            if vni % 2 == 0:
                pe.cmd_raises(f"ip addr add 192.168.{vni}.1/24 dev br{vni}")
            for m in range(MACS_PER_VNI):
                fdb.append(f"fdb add {_mac(vni, m)} dev acc{vni} master static")
        path = os.path.join(tgen.logdir, "PE1", "fdb-batch.txt")
        with open(path, "w") as f:
            f.write("\n".join(fdb) + "\n")
        pe.cmd_raises(f"bridge -batch {path}")

    for rname, router in tgen.routers().items():
        logger.info(f"Loading config to router {rname}")
        router.load_frr_config(os.path.join(CWD, f"{router.name}/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _log_path(router, daemon):
    return os.path.join(get_topogen().logdir, router.name, f"{daemon}.log")


def _evpn_established(router, peer):
    out = router.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True) or {}
    return out.get("peers", {}).get(peer, {}).get("state") == "Established"


def _installed(router):
    """Check every injected MAC and every advertised SVI, in both layers."""
    macs = router.vtysh_cmd("show evpn mac vni all json", isjson=True) or {}
    fdb = json.loads(router.cmd_raises("bridge -j fdb show"))
    installed = {
        (entry.get("ifname"), entry.get("mac"), entry.get("dst")) for entry in fdb
    }
    neighbours = json.loads(router.cmd_raises("ip -j neigh show"))
    ips = {
        (entry.get("dev"), entry.get("dst"), entry.get("lladdr"))
        for entry in neighbours
    }
    for vni in VNIS:
        table = macs.get(str(vni), {}).get("macs", {})
        for index in range(MACS_PER_VNI):
            mac = _mac(vni, index)
            if table.get(mac, {}).get("type") != "remote":
                return f"VNI {vni}: {mac} missing from zebra"
            if (f"vxlan{vni}", mac, "10.100.0.1") not in installed:
                return f"VNI {vni}: {mac} missing from kernel VXLAN FDB"
        if vni % 2 == 0:
            address = f"192.168.{vni}.1"
            mac = f"02:11:00:00:01:{vni:02x}"
            if (f"br{vni}", address, mac) not in ips:
                return f"VNI {vni}: {address} missing from kernel neighbours"
    return None


def _check_installed(router):
    _, result = topotest.run_and_expect(
        functools.partial(_installed, router), None, count=90, wait=1
    )
    assert result is None, result


def test_converged():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _check_installed(tgen.gears["PE2"])


PASS_RE = re.compile(r"Started doing BGP deferred path selection for L2VPN EVPN")
VNI_RE = re.compile(
    r"GR walking IP and MAC table for VNI (\d+)\. Deferred paths (\d+), batch cnt (\d+)"
)


CONTINUE_RE = re.compile(
    r"Continuing deferred path selection for L2VPN EVPN, #routes (\d+)"
)
COMPLETE = "VRF default afi: 3 safi: 5 Command ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE"


def _passes(log):
    """Pair entry counters with pending work at the next timer or completion.

    Entry logs alone do not account for the last VNI in a pass. The next
    timer's pending count (or completion at zero) closes that gap.
    """
    passes = []
    for line in log.splitlines():
        match = CONTINUE_RE.search(line)
        if match and passes:
            passes[-1]["remaining"] = int(match.group(1))
        if COMPLETE in line and passes:
            passes[-1]["remaining"] = 0
        if PASS_RE.search(line):
            passes.append({"entries": [], "remaining": None})
        match = VNI_RE.search(line)
        if match and passes:
            passes[-1]["entries"].append(tuple(map(int, match.groups())))
    return passes


def _read(path, offset=0):
    with open(path, errors="replace") as stream:
        stream.seek(offset)
        return stream.read()


def test_bgpd_restart_vni_budget():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    pe1, pe2 = tgen.gears["PE1"], tgen.gears["PE2"]

    # PE1's startup window (R bit for 120 s) would end PE2's deferral early
    result, _ = topotest.run_and_expect(
        lambda: "Startup timer expired" in _read(_log_path(pe1, "bgpd")),
        True,
        count=150,
        wait=1,
    )
    assert result, "PE1's bgpd startup window did not close"

    path = _log_path(pe2, "bgpd")
    start = os.path.getsize(path) if os.path.exists(path) else 0
    kill_router_daemons(tgen, "PE2", ["bgpd"])
    start_router_daemons(tgen, "PE2", ["bgpd"])
    pe2.cmd("vtysh -f {}".format(os.path.join(CWD, "PE2/frr.conf")))

    result, _ = topotest.run_and_expect(
        functools.partial(_evpn_established, pe1, "10.0.1.2"), True, count=60, wait=2
    )
    assert result, "PE1-PE2 EVPN session did not come back"

    result, _ = topotest.run_and_expect(
        lambda: COMPLETE in _read(path, start), True, count=120, wait=1
    )
    passes = _passes(_read(path, start))
    assert result, f"deferred selection did not finish: {passes}"
    assert passes and all(p["entries"] for p in passes), passes
    assert all(p["remaining"] is not None for p in passes), passes
    logger.info("Deferred selection passes: %s", passes)

    first = passes[0]["entries"]
    assert first[0][2] > 0, f"global table used no budget: {first[0]}"
    empty_table_with_count = False
    completed_table = False
    total_selected = 0
    for batch in passes:
        entries = batch["entries"]
        remaining = batch["remaining"]
        for (vni_a, deferred_a, count_a), (_, deferred_b, count_b) in zip(
            entries, entries[1:]
        ):
            assert count_b - count_a == deferred_a - deferred_b, (
                f"VNI {vni_a}: selected {deferred_a - deferred_b} destinations "
                f"but the count went {count_a} -> {count_b}"
            )
            if vni_a in EMPTY_VNIS and 0 < count_a < BUDGET:
                assert deferred_a == deferred_b, (vni_a, batch)
                assert count_a == count_b, (vni_a, batch)
                empty_table_with_count = True
            if batch is not passes[0] and vni_a in VNIS:
                if deferred_a == deferred_b:
                    assert count_a == count_b, (vni_a, batch)
                    completed_table = True
            assert 0 <= count_a <= count_b <= BUDGET, entries
        # Include the final VNI's work, which has no following entry log.
        initial = entries[0][1] + entries[0][2]
        selected = initial - remaining
        terminal = entries[-1][2] + entries[-1][1] - remaining
        assert 0 <= entries[-1][1] - remaining, batch
        assert selected == terminal == min(initial, BUDGET), batch
        total_selected += selected
        logger.info("Batch selected %d destinations, %d remain", selected, remaining)
    assert empty_table_with_count, "no empty table walked with an active budget"
    assert completed_table, "no completed table revisited on the next pass"
    assert passes[0]["remaining"] > 0, "work did not cross the batch boundary"
    assert any(count == BUDGET for _, _, count in first), first
    assert len(passes) == 2, f"{len(passes)} passes for {total_selected} destinations"
    assert passes[-1]["remaining"] == 0, passes
    _check_installed(pe2)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
