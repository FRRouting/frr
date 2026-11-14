#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Aviz Networks
#
# SRv6 L2 EVPN topotest - THREE PEs in ONE EVI (multi-remote-PE).
#
# This is the scenario the 2-PE suite cannot reach: a single EVI spanning
# THREE PEs, so each PE has TWO remote peers advertising TWO distinct per-EVI
# End.DT2U (unicast) / End.DT2M (BUM) SIDs.
#
#   EVI 10 <-> br10 (VLAN 10, eth1) on r1, r2, r3   192.0.2.0/24
#     host1 (r1)    host2 (r2)    host3 (r3)
#   Shared SRv6 core LAN (switch s1): r{1,2,3} eth0, 2001:db8:20::{1,2,3}
#
# The sr6 netdev carries its encap SID IMPLICITLY (the FDB entry is just
# `dev sr6-N`, no per-MAC SID), so two remote SIDs MUST land on two DISTINCT
# sr6/bum-sr6 ports or each overwrites the other's encap and both peers' traffic
# follows whichever SID was programmed last.  The operator therefore provisions
# ONE unicast sr6 + ONE BUM bum-sr6 port PER REMOTE PE (two of each here), and
# zebra hands each remote SID its own.  These tests assert exactly that:
#   - each PE programs its two remote host MACs onto two DISTINCT unicast ports;
#   - all three host pairs ping (impossible under a single shared port);
#   - withdrawing one peer resets only that peer's port, not the other's.
#
# All assertions are behaviour/kernel-based (robust to the zebra-assigned per-EVI
# SID function values and to which remote binds which port).

import os, sys, json, pytest
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]


def _sr6_kernel_supported():
    """End.DT2U/DT2M forwarding needs an 'sr6' netdev not in mainline Linux;
    probe once so the dataplane tests skip (not fail) on kernels without it."""
    import subprocess

    env = os.environ.get("SR6_SUPPORTED")
    if env is not None:
        return env not in ("0", "", "no", "false")

    probe = "sr6probe%d" % os.getpid()
    try:
        res = subprocess.run(["ip", "link", "add", "name", probe, "type", "sr6"],
                             capture_output=True)
    except OSError:
        return False
    if res.returncode == 0:
        subprocess.run(["ip", "link", "del", probe], capture_output=True)
        return True
    err = (res.stderr or b"").decode(errors="replace").lower()
    return not ("unknown" in err or "not supported" in err)


sr6_supported = _sr6_kernel_supported()
sr6_required = pytest.mark.skipif(
    not sr6_supported,
    reason="kernel lacks SRv6 sr6 netdev support (End.DT2U/DT2M dataplane)",
)


def _sr6_reprogram_supported():
    """Operator-owned sr6 model: the operator pre-creates the sr6 netdev with a
    placeholder SID and zebra rewrites it in place.  Some drivers reject the
    in-place change; without it L2 *encap* cannot work, so the forwarding tests
    SKIP (not fail) there.  SR6_REPROGRAM=0/1 overrides the auto-detect."""
    import subprocess

    env = os.environ.get("SR6_REPROGRAM")
    if env is not None:
        return env not in ("0", "", "no", "false")
    if not sr6_supported:
        return False
    dev = "sr6repr%d" % os.getpid()
    try:
        add = subprocess.run(
            ["ip", "link", "add", "name", dev, "type", "sr6", "mode", "full",
             "segs", "2001:db8::1"], capture_output=True)
        if add.returncode != 0:
            return False
        chg = subprocess.run(
            ["ip", "link", "set", dev, "type", "sr6", "mode", "full",
             "segs", "2001:db8::2"], capture_output=True)
        return chg.returncode == 0
    except OSError:
        return False
    finally:
        subprocess.run(["ip", "link", "del", dev], capture_output=True)


sr6_reprogram_supported = _sr6_reprogram_supported()
sr6_reprogram_required = pytest.mark.skipif(
    not sr6_reprogram_supported,
    reason="sr6 driver lacks in-place segs reprogram; operator-owned sr6 encap "
    "needs the sr6 kernel patch",
)

# One EVI spanning all three PEs.
EVI, BR, AC, VID = 10, "br10", "eth1", 10
# Two remote PEs per PE => one unicast + one BUM sr6 port per remote PE.
N_REMOTE = 2
# (PE -> [(remote host, remote host IP), ...]) from that PE's point of view.
VIEWS = {
    "r1": [("host2", "192.0.2.2"), ("host3", "192.0.2.3")],
    "r2": [("host1", "192.0.2.1"), ("host3", "192.0.2.3")],
    "r3": [("host1", "192.0.2.1"), ("host2", "192.0.2.2")],
}
# Peers each PE must bring to Established (full mesh over the core LAN).
PEERS = {
    "r1": ["2001:db8:20::2", "2001:db8:20::3"],
    "r2": ["2001:db8:20::1", "2001:db8:20::3"],
    "r3": ["2001:db8:20::1", "2001:db8:20::2"],
}
# Per-PE locator block prefix (for SID-allocation + underlay assertions).
LOCATOR = {"r1": "fcbb:bbbb:1:", "r2": "fcbb:bbbb:2:", "r3": "fcbb:bbbb:3:"}


def build_topo(tgen):
    for r in ("r1", "r2", "r3", "host1", "host2", "host3"):
        tgen.add_router(r)
    # Shared SRv6 core LAN so every PE reaches every router-id / locator (the
    # Type-3 originator IP == router-id must be reachable or BUM breaks).
    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"], nodeif="eth0")
    s1.add_link(tgen.gears["r2"], nodeif="eth0")
    s1.add_link(tgen.gears["r3"], nodeif="eth0")
    # EVI 10 access circuits.
    tgen.add_link(tgen.gears["host1"], tgen.gears["r1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["host2"], tgen.gears["r2"], "eth0", "eth1")
    tgen.add_link(tgen.gears["host3"], tgen.gears["r3"], "eth0", "eth1")


# Operator-owned sr6 model: FRR does not create/enslave/up the sr6 netdevs.
# The operator pre-creates them, enslaves to the EVI bridge, brings them up;
# zebra discovers them by name prefix and programs the zebra-assigned SID in
# place.  The segs below is a placeholder zebra overwrites.
_SR6_DUMMY_SID = "2001:db8:5262::1"


def _add_sr6(pe, name, br, is_bum, brport=True, vid=None):
    pe.run("ip link add name %s type sr6 mode full segs %s" % (name, _SR6_DUMMY_SID))
    pe.run("ip link set %s addrgenmode none" % name)
    pe.run("ip link set %s master %s" % (name, br))
    if vid:
        pe.run("bridge vlan add dev %s vid %d" % (name, vid))
    if brport:
        fl = "on" if is_bum else "off"
        pe.run("bridge link set dev %s learning off flood %s mcast_flood %s "
               "bcast_flood %s isolated on" % (name, fl, fl, fl))
    pe.run("ip link set %s up" % name)


def _pe_kernel(pe):
    # One VLAN-aware bridge for EVI 10, AC on eth1.
    pe.run("ip link add %s type bridge vlan_filtering 1" % BR)
    pe.run("ip link set %s up" % BR)
    pe.run("ip link set %s master %s" % (AC, BR))
    pe.run("bridge vlan add dev %s vid %d self" % (BR, VID))
    pe.run("bridge vlan add dev %s vid %d pvid untagged" % (AC, VID))
    pe.run("ip link set %s up" % AC)
    # One unicast + one BUM sr6 port PER REMOTE PE, so each remote SID gets its
    # own port (the distinct-port assignment under test).  Names are arbitrary;
    # zebra discovers by the sr6-/bum-sr6- prefix + bridge membership.
    for n in range(N_REMOTE):
        _add_sr6(pe, "sr6-%d" % (EVI + n), BR, is_bum=False, vid=VID)
        _add_sr6(pe, "bum-sr6-%d" % (EVI + n), BR, is_bum=True, vid=VID)


def setup_module(mod):
    if required_linux_kernel_version("5.14") is not True:
        pytest.skip("Kernel requirements are not met")
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "%s/frr.conf" % rname))
    for pe in ("r1", "r2", "r3"):
        _pe_kernel(tgen.gears[pe])
    tgen.start_router()

    # (Re)assert the VLAN->EVI binding after boot (the locator itself is already
    # instantiated by the unified frr.conf load; do NOT re-create it).
    evi_block = ("configure terminal\nsegment-routing\n srv6\n  l2-evpn\n"
                 "   evi %d locator MAIN bridge %s\n    service-type vlan-based\n"
                 "     vlan %d\n   exit\n" % (EVI, BR, VID))
    for pe in ("r1", "r2", "r3"):
        tgen.gears[pe].vtysh_cmd(evi_block)

    last = {"reason": "not evaluated"}

    def _converged():
        try:
            for pe, peers in PEERS.items():
                s = json.loads(tgen.gears[pe].vtysh_cmd(
                    "show bgp l2vpn evpn summary json"))
                for p in peers:
                    st = s.get("peers", {}).get(p, {}).get("state")
                    if st != "Established":
                        last["reason"] = "%s->%s BGP=%s" % (pe, p, st)
                        return False
            # Each PE must have both remote locator blocks in its RIB (the
            # configured static /48s confirm zebra processed config / is live).
            for pe in ("r1", "r2", "r3"):
                rib = tgen.gears[pe].run("ip -6 route show")
                for other, pfx in LOCATOR.items():
                    if other == pe:
                        continue
                    if pfx not in rib:
                        last["reason"] = "%s missing remote locator %s" % (pe, pfx)
                        return False
            return True
        except (KeyError, ValueError, TypeError) as e:
            last["reason"] = "exception: %r" % e
            return False

    reapplied = [False]

    def _converged_or_retry():
        if _converged():
            return True
        if not reapplied[0] and "missing remote locator" in last["reason"]:
            for pe in ("r1", "r2", "r3"):
                tgen.gears[pe].vtysh_cmd(evi_block)
            reapplied[0] = True
        return False

    _, ok = topotest.run_and_expect(_converged_or_retry, True, count=180, wait=1)
    assert ok is True, \
        "topology did not converge (BGP full mesh + underlay) within 180s: %s" \
        % last["reason"]


def teardown_module(mod):
    get_topogen().stop_topology()


def _mac(host):
    return get_topogen().gears[host].run(
        "cat /sys/class/net/eth0/address").strip().lower()


def _sr6_devs_for_mac(pe_gear, mac):
    """Unicast sr6- ports (not bum-sr6-) this MAC's FDB entries point at."""
    devs = set()
    for ln in pe_gear.run("bridge fdb show").splitlines():
        toks = ln.split()
        if not toks or toks[0].lower() != mac or "dev" not in toks:
            continue
        d = toks[toks.index("dev") + 1]
        if d.startswith("sr6-"):        # bum-sr6-* starts with "bum", excluded
            devs.add(d)
    return devs


def _nudge_full_mesh():
    """Make every host ping the other two so every PE learns the remote MACs
    and originates a Type-2 (echo request alone triggers local learning; no
    reply needed, so this holds even without the encap dataplane)."""
    tgen = get_topogen()
    pairs = [("host1", "192.0.2.2"), ("host1", "192.0.2.3"),
             ("host2", "192.0.2.1"), ("host2", "192.0.2.3"),
             ("host3", "192.0.2.1"), ("host3", "192.0.2.2")]
    for h, ip in pairs:
        tgen.gears[h].run("ping -c2 -W1 %s" % ip)


def _expect_text(router, cmd, needles, count=30, wait=1):
    def _missing():
        out = get_topogen().gears[router].vtysh_cmd(cmd)
        miss = [n for n in needles if n not in out]
        return miss if miss else None
    _, res = topotest.run_and_expect(_missing, None, count=count, wait=wait)
    assert res is None, "%s: missing %s in '%s'" % (router, res, cmd)


# (1) BGP full mesh: each PE Established with both other PEs.
def test_bgp_full_mesh_neighborship():
    def _down():
        bad = []
        for pe, peers in PEERS.items():
            try:
                s = json.loads(get_topogen().gears[pe].vtysh_cmd(
                    "show bgp l2vpn evpn summary json"))
            except ValueError:
                bad.append("%s: summary not json" % pe)
                continue
            for p in peers:
                st = s.get("peers", {}).get(p, {}).get("state")
                if st != "Established":
                    bad.append("%s->%s=%s" % (pe, p, st))
        return bad or None
    _, res = topotest.run_and_expect(_down, None, count=60, wait=1)
    assert res is None, "BGP not full-mesh Established: %s" % res


# (2) Each PE allocates its own per-EVI DT2U + DT2M under its locator block.
def test_srv6_sid_allocation():
    for pe in ("r1", "r2", "r3"):
        _expect_text(pe, "show bgp segment-routing srv6 evpn",
                     [LOCATOR[pe], "End.DT2U", "End.DT2M"])


# (3) THE regression assertion: on every PE the two remote host MACs are
#     programmed onto two DISTINCT unicast sr6 ports.  Pre-fix, both remote
#     SIDs resolve to the same first-match port, so both MACs collide on one
#     port (or one is missing) and this fails.
@sr6_required
def test_distinct_sr6_port_per_remote_pe():
    tgen = get_topogen()
    _nudge_full_mesh()

    def _bad():
        problems = []
        for pe, remotes in VIEWS.items():
            chosen = {}
            for host, _ip in remotes:
                devs = _sr6_devs_for_mac(tgen.gears[pe], _mac(host))
                if len(devs) != 1:
                    problems.append("%s: remote %s MAC on %d unicast sr6 ports %s "
                                    "(want exactly 1)" % (pe, host, len(devs),
                                                          sorted(devs)))
                else:
                    chosen[host] = next(iter(devs))
            if len(chosen) == len(remotes) and len(set(chosen.values())) < len(remotes):
                problems.append("%s: remote MACs collide on one port %s "
                                "(pre-fix shared-port behaviour)" % (pe, chosen))
        return problems or None

    _, res = topotest.run_and_expect(_bad, None, count=40, wait=1)
    assert res is None, "distinct-port-per-remote failed:\n%s" % res


# (4) End-to-end multi-remote proof: all three host pairs ping.  Under the
#     shared-port collision at most one remote per PE is reachable, so at least
#     one of these fails.
@sr6_required
@sr6_reprogram_required
def test_ping_full_mesh():
    check_ping("host1", "192.0.2.2", True, 20, 1)
    check_ping("host1", "192.0.2.3", True, 20, 1)
    check_ping("host2", "192.0.2.3", True, 20, 1)


# (5) Isolated withdraw (stays LAST - mutates r3): removing EVI 10 on r3 must
#     clear ONLY r3's port on r1; r2's port and its programmed MAC are
#     untouched.  Pre-fix, both remotes share one port, so withdrawing r3 would
#     reset the shared port and tear down r2's encap too.
@sr6_required
def test_peer_withdraw_isolates_only_its_port():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    _nudge_full_mesh()
    mac2, mac3 = _mac("host2"), _mac("host3")

    def _pre_not_ready():
        d2, d3 = _sr6_devs_for_mac(r1, mac2), _sr6_devs_for_mac(r1, mac3)
        if len(d2) == 1 and len(d3) == 1 and d2 != d3:
            return None
        return ("r1's two remote MACs not on distinct ports (host2=%s host3=%s)"
                % (sorted(d2), sorted(d3)))
    _, res = topotest.run_and_expect(_pre_not_ready, None, count=40, wait=1)
    assert res is None, "precondition: %s" % res
    dev2 = next(iter(_sr6_devs_for_mac(r1, mac2)))

    # Withdraw PE3 from the EVI.
    tgen.gears["r3"].vtysh_cmd(
        "configure terminal\nsegment-routing\n srv6\n  l2-evpn\n   no evi 10\n")

    def _bad():
        problems = []
        if _sr6_devs_for_mac(r1, mac3):
            problems.append("host3 MAC still on %s after r3 withdrew EVI 10"
                            % sorted(_sr6_devs_for_mac(r1, mac3)))
        d2 = _sr6_devs_for_mac(r1, mac2)
        if d2 != {dev2}:
            problems.append("host2 MAC port changed/lost (was %s now %s): r3 "
                            "withdraw disturbed r2's port" % (dev2, sorted(d2)))
        return problems or None

    _, res = topotest.run_and_expect(_bad, None, count=40, wait=1)
    assert res is None, "withdraw isolation failed:\n%s" % res


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
