#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Aviz Networks
#
# SRv6 L2 EVPN (VXLAN-decoupled) topotest - multi-VLAN-to-EVI mapping.
#
# Two VLAN-aware bridges, each bound to its own EVI via the zebra
# 'segment-routing srv6 l2-evpn' config (no VXLAN netdev, no 'sid vpn export'):
#   EVI 10 <-> br10 (VLAN 10, eth1)   host1  <-> host2   (10.10.0.0/24)
#   EVI 20 <-> br20 (VLAN 20, eth3)   host1c <-> host2c  (10.20.0.0/24)
# plus one VPWS End.DX2 cross-connect on eth2 (host1b <-> host2b).
# Per-EVI End.DT2U/End.DT2M SIDs are allocated by zebra and reported to bgpd.
#
# All RIB/kernel assertions are behaviour- and locator-prefix-based (robust to
# the zebra-assigned per-EVI SID function values); only r{1,2}/evpn_summary.json
# (BGP peer state, topology-independent) is compared as exact JSON.

import os, sys, json, functools, pytest
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]

def _srl2_kernel_supported():
    """End.DT2U/DT2M forwarding needs an 'srl2' netdev not in mainline Linux;
    probe once so the dataplane tests skip (not fail) on kernels without it.

    We probe with a bare `ip link add type srl2`, which the kernel rejects
    because srl2 needs a segment list ("SRH with segment list is required").
    That rejection still proves the type is RECOGNISED, so treat it as
    supported; only an "unknown device type" (stock kernel) means unsupported.
    SRL2_SUPPORTED=0/1 overrides the auto-detect if ever needed."""
    import subprocess

    env = os.environ.get("SRL2_SUPPORTED")
    if env is not None:
        return env not in ("0", "", "no", "false")

    probe = "srl2probe%d" % os.getpid()
    try:
        res = subprocess.run(["ip", "link", "add", "name", probe, "type", "srl2"],
                             capture_output=True)
    except OSError:
        return False
    if res.returncode == 0:
        subprocess.run(["ip", "link", "del", probe], capture_output=True)
        return True
    err = (res.stderr or b"").decode(errors="replace").lower()
    # Type recognised but our minimal args rejected -> supported.  Only an
    # unknown/unsupported link type means the kernel lacks srl2.
    return not ("unknown" in err or "not supported" in err)

srl2_supported = _srl2_kernel_supported()
srl2_required = pytest.mark.skipif(
    not srl2_supported,
    reason="kernel lacks SRv6 srl2 netdev support (End.DT2U/DT2M dataplane)",
)

# EVI id -> (bridge, member AC ifname, VLAN id) mapping applied on both PEs.
EVIS = ((10, "br10", "eth1", 10), (20, "br20", "eth3", 20))

def build_topo(tgen):
    for r in ("r1", "r2", "host1", "host2", "host1b", "host2b", "host1c", "host2c"):
        tgen.add_router(r)
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")        # SRv6 core
    tgen.add_link(tgen.gears["host1"],  tgen.gears["r1"], "eth0", "eth1")    # EVI 10 AC (br10/vlan10)
    tgen.add_link(tgen.gears["host2"],  tgen.gears["r2"], "eth0", "eth1")
    tgen.add_link(tgen.gears["host1b"], tgen.gears["r1"], "eth0", "eth2")    # VPWS AC (DX2)
    tgen.add_link(tgen.gears["host2b"], tgen.gears["r2"], "eth0", "eth2")
    tgen.add_link(tgen.gears["host1c"], tgen.gears["r1"], "eth0", "eth3")    # EVI 20 AC (br20/vlan20)
    tgen.add_link(tgen.gears["host2c"], tgen.gears["r2"], "eth0", "eth3")


def _pe_kernel(pe):
    # VXLAN-decoupled SRv6 L2 EVPN: no vxlan netdev.  One VLAN-aware bridge per
    # EVI, bound to the EVI purely via 'segment-routing srv6 l2-evpn'; zebra
    # creates the srl2 / bum-srl2 decap netdevs itself.  eth2 is the (unbridged)
    # VPWS AC.
    for _evi, br, ac, vid in EVIS:
        pe.run("ip link add %s type bridge vlan_filtering 1" % br)
        pe.run("ip link set %s up" % br)
        pe.run("ip link set %s master %s" % (ac, br))
        pe.run("bridge vlan add dev %s vid %d self" % (br, vid))
        pe.run("bridge vlan add dev %s vid %d pvid untagged" % (ac, vid))
        pe.run("ip link set %s up" % ac)

def setup_module(mod):
    if required_linux_kernel_version("5.14") is not True:
        pytest.skip("Kernel requirements are not met")
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "%s/zebra.conf" % rname))
        if rname in ("r1", "r2"):
            router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "%s/bgpd.conf" % rname))
    _pe_kernel(tgen.gears["r1"])
    _pe_kernel(tgen.gears["r2"])
    tgen.start_router()

    # Build the l2-evpn re-apply block (all EVIs) once.
    evi_block = "configure terminal\nsegment-routing\n srv6\n  l2-evpn\n"
    for evi, br, _ac, vid in EVIS:
        evi_block += ("   evi %d locator MAIN bridge %s\n"
                      "    service-type vlan-based\n     vlan %d\n   exit\n"
                      % (evi, br, vid))

    for r, pfx in (("r1", "fc00:0:1::/48"), ("r2", "fc00:0:2::/48")):
        # 1. (re)create zebra SRv6 locator (FRR 10.6 mgmtd does NOT instantiate
        #    the locator from a zebra.conf direct-load).
        tgen.gears[r].vtysh_cmd(
            "configure terminal\n"
            "segment-routing\n srv6\n  locators\n"
            "   locator MAIN\n    prefix %s block-len 32 node-len 16\n" % pfx)
        # 2. (re)apply the VLAN->EVI bindings so the per-EVI DT2U/DT2M SIDs are
        #    (re)allocated now that the locator above is instantiated.
        tgen.gears[r].vtysh_cmd(evi_block)

    # Gate on FULL convergence before any test: BGP Established AND the remote
    # SRv6 underlay /128s installed both ways.  Front-loads settling so no
    # per-test poll races on a slow (CI) run.
    last = {"reason": "not evaluated"}

    def _converged():
        try:
            s1 = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp l2vpn evpn summary json"))
            s2 = json.loads(tgen.gears["r2"].vtysh_cmd("show bgp l2vpn evpn summary json"))
            st1 = s1.get("peers", {}).get("2001:db8:20::2", {}).get("state")
            st2 = s2.get("peers", {}).get("2001:db8:20::1", {}).get("state")
            if st1 != "Established" or st2 != "Established":
                last["reason"] = "BGP not Established (r1->r2=%s, r2->r1=%s)" % (st1, st2)
                return False
            # remote underlay must be installed both directions: at least one
            # /128 under the peer's locator block (per-EVI SID function values
            # are zebra-assigned, so match the locator prefix, not an exact SID)
            r1r = tgen.gears["r1"].run("ip -6 route show")
            r2r = tgen.gears["r2"].run("ip -6 route show")
            have = ("fc00:0:2:" in r1r, "fc00:0:1:" in r2r)
            if not all(have):
                last["reason"] = ("underlay missing (r1 has fc00:0:2:=%s, r2 has fc00:0:1:=%s)"
                                  % have)
                return False
            return True
        except (KeyError, ValueError, TypeError) as e:
            last["reason"] = "exception: %r" % e
            return False

    reapplied = [False]

    def _converged_or_retry():
        if _converged():
            return True
        if not reapplied[0] and "underlay missing" in last["reason"]:
            for r in ("r1", "r2"):
                tgen.gears[r].vtysh_cmd(evi_block)
            reapplied[0] = True
        return False

    _, ok = topotest.run_and_expect(_converged_or_retry, True, count=180, wait=1)
    assert ok is True, "topology did not converge (BGP + underlay) within 180s: %s" % last["reason"]


def teardown_module(mod):
    get_topogen().stop_topology()

def _expect(name, cmd, expected_file, count=30, wait=1):
    def _c(r, c, e): return topotest.json_cmp(json.loads(r.vtysh_cmd(c)), e)
    tgen = get_topogen()
    with open(os.path.join(CWD, expected_file)) as f:
        expected = json.load(f)
    func = functools.partial(_c, tgen.gears[name], cmd, expected)
    _, res = topotest.run_and_expect(func, None, count, wait)
    assert res is None, "%s: %s != %s" % (name, cmd, expected_file)

def _expect_text(router, cmd, needles, count=30, wait=1):
    """Poll a (non-JSON) vtysh command until all needle substrings appear."""
    def _missing():
        out = get_topogen().gears[router].vtysh_cmd(cmd)
        miss = [n for n in needles if n not in out]
        return miss if miss else None  # None => success (all needles present)
    _, res = topotest.run_and_expect(_missing, None, count=count, wait=wait)
    assert res is None, "%s: missing %s in '%s'" % (router, res, cmd)

# (1) BGP neighborship
def test_bgp_evpn_neighborship():
    _expect("r1", "show bgp l2vpn evpn summary json", "r1/evpn_summary.json")
    _expect("r2", "show bgp l2vpn evpn summary json", "r2/evpn_summary.json")

# (2) SID allocation: per-EVI DT2U / DT2M (both EVIs) + VPWS DX2.
#     Per-EVI SID function values are zebra-assigned, so match the endpoint
#     behaviours + locator prefix rather than exact SID addresses.
def test_srv6_sid_allocation():
    _expect_text("r1", "show bgp segment-routing srv6 evpn",
                 ["fc00:0:1:", "End.DT2U", "End.DT2M", "End.DX2", "oif=eth2"])
    _expect_text("r2", "show bgp segment-routing srv6 evpn",
                 ["fc00:0:2:", "End.DT2U", "End.DT2M", "End.DX2"])

# (3) underlay + steady-state per-EVI L2 decap.  The remote underlay /128s (peer
#     locator block) land in the zebra RIB; each EVI's local L2 service SIDs
#     decap in the kernel as End.DT2U onto that EVI's OWN srl2-N bridge-slave, so
#     the number of distinct unicast srl2-N l2dev devices == number of EVIs.
#     Behaviour/prefix-based, so no per-SID expected-JSON is needed.
@srl2_required
def test_underlay_and_dt2m_routes():
    def _check(r, remote):
        gear = get_topogen().gears[r]
        if remote not in gear.vtysh_cmd("show ipv6 route"):
            return "remote underlay %s not in RIB" % remote
        kern = gear.run("ip -6 route show")
        srl2 = set()
        for ln in kern.splitlines():
            toks = ln.split()
            if "l2dev" in toks:
                dev = toks[toks.index("l2dev") + 1]
                if dev.startswith("srl2-"):   # per-EVI unicast srl2 (not bum-/vpws-)
                    srl2.add(dev)
        if len(srl2) < 2:
            return ("expected >=2 per-EVI L2 (End.DT2U) srl2 decap devices, got %s:\n%s"
                    % (sorted(srl2), kern))
        return None

    for r, remote in (("r1", "fc00:0:2:"), ("r2", "fc00:0:1:")):
        _, res = topotest.run_and_expect(
            lambda rr=r, rem=remote: _check(rr, rem), None, count=20, wait=1)
        assert res is None, "%s: %s" % (r, res)

# (3b) DX2 decap, kernel only (netlink-direct, never in RIB). VPWS DX2 SID
#      value is zebra-assigned, so match the behaviour + oif in the full table.
def test_decap_dx2_kernel():
    out = get_topogen().gears["r1"].run("ip -6 route show")
    dx2 = [ln for ln in out.splitlines() if "End.DX2" in ln and "oif eth2" in ln]
    assert dx2, "DX2 decap (End.DX2 oif eth2) not in kernel:\n%s" % out

# (4) interfaces - steady-state VPWS srl2 + a per-EVI bum-srl2 for each EVI.
@srl2_required
def test_srl2_interfaces():
    r1 = get_topogen().gears["r1"]
    links = r1.run("ip -o link show")
    assert "vpws-srl2-V2" in links, "missing vpws-srl2-V2 on r1:\n%s" % links
    n_bum = sum(1 for ln in links.splitlines() if "bum-srl2-" in ln)
    assert n_bum >= 2, \
        "expected >=2 bum-srl2 (one DT2M netdev per EVI) on r1, got %d:\n%s" % (n_bum, links)

# (5) E2E ping over each EVI - proves both VLAN->EVI bridges forward.
#     Each learns the remote MAC => triggers that EVI's unicast DT2U + srl2.
@srl2_required
def test_ping_evi10():
    check_ping("host1", "10.10.0.2", True, 20, 1)

@srl2_required
def test_ping_evi20():
    check_ping("host1c", "10.20.0.2", True, 20, 1)

# (5b) DT2U unicast decap, asserted RIGHT AFTER the pings. The unicast per-EVI
#      DT2U decap SID appears in the kernel with a per-MAC srl2 netdev (srl2-*,
#      distinct from the bum-srl2 BUM netdev).
@srl2_required
def test_decap_dt2u_after_traffic():
    r1 = get_topogen().gears["r1"]

    def _missing_dt2u():
        out = r1.run("ip -6 route show")
        dt2u = [ln for ln in out.splitlines()
                if "End.DT2U" in ln and "srl2-" in ln and "bum-srl2-" not in ln]
        return None if dt2u else (out or "<no route>")

    _, res = topotest.run_and_expect(_missing_dt2u, None, count=30, wait=1)
    assert res is None, "DT2U unicast decap not installed after traffic:\n%s" % res

# (6) teardown, stays LAST: removing the VLAN->EVI bindings releases the per-EVI
#     End.DT2U / End.DT2M service SIDs (replaces the old 'no sid vpn export').
def test_evi_unbind_releases_l2_sids():
    r1 = get_topogen().gears["r1"]
    r1.vtysh_cmd("configure terminal\nsegment-routing\n srv6\n  l2-evpn\n"
                 "   no evi 10\n   no evi 20\n")

    def _not_released():
        out = r1.run("ip -6 route show")
        released = ("End.DT2U" not in out and "End.DT2M" not in out)
        return None if released else out

    _, res = topotest.run_and_expect(_not_released, None, count=30, wait=1)
    assert res is None, "per-EVI DT2U/DT2M not released after 'no evi 10/20':\n%s" % res

if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
