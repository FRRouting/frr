#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Aviz Networks
#
# SRv6 L2 EVPN (VXLAN-decoupled) topotest - VLAN Bundle service type.
#
# One vlan-bundle EVI (50001) collapses three customer VLANs (11/12/13) into a
# single flat bridge-domain / MAC-VRF over ONE VLAN-UNAWARE bridge (br-bundle),
# Ethernet Tag ID 0, C-tags transported transparently (RFC 7432 sec 6.2).
#
# The EVI's End.DT2U / End.DT2M SIDs are drawn from a PER-EVI locator (LOC1)
# and advertised WITHOUT any instance-level `router bgp ... segment-routing
# srv6 locator` - exercising the per-EVI locator metadata that zebra ships in
# ZEBRA_VNI_ADD (the enabler in the vlan-bundle add-on).
#
# The customer side lives IN the PE namespace (mirrors the manual validation):
# a veth trunk cust2(bridge AC) <-> cust2p(customer), with a C-VLAN sub-if per
# VLAN on cust2p.  Each C-VLAN is its own /24, so an in-subnet ping only
# succeeds if the customer tag is preserved across the bundle.
#
#   r1: cust2p.{11,12,13} -> cust2p =veth= cust2 -> br-bundle(vlan-unaware)
#        -> zebra srl2 (EVI 50001) === SRv6 core === r2 (mirror) -> cust2p.{...}
#
# The VLAN-unaware bridge is essential: a vlan-bundle transports the C-tag as
# opaque payload (single FDB, vid 0); a vlan_filtering bridge would drop the
# tagged frame because the srl2 overlay port sits at vid 0.

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
    reason="kernel lacks SRv6 srl2 netdev support (End.DT2U/DT2M dataplane)")

BUNDLE_EVI = 50001
BUNDLE_BR = "br-bundle"
BUNDLE_VLANS = (11, 12, 13)


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")   # SRv6 core


def _pe_kernel(pe, last):
    # VLAN-UNAWARE bundle bridge: C-tags are opaque payload, single MAC FDB.
    pe.run("ip link add %s type bridge" % BUNDLE_BR)
    pe.run("ip link set %s up" % BUNDLE_BR)
    # Customer trunk via a veth pair: cust2 is the bridge AC, cust2p carries the
    # C-VLAN sub-interfaces (the "customer").
    pe.run("ip link add cust2 type veth peer name cust2p")
    pe.run("ip link set cust2 master %s up" % BUNDLE_BR)
    pe.run("ip link set cust2p up")
    for vid in BUNDLE_VLANS:
        pe.run("ip link add link cust2p name cust2p.%d type vlan id %d" % (vid, vid))
        pe.run("ip addr add 10.0.%d.%d/24 dev cust2p.%d" % (vid, last, vid))
        pe.run("ip link set cust2p.%d up" % vid)


def setup_module(mod):
    if required_linux_kernel_version("5.14") is not True:
        pytest.skip("Kernel requirements are not met")
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname in ("r1", "r2"):
        r = tgen.gears[rname]
        r.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "%s/zebra.conf" % rname))
        r.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "%s/bgpd.conf" % rname))
    _pe_kernel(tgen.gears["r1"], 1)
    _pe_kernel(tgen.gears["r2"], 2)
    tgen.start_router()

    # Re-apply the per-EVI locator + bundle binding once (mgmtd may render the
    # locator only after the zebra.conf direct-load; same race the vlan-based
    # test handles).
    vlan_lines = "".join("     vlan %d\n" % v for v in BUNDLE_VLANS)
    evi_tmpl = ("configure terminal\nsegment-routing\n srv6\n  l2-evpn\n"
                "   evi %d locator %%s bridge %s\n"
                "    service-type vlan-bundle\n%s   exit\n"
                % (BUNDLE_EVI, BUNDLE_BR, vlan_lines))

    for r, loc, pfx in (("r1", "LOC1", "fc00:0:1::/48"), ("r2", "LOC1", "fc00:0:2::/48")):
        tgen.gears[r].vtysh_cmd(
            "configure terminal\nsegment-routing\n srv6\n  locators\n"
            "   locator %s\n    prefix %s block-len 32 node-len 16\n" % (loc, pfx))
        tgen.gears[r].vtysh_cmd(evi_tmpl % loc)

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
            r1r = tgen.gears["r1"].run("ip -6 route show")
            r2r = tgen.gears["r2"].run("ip -6 route show")
            if not ("fc00:0:2:" in r1r and "fc00:0:1:" in r2r):
                last["reason"] = "underlay /128 missing"
                return False
            return True
        except (KeyError, ValueError, TypeError) as e:
            last["reason"] = "exception: %r" % e
            return False

    reapplied = [False]

    def _converged_or_retry():
        if _converged():
            return True
        if not reapplied[0] and "underlay" in last["reason"]:
            for r, loc in (("r1", "LOC1"), ("r2", "LOC1")):
                tgen.gears[r].vtysh_cmd(evi_tmpl % loc)
            reapplied[0] = True
        return False

    _, ok = topotest.run_and_expect(_converged_or_retry, True, count=60, wait=1)
    assert ok is True, "convergence failed: %s" % last["reason"]


def teardown_module(mod):
    get_topogen().stop_topology()


# ---------------------------------------------------------------------------

def test_bgp_evpn_neighborship():
    tgen = get_topogen()
    for r, peer in (("r1", "2001:db8:20::2"), ("r2", "2001:db8:20::1")):
        s = json.loads(tgen.gears[r].vtysh_cmd("show bgp l2vpn evpn summary json"))
        assert s["peers"][peer]["state"] == "Established", "%s->%s not Established" % (r, peer)


def test_srv6_sid_allocation():
    # The bundle EVI must have End.DT2U + End.DT2M SIDs drawn from its per-EVI
    # locator (LOC1), even though no instance-level bgp locator is configured.
    tgen = get_topogen()

    def _has_sids(r):
        out = tgen.gears[r].vtysh_cmd("show segment-routing srv6 sid json")
        try:
            sids = json.loads(out)
        except ValueError:
            return "unparsable sid json"
        blob = json.dumps(sids)
        if "DT2U" not in blob or "DT2M" not in blob:
            return "DT2U/DT2M not both present:\n%s" % out
        return None

    for r in ("r1", "r2"):
        _, res = topotest.run_and_expect(functools.partial(_has_sids, r), None, count=20, wait=1)
        assert res is None, "%s: %s" % (r, res)


def test_per_evi_locator_sid_advertised():
    # The enabler: with NO instance-level bgp locator, each PE must still
    # advertise the L2 Service TLV from its PER-EVI locator metadata, so the
    # peer receives+decodes the SID and installs the underlay /128.  The SID is
    # not printed in `show bgp l2vpn evpn` (summary) - only in the detailed
    # view - so assert on the installed kernel route under the peer's locator
    # block, which is the concrete result of the TLV being advertised+decoded.
    tgen = get_topogen()

    def _installed(r, peer_block):
        if peer_block in tgen.gears[r].run("ip -6 route show"):
            return None
        return "peer SID underlay (%s) not installed" % peer_block

    for r, peer_block in (("r1", "fc00:0:2:"), ("r2", "fc00:0:1:")):
        _, res = topotest.run_and_expect(
            functools.partial(_installed, r, peer_block), None, count=20, wait=1)
        assert res is None, "%s: %s" % (r, res)


@srl2_required
def test_bundle_single_srl2():
    # Single-FDB collapse: the 3 C-VLANs share ONE EVI, so there is exactly ONE
    # unicast srl2 decap netdev for the bundle (not one per C-VLAN).
    tgen = get_topogen()

    # kick learning on all C-VLANs first
    for vid in BUNDLE_VLANS:
        tgen.gears["r1"].run("ping -c1 -W1 -I 10.0.%d.1 10.0.%d.2" % (vid, vid))

    def _count(r):
        kern = tgen.gears[r].run("ip -6 route show")
        srl2 = set()
        for ln in kern.splitlines():
            toks = ln.split()
            if "l2dev" in toks:
                dev = toks[toks.index("l2dev") + 1]
                if dev.startswith("srl2-"):  # unicast (not bum-/vpws-)
                    srl2.add(dev)
        if len(srl2) != 1:
            return "expected exactly 1 unicast srl2 for the bundle, got %s:\n%s" % (
                sorted(srl2), kern)
        return None

    for r in ("r1", "r2"):
        _, res = topotest.run_and_expect(functools.partial(_count, r), None, count=30, wait=1)
        assert res is None, "%s: %s" % (r, res)


@srl2_required
def test_bundle_transparent_ping():
    # Ping within EACH customer VLAN's /24: success proves the C-tag is carried
    # transparently across the single bundle EVI.
    for vid in BUNDLE_VLANS:
        check_ping("r1", "10.0.%d.2" % vid, True, 20, 1, source_addr="10.0.%d.1" % vid)


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
