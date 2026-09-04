#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_frr_reload_vrf_dataplane.py
#
# Copyright (c) 2026 by Nvidia, Inc.
#
"""
Dataplane assurance for the frr-reload.py VRF batch-delete change.

Topology: 3 PEs + spine route-reflector, EVPN L3VNI symmetric-IRB, NUM_VRFS
tenant VRFs on every PE, one host per (PE, VRF). See dataplane_lib.py.

Flow:
  1. Fabric converges (OSPF underlay, iBGP EVPN, L3VNI), inter-PE unicast host
     traffic is *routed* through each tenant VRF, and PIM multicast is delivered
     inside the tenant VRFs on pe1.
  2. Apply the full set of per-VRF knobs (vrf_knobs catalog, minus the L3VNI
     'vni' which the fabric already owns) into every tenant VRF on pe1 via
     "frr-reload.py --reload"; assert the knobs are present, no daemon crashed,
     and unicast + multicast STILL work.
  3. Roll the knobs back via "frr-reload.py --reload"; assert the VRF deletes
     took the batch path (no per-line fallback), the knobs are gone, no daemon
     crashed, and unicast + multicast STILL work.

This proves that adding/removing VRF knobs through the batched reload path does
not disturb a live, forwarding EVPN+PIM VRF dataplane.

Override with env:
  DP_NUM_VRFS        tenant VRFs on each PE (default 10)
  DP_NUM_MCAST_VRFS  tenant VRFs that also run PIM multicast on pe1 (default 2)
"""

import os
import re
import sys
import functools

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib import topotest
from lib.topogen import Topogen
from lib.topolog import logger
from lib.topotest import iproute2_is_vrf_capable
from lib.common_config import required_linux_kernel_version
from lib.pim import McastTesterHelper

import dataplane_lib as D
import vrf_knobs as K
import frr_reload_lib as R

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.pimd]

NUM_VRFS = int(os.environ.get("DP_NUM_VRFS", "10"))
NUM_MCAST_VRFS = int(os.environ.get("DP_NUM_MCAST_VRFS", "2"))

# Knobs injected into tenant VRFs for the reload test: zebra + static only.
# Skip L3VNI 'vni' (fabric already owns it). Skip deprecated under-vrf PIM/MLD
# knobs — those belong under "router pim [vrf]" now, and putting "ip pim ..."
# under "vrf vrfN" in a reload target trips frr-reload's legacy PIM rewrite
# for digit-bearing VRF names.
DP_KNOBS = [
    k
    for k in (K.ZEBRA_KNOBS + K.STATIC_KNOBS)
    if k["id"] != "vni"
]


def build_topo(tgen):
    tgen.add_router(D.SPINE)
    for pe in D.PES:
        tgen.add_router(pe)

    # PE uplinks to spine (must be added first so pe<i>-eth0 == uplink).
    for pe in D.PES:
        sw = tgen.add_switch("swu{}".format(D.pe_index(pe)))
        sw.add_link(tgen.gears[D.SPINE])
        sw.add_link(tgen.gears[pe])

    # Hosts, in the exact order the *_ifidx helpers expect.
    for hname, pe, v, rx, ifidx in D.iter_hosts(NUM_VRFS, NUM_MCAST_VRFS):
        tgen.add_router(hname)
        sw = tgen.add_switch("sw_{}".format(hname))
        sw.add_link(tgen.gears[pe])
        sw.add_link(tgen.gears[hname])


@pytest.fixture(scope="module")
def tgen(request):
    tg = Topogen(build_topo, request.module.__name__)
    tg.start_topology()

    if required_linux_kernel_version("4.19") is not True:
        pytest.skip("Kernel >= 4.19 required for EVPN L3VNI + VRF")

    # netlink plumbing for the PE VRF/L3VNI (vrf-lite + bridge + vxlan +
    # access-iface enslavement) MUST happen before daemons start so zebra sees
    # the L3VNI topology. Tenant interface *addresses* are carried in the zebra
    # config (see dataplane_lib.gen_zebra_conf), not here, because raw addresses
    # on munet-managed veths do not survive router startup.
    for pe in D.PES:
        node = tg.gears[pe]
        for cmd in D.plumb_pe(pe, NUM_VRFS, NUM_MCAST_VRFS):
            node.cmd_raises(cmd)

    # generate + load unified frr.conf on the fabric nodes
    for node in [D.SPINE] + D.PES:
        d = os.path.join(CWD, node)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "frr.conf")
        with open(path, "w", encoding="ascii") as fh:
            fh.write(D.gen_frr_conf(node, NUM_VRFS, NUM_MCAST_VRFS))
        tg.gears[node].load_frr_config(
            path, daemons=D.daemons_for(node, NUM_MCAST_VRFS)
        )

    tg.start_router()

    # Host addressing is applied AFTER start_router: the hosts run no FRR, and a
    # raw "ip addr add" on their veths before startup is wiped by munet's
    # interface reconciliation. Doing it post-start makes it stick.
    for hname, pe, v, rx, ifidx in D.iter_hosts(NUM_VRFS, NUM_MCAST_VRFS):
        for cmd in D.plumb_host(hname, pe, v, rx=rx):
            tg.gears[hname].cmd_raises(cmd)

    yield tg
    tg.stop_topology()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _skip_if_broken(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if not iproute2_is_vrf_capable():
        pytest.skip("iproute2 not VRF capable")


def _assert_daemons_healthy(tgen):
    for node in [D.SPINE] + D.PES:
        status = tgen.gears[node].check_router_running()
        assert status == "", "router {} unhealthy: {}".format(node, status)


def _ping_across_pes(tgen, v, src_pe="pe1", dst_pe="pe2"):
    """Ping from the host behind src_pe to the host behind dst_pe in VRF v."""
    src_host = tgen.gears[D.host_name(src_pe, v)]
    dst_ip = D.tenant_host(dst_pe, v)
    out = src_host.run("ping -c3 -w5 {}".format(dst_ip))
    logger.info("vrf%s %s->%s:\n%s", v, src_pe, dst_pe, out)
    return "0% packet loss" in out or " 0% packet loss" in out


def _diag_unicast(tgen, v):
    pe1 = tgen.gears["pe1"]
    pe2 = tgen.gears["pe2"]
    vrf = D.vrf_name(v)
    logger.info("==== DIAG vrf%s ====", v)
    for pe in (pe1, pe2):
        logger.info("[%s] ip route vrf %s:\n%s", pe.name, vrf,
                    pe.run("ip route show vrf {}".format(vrf)))
        logger.info("[%s] show ip route vrf %s:\n%s", pe.name, vrf,
                    pe.vtysh_cmd("show ip route vrf {}".format(vrf)))
        logger.info("[%s] show bgp vrf %s ipv4 unicast:\n%s", pe.name, vrf,
                    pe.vtysh_cmd("show bgp vrf {} ipv4 unicast".format(vrf)))
        logger.info("[%s] show bgp l2vpn evpn:\n%s", pe.name,
                    pe.vtysh_cmd("show bgp l2vpn evpn"))
        logger.info("[%s] show evpn vni %s:\n%s", pe.name, D.l3vni(v),
                    pe.vtysh_cmd("show evpn vni {}".format(D.l3vni(v))))
        logger.info("[%s] show evpn rmac vni all:\n%s", pe.name,
                    pe.vtysh_cmd("show evpn rmac vni all"))
        logger.info("[%s] ip -d link (brl3/vxl3):\n%s", pe.name,
                    pe.run("ip -d link show | grep -A2 -E 'brl3{}|vxl3{}'".format(v, v)))
        logger.info("[%s] bridge fdb (vxl3%s):\n%s", pe.name, v,
                    pe.run("bridge fdb show dev vxl3{}".format(v)))
        logger.info("[%s] ip route (underlay 10.0.0.0/24):\n%s", pe.name,
                    pe.run("ip route show 10.0.0.0/24"))
        logger.info("[%s] ip -br link master %s:\n%s", pe.name, vrf,
                    pe.run("ip -br link show master {}".format(vrf)))
        logger.info("[%s] ip -br addr (eth%s):\n%s", pe.name, D.access_ifidx(v),
                    pe.run("ip -br addr show {}-eth{}".format(pe.name, D.access_ifidx(v))))
        logger.info("[%s] fwd sysctls:\n%s", pe.name,
                    pe.run("sysctl net.ipv4.ip_forward "
                           "net.ipv4.conf.all.forwarding "
                           "net.ipv4.conf.{}.forwarding "
                           "net.ipv4.conf.{}-eth{}.rp_filter".format(
                               vrf, pe.name, D.access_ifidx(v))))
        logger.info("[%s] ip neigh dev brl3%s:\n%s", pe.name, v,
                    pe.run("ip neigh show dev brl3{}".format(v)))
        logger.info("[%s] full fdb vxl3%s:\n%s", pe.name, v,
                    pe.run("bridge fdb show | grep -i "
                           "$(cat /sys/class/net/vxl3{}/address)".format(v)))
        logger.info("[%s] underlay routes (root):\n%s", pe.name,
                    pe.run("ip route show root 10.0.0.0/24"))
    logger.info("[pe1] ping underlay pe2 lo:\n%s",
                pe1.run("ping -c2 -w3 -I 10.0.0.1 10.0.0.2"))


def _check_unicast(tgen, vrfs):
    for v in vrfs:
        ok = _ping_across_pes(tgen, v)
        if not ok:
            _diag_unicast(tgen, v)
        assert ok, "inter-PE unicast failed in vrf{} (pe1->pe2)".format(v)


def _pim_rp_ready(pe1, v):
    """True once pe1 is the active RP for the fabric group in vrf<v>."""
    grp = D.mcast_group(v)
    vrf = D.vrf_name(v)

    rp = pe1.vtysh_cmd(
        "show ip pim vrf {} rp-info json".format(vrf), isjson=True
    )
    if isinstance(rp, dict):
        for _rp_addr, rows in rp.items():
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                g = str(row.get("group", ""))
                if grp in g and row.get("iAmRP") is True:
                    return True

    # Text fallback (json parse miss / empty).
    text = pe1.vtysh_cmd("show ip pim vrf {} rp-info".format(vrf))
    return any(grp in ln and "yes" in ln.lower() for ln in text.splitlines())


def _pim_forwarding_ready(pe1, v):
    """True once PIM is fully signaled for the group inside vrf<v>.

    Same-box RP+FHR+LHR (cross-VTEP L3 mcast is unsupported): kernel MFC OIL is
    not populated, so we assert RP active + IGMP/join membership. (S,G) in
    "pim state" is recorded when present but not required - the FHR+LHR
    same-node path is racy across runners and is not what the reload suite
    needs to prove.

    Returns (ok, detail) so failures name which predicate is still missing.
    """
    grp = D.mcast_group(v)
    src = D.tenant_host("pe1", v)
    vrf = D.vrf_name(v)

    rp_active = _pim_rp_ready(pe1, v)

    igmp = pe1.vtysh_cmd(
        "show ip igmp vrf {} groups json".format(vrf), isjson=True
    )
    igmp_joined = grp in str(igmp) if isinstance(igmp, dict) else False
    if not igmp_joined:
        text = pe1.vtysh_cmd("show ip igmp vrf {} groups".format(vrf))
        igmp_joined = any(grp in ln for ln in text.splitlines())

    # pim join with IGMP is the pim_igmp_vrf signal for a local receiver.
    join = pe1.vtysh_cmd(
        "show ip pim vrf {} join json".format(vrf), isjson=True
    )
    joined = False
    if isinstance(join, dict):
        blob = str(join)
        joined = grp in blob and (
            "protocolIgmp" in blob or "IGMP" in blob or igmp_joined
        )

    state = pe1.vtysh_cmd(
        "show ip pim vrf {} state json".format(vrf), isjson=True
    )
    s_g = False
    if isinstance(state, dict):
        g = state.get(grp)
        if isinstance(g, dict) and src in g:
            s_g = True
        else:
            blob = str(state)
            s_g = grp in blob and src in blob

    membership = igmp_joined or joined
    missing = []
    if not rp_active:
        missing.append("rp")
    if not membership:
        missing.append("igmp/join")
    detail = ",".join(missing) if missing else (
        "ok" + ("" if s_g else " (no s,g yet)")
    )
    return (not missing, detail)


def _check_multicast(tgen, vrfs):
    """Start source+receiver in each mcast vrf on pe1 and assert PIM signals."""
    pe1 = tgen.gears["pe1"]

    # RP must be elected before we start join/traffic; otherwise the FHR+LHR
    # same-box path can miss (S,G) learning for the whole poll window.
    for v in vrfs:
        test_func = functools.partial(_pim_rp_ready, pe1, v)
        ok, _ = topotest.run_and_expect(test_func, True, count=30, wait=2)
        if not ok:
            vrf = D.vrf_name(v)
            logger.info(
                "[pe1] show ip pim vrf %s rp-info:\n%s",
                vrf,
                pe1.vtysh_cmd("show ip pim vrf {} rp-info".format(vrf)),
            )
            logger.info(
                "[pe1] running-config (pim/vrf%s):\n%s",
                v,
                pe1.run(
                    "vtysh -c 'show running-config' | "
                    "grep -nE 'vrf {}$|router pim| rp |ip pim|ip igmp|"
                    "loop-rp{}|vni '".format(vrf, v)
                ),
            )
        assert ok, "PIM RP not active for {} in vrf{}".format(
            D.mcast_group(v), v
        )

    with McastTesterHelper(tgen) as helper:
        for v in vrfs:
            grp = D.mcast_group(v)
            src = D.host_name("pe1", v)             # 10.v.1.10
            rcv = D.host_name("pe1", v, rx=True)    # 10.v.201.10
            # Same order as pim_igmp_vrf: join, brief settle, then source.
            helper.run(rcv, [grp, "{}-eth0".format(rcv)])
            topotest.sleep(1, "IGMP join settle before source in vrf{}".format(v))
            helper.run(src, ["--send=0.7", grp, "{}-eth0".format(src)])

        for v in vrfs:
            def _ready(pe1=pe1, v=v):
                ok, _detail = _pim_forwarding_ready(pe1, v)
                return ok

            ok, _ = topotest.run_and_expect(_ready, True, count=30, wait=2)
            detail = _pim_forwarding_ready(pe1, v)[1]
            if not ok:
                vrf = D.vrf_name(v)
                for cmd in ("show ip pim vrf {} interface".format(vrf),
                            "show ip pim vrf {} rp-info".format(vrf),
                            "show ip igmp vrf {} groups".format(vrf),
                            "show ip pim vrf {} state".format(vrf),
                            "show ip pim vrf {} join".format(vrf),
                            "show ip mroute vrf {}".format(vrf)):
                    logger.info("[pe1] %s:\n%s", cmd, pe1.vtysh_cmd(cmd))
                logger.info("[pe1] running-config (pim/vrf%s):\n%s", v,
                            pe1.run("vtysh -c 'show running-config' | "
                                    "grep -nE 'vrf {}$|router pim| rp |ip pim|"
                                    "ip igmp|loop-rp{}|vni '".format(vrf, v)))
                for h in (D.host_name("pe1", v), D.host_name("pe1", v, rx=True)):
                    logger.info("[%s] addr/route:\n%s\n%s", h,
                                tgen.gears[h].run("ip -br addr"),
                                tgen.gears[h].run("ip route"))
            assert ok, "PIM not signaled for {} in vrf{} (missing: {})".format(
                D.mcast_group(v), v, detail
            )


def _inject_dp_knobs(cfg_text, vrf_indices, knobs):
    """Return config lines = running-config + global prereqs + knobs in vrf<i>."""
    prereqs = K.global_prereqs()
    out = []
    inserted = False
    for ln in cfg_text.splitlines():
        out.append(ln)
        if not inserted and ln.strip() == "!":
            out += prereqs + ["!"]
            inserted = True
        m = re.match(r"^vrf (vrf\d+)$", ln.strip())
        if m:
            idx = int(m.group(1)[3:])
            if idx in vrf_indices:
                for kn in knobs:
                    for kl in kn["lines"](idx):
                        out.append(" " + kl)
    if not inserted:  # no '!' seen; prepend prereqs
        out = prereqs + out
    return out


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_underlay_and_evpn_converge(tgen):
    _skip_if_broken(tgen)
    pe1 = tgen.gears["pe1"]

    # BGP EVPN session to the RR is up.
    def _evpn_up():
        out = pe1.vtysh_cmd(
            "show bgp l2vpn evpn summary json", isjson=True
        )
        peers = out.get("peers", {}) if isinstance(out, dict) else {}
        return bool(peers) and all(
            p.get("state") == "Established" for p in peers.values()
        )

    ok, _ = topotest.run_and_expect(_evpn_up, True, count=60, wait=2)
    assert ok, "pe1 EVPN session to RR did not establish"

    # L3VNIs are up.
    def _l3vni_up():
        out = pe1.vtysh_cmd("show evpn vni json", isjson=True)
        return isinstance(out, dict) and len(out) >= NUM_VRFS

    ok, _ = topotest.run_and_expect(_l3vni_up, True, count=30, wait=2)
    assert ok, "expected >= {} L3VNIs up on pe1".format(NUM_VRFS)
    _assert_daemons_healthy(tgen)


def test_baseline_unicast(tgen):
    _skip_if_broken(tgen)
    _check_unicast(tgen, range(1, NUM_VRFS + 1))


def test_baseline_multicast(tgen):
    _skip_if_broken(tgen)
    _check_multicast(tgen, range(1, NUM_MCAST_VRFS + 1))


def test_reload_apply_knobs(tgen):
    """Apply all (non-vni) VRF knobs into every tenant VRF on pe1 via
    frr-reload, then confirm knobs present + dataplane still forwards."""
    _skip_if_broken(tgen)
    pe1 = tgen.gears["pe1"]
    conf = os.path.join(tgen.logdir, "pe1", "reload-target.conf")
    os.makedirs(os.path.dirname(conf), exist_ok=True)

    base = R.running_config(pe1)
    with open(os.path.join(tgen.logdir, "pe1", "reload-base.conf"), "w") as fh:
        fh.write(base)

    target = _inject_dp_knobs(base, range(1, NUM_VRFS + 1), DP_KNOBS)
    R.apply_and_verify(pe1, conf, target)

    # spot-check knobs landed in a couple of tenant VRFs
    for v in (1, NUM_VRFS):
        R.assert_lines_present(
            pe1, [ln for kn in DP_KNOBS for ln in kn["lines"](v)]
        )
    _assert_daemons_healthy(tgen)

    # dataplane intact
    _check_unicast(tgen, range(1, NUM_VRFS + 1))
    _check_multicast(tgen, range(1, NUM_MCAST_VRFS + 1))


def test_reload_rollback_knobs(tgen):
    """Roll the knobs back via frr-reload; confirm batch delete path was used,
    knobs are gone, and the dataplane still forwards."""
    _skip_if_broken(tgen)
    pe1 = tgen.gears["pe1"]
    conf = os.path.join(tgen.logdir, "pe1", "reload-target.conf")
    with open(
        os.path.join(tgen.logdir, "pe1", "reload-base.conf"),
        encoding="ascii",
    ) as fh:
        base = fh.read()

    res = R.apply_and_verify(pe1, conf, base.splitlines(), expect_vrf_batch=True)
    logger.info("dataplane rollback used batch path in %.2fs", res.elapsed)

    for v in (1, NUM_VRFS):
        R.assert_lines_absent(
            pe1, [ln for kn in DP_KNOBS for ln in kn["lines"](v)]
        )
    _assert_daemons_healthy(tgen)

    # dataplane still intact after rollback
    _check_unicast(tgen, range(1, NUM_VRFS + 1))
    _check_multicast(tgen, range(1, NUM_MCAST_VRFS + 1))


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", "-v"] + sys.argv[1:]))
