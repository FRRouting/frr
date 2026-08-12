#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# dataplane_lib.py
#
# Copyright (c) 2026 by Nvidia, Inc.
#
"""
Builders for a multi-PE EVPN L3VNI (symmetric IRB) fabric with tenant VRFs,
used by test_frr_reload_vrf_dataplane.py.

Fabric (parameterized by NUM_VRFS tenant VRFs, NUM_MCAST_VRFS multicast VRFs):

                         +---------+
                         | spine1  |   iBGP EVPN route-reflector + OSPF underlay
                         +----+----+
                spine1-eth0/1/2 (to pe1/pe2/pe3)
                +-----------+-----------+
                |           |           |
            +---+--+    +---+--+    +---+--+
            |  pe1 |    |  pe2 |    |  pe3 |     VTEPs
            +---+--+    +---+--+    +---+--+
                |           |           |
             hosts        hosts       hosts

Per tenant VRF v (1..NUM_VRFS) on every PE i:
  * vrf-lite VRF "vrf<v>" (table 1000+v) with L3VNI 5000+v (symmetric IRB)
  * per-PE tenant subnet 10.v.i.0/24 on pe<i>-eth<v> (PE gw .1, host .10),
    enslaved to vrf<v>. Subnets differ per PE, so host<->host across PEs is
    *routed* through the VRF over the L3VNI (proves inter-PE VRF exchange).

Multicast (first NUM_MCAST_VRFS tenant VRFs, on pe1 only):
  * a second access subnet 10.v.201.0/24 + receiver host on pe1
  * RP = pe1 loopback 10.v.255.1 inside vrf<v>
  * PIM-SM routes the group inside vrf<v> between the source subnet (shared with
    the unicast host) and the receiver subnet - the proven pim_igmp_vrf pattern,
    applied to an EVPN-L3VNI VRF. Multicast stays local to pe1 (no cross-VTEP
    L3 mcast, which is not a supported feature), so it is fully verifiable.

Interface numbering (kept consistent across build_topo / plumbing / config via
the *_ifidx helpers below):
  pe<i>-eth0             uplink to spine
  pe<i>-eth<v>           access for tenant VRF v         (v = 1..NUM_VRFS)
  pe1-eth<NUM_VRFS+v>    mcast receiver access for VRF v (v = 1..NUM_MCAST_VRFS)

NOTE: dataplane-heavy; validate/iterate in a real topogen env (root + netns +
installed FRR). Command forms follow bgp_evpn_rt5 (L3VNI) and pim_igmp_vrf (PIM).
"""

AS_NUM = 65000
SPINE = "spine1"
PES = ["pe1", "pe2", "pe3"]
MCAST_PE = "pe1"
RX_OCTET = 201  # pe1 receiver subnet 10.v.201.0/24


def pe_index(pe):
    return PES.index(pe) + 1  # 1-based


# ---- interface index helpers (single source of truth) --------------------


def uplink_ifidx():
    return 0


def access_ifidx(v):
    return v


def rx_ifidx(num_vrfs, v):
    return num_vrfs + v


def pe_num_ifaces(pe, num_vrfs, num_mcast_vrfs):
    n = 1 + num_vrfs  # uplink + one access per vrf
    if pe == MCAST_PE:
        n += num_mcast_vrfs  # receiver access ifaces
    return n


# ---- addressing -----------------------------------------------------------


def loopback(node):
    if node == SPINE:
        return "10.0.0.254"
    return "10.0.0.{}".format(pe_index(node))


def underlay(pe):
    """Return (net_prefix24_base, pe_ip, spine_ip) for the pe<->spine /30."""
    i = pe_index(pe)
    return "10.1.{}".format(i), "10.1.{}.1".format(i), "10.1.{}.2".format(i)


def vrf_name(v):
    return "vrf{}".format(v)


def vrf_table(v):
    return 1000 + v


def l3vni(v):
    return 5000 + v


def tenant_gw(pe, v):
    return "10.{}.{}.1".format(v, pe_index(pe))


def tenant_host(pe, v):
    return "10.{}.{}.10".format(v, pe_index(pe))


def tenant_subnet(pe, v):
    return "10.{}.{}.0/24".format(v, pe_index(pe))


def rx_gw(v):
    return "10.{}.{}.1".format(v, RX_OCTET)


def rx_host(v):
    return "10.{}.{}.10".format(v, RX_OCTET)


def rp_addr(v):
    return "10.{}.255.1".format(v)


def mcast_group(v):
    return "239.{}.0.1".format(v)


# ---- node/link inventory (consumed by build_topo) -------------------------


def host_name(pe, v, rx=False):
    return "h{}v{}{}".format(pe_index(pe), v, "r" if rx else "")


def iter_hosts(num_vrfs, num_mcast_vrfs):
    """Yield (host_name, pe, v, rx, pe_ifidx) for every host to create."""
    for pe in PES:
        for v in range(1, num_vrfs + 1):
            yield host_name(pe, v), pe, v, False, access_ifidx(v)
    for v in range(1, num_mcast_vrfs + 1):
        yield host_name(MCAST_PE, v, rx=True), MCAST_PE, v, True, rx_ifidx(
            num_vrfs, v
        )


# ---------------------------------------------------------------------------
# netlink plumbing (run in setup, before daemons start)
# ---------------------------------------------------------------------------


def plumb_pe(node, num_vrfs, num_mcast_vrfs):
    """'ip'/'bridge' commands to build vrf-lite + L3VNI on a PE."""
    lo = loopback(node)
    cmds = []
    for v in range(1, num_vrfs + 1):
        vrf = vrf_name(v)
        cmds += [
            "ip link add {} type vrf table {}".format(vrf, vrf_table(v)),
            "ip link set dev {} up".format(vrf),
            "ip link add brl3{} type bridge".format(v),
            "ip link set dev brl3{} master {}".format(v, vrf),
            "ip link set dev brl3{} up".format(v),
            "ip link add vxl3{} type vxlan id {} dstport 4789 local {} nolearning".format(
                v, l3vni(v), lo
            ),
            "ip link set dev vxl3{} master brl3{}".format(v, v),
            "ip link set dev vxl3{} up".format(v),
            # Enslave the tenant access iface to the vrf and bring it up. Its
            # IPv4 address is assigned via the zebra config (interface stanza),
            # NOT here: a raw "ip addr add" on a munet-managed veth does not
            # survive router startup (munet reconciles veth addressing), whereas
            # zebra owns and continuously reinstalls addresses it is configured
            # with. Dummy interfaces (loop-rp) are unaffected but are handled the
            # same way for consistency.
            "ip link set dev {}-eth{} master {}".format(node, access_ifidx(v), vrf),
            "ip link set dev {}-eth{} up".format(node, access_ifidx(v)),
        ]
        if node == MCAST_PE and v <= num_mcast_vrfs:
            rxidx = rx_ifidx(num_vrfs, v)
            cmds += [
                # RP loopback in the vrf (address via zebra config)
                "ip link add loop-rp{} type dummy".format(v),
                "ip link set dev loop-rp{} master {}".format(v, vrf),
                "ip link set dev loop-rp{} up".format(v),
                # receiver access iface in the vrf (address via zebra config)
                "ip link set dev {}-eth{} master {}".format(node, rxidx, vrf),
                "ip link set dev {}-eth{} up".format(node, rxidx),
            ]
    return cmds


def plumb_host(node, pe, v, rx=False):
    gw = rx_gw(v) if rx else tenant_gw(pe, v)
    ip = rx_host(v) if rx else tenant_host(pe, v)
    return [
        "ip addr add {}/24 dev {}-eth0".format(ip, node),
        "ip link set dev {}-eth0 up".format(node),
        "ip route add default via {}".format(gw),
    ]


# ---------------------------------------------------------------------------
# FRR config generation
# ---------------------------------------------------------------------------


def gen_zebra_conf(node, num_vrfs, num_mcast_vrfs):
    lines = ["hostname {}".format(node), "log stdout", "!",
             "interface lo", " ip address {}/32".format(loopback(node)), "!"]
    if node == SPINE:
        for pe in PES:
            _, _, spine_ip = underlay(pe)
            lines += ["interface {}-eth{}".format(SPINE, pe_index(pe) - 1),
                      " ip address {}/30".format(spine_ip), "!"]
        return "\n".join(lines) + "\n"

    _, pe_ip, _ = underlay(node)
    lines += ["interface {}-eth0".format(node),
              " ip address {}/30".format(pe_ip), "!"]
    # One vrf stanza per VRF carrying ALL per-vrf commands (vni for zebra, and
    # for mcast VRFs the pim RP for pimd). Emitting a single stanza avoids
    # duplicate "vrf NAME" stanzas across merged sections, which the integrated
    # config loader can misattribute (a second "vrf NAME" stanza's commands can
    # leak into the default VRF).
    for v in range(1, num_vrfs + 1):
        stanza = ["vrf {}".format(vrf_name(v)), " vni {}".format(l3vni(v))]
        if node == MCAST_PE and v <= num_mcast_vrfs:
            stanza.append(
                " ip pim rp {} {}/32".format(rp_addr(v), mcast_group(v))
            )
        stanza += ["exit-vrf", "!"]
        lines += stanza
    # Tenant access interface addresses live in the vrf (zebra owns them).
    for v in range(1, num_vrfs + 1):
        lines += ["interface {}-eth{} vrf {}".format(
                      node, access_ifidx(v), vrf_name(v)),
                  " ip address {}/24".format(tenant_gw(node, v)), "!"]
    if node == MCAST_PE:
        for v in range(1, num_mcast_vrfs + 1):
            lines += ["interface loop-rp{} vrf {}".format(v, vrf_name(v)),
                      " ip address {}/32".format(rp_addr(v)), "!",
                      "interface {}-eth{} vrf {}".format(
                          node, rx_ifidx(num_vrfs, v), vrf_name(v)),
                      " ip address {}/24".format(rx_gw(v)), "!"]
    return "\n".join(lines) + "\n"


def gen_ospf_conf(node, num_vrfs):
    lines = ["hostname {}".format(node), "!", "router ospf",
             " redistribute connected"]
    if node == SPINE:
        for pe in PES:
            net, _, _ = underlay(pe)
            lines.append(" network {}.0/30 area 0".format(net))
    else:
        net, _, _ = underlay(node)
        lines.append(" network {}.0/30 area 0".format(net))
    lines += [" network {}/32 area 0".format(loopback(node)), "!"]
    return "\n".join(lines) + "\n"


def gen_bgp_conf(node, num_vrfs):
    lo = loopback(node)
    lines = ["hostname {}".format(node), "!",
             "router bgp {}".format(AS_NUM),
             " bgp router-id {}".format(lo),
             " no bgp default ipv4-unicast"]
    if node == SPINE:
        for pe in PES:
            peer = loopback(pe)
            lines += [" neighbor {} remote-as {}".format(peer, AS_NUM),
                      " neighbor {} update-source lo".format(peer)]
        lines += [" !", " address-family l2vpn evpn"]
        for pe in PES:
            peer = loopback(pe)
            lines += ["  neighbor {} activate".format(peer),
                      "  neighbor {} route-reflector-client".format(peer)]
        lines += [" exit-address-family", "!"]
        return "\n".join(lines) + "\n"

    spine_lo = loopback(SPINE)
    lines += [" neighbor {} remote-as {}".format(spine_lo, AS_NUM),
              " neighbor {} update-source lo".format(spine_lo), " !",
              " address-family l2vpn evpn",
              "  neighbor {} activate".format(spine_lo),
              "  advertise-all-vni",
              " exit-address-family", "!"]
    for v in range(1, num_vrfs + 1):
        lines += ["router bgp {} vrf {}".format(AS_NUM, vrf_name(v)),
                  " bgp router-id {}".format(tenant_gw(node, v)),
                  " no bgp default ipv4-unicast",
                  " address-family ipv4 unicast",
                  "  redistribute connected",
                  " exit-address-family",
                  " address-family l2vpn evpn",
                  "  advertise ipv4 unicast",
                  " exit-address-family", "!"]
    return "\n".join(lines) + "\n"


def gen_pim_conf(node, num_vrfs, num_mcast_vrfs):
    lines = ["hostname {}".format(node), "!"]
    if node != MCAST_PE:
        return "\n".join(lines) + "\n"
    # NOTE: the per-vrf "ip pim rp" lives in the single vrf stanza emitted by
    # gen_zebra_conf (avoids duplicate "vrf NAME" stanzas). Here we only emit
    # the PIM/IGMP interface enablement.
    for v in range(1, num_mcast_vrfs + 1):
        vrf = vrf_name(v)
        lines += ["interface {}-eth{} vrf {}".format(
                      MCAST_PE, access_ifidx(v), vrf),
                  " ip pim", " ip igmp", "!",
                  "interface {}-eth{} vrf {}".format(
                      MCAST_PE, rx_ifidx(num_vrfs, v), vrf),
                  " ip pim", " ip igmp", "!",
                  "interface loop-rp{} vrf {}".format(v, vrf),
                  " ip pim", "!"]
    return "\n".join(lines) + "\n"


def _body(conf_text):
    """Drop the leading 'hostname'/'log stdout' header lines from a section."""
    out = []
    for ln in conf_text.splitlines():
        s = ln.strip()
        if s.startswith("hostname ") or s == "log stdout":
            continue
        out.append(ln)
    # trim leading/trailing bang-only noise
    while out and out[0] == "!":
        out.pop(0)
    return out


def gen_frr_conf(node, num_vrfs, num_mcast_vrfs):
    """Unified frr.conf for `node` (integrated-vtysh-config), so frr-reload works.

    Merges the zebra / ospf / bgp / pim sections under one hostname. vtysh
    happily merges repeated 'interface'/'vrf' stanzas across sections.
    """
    lines = ["frr defaults datacenter", "hostname {}".format(node),
             "log stdout", "!"]
    lines += _body(gen_zebra_conf(node, num_vrfs, num_mcast_vrfs))
    lines.append("!")
    lines += _body(gen_ospf_conf(node, num_vrfs))
    lines.append("!")
    lines += _body(gen_bgp_conf(node, num_vrfs))
    lines.append("!")
    lines += _body(gen_pim_conf(node, num_vrfs, num_mcast_vrfs))
    lines.append("!")
    return "\n".join(lines) + "\n"


def daemons_for(node, num_mcast_vrfs):
    """RD_* daemon list for a node's unified config."""
    # Imported lazily to avoid a hard dependency at module import time.
    from lib.topogen import TopoRouter

    d = [TopoRouter.RD_ZEBRA, TopoRouter.RD_OSPF, TopoRouter.RD_BGP]
    if node == MCAST_PE and num_mcast_vrfs > 0:
        # pim6d is started too so the reload test can inject the full knob
        # catalog (which includes the IPv6 PIM/MLD knobs) into the tenant VRFs.
        # The baseline multicast dataplane itself is IPv4-only.
        d.append(TopoRouter.RD_PIM)
        d.append(TopoRouter.RD_PIM6)
    return d
