#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_mh_bpp.py
#
# Copyright (c) 2026 by
# Cisco Systems, Inc.
# Patrice Brissette
#

"""
EVPN bridge-port protection (L3 multihoming).

              +--------+         +--------+
              | spine1 |         | spine2 |        eBGP underlay + EVPN
              +--------+         +--------+
             /   |   |   \      /   |   |   \
        +------+ +------+ +------+ +------+
        | tor1 | | tor2 | | tor3 | | tor4 |       VTEPs (tor3 is IPv6)
        +------+ +------+ +------+ +------+
           |  \     |  \     |  \     |  \
           |   \    |   \    |   \    |   \
        +--------+                +--------+
        | hostd1 |  (to all tors) | hostd2 |
        +--------+                +--------+

hostd1 is LACP-bonded to all four tors (hostbond1 = ES-1 on every tor) and
hostd2 likewise (hostbond2 = ES-2). On each tor, both ES bonds are trunks on
the VLAN-aware bridge br_default. Their VLANs are no-L2VNI access BDs whose
SVIs sit in an IP-VRF with an L3VNI:

    VLAN 10 -> vlan10 in vrf-a (L3VNI 4001)
    VLAN 20 -> vlan20 in vrf-b (L3VNI 4002)
    VLAN 30 -> vlan30 in vrf-a (added to hostbond1 by the tests)

A protection entry is kept per (ES bond, VLAN). The protection tests run on
tor1, on hostbond1.
"""

import os
import sys
import json
import time
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.bpp_export_check import bpp_export_check
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

SPINES = ("spine1", "spine2")
TORS = ("tor1", "tor2", "tor3", "tor4")
HOSTS = ("hostd1", "hostd2")

ES_IF = "hostbond1"
ES1_ID = "03:44:38:39:ff:ff:01:00:00:01"
ES2_ID = "03:44:38:39:ff:ff:02:00:00:02"
# host -> (ES bond, es-sys-mac, ESI)
HOST_ES = {
    "hostd1": ("hostbond1", "44:38:39:ff:ff:01", ES1_ID),
    "hostd2": ("hostbond2", "44:38:39:ff:ff:02", ES2_ID),
}
BPP_XPATH = "/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/evpn-mh" % ES_IF

# vrf -> (table, L3VNI)
VRFS = {"vrf-a": (1001, 4001), "vrf-b": (1002, 4002)}
# access VLAN -> (SVI VRF, anycast gateway)
ACCESS_VLANS = {
    10: ("vrf-a", "10.10.0.1/24"),
    20: ("vrf-b", "10.20.0.1/24"),
    30: ("vrf-a", "10.30.0.1/24"),
}
ANYCAST_GW_MAC = "44:38:39:ff:00:01"
ES_VLANS = (10, 20)
# host -> last octet of its address in each ES VLAN subnet
HOST_ID = {"hostd1": 101, "hostd2": 102}

WAIT_COUNT = 60
WAIT_STEP = 1


def tor_lo(tor):
    """IPv4 loopback / underlay / BGP router-id."""
    return "10.0.0.%d" % (TORS.index(tor) + 1)


def tor_vtep(tor):
    """EVPN VTEP / originator IP. tor3 is IPv6; the others are IPv4."""
    n = TORS.index(tor) + 1
    if tor == "tor3":
        return "2001:db8::%d" % n
    return tor_lo(tor)


def link_subnet(spine, tor):
    """192.168.<spine><tor>.0/24: spine is .1, tor is .2."""
    return "192.168.%d%d" % (SPINES.index(spine) + 1, TORS.index(tor) + 1)


def build_topo(tgen):
    for name in SPINES + TORS + HOSTS:
        tgen.add_router(name)

    # Spine-major so that torN-eth0 -> spine1, torN-eth1 -> spine2, and
    # spineM-eth0..3 -> tor1..4.
    for s, spine in enumerate(SPINES, 1):
        for t, tor in enumerate(TORS, 1):
            sw = tgen.add_switch("s%dt%d" % (s, t))
            sw.add_link(tgen.gears[spine])
            sw.add_link(tgen.gears[tor])

    # torN-eth2 -> hostd1, torN-eth3 -> hostd2; hostdX-eth0..3 -> tor1..4.
    for h, host in enumerate(HOSTS, 1):
        for t, tor in enumerate(TORS, 1):
            sw = tgen.add_switch("h%dt%d" % (h, t))
            sw.add_link(tgen.gears[tor])
            sw.add_link(tgen.gears[host])


def add_l3vni_dataplane(tor, vrf, table, l3vni):
    vtep = tor_vtep(tor.name)
    tor.run("ip link add %s type vrf table %d" % (vrf, table))
    tor.run("ip link set dev %s up" % vrf)

    tor.run(
        "ip link add vni%d type vxlan id %d dstport 4789 local %s nolearning"
        % (l3vni, l3vni, vtep)
    )
    tor.run("ip link set dev vni%d master br_default" % l3vni)
    tor.run("/sbin/bridge link set dev vni%d learning off" % l3vni)
    tor.run("/sbin/bridge vlan del vid 1 dev vni%d" % l3vni)
    tor.run("/sbin/bridge vlan add vid %d dev vni%d pvid untagged" % (l3vni, l3vni))
    tor.run("ip link set dev vni%d up" % l3vni)

    tor.run("/sbin/bridge vlan add vid %d dev br_default self" % l3vni)
    tor.run("ip link add link br_default name vlan%d type vlan id %d" % (l3vni, l3vni))
    tor.run("ip link set dev vlan%d master %s" % (l3vni, vrf))
    tor.run("ip link set dev vlan%d up" % l3vni)


def config_tor_dataplane(tor):
    lo = tor_lo(tor.name)
    vtep = tor_vtep(tor.name)
    tor.run("ip addr add %s/32 dev lo" % lo)
    if vtep != lo:
        tor.run("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
        tor.run("sysctl -w net.ipv6.conf.lo.disable_ipv6=0")
        tor.run("ip link set lo up")
        tor.run(
            "ip -6 addr add 2001:db8:ffff::%d/128 dev lo" % (TORS.index(tor.name) + 1)
        )
        tor.run("ip -6 addr add %s/128 dev lo" % vtep)

    tor.run("ip link add dev br_default type bridge stp_state 0")
    tor.run("ip link set dev br_default type bridge vlan_filtering 1")
    tor.run("ip link set dev br_default up")

    for vrf, (table, l3vni) in VRFS.items():
        add_l3vni_dataplane(tor, vrf, table, l3vni)

    # No-L2VNI access BDs, with the same anycast gateway on every tor.
    for vid, (vrf, gw) in ACCESS_VLANS.items():
        tor.run("/sbin/bridge vlan add vid %d dev br_default self" % vid)
        tor.run("ip link add link br_default name vlan%d type vlan id %d" % (vid, vid))
        tor.run("ip link set dev vlan%d address %s" % (vid, ANYCAST_GW_MAC))
        tor.run("ip link set dev vlan%d master %s" % (vid, vrf))
        tor.run("ip addr add %s dev vlan%d" % (gw, vid))
        tor.run("ip link set dev vlan%d up" % vid)

    for idx, host in enumerate(HOSTS):
        bond, sys_mac, _ = HOST_ES[host]
        member = "%s-eth%d" % (tor.name, len(SPINES) + idx)
        tor.run("ip link add dev %s type bond mode 802.3ad" % bond)
        tor.run("ip link set dev %s type bond lacp_rate 1" % bond)
        tor.run("ip link set dev %s type bond miimon 100" % bond)
        tor.run("ip link set dev %s type bond min_links 1" % bond)
        tor.run("ip link set dev %s type bond ad_actor_system %s" % (bond, sys_mac))
        tor.run("ip link set dev %s down" % member)
        tor.run("ip link set dev %s master %s" % (member, bond))
        tor.run("ip link set dev %s up" % member)
        tor.run("ip link set dev %s up" % bond)
        tor.run("ip link set dev %s master br_default" % bond)
        tor.run("/sbin/bridge vlan del vid 1 dev %s" % bond)
        for vid in ES_VLANS:
            tor.run("/sbin/bridge vlan add vid %d dev %s" % (vid, bond))


def config_host(host):
    host.run("ip link add dev bond0 type bond mode 802.3ad")
    host.run("ip link set dev bond0 type bond lacp_rate 1")
    host.run("ip link set dev bond0 type bond miimon 100")
    for idx in range(len(TORS)):
        member = "%s-eth%d" % (host.name, idx)
        host.run("ip link set dev %s down" % member)
        host.run("ip link set dev %s master bond0" % member)
        host.run("ip link set dev %s up" % member)
    host.run("ip link set dev bond0 up")

    for vid in ES_VLANS:
        _, gw = ACCESS_VLANS[vid]
        prefix = gw.split("/")[0].rsplit(".", 1)[0]
        host.run("ip link add link bond0 name bond0.%d type vlan id %d" % (vid, vid))
        host.run(
            "ip addr add %s.%d/24 dev bond0.%d" % (prefix, HOST_ID[host.name], vid)
        )
        host.run("ip link set dev bond0.%d up" % vid)


def _enable_ipv6(router):
    router.run("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
    router.run("sysctl -w net.ipv6.conf.default.disable_ipv6=0")
    router.run("sysctl -w net.ipv6.conf.all.forwarding=1")


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for name in SPINES + TORS:
        _enable_ipv6(tgen.gears[name])

    for name in TORS:
        config_tor_dataplane(tgen.gears[name])

    for name in SPINES + TORS:
        router = tgen.gears[name]
        router.load_frr_config(os.path.join(CWD, "%s/frr.conf" % name))
    tgen.start_router()

    for name in HOSTS:
        config_host(tgen.gears[name])


def teardown_module(_mod):
    get_topogen().stop_topology()


def _bgp_peers_up(router, afi, peers):
    output = json.loads(router.vtysh_cmd("show bgp %s summary json" % afi))
    for key in ("ipv4Unicast", "ipv6Unicast", "l2VpnEvpn"):
        if key in output:
            output = output[key]
            break
    for peer in peers:
        state = output.get("peers", {}).get(peer, {}).get("state")
        if state != "Established":
            return "%s: %s peer %s is %s" % (router.name, afi, peer, state)
    return None


def test_bgp_sessions():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for tor in TORS:
        peers = ["%s.1" % link_subnet(spine, tor) for spine in SPINES]
        for afi in ("ipv4 unicast", "l2vpn evpn"):
            test_func = partial(_bgp_peers_up, tgen.gears[tor], afi, peers)
            _, result = topotest.run_and_expect(
                test_func, None, count=WAIT_COUNT, wait=WAIT_STEP
            )
            assert result is None, result


def _l3vnis_up(router):
    for vrf, (_, l3vni) in VRFS.items():
        output = json.loads(router.vtysh_cmd("show evpn vni %d json" % l3vni))
        expected = {"vni": l3vni, "type": "L3", "tenantVrf": vrf, "state": "Up"}
        result = topotest.json_cmp(output, expected)
        if result:
            return "%s: L3VNI %d: %s" % (router.name, l3vni, result)
    return None


def test_l3vnis_up():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for tor in TORS:
        test_func = partial(_l3vnis_up, tgen.gears[tor])
        _, result = topotest.run_and_expect(
            test_func, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result


def _es_peers(router):
    """Each ES is local on every tor, with the three other tors as peers."""
    output = json.loads(router.vtysh_cmd("show bgp l2vpn evpn es json"))
    if isinstance(output, dict):
        output = output.get("es", [])
    entries = {es.get("esi"): es for es in output}
    remote = sorted(tor_vtep(t) for t in TORS if t != router.name)

    for _, _, esi in HOST_ES.values():
        es = entries.get(esi)
        if not es:
            return "%s: ES %s missing" % (router.name, esi)
        if "local" not in es.get("type", []):
            return "%s: ES %s not local" % (router.name, esi)
        vteps = sorted(v.get("vtep_ip") for v in es.get("vteps", []))
        if vteps != remote:
            return "%s: ES %s peers %s, want %s" % (router.name, esi, vteps, remote)
    return None


def test_es_on_all_tors():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for tor in TORS:
        test_func = partial(_es_peers, tgen.gears[tor])
        _, result = topotest.run_and_expect(
            test_func, None, count=WAIT_COUNT, wait=WAIT_STEP
        )
        assert result is None, result


def _bpp_in_running_config(router):
    return "evpn mh bridge-port-protection" in router.vtysh_cmd("show running-config")


def _check_bpp(router, expected):
    if _bpp_in_running_config(router) != expected:
        return "running-config: protection %s" % ("missing" if expected else "set")

    output = router.vtysh_cmd(
        "show mgmt get-data %s datastore running only-config json" % BPP_XPATH
    )
    leaf = (
        json.loads(output)
        .get("frr-interface:lib", {})
        .get("interface", [{}])[0]
        .get("frr-zebra:zebra", {})
        .get("evpn-mh", {})
        .get("bridge-port-protection")
    )
    if bool(leaf) != expected:
        return "mgmt running datastore: bridge-port-protection=%s" % leaf
    return None


def _expect_bpp(router, expected):
    test_func = partial(_check_bpp, router, expected)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, result


def test_bpp_config():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    # Off by default.
    _expect_bpp(tor1, False)

    # Add after es-id.
    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nevpn mh bridge-port-protection" % ES_IF
    )
    _expect_bpp(tor1, True)

    # Remove.
    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nno evpn mh bridge-port-protection" % ES_IF
    )
    _expect_bpp(tor1, False)

    # Add before es-id: the knob is kept across es-id removal and re-add.
    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nno evpn mh es-id\n"
        "evpn mh bridge-port-protection\nevpn mh es-id 1" % ES_IF
    )
    _expect_bpp(tor1, True)

    tor1.vtysh_cmd("configure terminal\ninterface %s\nno evpn mh es-id" % ES_IF)
    _expect_bpp(tor1, True)

    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nevpn mh es-id 1\n"
        "no evpn mh bridge-port-protection" % ES_IF
    )
    _expect_bpp(tor1, False)


def _set_bpp(router, enable):
    router.vtysh_cmd(
        "configure terminal\ninterface %s\n%sevpn mh bridge-port-protection"
        % (ES_IF, "" if enable else "no ")
    )


def _ready_vlans(vlans):
    return {
        str(vid): {
            "vrf": ACCESS_VLANS[vid][0],
            "l3vni": VRFS[ACCESS_VLANS[vid][0]][1],
            "state": "PENDING",
            "ready": True,
            "reasons": ["__ordered__", "no eligible peer"],
        }
        for vid in vlans
    }


def _active_vlans(vlans):
    return {
        str(vid): {
            "vrf": ACCESS_VLANS[vid][0],
            "l3vni": VRFS[ACCESS_VLANS[vid][0]][1],
            "state": "ACTIVE",
            "ready": True,
            "reasons": ["__ordered__"],
        }
        for vid in vlans
    }


def _member(vtep, rmac=None, family=None):
    if family is None:
        family = "ipv6" if ":" in vtep else "ipv4"
    rec = {"vtep": vtep, "family": family, "type": "L3"}
    if rmac is not None:
        rec["rmac"] = rmac
    return rec


def _members(*vteps):
    return ["__ordered__"] + [_member(v) for v in sorted(vteps)]


def _pending(reasons, **kwargs):
    return dict(kwargs, ready=False, reasons=["__ordered__"] + reasons)


def _expect_entries(router, expected, msg):
    def _check():
        output = json.loads(
            router.vtysh_cmd("show evpn mh bridge-port-protection json")
        )
        if expected == {}:
            return None if output == {} else output
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def test_bpp_entries():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    _expect_entries(tor1, {}, "entries without protection")

    _set_bpp(tor1, True)
    _expect_entries(
        tor1,
        {ES_IF: {"esi": ES1_ID, "vlans": _ready_vlans(ES_VLANS)}},
        "one ready entry per VLAN of the ES bond",
    )

    tor1.run("/sbin/bridge vlan add vid 30 dev %s" % ES_IF)
    _expect_entries(
        tor1,
        {ES_IF: {"vlans": _ready_vlans(ES_VLANS + (30,))}},
        "entry for the added VLAN",
    )

    tor1.run("/sbin/bridge vlan del vid 30 dev %s" % ES_IF)
    expected = _ready_vlans(ES_VLANS)
    expected["30"] = None
    _expect_entries(tor1, {ES_IF: {"vlans": expected}}, "entry removed with the VLAN")

    _set_bpp(tor1, False)
    _expect_entries(tor1, {}, "entries after protection removed")


def test_bpp_pending_reasons():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    ready = {ES_IF: {"esi": ES1_ID, "vlans": _ready_vlans(ES_VLANS)}}

    _set_bpp(tor1, True)
    _expect_entries(tor1, ready, "initial state")

    tor1.vtysh_cmd("configure terminal\ninterface %s\nno evpn mh es-id" % ES_IF)
    _expect_entries(
        tor1,
        {
            ES_IF: {
                "esi": None,
                "vlans": {
                    "10": _pending(["no local ES"]),
                    "20": _pending(["no local ES"]),
                },
            }
        },
        "es-id removed",
    )
    tor1.vtysh_cmd("configure terminal\ninterface %s\nevpn mh es-id 1" % ES_IF)
    _expect_entries(tor1, ready, "es-id restored")

    tor1.run("ip link set dev vlan20 nomaster")
    _expect_entries(
        tor1,
        {
            ES_IF: {
                "vlans": {
                    "10": _ready_vlans((10,))["10"],
                    "20": _pending(["IP-VRF has no L3VNI"], vrf="default", l3vni=None),
                }
            }
        },
        "VRF-B SVI out of its VRF",
    )
    tor1.run("ip link set dev vlan20 master vrf-b")
    tor1.run("ip link set dev vlan20 up")
    _expect_entries(tor1, ready, "VRF-B SVI back in its VRF")

    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001\naddress-family l2vpn evpn\n"
        "no advertise-all-vni l3vni-neigh"
    )
    _expect_entries(
        tor1,
        {
            ES_IF: {
                "vlans": {
                    "10": _pending(["l3vni-neigh off"]),
                    "20": _pending(["l3vni-neigh off"]),
                }
            }
        },
        "l3vni-neigh removed",
    )
    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001\naddress-family l2vpn evpn\n"
        "advertise-all-vni l3vni-neigh"
    )
    _expect_entries(tor1, ready, "l3vni-neigh restored")

    _set_bpp(tor1, False)
    _expect_entries(tor1, {}, "protection removed")


def test_bpp_link_state():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    ready = {ES_IF: {"esi": ES1_ID, "vlans": _ready_vlans(ES_VLANS)}}

    _set_bpp(tor1, True)
    _expect_entries(tor1, ready, "initial state")

    # Readiness comes from config only.
    tor1.run("ip link set dev %s down" % ES_IF)
    _expect_entries(tor1, ready, "ES bond down")
    tor1.run("ip link set dev %s up" % ES_IF)
    _expect_entries(tor1, ready, "ES bond up")

    _set_bpp(tor1, False)
    _expect_entries(tor1, {}, "protection removed")


def _set_bpp_if(router, ifname, enable):
    router.vtysh_cmd(
        "configure terminal\ninterface %s\n%sevpn mh bridge-port-protection"
        % (ifname, "" if enable else "no ")
    )


def _expect_json(router, cmd, expected, msg):
    def _check():
        output = json.loads(router.vtysh_cmd(cmd))
        if expected == {}:
            return None if output == {} else output
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def _member_es(ifname):
    return {
        "interface": ifname,
        "state": "PENDING",
        "vlanCount": len(ES_VLANS),
        "readyVrfs": ["__ordered__", "vrf-a", "vrf-b"],
        "esEviL3vnis": ["__ordered__", 4001, 4002],
        "members": ["__ordered__"],
    }


def test_bpp_show():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    cmd = "show evpn mh bridge-port-protection"

    for bond, _, _ in HOST_ES.values():
        _set_bpp_if(tor1, bond, True)

    with open(os.path.join(CWD, "tor1/show_bpp_pending.json")) as f:
        pending = json.load(f)
    _expect_json(tor1, cmd + " json", pending, "all entries")

    _expect_json(
        tor1,
        cmd + " interface hostbond2 json",
        {"hostbond1": None, "hostbond2": pending["hostbond2"]},
        "interface filter",
    )

    detail = {"hostbond1": {"vlans": {str(v): {"memberCount": 0} for v in ES_VLANS}}}
    _expect_json(tor1, cmd + " interface hostbond1 detail json", detail, "detail")

    _expect_json(
        tor1,
        cmd + " member json",
        {ES1_ID: _member_es("hostbond1"), ES2_ID: _member_es("hostbond2")},
        "member view",
    )
    _expect_json(
        tor1,
        cmd + " member %s json" % ES1_ID,
        {ES1_ID: _member_es("hostbond1"), ES2_ID: None},
        "member ESI filter",
    )

    output = tor1.vtysh_cmd(cmd)
    for text in ("Group", "hostbond1", "hostbond2", "no eligible peer"):
        assert text in output, "'%s' missing from:\n%s" % (text, output)
    output = tor1.vtysh_cmd(cmd + " member")
    for text in (
        "ESI %s" % ES1_ID,
        "VRFs: vrf-a, vrf-b",
        "ES-EVI L3VNIs: 4001, 4002",
        "NH-ID",
    ):
        assert text in output, "'%s' missing from:\n%s" % (text, output)

    _set_bpp_if(tor1, "hostbond2", False)
    _expect_json(
        tor1,
        cmd + " member json",
        {ES1_ID: _member_es("hostbond1"), ES2_ID: None},
        "unprotected ES not in member view",
    )

    _set_bpp_if(tor1, ES_IF, False)
    _expect_json(tor1, cmd + " json", {}, "protection removed")
    _expect_json(tor1, cmd + " member json", {}, "no protected ES")


def _expect_log(tgen, router, text):
    path = os.path.join(tgen.logdir, router.name, "zebra.log")

    def _check():
        with open(path) as f:
            return None if text in f.read() else "'%s' not in %s" % (text, path)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result


def _set_l3vni_neigh(router, enable):
    router.vtysh_cmd(
        "configure terminal\nrouter bgp 65001\naddress-family l2vpn evpn\n"
        "%sadvertise-all-vni l3vni-neigh" % ("" if enable else "no ")
    )


def test_bpp_debug():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    cmd = "show evpn mh bridge-port-protection json"
    zebra_on = "Zebra EVPN-MH protection debugging is on"
    bgp_on = "BGP EVPN-MH protection debugging is on"

    tor1.vtysh_cmd(
        "configure terminal\ndebug zebra evpn mh protection\n"
        "debug bgp evpn mh protection"
    )
    output = tor1.vtysh_cmd("show debugging")
    assert zebra_on in output and bgp_on in output, output
    output = tor1.vtysh_cmd("show running-config")
    for line in ("debug zebra evpn mh protection", "debug bgp evpn mh protection"):
        assert line in output, "'%s' not in running-config" % line

    _set_bpp(tor1, True)
    _expect_log(
        tgen, tor1, "bridge-port protection %s vlan 10 add: no eligible peer" % ES_IF
    )
    _expect_json(
        tor1, cmd, {ES_IF: {"vlans": {"10": {"lastEvent": "created"}}}}, "created"
    )

    _set_l3vni_neigh(tor1, False)
    _expect_log(
        tgen,
        tor1,
        "bridge-port protection %s vlan 10: no eligible peer -> l3vni-neigh off"
        % ES_IF,
    )
    _expect_json(
        tor1,
        cmd,
        {ES_IF: {"vlans": {"10": {"lastEvent": "reasons changed"}}}},
        "reasons changed",
    )
    _set_l3vni_neigh(tor1, True)
    _expect_log(
        tgen,
        tor1,
        "bridge-port protection %s vlan 10: l3vni-neigh off -> no eligible peer"
        % ES_IF,
    )

    _set_bpp(tor1, False)
    _expect_log(tgen, tor1, "bridge-port protection %s vlan 10 del" % ES_IF)

    tor1.vtysh_cmd(
        "configure terminal\nno debug zebra evpn mh protection\n"
        "no debug bgp evpn mh protection"
    )
    output = tor1.vtysh_cmd("show debugging")
    assert zebra_on not in output and bgp_on not in output, output


def _es_vrfs(router, esi):
    """BGP ES-VRFs of an ES, keyed by VRF name ("VRF <name>" in the output)."""
    output = json.loads(router.vtysh_cmd("show bgp l2vpn evpn es-vrf json"))
    return {e["vrf"].split()[-1]: e for e in output if e.get("esi") == esi}


def _l3mh_es_vrf(l3_ref_cnt=1):
    return {
        "flags": ["l3mh"],
        "ipv4NHG": 0,
        "ipv6NHG": 0,
        "refCount": 0,
        "l3RefCount": l3_ref_cnt,
    }


def _expect_es_vrfs(router, esi, expected, msg):
    """expected maps VRF -> partial ES-VRF; the VRF set must match."""

    def _check():
        es_vrfs = _es_vrfs(router, esi)
        if sorted(es_vrfs) != sorted(expected):
            return "VRFs %s, want %s" % (sorted(es_vrfs), sorted(expected))
        return topotest.json_cmp(es_vrfs, expected)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def _expect_es_evi_l3vnis(router, l3vnis, msg):
    expected = {ES1_ID: {"esEviL3vnis": l3vnis}} if l3vnis is not None else {}
    _expect_json(
        router, "show evpn mh bridge-port-protection member json", expected, msg,
    )


ES1_L3MH_VRFS = {"vrf-a": _l3mh_es_vrf(), "vrf-b": _l3mh_es_vrf()}


def test_bpp_es_vrf_assoc():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    _expect_es_vrfs(tor1, ES1_ID, {}, "no ES-VRF without protection")

    _set_bpp(tor1, True)
    _expect_es_evi_l3vnis(tor1, ["__ordered__", 4001, 4002], "ES-EVIs sent")
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "ES-1 associated with both IP-VRFs")
    _expect_es_vrfs(tor1, ES2_ID, {}, "unprotected ES-2 not associated")

    # A second VLAN in vrf-a does not add a reference.
    tor1.run("/sbin/bridge vlan add vid 30 dev %s" % ES_IF)
    _expect_entries(
        tor1, {ES_IF: {"vlans": _ready_vlans((30,))}}, "VLAN 30 entry ready"
    )
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "one ES-EVI per IP-VRF")

    # vrf-a stays associated through VLAN 30.
    tor1.run("/sbin/bridge vlan del vid 10 dev %s" % ES_IF)
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "vrf-a kept by VLAN 30")

    tor1.run("/sbin/bridge vlan del vid 30 dev %s" % ES_IF)
    _expect_es_evi_l3vnis(tor1, ["__ordered__", 4002], "vrf-a ES-EVI withdrawn")
    _expect_es_vrfs(tor1, ES1_ID, {"vrf-b": _l3mh_es_vrf()}, "last vrf-a VLAN removed")

    tor1.run("/sbin/bridge vlan add vid 10 dev %s" % ES_IF)
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "VLAN 10 restored")

    _set_bpp(tor1, False)
    _expect_es_evi_l3vnis(tor1, None, "no ES-EVI after protection removed")
    _expect_es_vrfs(tor1, ES1_ID, {}, "ES-VRFs released")


def test_bpp_l3mh_gate():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    _set_bpp(tor1, True)
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "initial state")

    _set_l3vni_neigh(tor1, False)
    _expect_es_evi_l3vnis(tor1, ["__ordered__"], "ES-EVIs withdrawn")
    _expect_es_vrfs(tor1, ES1_ID, {}, "l3vni-neigh off")

    _set_l3vni_neigh(tor1, True)
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "l3vni-neigh on")

    _set_bpp(tor1, False)
    _expect_es_vrfs(tor1, ES1_ID, {}, "protection removed")


L2VNI = 1020
L2VNI_VLAN = 20


def _add_l2vni(router):
    lo = tor_lo(router.name)
    router.run(
        "ip link add vni%d type vxlan id %d dstport 4789 local %s nolearning"
        % (L2VNI, L2VNI, lo)
    )
    router.run("ip link set dev vni%d master br_default" % L2VNI)
    router.run("/sbin/bridge link set dev vni%d learning off" % L2VNI)
    router.run("/sbin/bridge vlan del vid 1 dev vni%d" % L2VNI)
    router.run(
        "/sbin/bridge vlan add vid %d dev vni%d pvid untagged" % (L2VNI_VLAN, L2VNI)
    )
    router.run("ip link set dev vni%d up" % L2VNI)


def _del_l2vni(router):
    router.run("ip link del dev vni%d" % L2VNI)


def _expect_l2_es_evi(router, esi, present, msg):
    def _check():
        output = json.loads(
            router.vtysh_cmd("show bgp l2vpn evpn es-evi vni %d json" % L2VNI)
        )
        found = any(
            e.get("esi") == esi and "local" in e.get("type", []) for e in output or []
        )
        if found != present:
            return "ES-EVI %s vni %d %s" % (
                esi,
                L2VNI,
                "missing" if present else "present",
            )
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def test_bpp_l3mh_bd_gets_l2vni():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    _set_bpp(tor1, True)
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "initial state")

    # VLAN 20 gets an L2VNI: every entry of ES-1 is pending and its L3VNI
    # ES-EVIs are withdrawn; both ESs get the L2VNI ES-EVI as before.
    _add_l2vni(tor1)
    _expect_entries(
        tor1,
        {
            ES_IF: {
                "vlans": {
                    "10": _pending(["ES has an L2VNI"]),
                    "20": _pending(["L2VNI on BD"]),
                }
            }
        },
        "L2VNI on VLAN 20",
    )
    _expect_es_evi_l3vnis(tor1, ["__ordered__"], "L3VNI ES-EVIs withdrawn")
    for esi in (ES1_ID, ES2_ID):
        _expect_l2_es_evi(tor1, esi, True, "L2VNI ES-EVI")
        _expect_es_vrfs(
            tor1, esi, {"vrf-b": {"refCount": 1, "l3RefCount": 0}}, "L2VNI ES-VRF",
        )

    _del_l2vni(tor1)
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "L2VNI removed")
    _expect_es_vrfs(tor1, ES2_ID, {}, "ES-2 L2VNI ES-VRF released")

    _set_bpp(tor1, False)
    _expect_es_vrfs(tor1, ES1_ID, {}, "protection removed")


def test_bpp_es_evi_l2vni_unchanged():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    # Without protection, an L2VNI ES-EVI and its ES-VRF are unchanged.
    _add_l2vni(tor1)
    _expect_l2_es_evi(tor1, ES2_ID, True, "L2VNI ES-EVI")
    _expect_es_vrfs(
        tor1, ES2_ID, {"vrf-b": {"refCount": 1, "l3RefCount": 0}}, "L2VNI ES-VRF",
    )
    nhg = _es_vrfs(tor1, ES2_ID)["vrf-b"]["ipv4NHG"]
    assert nhg, "L2VNI ES-VRF has no L3 NHG"

    _del_l2vni(tor1)
    _expect_l2_es_evi(tor1, ES2_ID, False, "L2VNI ES-EVI removed")
    _expect_es_vrfs(tor1, ES2_ID, {}, "L2VNI ES-VRF released")


def test_bpp_es_evi_bgpd_restart():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    _set_bpp(tor1, True)
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "initial state")

    # zebra replays the L3VNI ES-EVIs to the new bgpd, whatever the
    # order of the L3VNI and ES-EVI messages.
    kill_router_daemons(tgen, "tor1", ["bgpd"])
    start_router_daemons(tgen, "tor1", ["bgpd"])
    _expect_es_vrfs(tor1, ES1_ID, ES1_L3MH_VRFS, "after bgpd restart")

    _set_bpp(tor1, False)
    _expect_es_vrfs(tor1, ES1_ID, {}, "protection removed")


# bgpd hidden test commands inject ES-EVIs in a chosen order.
ES9_ID = "03:44:38:39:ff:ff:09:00:00:09"
VRF_C, VRF_C_TABLE, VRF_C_L3VNI = "vrf-c", 1003, 4003


def _evpn_cmd(router, cmd):
    return router.vtysh_cmd(
        "configure terminal\nrouter bgp 65001\naddress-family l2vpn evpn\n" + cmd
    )


def _expect_bgpd_log(tgen, router, text):
    path = os.path.join(tgen.logdir, router.name, "bgpd.log")

    def _check():
        with open(path) as f:
            return None if text in f.read() else "'%s' not in %s" % (text, path)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result


def _set_bgp_prot_debug(router, enable):
    router.vtysh_cmd(
        "configure terminal\n%sdebug bgp evpn mh protection" % ("" if enable else "no ")
    )


def test_bpp_es_evi_pending_es():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    _set_bgp_prot_debug(tor1, True)

    # L3VNI ES-EVI before the ES: kept pending, applied on local ES add.
    _evpn_cmd(tor1, "test es %s vni %d" % (ES9_ID, VRFS["vrf-a"][1]))
    _expect_bgpd_log(
        tgen, tor1, "es %s l3vni %d pending: no local ES" % (ES9_ID, VRFS["vrf-a"][1])
    )
    _expect_es_vrfs(tor1, ES9_ID, {}, "no ES yet")

    _evpn_cmd(tor1, "test es %s" % ES9_ID)
    _expect_es_vrfs(tor1, ES9_ID, {"vrf-a": _l3mh_es_vrf()}, "ES added")

    # The local ES delete releases its L3VNI ES-EVIs.
    _evpn_cmd(tor1, "no test es %s" % ES9_ID)
    _expect_es_vrfs(tor1, ES9_ID, {}, "ES deleted")
    _evpn_cmd(tor1, "test es %s" % ES9_ID)
    _expect_es_vrfs(tor1, ES9_ID, {}, "nothing left pending")
    _evpn_cmd(tor1, "no test es %s" % ES9_ID)

    _set_bgp_prot_debug(tor1, False)


def _add_vrf_c(router):
    add_l3vni_dataplane(router, VRF_C, VRF_C_TABLE, VRF_C_L3VNI)
    router.vtysh_cmd(
        "configure terminal\nvrf %s\nvni %d\nexit-vrf" % (VRF_C, VRF_C_L3VNI)
    )


def _del_vrf_c_l3vni(router):
    router.vtysh_cmd(
        "configure terminal\nvrf %s\nno vni %d\nexit-vrf" % (VRF_C, VRF_C_L3VNI)
    )


def _del_vrf_c(router):
    _del_vrf_c_l3vni(router)
    router.run("ip link del dev vlan%d" % VRF_C_L3VNI)
    router.run("ip link del dev vni%d" % VRF_C_L3VNI)
    router.run("ip link del dev %s" % VRF_C)


def test_bpp_es_evi_l3vni_order():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    _set_bgp_prot_debug(tor1, True)

    # L3VNI ES-EVI before bgpd knows the L3VNI: pending, applied on L3VNI add.
    _evpn_cmd(tor1, "test es %s vni %d" % (ES1_ID, VRF_C_L3VNI))
    _expect_bgpd_log(
        tgen, tor1, "es %s l3vni %d pending: no BGP VRF" % (ES1_ID, VRF_C_L3VNI)
    )
    _expect_es_vrfs(tor1, ES1_ID, {}, "L3VNI unknown")

    _add_vrf_c(tor1)
    _expect_es_vrfs(tor1, ES1_ID, {VRF_C: _l3mh_es_vrf()}, "L3VNI added")

    # L3VNI removed: back to pending; re-added: applied again.
    _del_vrf_c_l3vni(tor1)
    _expect_es_vrfs(tor1, ES1_ID, {}, "L3VNI removed")
    tor1.vtysh_cmd(
        "configure terminal\nvrf %s\nvni %d\nexit-vrf" % (VRF_C, VRF_C_L3VNI)
    )
    _expect_es_vrfs(tor1, ES1_ID, {VRF_C: _l3mh_es_vrf()}, "L3VNI re-added")

    _evpn_cmd(tor1, "no test es %s vni %d" % (ES1_ID, VRF_C_L3VNI))
    _expect_es_vrfs(tor1, ES1_ID, {}, "ES-EVI deleted")

    _del_vrf_c(tor1)
    _set_bgp_prot_debug(tor1, False)


def test_bpp_es_evi_unknown_vni_rejected():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    # Without l3vni-neigh an unknown VNI is rejected as before, not kept.
    _set_l3vni_neigh(tor1, False)
    for esi in (ES1_ID, ES9_ID):
        output = _evpn_cmd(tor1, "test es %s vni %d" % (esi, VRFS["vrf-a"][1]))
        assert "Failed to ref ES VNI" in output, output

    _set_l3vni_neigh(tor1, True)
    _evpn_cmd(tor1, "test es %s" % ES9_ID)
    _expect_es_vrfs(tor1, ES1_ID, {}, "ES-1 nothing kept")
    _expect_es_vrfs(tor1, ES9_ID, {}, "ES-9 nothing kept")
    _evpn_cmd(tor1, "no test es %s" % ES9_ID)


ETH_TAG_ES = 4294967295
EAD_EVI_ET = 0


def _vrf_rt(router, vrf):
    return "%d:%d" % (65000 + TORS.index(router.name) + 1, VRFS[vrf][1])


def _path_dicts(paths):
    for path in paths or []:
        if isinstance(path, list):
            for inner in path:
                if isinstance(inner, dict):
                    yield inner
        elif isinstance(path, dict):
            yield path


def _path_nexthop(path):
    nh = path.get("nexthop") or path.get("ip")
    if nh:
        return nh
    for hop in path.get("nexthops") or []:
        if isinstance(hop, dict) and hop.get("ip"):
            return hop["ip"]
    return None


def _known_l3vnis():
    vnis = set(v[1] for v in VRFS.values())
    vnis.add(VRF_C_L3VNI)
    return vnis


def _route_vni(route):
    vni = route.get("vni")
    if vni not in (None, "0", 0, "0"):
        return int(vni)
    known = _known_l3vnis()
    for tok in (route.get("extcomm") or "").split():
        if tok.startswith("RT:") and tok.count(":") >= 2:
            try:
                val = int(tok.rsplit(":", 1)[1])
            except ValueError:
                continue
            if val in known:
                return val
    return None


def _ead_routes(router):
    """Local type-1 routes: list of {rd, eth_tag, esi, extcomm, vni}."""
    output = json.loads(
        router.vtysh_cmd("show bgp l2vpn evpn route type 1 self-originate json") or "{}"
    )
    routes = []
    local_nhs = {tor_lo(router.name), tor_vtep(router.name)}

    def _walk(obj, rd=None):
        if not isinstance(obj, dict):
            return
        prefix = obj.get("prefix")
        paths = obj.get("paths")
        if isinstance(prefix, str) and prefix.startswith("[1]:[") and paths:
            try:
                eth_tag = int(prefix.split("[1]:[")[1].split("]")[0])
            except (IndexError, ValueError):
                eth_tag = None
            esi = None
            parts = prefix.split("]:[")
            if len(parts) >= 3:
                esi = parts[2].rstrip("]")
            for path in _path_dicts(paths):
                nh = _path_nexthop(path)
                if nh and nh not in local_nhs:
                    continue
                ext = (path.get("extendedCommunity") or {}).get("string", "")
                rec = {
                    "rd": rd,
                    "eth_tag": eth_tag,
                    "esi": esi,
                    "prefix": prefix,
                    "extcomm": ext,
                    "vni": path.get("vni"),
                    "nexthop": nh,
                }
                rec["vni"] = _route_vni(rec)
                routes.append(rec)
            return
        rd_here = obj.get("rd", rd)
        for key, val in obj.items():
            if (
                isinstance(key, str)
                and key.startswith("[1]:[")
                and isinstance(val, dict)
            ):
                val = dict(val, prefix=val.get("prefix") or key)
            _walk(val, rd_here if isinstance(rd_here, str) else rd)

    _walk(output)
    return routes


def _ead_evi(router, esi=ES1_ID):
    return [
        r for r in _ead_routes(router) if r["eth_tag"] == EAD_EVI_ET and r["esi"] == esi
    ]


def _ead_es(router, esi=ES1_ID):
    return [
        r for r in _ead_routes(router) if r["eth_tag"] == ETH_TAG_ES and r["esi"] == esi
    ]


def _expect_ip_ead(
    router, msg, evi_vrfs=None, es_rts=None, evi_absent=False, es_absent=False
):
    def _check():
        evi = _ead_evi(router)
        esr = _ead_es(router)
        if evi_absent and evi:
            return "per-EVI present: %s" % evi
        if es_absent and esr:
            return "per-ES present: %s" % esr
        if evi_vrfs is not None:
            vnis = sorted(r["vni"] for r in evi if r.get("vni") is not None)
            want = sorted(VRFS[v][1] for v in evi_vrfs)
            if vnis != want:
                return "per-EVI VNIs %s, want %s (%s)" % (vnis, want, evi)
            for r in evi:
                ext = r["extcomm"] or ""
                if "Rmac:" not in ext:
                    return "per-EVI missing Router's MAC: %s" % r
                if "L2:" not in ext or "P" not in ext:
                    return "per-EVI missing L2 P=1: %s" % r
                if "ET:8" not in ext:
                    return "per-EVI missing VXLAN encap: %s" % r
        if es_rts is not None:
            union = " ".join(r["extcomm"] or "" for r in esr)
            missing = [rt for rt in es_rts if "RT:%s" % rt not in union]
            if missing:
                return "per-ES missing RTs %s in %s" % (missing, esr)
            if not esr:
                return "no per-ES route"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def _clear_ip_ead(router):
    _set_bpp_if(router, ES_IF, False)
    _expect_ip_ead(router, "IP A-D withdrawn", evi_absent=True, es_absent=True)


def test_bpp_ip_ead_tx():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    rts = (_vrf_rt(tor1, "vrf-a"), _vrf_rt(tor1, "vrf-b"))

    _expect_ip_ead(
        tor1, "no IP A-D without protection", evi_absent=True, es_absent=True
    )

    _set_bpp(tor1, True)
    _expect_ip_ead(tor1, "protected ES", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts)
    _clear_ip_ead(tor1)


def test_bpp_ip_ead_tx_ipv6():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor3 = tgen.gears["tor3"]
    vtep = tor_vtep("tor3")
    rts = (_vrf_rt(tor3, "vrf-a"), _vrf_rt(tor3, "vrf-b"))

    _set_bpp(tor3, True)
    _expect_ip_ead(
        tor3, "configured IPv6 VTEP", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts,
    )

    def _check_nh():
        evi = _ead_evi(tor3)
        nhs = sorted(set(r.get("nexthop") for r in evi if r.get("nexthop")))
        if nhs != [vtep]:
            return "per-EVI nexthops %s, want [%s]" % (nhs, vtep)
        return None

    _, result = topotest.run_and_expect(_check_nh, None, count=30, wait=1)
    assert result is None, result
    _clear_ip_ead(tor3)


def test_bpp_ip_ead_tx_per_es_frag():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    rts = (_vrf_rt(tor1, "vrf-a"), _vrf_rt(tor1, "vrf-b"))

    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001\naddress-family l2vpn evpn\n"
        "ead-es-frag evi-limit 1"
    )
    _set_bpp(tor1, True)

    def _check_frags():
        esr = _ead_es(tor1)
        if len(esr) < 2:
            return "want >= 2 per-ES fragments, got %s" % esr
        rds = set(r["rd"] for r in esr)
        if len(rds) < 2:
            return "fragments share RD: %s" % esr
        union = " ".join(r["extcomm"] or "" for r in esr)
        for rt in rts:
            if "RT:%s" % rt not in union:
                return "union missing RT:%s in %s" % (rt, esr)
        return None

    _, result = topotest.run_and_expect(_check_frags, None, count=30, wait=1)
    assert result is None, "fragments: %s" % result

    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001\naddress-family l2vpn evpn\n"
        "ead-es-route-target export 65001:1"
    )

    def _check_ead_rt():
        esr = _ead_es(tor1)
        union = " ".join(r["extcomm"] or "" for r in esr)
        missing = [rt for rt in rts + ("65001:1",) if "RT:%s" % rt not in union]
        if missing:
            return "missing %s in %s" % (missing, esr)
        return None

    _, result = topotest.run_and_expect(_check_ead_rt, None, count=30, wait=1)
    assert result is None, "ead-es-route-target: %s" % result

    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001\naddress-family l2vpn evpn\n"
        "no ead-es-route-target export 65001:1\nno ead-es-frag evi-limit 1"
    )
    _clear_ip_ead(tor1)


def test_bpp_ip_ead_tx_no_l3mh():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    _expect_ip_ead(tor1, "unprotected", evi_absent=True, es_absent=True)

    _set_bpp(tor1, True)
    _set_l3vni_neigh(tor1, False)
    _expect_ip_ead(tor1, "l3vni-neigh off", evi_absent=True, es_absent=True)
    _set_l3vni_neigh(tor1, True)
    _clear_ip_ead(tor1)


def test_bpp_ip_ead_tx_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor2 = tgen.gears["tor2"]
    rts = (_vrf_rt(tor2, "vrf-a"), _vrf_rt(tor2, "vrf-b"))

    _set_bpp_if(tor2, ES_IF, True)
    _expect_ip_ead(tor2, "tor2 initial", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts)

    tor2.run("/sbin/bridge vlan del vid 20 dev %s" % ES_IF)
    _expect_ip_ead(tor2, "vrf-b VLAN gone", evi_vrfs=("vrf-a",), es_rts=(rts[0],))

    tor2.run("ip link set %s down" % ES_IF)

    def _check_es_down():
        if _ead_es(tor2):
            return "per-ES still present"
        evi = _ead_evi(tor2)
        vnis = sorted(r["vni"] for r in evi if r.get("vni") is not None)
        if vnis != [4001]:
            return "per-EVI VNIs %s, want [4001]" % vnis
        return None

    _, result = topotest.run_and_expect(_check_es_down, None, count=30, wait=1)
    assert result is None, "ES down: %s" % result

    tor2.run("ip link set %s up" % ES_IF)
    tor2.run("/sbin/bridge vlan add vid 20 dev %s" % ES_IF)
    _expect_ip_ead(tor2, "tor2 restored", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts)
    _clear_ip_ead(tor2)


def test_bpp_ip_ead_tx_svi_oper():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    rts = (_vrf_rt(tor1, "vrf-a"), _vrf_rt(tor1, "vrf-b"))
    _set_bpp(tor1, True)
    _expect_ip_ead(tor1, "before SVI down", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts)

    before = [(r["prefix"], r["extcomm"], r["vni"]) for r in _ead_routes(tor1)]
    tor1.run("ip link set vlan20 down")
    _expect_ip_ead(tor1, "SVI down", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts)
    after = [(r["prefix"], r["extcomm"], r["vni"]) for r in _ead_routes(tor1)]
    assert after == before, "SVI down changed type-1: %s -> %s" % (before, after)

    tor1.run("ip link set vlan20 up")
    _expect_ip_ead(tor1, "SVI up", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts)
    _clear_ip_ead(tor1)


def test_bpp_ip_ead_tx_local_es_down():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    rts = (_vrf_rt(tor1, "vrf-a"), _vrf_rt(tor1, "vrf-b"))
    _set_bpp(tor1, True)
    _expect_ip_ead(tor1, "before ES down", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts)

    tor1.run("ip link set %s down" % ES_IF)

    def _check():
        if _ead_es(tor1):
            return "per-ES still present"
        evi = _ead_evi(tor1)
        vnis = sorted(r["vni"] for r in evi if r.get("vni") is not None)
        if vnis != [4001, 4002]:
            return "per-EVI VNIs %s" % vnis
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "local ES down: %s" % result

    tor1.run("ip link set %s up" % ES_IF)
    _expect_ip_ead(tor1, "ES restored", evi_vrfs=("vrf-a", "vrf-b"), es_rts=rts)
    _clear_ip_ead(tor1)


def test_bpp_ip_ead_tx_rt_change():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    _set_bpp(tor1, True)
    new_rt = "65001:9999"

    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001 vrf vrf-a\naddress-family l2vpn evpn\n"
        "route-target export %s" % new_rt
    )

    def _check():
        evi = _ead_evi(tor1)
        hit = [r for r in evi if "RT:%s" % new_rt in (r["extcomm"] or "")]
        if not hit:
            return "per-EVI missing %s: %s" % (new_rt, evi)
        union = " ".join(r["extcomm"] or "" for r in _ead_es(tor1))
        if "RT:%s" % new_rt not in union:
            return "per-ES missing %s: %s" % (new_rt, union)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "RT change: %s" % result

    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001 vrf vrf-a\naddress-family l2vpn evpn\n"
        "no route-target export %s" % new_rt
    )
    _clear_ip_ead(tor1)


def test_bpp_ip_ead_tx_rmac_change():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    _set_bpp(tor1, True)
    _expect_ip_ead(tor1, "before RMAC change", evi_vrfs=("vrf-a", "vrf-b"))

    evi = [r for r in _ead_evi(tor1) if r.get("vni") == 4001]
    assert evi, "no vrf-a per-EVI"
    old_ext = evi[0]["extcomm"]
    new_mac = "44:38:39:00:00:99"
    old_mac = tor1.run("cat /sys/class/net/vlan4001/address").strip()
    tor1.run("ip link set vlan4001 address %s" % new_mac)

    def _check():
        cur = [r for r in _ead_evi(tor1) if r.get("vni") == 4001]
        if not cur:
            return "no vrf-a per-EVI"
        ext = cur[0]["extcomm"] or ""
        if "Rmac:%s" % new_mac not in ext:
            return "RMAC not updated (%s -> %s): %s" % (old_ext, new_mac, ext)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "RMAC change: %s" % result

    tor1.run("ip link set vlan4001 address %s" % old_mac)
    _clear_ip_ead(tor1)


def _evpn_nbrs(router):
    t = TORS.index(router.name) + 1
    return ["192.168.%d%d.1" % (s, t) for s in (1, 2)]


def _es_vrf_vteps(router, esi, vrf):
    entry = _es_vrfs(router, esi).get(vrf, {})
    return {v.get("vtep"): v for v in entry.get("vteps") or []}, entry


def _expect_ip_ead_rx(router, esi, vrf, vtep_ips, msg, evi=True, es=True):
    want = sorted(vtep_ips)

    def _check():
        vteps, _ = _es_vrf_vteps(router, esi, vrf)
        got = sorted(
            ip
            for ip, rec in vteps.items()
            if rec.get("ip_ead_per_evi") or rec.get("ip_ead_per_es")
        )
        if sorted(vteps) != want and got != want:
            return "vteps %s, want %s" % (sorted(vteps), want)
        for ip in want:
            rec = vteps.get(ip)
            if rec is None:
                return "missing %s" % ip
            if bool(rec.get("ip_ead_per_evi")) != evi:
                return "%s ip_ead_per_evi=%s want %s (%s)" % (
                    ip,
                    rec.get("ip_ead_per_evi"),
                    evi,
                    rec,
                )
            if bool(rec.get("ip_ead_per_es")) != es:
                return "%s ip_ead_per_es=%s want %s (%s)" % (
                    ip,
                    rec.get("ip_ead_per_es"),
                    es,
                    rec,
                )
            if evi and not rec.get("rmac"):
                return "%s missing rmac: %s" % (ip, rec)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def _expect_no_ip_ead_rx(router, esi, msg, vrfs=None):
    vrfs = vrfs or list(VRFS)

    def _check():
        for vrf in vrfs:
            vteps, _ = _es_vrf_vteps(router, esi, vrf)
            if vteps:
                return "%s %s vteps %s" % (esi, vrf, vteps)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def _set_vrf_auto_rt(router, vrf, enable):
    asn = 65000 + TORS.index(router.name) + 1
    if enable:
        cmd = "no auto-route-target both add-never"
    else:
        cmd = "auto-route-target both add-never"
    router.vtysh_cmd(
        "configure terminal\nrouter bgp %d vrf %s\naddress-family l2vpn evpn\n%s"
        % (asn, vrf, cmd)
    )


def test_bpp_ip_ead_rx_classify():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    peers = (tor_lo("tor2"), tor_vtep("tor3"))

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    for vrf in VRFS:
        _expect_ip_ead_rx(tor1, ES1_ID, vrf, peers, "tor2/tor3 classified in %s" % vrf)

    for vrf in VRFS:
        _set_vrf_auto_rt(tor2, vrf, False)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (tor_vtep("tor3"),), "tor2 RTs removed")
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-b", (tor_vtep("tor3"),), "tor2 RTs removed")

    for vrf in VRFS:
        _set_vrf_auto_rt(tor2, vrf, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", peers, "tor2 RTs restored")

    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "remotes withdrawn")


def test_bpp_ip_ead_rx_attr_update_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo = tor_lo("tor2")
    nbrs = _evpn_nbrs(tor2)
    asn = 65002

    _set_bpp_if(tor2, ES_IF, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (lo,), "before attribute update")

    rmap = (
        "route-map EAD-ASPATH permit 10\n"
        " match evpn route-type ead\n"
        " set as-path prepend 65002 65002\n"
        "route-map EAD-ASPATH permit 20\n"
    )
    nbr_cfg = "".join(
        "router bgp %d\naddress-family l2vpn evpn\n"
        "neighbor %s route-map EAD-ASPATH out\n" % (asn, nbr)
        for nbr in nbrs
    )
    tor2.vtysh_cmd("configure terminal\n%s%s" % (rmap, nbr_cfg))

    def _updated():
        output = json.loads(
            tor1.vtysh_cmd("show bgp l2vpn evpn route type 1 json") or "{}"
        )

        def _walk(obj):
            if isinstance(obj, dict):
                for path in _path_dicts(obj.get("paths")):
                    if (
                        _path_nexthop(path) == lo
                        and json.dumps(path).count("65002") >= 3
                    ):
                        return True
                return any(_walk(value) for value in obj.values())
            if isinstance(obj, list):
                return any(_walk(value) for value in obj)
            return False

        return None if _walk(output) else "updated path not received"

    _, result = topotest.run_and_expect(_updated, None, count=30, wait=1)
    assert result is None, result

    _clear_ip_ead(tor2)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "attribute-updated path withdrawn")

    nbr_del = "".join(
        "router bgp %d\naddress-family l2vpn evpn\n"
        "no neighbor %s route-map EAD-ASPATH out\n" % (asn, nbr)
        for nbr in nbrs
    )
    tor2.vtysh_cmd("configure terminal\n%sno route-map EAD-ASPATH\n" % nbr_del)


def test_bpp_ip_ead_rx_mac_scope_only():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_bpp_if(tor2, ES_IF, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (tor_lo("tor2"),), "ES-1 IP A-D")
    _expect_no_ip_ead_rx(tor1, ES2_ID, "ES-2 has no IP A-D")
    _clear_ip_ead(tor2)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "cleaned")


def test_bpp_ip_ead_rx_label_mismatch():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo = tor_lo("tor2")

    _add_vrf_c(tor1)
    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001 vrf %s\naddress-family l2vpn evpn\n"
        "route-target import 65002:4001" % VRF_C
    )
    _set_bpp(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (lo,), "vrf-a still matches")

    def _check():
        vteps, entry = _es_vrf_vteps(tor1, ES1_ID, VRF_C)
        rec = vteps.get(lo, {})
        if rec.get("ip_ead_per_evi"):
            return "per-EVI set on %s: %s" % (VRF_C, rec)
        if not rec.get("ip_ead_per_es"):
            return "per-ES not set on %s: %s" % (VRF_C, rec)
        if not entry.get("dropLabelMismatch"):
            return "dropLabelMismatch not incremented: %s" % entry
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "label mismatch: %s" % result

    _clear_ip_ead(tor2)
    _set_bpp(tor1, False)
    tor1.vtysh_cmd(
        "configure terminal\nrouter bgp 65001 vrf %s\naddress-family l2vpn evpn\n"
        "no route-target import 65002:4001" % VRF_C
    )
    _del_vrf_c(tor1)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "cleaned")


def test_bpp_ip_ead_rx_no_rmac_ec():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo = tor_lo("tor2")
    asn = 65002

    _set_bpp(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (lo,), "with rmac")

    nbrs = _evpn_nbrs(tor2)
    rmap = (
        "bgp extcommunity-list expanded STRIP-RMAC permit Rmac:.*\n"
        "route-map NO-RMAC permit 10\n"
        " match evpn route-type ead\n"
        " set extended-comm-list STRIP-RMAC delete\n"
        "route-map NO-RMAC permit 20\n"
    )
    nbr_cfg = "".join(
        "router bgp %d\naddress-family l2vpn evpn\nneighbor %s route-map NO-RMAC out\n"
        % (asn, n)
        for n in nbrs
    )
    tor2.vtysh_cmd("configure terminal\n%s%s" % (rmap, nbr_cfg))

    def _check():
        vteps, entry = _es_vrf_vteps(tor1, ES1_ID, "vrf-a")
        rec = vteps.get(lo, {})
        if rec.get("ip_ead_per_evi"):
            return "per-EVI still set: %s" % rec
        if not rec.get("ip_ead_per_es"):
            return "per-ES cleared: %s" % rec
        if not entry.get("dropNoRmac"):
            return "dropNoRmac not incremented: %s" % entry
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "no rmac: %s" % result

    nbr_del = "".join(
        "router bgp %d\naddress-family l2vpn evpn\nno neighbor %s route-map NO-RMAC out\n"
        % (asn, n)
        for n in nbrs
    )
    tor2.vtysh_cmd(
        "configure terminal\n%sno route-map NO-RMAC\nno bgp extcommunity-list expanded STRIP-RMAC\n"
        % nbr_del
    )
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (lo,), "rmac restored")
    _clear_ip_ead(tor2)
    _set_bpp(tor1, False)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "cleaned")


def test_bpp_ip_ead_rx_knob_off():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_bpp_if(tor2, ES_IF, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (tor_lo("tor2"),), "before knob off")

    _set_l3vni_neigh(tor1, False)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "l3vni-neigh off")

    _set_l3vni_neigh(tor1, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (tor_lo("tor2"),), "l3vni-neigh restored")
    _clear_ip_ead(tor2)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "cleaned")


def test_bpp_ip_ead_rx_protection_off():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    peers = (tor_lo("tor2"), tor_vtep("tor3"))

    _set_bpp(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", peers, "with protection")

    _set_bpp(tor1, False)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", peers, "protection off, RX kept")
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-b", peers, "protection off, RX kept")

    _set_bpp(tor1, True)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", peers, "protection back, no reprocess")
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "cleaned")


def test_bpp_ip_ead_rx_remote_only_es():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    tor1.vtysh_cmd("configure terminal\ninterface hostbond2\nno evpn mh es-id")
    _set_bpp_if(tor2, "hostbond2", True)
    _expect_ip_ead_rx(tor1, ES2_ID, "vrf-a", (tor_lo("tor2"),), "remote-only ES-2")
    _expect_ip_ead_rx(tor1, ES2_ID, "vrf-b", (tor_lo("tor2"),), "remote-only ES-2")

    _set_bpp_if(tor2, "hostbond2", False)
    tor1.vtysh_cmd("configure terminal\ninterface hostbond2\nevpn mh es-id 2")
    _expect_no_ip_ead_rx(tor1, ES2_ID, "cleaned")


def test_bpp_neigh_sync_coexist():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    host = tgen.gears["hostd1"]
    vid = ES_VLANS[0]
    gw = ACCESS_VLANS[vid][1].split("/")[0]
    ip = "%s.%d" % (gw.rsplit(".", 1)[0], HOST_ID["hostd1"])

    _set_bpp(tor1, True)
    host.run("ping -c 3 -W 1 %s" % gw)

    def _check():
        synced = []
        for name in TORS:
            for line in (
                tgen.gears[name].run("ip neigh show dev vlan%d" % vid).splitlines()
            ):
                if line.split()[:1] == [ip] and "extern_learn" in line:
                    synced.append(name)
        if synced:
            return None
        return "no tor synced %s" % ip

    _, result = topotest.run_and_expect(_check, None, count=40, wait=1)
    assert result is None, result

    _set_bpp(tor1, False)


def _set_prot_debug(router, enable):
    pfx = "" if enable else "no "
    router.vtysh_cmd(
        "configure terminal\n%sdebug zebra evpn mh protection\n"
        "%sdebug bgp evpn mh protection" % (pfx, pfx)
    )


def _log_text(tgen, router, daemon):
    with open(os.path.join(tgen.logdir, router.name, daemon + ".log")) as f:
        return f.read()


def _bpp_peer_lines(text, esi=None, action=None):
    lines = []
    for line in text.splitlines():
        if "bpp peer " not in line:
            continue
        if esi and esi not in line:
            continue
        if action and "bpp peer %s " % action not in line:
            continue
        lines.append(line)
    return lines


def _expect_bpp_peer(tgen, router, esi, vtep_ip, action, msg, rmac=None, after=""):
    def _check():
        text = _log_text(tgen, router, "zebra")
        if after and text.startswith(after):
            text = text[len(after) :]
        hit = [ln for ln in _bpp_peer_lines(text, esi, action) if vtep_ip in ln]
        if not hit:
            return "no %s for %s %s" % (action, vtep_ip, _bpp_peer_lines(text, esi))
        if rmac and action == "add" and not any("rmac %s" % rmac in ln for ln in hit):
            return "rmac %s not in %s" % (rmac, hit)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def _expect_no_new_bpp_peer(tgen, router, after, msg, esi=None, delay=5):
    time.sleep(delay)
    text = _log_text(tgen, router, "zebra")
    new = text[len(after) :] if after and text.startswith(after) else text
    lines = _bpp_peer_lines(new, esi)
    assert not lines, "%s: unexpected %s" % (msg, lines)


def _expect_eligible(router, esi, vtep_ips, msg, eligible=True, missing=None):
    want = list(vtep_ips) if isinstance(vtep_ips, (list, tuple)) else [vtep_ips]

    def _check():
        found = {}
        for vrf in VRFS:
            vteps, _ = _es_vrf_vteps(router, esi, vrf)
            found.update(vteps)
        for ip in want:
            rec = found.get(ip)
            if eligible:
                if rec is None:
                    return "missing %s" % ip
                if not rec.get("eligible"):
                    return "%s not eligible: %s" % (ip, rec)
                if not rec.get("active"):
                    return "%s not active in a ready vrf: %s" % (ip, rec)
            elif rec and rec.get("eligible"):
                return "%s still eligible: %s" % (ip, rec)
            if missing is not None and rec is not None:
                got = sorted(rec.get("missingVrfs") or [])
                if got != sorted(missing):
                    return "%s missingVrfs %s want %s" % (ip, got, missing)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "%s: %s" % (msg, result)


def _set_rt4_filter(router, enable):
    asn = 65000 + TORS.index(router.name) + 1
    nbrs = _evpn_nbrs(router)
    if enable:
        rmap = (
            "route-map DENY-ESR deny 10\n"
            " match evpn route-type es\n"
            "route-map DENY-ESR permit 20\n"
        )
        nbr = "".join(
            "router bgp %d\naddress-family l2vpn evpn\nneighbor %s route-map DENY-ESR out\n"
            % (asn, n)
            for n in nbrs
        )
        router.vtysh_cmd("configure terminal\n%s%s" % (rmap, nbr))
    else:
        nbr = "".join(
            "router bgp %d\naddress-family l2vpn evpn\nno neighbor %s route-map DENY-ESR out\n"
            % (asn, n)
            for n in nbrs
        )
        router.vtysh_cmd("configure terminal\n%sno route-map DENY-ESR\n" % nbr)


def _if_mac(router, ifname):
    return router.run("cat /sys/class/net/%s/address" % ifname).strip()


def _add_vrf_c_vlan(router, vid=40):
    asn = 65000 + TORS.index(router.name) + 1
    _add_vrf_c(router)
    router.vtysh_cmd(
        "configure terminal\nrouter bgp %d vrf %s\nbgp router-id %s\n"
        "address-family ipv4 unicast\nredistribute connected\n"
        "address-family l2vpn evpn\nadvertise ipv4 unicast\n"
        % (asn, VRF_C, tor_lo(router.name))
    )
    router.run("/sbin/bridge vlan add vid %d dev br_default self" % vid)
    router.run("ip link add link br_default name vlan%d type vlan id %d" % (vid, vid))
    router.run("ip link set dev vlan%d master %s" % (vid, VRF_C))
    router.run("ip link set dev vlan%d up" % vid)
    router.run("/sbin/bridge vlan add vid %d dev %s" % (vid, ES_IF))


def _del_vrf_c_vlan(router, vid=40):
    asn = 65000 + TORS.index(router.name) + 1
    router.run("/sbin/bridge vlan del vid %d dev %s" % (vid, ES_IF))
    router.run("ip link del dev vlan%d" % vid)
    router.vtysh_cmd("configure terminal\nno router bgp %d vrf %s\n" % (asn, VRF_C))
    _del_vrf_c(router)


def test_bpp_zapi():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "tor2 eligible")
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo2, "add", "ADD logged")

    before = json.loads(tor1.vtysh_cmd("show bgp l2vpn evpn es json"))
    assert any(
        e.get("esi") == ES1_ID
        for e in (before if isinstance(before, list) else before.get("es", []))
    )

    _set_bpp(tor1, False)
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo2, "del", "DEL logged")
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_l2_untouched():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    before_es = tor1.vtysh_cmd("show evpn es %s json" % ES2_ID)
    before_nh = tor1.run("ip -j nexthop show")
    _set_prot_debug(tor1, True)
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (tor_lo("tor2"),), "ES-1 eligible")
    _expect_no_new_bpp_peer(tgen, tor1, snap, "no ES-2 BPP_PEER", esi=ES2_ID, delay=3)
    after_es = tor1.vtysh_cmd("show evpn es %s json" % ES2_ID)
    after_nh = tor1.run("ip -j nexthop show")
    assert json.loads(before_es) == json.loads(after_es), "ES-2 changed"
    assert json.loads(before_nh) == json.loads(after_nh), "nexthop table changed"
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_eligibility():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    peers = (tor_lo("tor2"), tor_vtep("tor3"))

    _set_prot_debug(tor1, True)
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, peers, "tor2 and tor3 eligible")
    for lo in peers:
        _expect_bpp_peer(tgen, tor1, ES1_ID, lo, "add", "one ADD", after=snap)
    text = _log_text(tgen, tor1, "zebra")
    new = text[len(snap) :] if text.startswith(snap) else text
    for lo in peers:
        adds = [ln for ln in _bpp_peer_lines(new, ES1_ID, "add") if lo in ln]
        assert len(adds) == 1, "want 1 ADD for %s, got %s" % (lo, adds)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)
    _set_prot_debug(tor1, False)


def test_bpp_eligibility_all_vrfs():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo3 = tor_vtep("tor3")

    _set_vrf_auto_rt(tor3, "vrf-b", False)
    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (tor_lo("tor2"),), "tor2 eligible")
    _expect_eligible(
        tor1, ES1_ID, (lo3,), "tor3 missing vrf-b", eligible=False, missing=["vrf-b"]
    )
    snap = _log_text(tgen, tor1, "zebra")
    _set_vrf_auto_rt(tor3, "vrf-b", True)
    _expect_eligible(tor1, ES1_ID, (lo3,), "tor3 eligible after vrf-b")
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo3, "add", "tor3 ADD", after=snap)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)
    _set_prot_debug(tor1, False)


def test_bpp_new_local_vrf():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "before vrf-c")
    snap = _log_text(tgen, tor1, "zebra")
    _add_vrf_c_vlan(tor1)
    _expect_eligible(
        tor1, ES1_ID, (lo2,), "vrf-c ready, peer missing it", eligible=False
    )
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo2, "del", "DEL without vrf-c", after=snap)
    snap = _log_text(tgen, tor1, "zebra")
    _add_vrf_c_vlan(tor2)
    _expect_eligible(tor1, ES1_ID, (lo2,), "vrf-c on peer")
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo2, "add", "ADD after vrf-c", after=snap)
    _set_bpp(tor1, False)
    _del_vrf_c_vlan(tor1)
    _del_vrf_c_vlan(tor2)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_single_resolver():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "eligible")
    snap_z = _log_text(tgen, tor1, "zebra")
    snap_b = _log_text(tgen, tor1, "bgpd")
    _set_bpp_if(tor2, ES_IF, False)
    _expect_eligible(tor1, ES1_ID, (lo2,), "withdrawn", eligible=False)
    _set_bpp_if(tor2, ES_IF, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "restored")
    znew = _log_text(tgen, tor1, "zebra")[len(snap_z) :]
    bnew = _log_text(tgen, tor1, "bgpd")[len(snap_b) :]
    z_send = _bpp_peer_lines(znew, ES1_ID)
    b_send = [ln for ln in bnew.splitlines() if "bpp-peer " in ln and lo2 in ln]
    assert z_send, "zebra saw no BPP_PEER on churn"
    assert b_send, "resolver logged no BPP_PEER on churn"
    assert len(z_send) == len(b_send), "zebra %s vs resolver %s" % (z_send, b_send)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_rmac_common_multi_vrf():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")
    mac = "44:38:39:00:11:22"
    old1, old2 = _if_mac(tor2, "vlan4001"), _if_mac(tor2, "vlan4002")
    tor2.run("ip link set vlan4001 address %s" % mac)
    tor2.run("ip link set vlan4002 address %s" % mac)

    _set_prot_debug(tor1, True)
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "same rmac")
    _expect_bpp_peer(
        tgen, tor1, ES1_ID, lo2, "add", "one ADD with common rmac", rmac=mac, after=snap
    )
    tor2.run("ip link set vlan4001 address %s" % old1)
    tor2.run("ip link set vlan4002 address %s" % old2)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_rmac_latest():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")
    mac_a, mac_b = "44:38:39:00:11:01", "44:38:39:00:11:02"
    old1, old2 = _if_mac(tor2, "vlan4001"), _if_mac(tor2, "vlan4002")
    tor2.run("ip link set vlan4001 address %s" % mac_a)
    tor2.run("ip link set vlan4002 address %s" % mac_a)

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "common rmac")
    snap = _log_text(tgen, tor1, "zebra")
    tor2.run("ip link set vlan4002 address %s" % mac_b)
    _expect_bpp_peer(
        tgen, tor1, ES1_ID, lo2, "add", "latest rmac", rmac=mac_b, after=snap
    )
    text = _log_text(tgen, tor1, "zebra")[len(snap) :]
    assert not _bpp_peer_lines(text, ES1_ID, "del"), text
    tor2.run("ip link set vlan4001 address %s" % old1)
    tor2.run("ip link set vlan4002 address %s" % old2)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_rmac_change():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")
    new_mac = "44:38:39:00:00:99"
    old1, old2 = _if_mac(tor2, "vlan4001"), _if_mac(tor2, "vlan4002")

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "before rmac change")
    snap = _log_text(tgen, tor1, "zebra")
    tor2.run("ip link set vlan4001 address %s" % new_mac)
    _expect_bpp_peer(
        tgen, tor1, ES1_ID, lo2, "add", "first rmac update", rmac=new_mac, after=snap
    )
    snap2 = _log_text(tgen, tor1, "zebra")
    tor2.run("ip link set vlan4002 address %s" % new_mac)
    _expect_no_new_bpp_peer(tgen, tor1, snap2, "second vrf same rmac", delay=5)
    tor2.run("ip link set vlan4001 address %s" % old1)
    tor2.run("ip link set vlan4002 address %s" % old2)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_eligibility_order():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")
    asn = 65002
    nbrs = _evpn_nbrs(tor2)
    rmap = (
        "bgp extcommunity-list expanded STRIP-RMAC permit Rmac:.*\n"
        "route-map NO-RMAC permit 10\n"
        " match evpn route-type ead\n"
        " set extended-comm-list STRIP-RMAC delete\n"
        "route-map NO-RMAC permit 20\n"
    )
    nbr_cfg = "".join(
        "router bgp %d\naddress-family l2vpn evpn\nneighbor %s route-map NO-RMAC out\n"
        % (asn, n)
        for n in nbrs
    )

    _set_prot_debug(tor1, True)
    tor2.vtysh_cmd("configure terminal\n%s%s" % (rmap, nbr_cfg))
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "per-ES only", eligible=False)
    snap = _log_text(tgen, tor1, "zebra")
    tor2.vtysh_cmd(
        "configure terminal\n"
        + "".join(
            "router bgp %d\naddress-family l2vpn evpn\nno neighbor %s route-map NO-RMAC out\n"
            % (asn, n)
            for n in nbrs
        )
        + "no route-map NO-RMAC\n"
    )
    _expect_eligible(tor1, ES1_ID, (lo2,), "both routes")
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo2, "add", "ADD once both exist", after=snap)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_rt4_initial_admission():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_rt4_filter(tor2, True)
    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "eligible without rt4")
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo2, "add", "ADD without rt4")
    _expect_bgpd_log(tgen, tor1, "eligible without type-4")
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_rt4_filter(tor2, False)
    _set_prot_debug(tor1, False)


def test_bpp_rt4_late_arrival():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_rt4_filter(tor2, True)
    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "eligible")
    snap = _log_text(tgen, tor1, "zebra")
    _set_rt4_filter(tor2, False)
    _expect_no_new_bpp_peer(tgen, tor1, snap, "rt4 late arrival", esi=ES1_ID)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_rt4_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "with rt4")
    snap = _log_text(tgen, tor1, "zebra")
    _set_rt4_filter(tor2, True)
    _expect_no_new_bpp_peer(tgen, tor1, snap, "rt4 withdraw", esi=ES1_ID)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_rt4_filter(tor2, False)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "tor2 IP A-D gone")
    _set_prot_debug(tor1, False)


def test_bpp_rt4_only():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _clear_ip_ead(tor2)
    _expect_no_ip_ead_rx(tor1, ES1_ID, "no leftover IP A-D")
    _set_prot_debug(tor1, True)
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "rt4 only", eligible=False)
    _expect_no_new_bpp_peer(
        tgen, tor1, snap, "no ADD for rt4-only", esi=ES1_ID, delay=5
    )
    _expect_bgpd_log(tgen, tor1, "type-4 without ip-ead coverage")
    _set_bpp(tor1, False)
    _set_prot_debug(tor1, False)


def test_bpp_host_route_no_effect():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    host = tgen.gears["hostd1"]
    lo2 = tor_lo("tor2")
    gw = ACCESS_VLANS[ES_VLANS[0]][1].split("/")[0]

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "before ping")
    snap = _log_text(tgen, tor1, "zebra")
    host.run("ping -c 3 -W 1 %s" % gw)
    _expect_no_new_bpp_peer(tgen, tor1, snap, "host route no zapi", esi=ES1_ID)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_other_esi():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo4 = tor_lo("tor4")

    _set_prot_debug(tor1, True)
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (tor_lo("tor2"),), "tor2 eligible")
    _expect_eligible(tor1, ES1_ID, (lo4,), "tor4 never eligible", eligible=False)
    text = _log_text(tgen, tor1, "zebra")[len(snap) :]
    assert not [ln for ln in _bpp_peer_lines(text, ES1_ID) if lo4 in ln], text
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_non_l3mh_es():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_prot_debug(tor1, True)
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (tor_lo("tor2"),), "ES-1")
    _expect_no_new_bpp_peer(
        tgen, tor1, snap, "no BPP_PEER for ES-2", esi=ES2_ID, delay=3
    )
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_ineligible_rx():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")
    asn = 65002
    nbrs = _evpn_nbrs(tor2)
    rmap = (
        "bgp extcommunity-list expanded STRIP-RMAC permit Rmac:.*\n"
        "route-map NO-RMAC permit 10\n"
        " match evpn route-type ead\n"
        " set extended-comm-list STRIP-RMAC delete\n"
        "route-map NO-RMAC permit 20\n"
    )
    nbr_cfg = "".join(
        "router bgp %d\naddress-family l2vpn evpn\nneighbor %s route-map NO-RMAC out\n"
        % (asn, n)
        for n in nbrs
    )

    _set_prot_debug(tor1, True)
    tor2.vtysh_cmd("configure terminal\n%s%s" % (rmap, nbr_cfg))
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "no rmac, not eligible", eligible=False)
    _expect_no_new_bpp_peer(tgen, tor1, snap, "no ADD without rmac", esi=ES1_ID)
    tor2.vtysh_cmd(
        "configure terminal\n"
        + "".join(
            "router bgp %d\naddress-family l2vpn evpn\nno neighbor %s route-map NO-RMAC out\n"
            % (asn, n)
            for n in nbrs
        )
        + "no route-map NO-RMAC\n"
    )
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_knob_off_del():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "before knob off")
    snap = _log_text(tgen, tor1, "zebra")
    _set_l3vni_neigh(tor1, False)
    _expect_bpp_peer(
        tgen, tor1, ES1_ID, lo2, "del", "DEL on l3vni-neigh off", after=snap
    )
    snap = _log_text(tgen, tor1, "zebra")
    _set_l3vni_neigh(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "knob restored")
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo2, "add", "ADD on restore", after=snap)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_protection_off_del():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "protected")
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp(tor1, False)
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (lo2,), "rx kept")
    _expect_bpp_peer(
        tgen, tor1, ES1_ID, lo2, "del", "DEL on protection off", after=snap
    )
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "protection back")
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo2, "add", "ADD on re-enable", after=snap)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_remote_only_es_no_send():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_prot_debug(tor1, True)
    tor1.vtysh_cmd("configure terminal\ninterface hostbond2\nno evpn mh es-id")
    snap = _log_text(tgen, tor1, "zebra")
    _set_bpp_if(tor2, "hostbond2", True)
    _expect_ip_ead_rx(tor1, ES2_ID, "vrf-a", (tor_lo("tor2"),), "remote-only rx")
    _expect_no_new_bpp_peer(tgen, tor1, snap, "no BPP_PEER for remote-only", esi=ES2_ID)
    _set_bpp_if(tor2, "hostbond2", False)
    tor1.vtysh_cmd("configure terminal\ninterface hostbond2\nevpn mh es-id 2")
    _set_prot_debug(tor1, False)


def test_bpp_vrf_leaves_ready_set():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo3 = tor_vtep("tor3")

    _set_vrf_auto_rt(tor3, "vrf-b", False)
    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(
        tor1, ES1_ID, (lo3,), "missing vrf-b", eligible=False, missing=["vrf-b"]
    )
    snap = _log_text(tgen, tor1, "zebra")
    tor1.run("/sbin/bridge vlan del vid 20 dev %s" % ES_IF)
    _expect_eligible(tor1, ES1_ID, (lo3,), "vrf-b left ready set")
    _expect_bpp_peer(tgen, tor1, ES1_ID, lo3, "add", "ADD after vrf-b left", after=snap)
    tor1.run("/sbin/bridge vlan add vid 20 dev %s" % ES_IF)
    _set_vrf_auto_rt(tor3, "vrf-b", True)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)
    _set_prot_debug(tor1, False)


def _expect_members(router, esi, vteps, msg, bound=True, state=None):
    if state is None:
        state = "ACTIVE" if bound else "PENDING"
    expected = {
        esi: {
            "interface": ES_IF,
            "state": state,
            "bound": bound,
            "members": _members(*vteps) if vteps else ["__ordered__"],
        }
    }
    _expect_json(
        router, "show evpn mh bridge-port-protection member json", expected, msg
    )


def test_bpp_fanout():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_prot_debug(tor1, True)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "tor2 eligible")
    _expect_entries(
        tor1,
        {ES_IF: {"esi": ES1_ID, "bound": True, "vlans": _active_vlans(ES_VLANS)}},
        "VRF-A and VRF-B ACTIVE",
    )
    _expect_members(tor1, ES1_ID, (lo2,), "one Group, bond bound")

    snap = _log_text(tgen, tor1, "zebra")
    tor1.run("/sbin/bridge vlan add vid 30 dev %s" % ES_IF)
    _expect_entries(
        tor1,
        {ES_IF: {"vlans": _active_vlans(ES_VLANS + (30,))}},
        "new VRF-A VLAN ACTIVE",
    )
    _expect_no_new_bpp_peer(
        tgen, tor1, snap, "no bgpd message for extra VLAN", esi=ES1_ID
    )

    tor1.run("/sbin/bridge vlan del vid 30 dev %s" % ES_IF)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _set_prot_debug(tor1, False)


def test_bpp_pending_vlan():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_entries(
        tor1,
        {ES_IF: {"bound": True, "vlans": _active_vlans(ES_VLANS)}},
        "both VLANs ACTIVE",
    )

    tor1.run("ip link set dev vlan20 nomaster")
    _expect_entries(
        tor1,
        {
            ES_IF: {
                "bound": True,
                "vlans": {
                    "10": _active_vlans((10,))["10"],
                    "20": _pending(["IP-VRF has no L3VNI"], vrf="default", l3vni=None),
                },
            }
        },
        "VRF-B PENDING, VRF-A ACTIVE, bond bound",
    )
    _expect_members(tor1, ES1_ID, (tor_lo("tor2"),), "bond still bound")

    tor1.run("ip link set dev vlan20 master vrf-b")
    tor1.run("ip link set dev vlan20 up")
    _expect_entries(tor1, {ES_IF: {"vlans": _active_vlans(ES_VLANS)}}, "VRF-B restored")

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_show_member():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")
    macs2 = {_if_mac(tor2, "vlan4001"), _if_mac(tor2, "vlan4002")}
    macs3 = {_if_mac(tor3, "vlan4001"), _if_mac(tor3, "vlan4002")}

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2, lo3), "tor2 and tor3 in member view")

    output = json.loads(
        tor1.vtysh_cmd("show evpn mh bridge-port-protection member json")
    )
    members = {m["vtep"]: m for m in output[ES1_ID]["members"]}
    assert members[lo2]["rmac"] in macs2, members[lo2]
    assert members[lo3]["rmac"] in macs3, members[lo3]
    assert members[lo2]["family"] == "ipv4"
    assert members[lo3]["family"] == "ipv6"

    _set_vrf_auto_rt(tor3, "vrf-b", False)
    _expect_members(tor1, ES1_ID, (lo2,), "peer missing VRF-B absent")
    _set_vrf_auto_rt(tor3, "vrf-b", True)

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_group_all_vrfs():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")

    _set_vrf_auto_rt(tor3, "vrf-b", False)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "Group is tor2 only")

    _set_vrf_auto_rt(tor3, "vrf-b", True)
    _expect_members(tor1, ES1_ID, (lo2, lo3), "tor3 joins after VRF-B per-EVI")

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_vrf_no_per_evi():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]

    _set_vrf_auto_rt(tor2, "vrf-b", False)
    _set_vrf_auto_rt(tor3, "vrf-b", False)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_entries(
        tor1,
        {ES_IF: {"bound": False, "vlans": _ready_vlans(ES_VLANS)}},
        "Group empty, all PENDING",
    )
    _expect_members(tor1, ES1_ID, (), "no Members", bound=False)

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)
    _set_vrf_auto_rt(tor2, "vrf-b", True)
    _set_vrf_auto_rt(tor3, "vrf-b", True)


def test_bpp_unprotected_l3mh_es():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _expect_es_evi_l3vnis(tor1, None, "no L3VNI ES-EVI without protection")
    _expect_es_vrfs(tor1, ES1_ID, {}, "no ES-VRF without protection")
    _expect_ip_ead(
        tor1, "no IP A-D without protection", evi_absent=True, es_absent=True
    )
    _expect_json(
        tor1, "show evpn mh bridge-port-protection member json", {}, "no Group"
    )

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_es_evi_l3vnis(tor1, ["__ordered__", 4001, 4002], "L3VNI ES-EVIs sent")
    _expect_entries(
        tor1, {ES_IF: {"bound": True, "vlans": _active_vlans(ES_VLANS)}}, "ports ACTIVE"
    )

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_member_rmac():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")
    mac = "02:02:00:00:00:22"
    old1, old2 = _if_mac(tor2, "vlan4001"), _if_mac(tor2, "vlan4002")

    tor2.run("ip link set vlan4001 address %s" % mac)
    tor2.run("ip link set vlan4002 address %s" % mac)
    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member present")
    output = json.loads(
        tor1.vtysh_cmd("show evpn mh bridge-port-protection member json")
    )
    assert output[ES1_ID]["members"][0]["rmac"] == mac, output

    asn = 65002
    tor2.vtysh_cmd(
        "configure terminal\nrouter bgp %d vrf vrf-a\naddress-family l2vpn evpn\n"
        "no advertise ipv4 unicast" % asn
    )
    _expect_json(
        tor1,
        "show evpn mh bridge-port-protection member json",
        {ES1_ID: {"members": [{"vtep": lo2, "rmac": mac}]}},
        "RT-5 withdraw does not change Member RMAC",
    )
    tor2.vtysh_cmd(
        "configure terminal\nrouter bgp %d vrf vrf-a\naddress-family l2vpn evpn\n"
        "advertise ipv4 unicast" % asn
    )

    tor2.run("ip link set vlan4001 address %s" % old1)
    tor2.run("ip link set vlan4002 address %s" % old2)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_ipv6_vtep():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor3 = tgen.gears["tor3"]
    vtep = tor_vtep("tor3")

    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_json(
        tor1,
        "show evpn mh bridge-port-protection member json",
        {ES1_ID: {"members": [{"vtep": vtep, "family": "ipv6", "type": "L3"}]}},
        "tor3 IPv6 Member",
    )
    _expect_ip_ead_rx(tor1, ES1_ID, "vrf-a", (vtep,), "IPv6 IP A-D classified")
    _expect_eligible(tor1, ES1_ID, (vtep,), "IPv6 VTEP eligible")

    _set_bpp(tor1, False)
    _clear_ip_ead(tor3)


def test_bpp_dual_family_same_peer():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2, lo3), "IPv4 and IPv6 Members")
    _expect_json(
        tor1,
        "show evpn mh bridge-port-protection member json",
        {
            ES1_ID: {
                "members": [
                    {"vtep": lo2, "family": "ipv4"},
                    {"vtep": lo3, "family": "ipv6"},
                ]
            }
        },
        "both families present",
    )

    _clear_ip_ead(tor3)
    _expect_members(tor1, ES1_ID, (lo2,), "removing IPv6 keeps IPv4")

    _set_bpp_if(tor3, ES_IF, True)
    _clear_ip_ead(tor2)
    _expect_members(tor1, ES1_ID, (lo3,), "removing IPv4 keeps IPv6")

    _set_bpp(tor1, False)
    _clear_ip_ead(tor3)


NHG_TYPE_L2_NH = 1
NHG_TYPE_L2 = 2
NHG_TYPE_L3_BPP_NH = 4
NHG_TYPE_L3_BPP = 8


def _nhg_type(nhid):
    return (int(nhid) >> 28) & 0xF


def _member_view(router, esi=None):
    out = json.loads(
        router.vtysh_cmd("show evpn mh bridge-port-protection member json")
    )
    if esi is None:
        return out
    return out.get(esi, {})


def _bpp_ids(router, esi):
    es = _member_view(router, esi)
    ids = set()
    gid = es.get("groupId")
    if gid:
        ids.add(int(gid))
    for member in es.get("members", []):
        nhid = member.get("nhId")
        if nhid:
            ids.add(int(nhid))
    return ids


def _l2_nh_by_vtep(router):
    out = json.loads(router.vtysh_cmd("show evpn l2-nh json"))
    if isinstance(out, dict):
        out = out.get("nexthops", out.get("l2Nexthops", []))
    return {nh["vtep"]: int(nh["nhId"]) for nh in out or []}


def _es_nhg_id(router, esi):
    out = json.loads(router.vtysh_cmd("show evpn es %s json" % esi))
    if isinstance(out, list):
        out = out[0] if out else {}
    return int(out.get("nexthopGroup", 0))


def _kernel_nh_ids(router):
    raw = router.run("ip -j nexthop show")
    if not raw or not raw.strip():
        return set()
    return {int(nh["id"]) for nh in json.loads(raw) if "id" in nh}


def _id_errors(router, esi):
    return int(_member_view(router, esi).get("idChannelErrors", 0))


def test_bpp_id_disjoint():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member present")

    bpp = _bpp_ids(tor1, ES1_ID)
    kernel = _kernel_nh_ids(tor1)
    assert bpp, "no protection IDs"
    assert bpp.isdisjoint(kernel), "protection IDs overlap kernel: %s & %s" % (
        bpp,
        bpp & kernel,
    )
    es = _member_view(tor1, ES1_ID)
    assert _nhg_type(es["groupId"]) == NHG_TYPE_L3_BPP, es
    assert es["groupIdChannel"] == "fpm", es
    for member in es["members"]:
        assert _nhg_type(member["nhId"]) == NHG_TYPE_L3_BPP_NH, member
        assert member["nhIdChannel"] == "fpm", member
    assert _id_errors(tor1, ES1_ID) == 0

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_id_disjoint_same_vtep():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "L3 member")

    l3_id = _member_view(tor1, ES1_ID)["members"][0]["nhId"]
    l2_nhg = _es_nhg_id(tor1, ES1_ID)
    l2_id = _l2_nh_by_vtep(tor1).get(lo2)
    assert _nhg_type(l3_id) == NHG_TYPE_L3_BPP_NH, hex(l3_id)
    assert _nhg_type(l2_nhg) == NHG_TYPE_L2, hex(l2_nhg)
    assert l3_id != l2_nhg, "Member ID equals L2 NHG %s" % l3_id
    if l2_id is not None:
        assert l3_id != l2_id, "L2 NH and L3 Member share id %s" % l3_id
        assert _nhg_type(l2_id) == NHG_TYPE_L2_NH, hex(l2_id)

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_member_shared():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor2, "hostbond2", True)
    _set_bpp_if(tor1, "hostbond2", True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "ES-1 member")
    _expect_json(
        tor1,
        "show evpn mh bridge-port-protection member json",
        {ES2_ID: {"interface": "hostbond2", "members": [{"vtep": lo2}]}},
        "ES-2 member",
    )

    id1 = _member_view(tor1, ES1_ID)["members"][0]["nhId"]
    id2 = _member_view(tor1, ES2_ID)["members"][0]["nhId"]
    assert id1 == id2, "Member IDs %s vs %s" % (id1, id2)

    _set_bpp_if(tor2, "hostbond2", False)
    _expect_members(tor1, ES1_ID, (lo2,), "ES-1 keeps Member")
    _expect_json(
        tor1,
        "show evpn mh bridge-port-protection member json",
        {ES2_ID: {"members": ["__ordered__"]}},
        "ES-2 Member gone",
    )
    assert _member_view(tor1, ES1_ID)["members"][0]["nhId"] == id1

    _set_bpp_if(tor2, ES_IF, False)
    _expect_members(tor1, ES1_ID, (), "Member deleted after last Group", bound=False)

    _set_bpp_if(tor1, "hostbond2", False)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_group_per_es_same_peers():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor2, "hostbond2", True)
    _set_bpp_if(tor1, "hostbond2", True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "ES-1")
    _expect_json(
        tor1,
        "show evpn mh bridge-port-protection member json",
        {ES2_ID: {"members": [{"vtep": lo2}]}},
        "ES-2",
    )

    es1 = _member_view(tor1, ES1_ID)
    es2 = _member_view(tor1, ES2_ID)
    assert es1["groupId"] != es2["groupId"], es1
    assert es1["members"][0]["nhId"] == es2["members"][0]["nhId"]
    gid1 = es1["groupId"]

    _set_bpp_if(tor2, "hostbond2", False)
    _expect_members(tor1, ES1_ID, (lo2,), "ES-1 unchanged")
    assert _member_view(tor1, ES1_ID)["groupId"] == gid1
    _expect_json(
        tor1,
        "show evpn mh bridge-port-protection member json",
        {ES2_ID: {"members": ["__ordered__"]}},
        "ES-2 emptied",
    )

    _set_bpp_if(tor1, "hostbond2", False)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_id_disjoint_churn():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2, lo3), "both Members")
    _clear_ip_ead(tor3)
    _expect_members(tor1, ES1_ID, (lo2,), "tor3 gone")
    _set_bpp_if(tor3, ES_IF, True)
    _expect_members(tor1, ES1_ID, (lo2, lo3), "tor3 back")

    bpp = _bpp_ids(tor1, ES1_ID)
    kernel = _kernel_nh_ids(tor1)
    assert bpp.isdisjoint(kernel), bpp & kernel
    assert _id_errors(tor1, ES1_ID) == 0

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_group_separate_from_l2_nhg():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member present")

    l2_nhg = _es_nhg_id(tor1, ES1_ID)
    es = _member_view(tor1, ES1_ID)
    assert es["groupId"] != l2_nhg, es
    assert _nhg_type(l2_nhg) == NHG_TYPE_L2, hex(l2_nhg)
    l2_nhs = set(_l2_nh_by_vtep(tor1).values())
    for member in es["members"]:
        assert member["nhId"] not in l2_nhs, member

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_ids_stable():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2 = tor_lo("tor2")
    mac = "02:02:00:00:00:22"
    old1, old2 = _if_mac(tor2, "vlan4001"), _if_mac(tor2, "vlan4002")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "initial")
    before = _member_view(tor1, ES1_ID)
    gid, nid = before["groupId"], before["members"][0]["nhId"]

    tor2.run("ip link set vlan4001 address %s" % mac)
    tor2.run("ip link set vlan4002 address %s" % mac)
    _expect_json(
        tor1,
        "show evpn mh bridge-port-protection member json",
        {ES1_ID: {"members": [{"vtep": lo2, "rmac": mac, "nhId": nid}]}},
        "RMAC change keeps Member ID",
    )
    assert _member_view(tor1, ES1_ID)["groupId"] == gid

    _set_bpp_if(tor3, ES_IF, True)
    _expect_members(tor1, ES1_ID, (lo2, tor_vtep("tor3")), "tor3 joins")
    after = _member_view(tor1, ES1_ID)
    assert after["groupId"] == gid
    assert any(m["nhId"] == nid and m["vtep"] == lo2 for m in after["members"])

    tor2.run("ip link set vlan4001 address %s" % old1)
    tor2.run("ip link set vlan4002 address %s" % old2)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_id_no_reuse():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member present")
    old = _member_view(tor1, ES1_ID)["members"][0]["nhId"]

    _set_bpp_if(tor2, ES_IF, False)
    _expect_members(tor1, ES1_ID, (), "Member deleted", bound=False)
    members = _member_view(tor1, ES1_ID).get("members", [])
    assert all(m.get("nhId") != old for m in members), members

    _set_bpp_if(tor2, ES_IF, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member back")
    ids = [m["nhId"] for m in _member_view(tor1, ES1_ID)["members"]]
    assert len(ids) == len(set(ids)), ids
    assert _id_errors(tor1, ES1_ID) == 0

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def _export(router):
    out = router.vtysh_cmd("show evpn mh bridge-port-protection export json")
    return json.loads(out) if out and out.strip() else {}


def _expect_export_clean(
    router, msg, members=None, groups=1, bindings=1, esi=None, released=False
):
    def _check():
        out = _export(router)
        errs = bpp_export_check(out)
        if errs:
            return errs
        tables = out.get("tables") or {}
        mem = tables.get("members") or {}
        grp = tables.get("groups") or {}
        bind = tables.get("bindings") or {}
        if members is not None and len(mem) != members:
            return "members %s want %s" % (list(mem), members)
        if groups is not None and len(grp) != groups:
            return "groups %s want %s" % (list(grp), groups)
        if bindings is not None and len(bind) != bindings:
            return "bindings %s want %s" % (list(bind), bindings)
        if esi:
            if not any(g.get("esi") == esi for g in grp.values()):
                return "no Group ESI %s in %s" % (esi, grp)
        log = out.get("log") or []
        pending = [e for e in log if not e.get("completed")]
        if pending:
            return "incomplete %s" % pending
        failed = [
            e
            for e in log
            if e.get("completed") and e.get("result") not in (None, "SUCCESS")
        ]
        if failed:
            return "failed %s" % failed
        if released:
            counters = out.get("counters") or {}
            live = counters.get("membersLive")
            pending_del = counters.get("pendingDeletes")
            if live:
                return "membersLive %s" % live
            if pending_del:
                return "pendingDeletes %s" % pending_del
        return None

    _, result = topotest.run_and_expect(_check, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, "%s: %s" % (msg, result)


def _export_marker(router):
    log = _export(router).get("log") or []
    return max((int(ent.get("seq") or 0) for ent in log), default=0)


def _export_events(router, after):
    return [
        (ent.get("op"), ent.get("action"))
        for ent in (_export(router).get("log") or [])
        if int(ent.get("seq") or 0) > after
        and ent.get("op")
        in ("EVPN_MH_NH_UPDATE", "EVPN_MH_NHG_UPDATE", "BR_PORT_UPDATE")
    ]


def _expect_export_events(router, after, expected, msg):
    def _check():
        events = _export_events(router, after)
        return None if events == expected else events

    _, result = topotest.run_and_expect(_check, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, "%s: %s" % (msg, result)


def _export_member(router, vtep):
    tables = _export(router).get("tables") or {}
    for member in (tables.get("members") or {}).values():
        if member.get("vtep") == vtep:
            return member
    return None


def _local_forwarding_state(router):
    return {
        "export": (_export(router).get("tables") or {}),
        "mac": json.loads(router.vtysh_cmd("show evpn mac vni all json") or "{}"),
        "arp": json.loads(router.vtysh_cmd("show evpn arp-cache vni all json") or "{}"),
        "routes": {
            vrf: json.loads(router.run("ip -j route show table %d" % table) or "[]")
            for vrf, (table, _) in VRFS.items()
        },
        "neighbors": json.loads(router.run("ip -j neigh show") or "[]"),
    }


def _replay_forwarding_state(router):
    state = _local_forwarding_state(router)
    state["es"] = json.loads(router.vtysh_cmd("show evpn es %s json" % ES1_ID) or "{}")
    state["fdb"] = json.loads(router.run("bridge -j fdb show br br_default") or "[]")
    return state


def _dplane_primary_counters(router):
    output = router.vtysh_cmd("show zebra dplane detailed")
    labels = ("Route updates", "EVPN MAC updates", "EVPN neigh updates")
    counters = {}
    for line in output.splitlines():
        for label in labels:
            if line.startswith(label + ":"):
                counters[label] = int(line.rsplit(None, 1)[-1])
    assert set(counters) == set(labels), output
    return counters


def _replay_events(router, after):
    return [
        ent
        for ent in (_export(router).get("log") or [])
        if int(ent.get("seq") or 0) > after
    ]


def _expect_replay(router, after, tables, msg):
    members = tables.get("members") or {}
    groups = tables.get("groups") or {}
    bindings = tables.get("bindings") or {}
    expected_ops = (
        ["EVPN_MH_NH_UPDATE"] * len(members)
        + ["EVPN_MH_NHG_UPDATE"] * len(groups)
        + ["BR_PORT_UPDATE"] * len(bindings)
        + ["EVPN_MH_REPLAY_DONE"]
    )

    def _check():
        events = _replay_events(router, after)
        if [ent.get("op") for ent in events] != expected_ops:
            return events
        if any(
            not ent.get("replay")
            or ent.get("action") != "add"
            or not ent.get("completed")
            or ent.get("result") != "SUCCESS"
            for ent in events
        ):
            return events
        member_end = len(members)
        group_end = member_end + len(groups)
        binding_end = group_end + len(bindings)
        if {ent.get("id") for ent in events[:member_end]} != {
            rec.get("nhId") for rec in members.values()
        }:
            return events
        if {ent.get("id") for ent in events[member_end:group_end]} != {
            rec.get("nhgId") for rec in groups.values()
        }:
            return events
        replay_groups = {
            ent.get("id"): sorted(ent.get("memberIds") or [])
            for ent in events[member_end:group_end]
        }
        table_groups = {
            rec.get("nhgId"): sorted(
                member.get("nhId") for member in rec.get("members", [])
            )
            for rec in groups.values()
        }
        if replay_groups != table_groups:
            return events
        if {ent.get("interface") for ent in events[group_end:binding_end]} != set(
            bindings
        ):
            return events
        if {
            ent.get("interface"): ent.get("id") for ent in events[group_end:binding_end]
        } != {ifname: rec.get("backupNhgId") for ifname, rec in bindings.items()}:
            return events
        return None

    _, result = topotest.run_and_expect(_check, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, "%s: %s" % (msg, result)
    return _replay_events(router, after)


SCALE_VRFS = (
    ("vrf-a", 1001, 4001),
    ("vrf-b", 1002, 4002),
    ("vrf-c", 1003, 4003),
    ("vrf-d", 1004, 4004),
)
SCALE_ES_COUNT = 8


def _scale_es_name(index):
    return "bpp%d" % index


def _scale_es_id(index):
    return "03:44:38:39:aa:00:%02x:00:00:%02x" % (index, index)


def _scale_es_mac(index):
    return "44:38:39:aa:00:%02x" % index


def _scale_vid(index, vrf_index):
    return 100 + ((index - 1) * len(SCALE_VRFS)) + vrf_index


def _scale_vrf_add(router, vrf, table, l3vni):
    asn = 65000 + TORS.index(router.name) + 1

    add_l3vni_dataplane(router, vrf, table, l3vni)
    router.vtysh_cmd(
        "configure terminal\nvrf %s\nvni %d\nexit-vrf\n"
        "router bgp %d vrf %s\nbgp router-id %s\n"
        "address-family ipv4 unicast\nredistribute connected\n"
        "address-family l2vpn evpn\nadvertise ipv4 unicast"
        % (vrf, l3vni, asn, vrf, tor_lo(router.name))
    )


def _scale_vrf_del(router, vrf, l3vni):
    asn = 65000 + TORS.index(router.name) + 1

    router.vtysh_cmd(
        "configure terminal\nno router bgp %d vrf %s\n"
        "vrf %s\nno vni %d\nexit-vrf\nno vrf %s" % (asn, vrf, vrf, l3vni, vrf)
    )
    router.run("ip link del dev vlan%d" % l3vni)
    router.run("ip link del dev vni%d" % l3vni)
    router.run("ip link del dev %s" % vrf)
    router.run("/sbin/bridge vlan del vid %d dev br_default self" % l3vni)


def _scale_dataplane_add(router):
    for vrf, table, l3vni in SCALE_VRFS[2:]:
        _scale_vrf_add(router, vrf, table, l3vni)

    for index in range(1, SCALE_ES_COUNT + 1):
        bond = _scale_es_name(index)
        peer = "%sp" % bond
        far = "%sq" % bond

        router.run("ip link add dev %s type bond mode active-backup" % bond)
        router.run("ip link set dev %s address %s" % (bond, _scale_es_mac(index)))
        router.run("ip link add dev %s type veth peer name %s" % (peer, far))
        router.run("ip link set dev %s master %s" % (peer, bond))
        router.run("ip link set dev %s up" % far)
        router.run("ip link set dev %s up" % peer)
        router.run("ip link set dev %s up" % bond)
        router.run("ip link set dev %s master br_default" % bond)
        router.run("/sbin/bridge vlan del vid 1 dev %s" % bond)

        for vrf_index, (vrf, _, _) in enumerate(SCALE_VRFS, 1):
            vid = _scale_vid(index, vrf_index)
            router.run("/sbin/bridge vlan add vid %d dev br_default self" % vid)
            router.run(
                "ip link add link br_default name vlan%d type vlan id %d" % (vid, vid)
            )
            router.run("ip link set dev vlan%d master %s" % (vid, vrf))
            router.run("ip link set dev vlan%d up" % vid)
            router.run("/sbin/bridge vlan add vid %d dev %s" % (vid, bond))

    config = ["configure terminal"]
    for index in range(1, SCALE_ES_COUNT + 1):
        config.extend(
            (
                "interface %s" % _scale_es_name(index),
                "evpn mh es-id %d" % index,
                "evpn mh es-sys-mac %s" % _scale_es_mac(index),
                "evpn mh bridge-port-protection",
            )
        )
    router.vtysh_cmd("\n".join(config))


def _scale_dataplane_del(router):
    config = ["configure terminal"]
    for index in range(1, SCALE_ES_COUNT + 1):
        config.extend(
            (
                "interface %s" % _scale_es_name(index),
                "no evpn mh bridge-port-protection",
                "no evpn mh es-id",
            )
        )
    router.vtysh_cmd("\n".join(config))

    for index in range(1, SCALE_ES_COUNT + 1):
        bond = _scale_es_name(index)
        for vrf_index in range(1, len(SCALE_VRFS) + 1):
            vid = _scale_vid(index, vrf_index)
            router.run("ip link del dev vlan%d" % vid)
            router.run("/sbin/bridge vlan del vid %d dev br_default self" % vid)
        router.run("ip link del dev %s" % bond)
        router.run("ip link del dev %sp" % bond)
        router.vtysh_cmd("configure terminal\nno interface %s" % bond)

    for vrf, _, l3vni in reversed(SCALE_VRFS[2:]):
        _scale_vrf_del(router, vrf, l3vni)


def _expect_scale_export(router, peers, msg):
    esis = {_scale_es_id(index) for index in range(1, SCALE_ES_COUNT + 1)}

    def _check():
        output = _export(router)
        errors = bpp_export_check(output)
        if errors:
            return errors
        tables = output.get("tables") or {}
        members = tables.get("members") or {}
        groups = tables.get("groups") or {}
        bindings = tables.get("bindings") or {}
        if len(members) != len(peers):
            return "member VTEPs %s want %s" % (
                {member.get("vtep") for member in members.values()},
                set(peers),
            )
        if len(groups) != SCALE_ES_COUNT:
            return "groups %d want %d" % (len(groups), SCALE_ES_COUNT)
        if len(bindings) != SCALE_ES_COUNT:
            return "bindings %d want %d" % (len(bindings), SCALE_ES_COUNT)
        if {group.get("esi") for group in groups.values()} != esis:
            return "Group ESIs %s want %s" % (
                {group.get("esi") for group in groups.values()},
                esis,
            )
        for group in groups.values():
            got = {member.get("vtep") for member in group.get("members", [])}
            if got != set(peers):
                return "Group %s peers %s want %s" % (
                    group.get("esi"),
                    got,
                    set(peers),
                )
        return None

    _, result = topotest.run_and_expect(_check, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, "%s: %s" % (msg, result)


def test_bpp_dplane_emit():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2, lo3), "members present")
    _expect_export_clean(
        tor1, "export tables", members=2, groups=1, bindings=1, esi=ES1_ID
    )

    out = _export(tor1)
    bind = (out.get("tables") or {}).get("bindings") or {}
    assert ES_IF in bind, bind
    assert bind[ES_IF].get("esi") == ES1_ID, bind
    kernel = _kernel_nh_ids(tor1)
    exp_ids = set()
    for rec in ((out.get("tables") or {}).get("members") or {}).values():
        exp_ids.add(int(rec["nhId"]))
    for rec in ((out.get("tables") or {}).get("groups") or {}).values():
        exp_ids.add(int(rec["nhgId"]))
    assert exp_ids.isdisjoint(kernel), exp_ids & kernel

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)
    _expect_export_clean(
        tor1, "cleanup", members=0, groups=0, bindings=0, released=True
    )


def test_bpp_peer_join_leave():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "initial peer", members=1)

    marker = _export_marker(tor1)
    _set_bpp_if(tor3, ES_IF, True)
    _expect_members(tor1, ES1_ID, (lo2, lo3), "peer joined")
    _expect_export_clean(tor1, "peer join export", members=2)
    _expect_export_events(
        tor1,
        marker,
        [("EVPN_MH_NH_UPDATE", "add"), ("EVPN_MH_NHG_UPDATE", "add"),],
        "Member then Group on peer join",
    )

    marker = _export_marker(tor1)
    _set_bpp_if(tor3, ES_IF, False)
    _expect_members(tor1, ES1_ID, (lo2,), "peer left")
    _expect_export_clean(tor1, "peer leave export", members=1)
    _expect_export_events(
        tor1,
        marker,
        [("EVPN_MH_NHG_UPDATE", "add"), ("EVPN_MH_NH_UPDATE", "del"),],
        "Group then Member on peer leave",
    )

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _expect_export_clean(
        tor1, "cleanup", members=0, groups=0, bindings=0, released=True
    )


def test_bpp_last_peer():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "initial peer", members=1)

    marker = _export_marker(tor1)
    _set_bpp_if(tor2, ES_IF, False)
    _expect_members(tor1, ES1_ID, (), "last peer left", bound=False)
    _expect_export_clean(
        tor1, "last peer export", members=0, groups=0, bindings=0, released=True,
    )
    _expect_export_events(
        tor1,
        marker,
        [
            ("BR_PORT_UPDATE", "del"),
            ("EVPN_MH_NHG_UPDATE", "del"),
            ("EVPN_MH_NH_UPDATE", "del"),
        ],
        "Binding, Group, Member on last peer",
    )

    _set_bpp(tor1, False)


def test_bpp_disable():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "protected", members=2)

    marker = _export_marker(tor1)
    _set_bpp(tor1, False)
    _expect_export_clean(
        tor1, "disabled", members=0, groups=0, bindings=0, released=True,
    )
    _expect_export_events(
        tor1,
        marker,
        [
            ("BR_PORT_UPDATE", "del"),
            ("EVPN_MH_NHG_UPDATE", "del"),
            ("EVPN_MH_NH_UPDATE", "del"),
            ("EVPN_MH_NH_UPDATE", "del"),
        ],
        "Binding, Group, Members on disable",
    )

    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_es_delete():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "protected", members=1)

    marker = _export_marker(tor1)
    tor1.vtysh_cmd("configure terminal\ninterface %s\nno evpn mh es-id" % ES_IF)
    _expect_export_clean(
        tor1, "ES deleted", members=0, groups=0, bindings=0, released=True,
    )
    _expect_export_events(
        tor1,
        marker,
        [
            ("BR_PORT_UPDATE", "del"),
            ("EVPN_MH_NHG_UPDATE", "del"),
            ("EVPN_MH_NH_UPDATE", "del"),
        ],
        "Binding, Group, Member on ES delete",
    )

    tor1.vtysh_cmd("configure terminal\ninterface %s\nevpn mh es-id 1" % ES_IF)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_per_evi_one_vrf():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "both peers", members=2)

    marker = _export_marker(tor1)
    _set_vrf_auto_rt(tor2, "vrf-a", False)
    _expect_eligible(
        tor1, ES1_ID, (lo2,), "tor2 missing vrf-a", eligible=False, missing=["vrf-a"]
    )
    _expect_members(tor1, ES1_ID, (lo3,), "tor3 remains")
    _expect_export_clean(tor1, "one peer remains", members=1)
    _expect_export_events(
        tor1,
        marker,
        [("EVPN_MH_NHG_UPDATE", "add"), ("EVPN_MH_NH_UPDATE", "del"),],
        "Group update before Member delete",
    )

    marker = _export_marker(tor1)
    _set_vrf_auto_rt(tor2, "vrf-a", True)
    _expect_eligible(tor1, ES1_ID, (lo2,), "tor2 restored")
    _expect_members(tor1, ES1_ID, (lo2, lo3), "both peers restored")
    _expect_export_clean(tor1, "both peers restored", members=2)
    _expect_export_events(
        tor1,
        marker,
        [("EVPN_MH_NH_UPDATE", "add"), ("EVPN_MH_NHG_UPDATE", "add"),],
        "Member add before Group update",
    )

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_per_es_mass_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "both peers", members=2)

    marker = _export_marker(tor1)
    tor2.vtysh_cmd("configure terminal\ninterface %s\nno evpn mh es-id" % ES_IF)
    _expect_eligible(tor1, ES1_ID, (lo2,), "tor2 withdrawn", eligible=False)
    _expect_members(tor1, ES1_ID, (lo3,), "tor3 remains")
    _expect_export_events(
        tor1,
        marker,
        [("EVPN_MH_NHG_UPDATE", "add"), ("EVPN_MH_NH_UPDATE", "del"),],
        "first peer mass-withdraw",
    )

    marker = _export_marker(tor1)
    tor3.vtysh_cmd("configure terminal\ninterface %s\nno evpn mh es-id" % ES_IF)
    _expect_members(tor1, ES1_ID, (), "all peers withdrawn", bound=False)
    _expect_export_clean(
        tor1, "all peers withdrawn", members=0, groups=0, bindings=0, released=True,
    )
    _expect_export_events(
        tor1,
        marker,
        [
            ("BR_PORT_UPDATE", "del"),
            ("EVPN_MH_NHG_UPDATE", "del"),
            ("EVPN_MH_NH_UPDATE", "del"),
        ],
        "last peer mass-withdraw",
    )

    tor2.vtysh_cmd("configure terminal\ninterface %s\nevpn mh es-id 1" % ES_IF)
    tor3.vtysh_cmd("configure terminal\ninterface %s\nevpn mh es-id 1" % ES_IF)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_peer_vtep_unreachable():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]
    lo2, lo3 = tor_lo("tor2"), tor_vtep("tor3")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "both peers", members=2)

    marker = _export_marker(tor1)
    tor2.run("ip addr del %s/32 dev lo" % lo2)
    _expect_eligible(tor1, ES1_ID, (lo2,), "tor2 VTEP unreachable", eligible=False)
    _expect_members(tor1, ES1_ID, (lo3,), "tor3 remains")
    _expect_export_events(
        tor1,
        marker,
        [("EVPN_MH_NHG_UPDATE", "add"), ("EVPN_MH_NH_UPDATE", "del"),],
        "unreachable peer removed",
    )

    marker = _export_marker(tor1)
    tor2.run("ip addr add %s/32 dev lo" % lo2)
    _expect_eligible(tor1, ES1_ID, (lo2,), "tor2 VTEP reachable")
    _expect_members(tor1, ES1_ID, (lo2, lo3), "tor2 restored")
    _expect_export_events(
        tor1,
        marker,
        [("EVPN_MH_NH_UPDATE", "add"), ("EVPN_MH_NHG_UPDATE", "add"),],
        "reachable peer restored",
    )

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_rmac_change_export():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")
    new_mac = "44:38:39:00:00:99"
    old1, old2 = _if_mac(tor2, "vlan4001"), _if_mac(tor2, "vlan4002")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "initial RMAC", members=1)
    old_id = _export_member(tor1, lo2)["nhId"]

    marker = _export_marker(tor1)
    tor2.run("ip link set vlan4001 address %s" % new_mac)

    def _check_rmac():
        member = _export_member(tor1, lo2)
        if not member or member.get("rmac") != new_mac:
            return member
        groups = ((_export(tor1).get("tables") or {}).get("groups") or {}).values()
        group_members = [m for group in groups for m in group.get("members", [])]
        if not any(
            m.get("vtep") == lo2 and m.get("rmac") == new_mac for m in group_members
        ):
            return group_members
        return None

    _, result = topotest.run_and_expect(
        _check_rmac, None, count=WAIT_COUNT, wait=WAIT_STEP
    )
    assert result is None, "RMAC export did not converge: %s" % result
    assert _export_member(tor1, lo2)["nhId"] == old_id
    _expect_export_events(
        tor1,
        marker,
        [("EVPN_MH_NH_UPDATE", "add"), ("EVPN_MH_NHG_UPDATE", "add"),],
        "RMAC changes Member and Group only",
    )

    tor2.run("ip link set vlan4001 address %s" % old1)
    tor2.run("ip link set vlan4002 address %s" % old2)
    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_local_link_down():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    host = tgen.gears["hostd1"]
    gw = ACCESS_VLANS[10][1].split("/")[0]

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "protected", members=1)
    host.run("ping -c 3 -W 1 %s" % gw)
    before = _local_forwarding_state(tor1)

    marker = _export_marker(tor1)
    tor1.run("ip link set dev %s down" % ES_IF)
    _expect_members(tor1, ES1_ID, (tor_lo("tor2"),), "objects kept")
    _expect_export_clean(tor1, "link down export unchanged", members=1)
    assert _local_forwarding_state(tor1) == before
    _expect_export_events(tor1, marker, [], "link down has no export")

    tor1.run("ip link set dev %s up" % ES_IF)
    _expect_export_clean(tor1, "link up export unchanged", members=1)
    assert _local_forwarding_state(tor1) == before
    _expect_export_events(tor1, marker, [], "link up has no export")

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_replay():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    tor3 = tgen.gears["tor3"]

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp_if(tor3, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "before replay", members=2)
    before = _replay_forwarding_state(tor1)
    counters = _dplane_primary_counters(tor1)

    marker = _export_marker(tor1)
    tor1.vtysh_cmd("clear evpn mh bridge-port-protection replay")
    _expect_replay(tor1, marker, before["export"], "full replay")

    assert _replay_forwarding_state(tor1) == before
    assert _dplane_primary_counters(tor1) == counters
    _expect_export_clean(tor1, "after replay", members=2)

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _clear_ip_ead(tor3)


def test_bpp_replay_empty():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    _expect_export_clean(
        tor1, "empty before replay", members=0, groups=0, bindings=0, released=True
    )

    marker = _export_marker(tor1)
    tor1.vtysh_cmd("clear evpn mh bridge-port-protection replay")
    events = _expect_replay(tor1, marker, {}, "empty replay")
    assert [ent.get("op") for ent in events] == ["EVPN_MH_REPLAY_DONE"]


def test_bpp_replay_idempotent():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "before repeated replay", members=1)
    tables = _export(tor1).get("tables") or {}

    for attempt in range(2):
        marker = _export_marker(tor1)
        tor1.vtysh_cmd("clear evpn mh bridge-port-protection replay")
        _expect_replay(tor1, marker, tables, "replay %d" % (attempt + 1))
        assert (_export(tor1).get("tables") or {}) == tables
        _expect_export_clean(tor1, "after replay %d" % (attempt + 1), members=1)

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_config_reload():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_export_clean(tor1, "before config reload", members=1)
    before = _export(tor1).get("tables") or {}
    before_groups = set((before.get("groups") or {}))

    tor1.vtysh_cmd("write memory")
    marker = _export_marker(tor1)
    rc, stdout, stderr = tor1.net.cmd_status(
        "/usr/lib/frr/frr-reload.py --reload /etc/frr/frr.conf", warn=False
    )
    assert rc == 0, "frr-reload.py failed: %s%s" % (stdout, stderr)
    assert _replay_events(tor1, marker) == []
    assert (_export(tor1).get("tables") or {}) == before

    kill_router_daemons(tgen, "tor1", ["zebra"], save_config=False)
    start_router_daemons(tgen, "tor1", ["zebra"])
    _expect_export_clean(tor1, "after zebra restart", members=1, esi=ES1_ID)
    after = _export(tor1).get("tables") or {}
    after_groups = set((after.get("groups") or {}))
    assert after_groups.isdisjoint(before_groups), (before_groups, after_groups)

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)


def test_bpp_scale():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    peers = tuple(tor_vtep(name) for name in TORS if name != "tor1")

    try:
        for name in TORS:
            _scale_dataplane_add(tgen.gears[name])

        expected = {}
        for index in range(1, SCALE_ES_COUNT + 1):
            vlans = {}
            for vrf_index, (vrf, _, l3vni) in enumerate(SCALE_VRFS, 1):
                vlans[str(_scale_vid(index, vrf_index))] = {
                    "vrf": vrf,
                    "l3vni": l3vni,
                    "state": "ACTIVE",
                    "ready": True,
                    "reasons": ["__ordered__"],
                }
            expected[_scale_es_name(index)] = {
                "esi": _scale_es_id(index),
                "bound": True,
                "vlans": vlans,
            }

        _expect_entries(tor1, expected, "32 protected VLANs across 8 ESes")
        _expect_scale_export(tor1, peers, "8 Groups with 3 peers")
        before = _export(tor1)
        binding_adds = (before.get("counters") or {}).get("bindingAdd")
        bindings = (before.get("tables") or {}).get("bindings")

        marker = _export_marker(tor1)
        config = ["configure terminal"]
        for index in range(1, SCALE_ES_COUNT + 1):
            config.extend(
                (
                    "interface %s" % _scale_es_name(index),
                    "no evpn mh bridge-port-protection",
                )
            )
        tgen.gears["tor4"].vtysh_cmd("\n".join(config))

        remaining = tuple(tor_vtep(name) for name in ("tor2", "tor3"))
        _expect_scale_export(tor1, remaining, "peer churn withdrawal")
        after = _export(tor1)
        assert (after.get("tables") or {}).get("bindings") == bindings
        assert (after.get("counters") or {}).get("bindingAdd") == binding_adds
        assert not any(op == "BR_PORT_UPDATE" for op, _ in _export_events(tor1, marker))

        marker = _export_marker(tor1)
        config = ["configure terminal"]
        for index in range(1, SCALE_ES_COUNT + 1):
            config.extend(
                (
                    "interface %s" % _scale_es_name(index),
                    "evpn mh bridge-port-protection",
                )
            )
        tgen.gears["tor4"].vtysh_cmd("\n".join(config))

        _expect_scale_export(tor1, peers, "peer churn restoration")
        after = _export(tor1)
        assert (after.get("tables") or {}).get("bindings") == bindings
        assert (after.get("counters") or {}).get("bindingAdd") == binding_adds
        assert not any(op == "BR_PORT_UPDATE" for op, _ in _export_events(tor1, marker))
    finally:
        for name in TORS:
            _scale_dataplane_del(tgen.gears[name])

    _expect_entries(tor1, {}, "scale entries removed")
    _expect_export_clean(
        tor1, "scale exports removed", members=0, groups=0, bindings=0, released=True,
    )


def test_bpp_fpm_kernel_disjoint():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member present")
    _expect_export_clean(tor1, "typed IDs", members=1, groups=1, bindings=1)

    out = _export(tor1)
    tables = out.get("tables") or {}
    for rec in (tables.get("members") or {}).values():
        assert _nhg_type(rec["nhId"]) == NHG_TYPE_L3_BPP_NH, rec
    for rec in (tables.get("groups") or {}).values():
        assert _nhg_type(rec["nhgId"]) == NHG_TYPE_L3_BPP, rec
    kernel = _kernel_nh_ids(tor1)
    for rec in list((tables.get("members") or {}).values()) + list(
        (tables.get("groups") or {}).values()
    ):
        nid = int(rec.get("nhId") or rec.get("nhgId"))
        assert nid not in kernel, hex(nid)

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _expect_export_clean(
        tor1, "cleanup", members=0, groups=0, bindings=0, released=True
    )


def test_bpp_l2_br_port_unchanged():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member present")
    _expect_export_clean(tor1, "hostbond1 Binding", bindings=1)

    out = _export(tor1)
    bind = (out.get("tables") or {}).get("bindings") or {}
    assert list(bind) == [ES_IF], bind
    l2_nhg = _es_nhg_id(tor1, ES2_ID)
    assert _nhg_type(l2_nhg) == NHG_TYPE_L2, hex(l2_nhg)

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _expect_export_clean(
        tor1, "cleanup", members=0, groups=0, bindings=0, released=True
    )


def test_bpp_l2vni_on_bd_binding():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member present")
    _expect_export_clean(tor1, "protection Binding", bindings=1)

    _add_l2vni(tor1)
    _expect_export_clean(
        tor1, "L2VNI withdraws protection", members=0, groups=0, bindings=0
    )
    assert bpp_export_check(_export(tor1)) == []

    _del_l2vni(tor1)
    _expect_members(tor1, ES1_ID, (lo2,), "protection back")
    _expect_export_clean(tor1, "protection Binding restored", bindings=1)
    assert bpp_export_check(_export(tor1)) == []

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _expect_export_clean(
        tor1, "cleanup", members=0, groups=0, bindings=0, released=True
    )


def test_bpp_export_status():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]
    tor2 = tgen.gears["tor2"]
    lo2 = tor_lo("tor2")

    _set_bpp_if(tor2, ES_IF, True)
    _set_bpp(tor1, True)
    _expect_members(tor1, ES1_ID, (lo2,), "member present")

    def _check():
        out = json.loads(tor1.vtysh_cmd("show evpn mh bridge-port-protection json"))
        vlans = (out.get(ES_IF) or {}).get("vlans") or {}
        for vid in ("10", "20"):
            rec = vlans.get(vid) or {}
            if rec.get("state") == "ACTIVE" and rec.get("exportStatus") != "acked":
                return rec
        if not vlans:
            return out
        return None

    _, result = topotest.run_and_expect(_check, None, count=WAIT_COUNT, wait=WAIT_STEP)
    assert result is None, "ACTIVE entries not acked: %s" % result

    _set_bpp(tor1, False)
    _clear_ip_ead(tor2)
    _expect_export_clean(
        tor1, "cleanup", members=0, groups=0, bindings=0, released=True
    )


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
