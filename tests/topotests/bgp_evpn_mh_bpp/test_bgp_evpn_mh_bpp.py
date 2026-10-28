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
        | tor1 | | tor2 | | tor3 | | tor4 |       VTEPs, L3VNI only
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
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
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
BPP_XPATH = (
    "/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/evpn-mh" % ES_IF
)

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
    return "10.0.0.%d" % (TORS.index(tor) + 1)


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
    lo = tor_lo(tor.name)
    tor.run("ip link add %s type vrf table %d" % (vrf, table))
    tor.run("ip link set dev %s up" % vrf)

    tor.run(
        "ip link add vni%d type vxlan id %d dstport 4789 local %s nolearning"
        % (l3vni, l3vni, lo)
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
    tor.run("ip addr add %s/32 dev lo" % lo)

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


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

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
    for key in ("ipv4Unicast", "l2VpnEvpn"):
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
    remote = sorted(tor_lo(t) for t in TORS if t != router.name)

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
    return "evpn mh bridge-port-protection" in router.vtysh_cmd(
        "show running-config"
    )


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
        "configure terminal\ninterface %s\nno evpn mh bridge-port-protection"
        % ES_IF
    )
    _expect_bpp(tor1, False)

    # Add before es-id: the knob is kept across es-id removal and re-add.
    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nno evpn mh es-id\n"
        "evpn mh bridge-port-protection\nevpn mh es-id 1" % ES_IF
    )
    _expect_bpp(tor1, True)

    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nno evpn mh es-id" % ES_IF
    )
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
                    "20": _pending(
                        ["IP-VRF has no L3VNI"], vrf="default", l3vni=None
                    ),
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
    _expect_log(tgen, tor1, "bridge-port protection %s vlan 10 add: no eligible peer" % ES_IF)
    _expect_json(
        tor1, cmd, {ES_IF: {"vlans": {"10": {"lastEvent": "created"}}}}, "created"
    )

    _set_l3vni_neigh(tor1, False)
    _expect_log(
        tgen,
        tor1,
        "bridge-port protection %s vlan 10: no eligible peer -> l3vni-neigh off" % ES_IF,
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
        "bridge-port protection %s vlan 10: l3vni-neigh off -> no eligible peer" % ES_IF,
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
    return {
        e["vrf"].split()[-1]: e for e in output if e.get("esi") == esi
    }


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
        router,
        "show evpn mh bridge-port-protection member json",
        expected,
        msg,
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
    _expect_es_vrfs(
        tor1, ES1_ID, {"vrf-b": _l3mh_es_vrf()}, "last vrf-a VLAN removed"
    )

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
            tor1,
            esi,
            {"vrf-b": {"refCount": 1, "l3RefCount": 0}},
            "L2VNI ES-VRF",
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
        tor1,
        ES2_ID,
        {"vrf-b": {"refCount": 1, "l3RefCount": 0}},
        "L2VNI ES-VRF",
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


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
