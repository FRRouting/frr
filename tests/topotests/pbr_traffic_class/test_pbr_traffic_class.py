#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_pbr_traffic_class.py
#
# Copyright (c) 2026 Aviz Networks
#

"""
QoS 2.21: pbr-map `set traffic-class` realised as tc clsact ingress
flower filters with a skbedit action.

r1-eth0  routed, policy QOS (classify-only and classify+forward)
r1-eth1  nexthop interface for QOS seq 30
r1-eth2  bridge port of br0, policy L2 (untagged and 802.1Q shapes)
r1-eth3  routed, has an operator clsact + filter and a fake leftover
         zebra filter before zebra starts; policy QOS
r1-eth4  spare
"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.pbrd]

ZEBRA_HANDLE = 0x80000000


def build_topo(tgen):
    tgen.add_router("r1")
    for n in range(1, 6):
        sw = tgen.add_switch("sw{}".format(n))
        sw.add_link(tgen.gears["r1"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]

    # bridge port for the L2 policy
    r1.cmd_raises("ip link add br0 type bridge vlan_filtering 1")
    r1.cmd_raises("ip link set r1-eth2 master br0")
    r1.cmd_raises("ip link set br0 up")

    # operator-owned clsact with a filter of its own, plus a fake leftover
    # of a previous zebra (zebra handle bit + FRRzebra cookie) and a
    # look-alike without the cookie, which must survive
    r1.cmd_raises("tc qdisc add dev r1-eth3 clsact")
    r1.cmd_raises(
        "tc filter add dev r1-eth3 ingress pref 9000 protocol ip handle 0x1 "
        "flower ip_proto icmp action skbedit priority 1 pipe"
    )
    r1.cmd_raises(
        "tc filter add dev r1-eth3 ingress pref 9001 protocol ip handle 0x80000ff8 "
        "flower ip_proto udp action skbedit priority 2 pipe "
        "cookie 4652527a65627261"
    )
    r1.cmd_raises(
        "tc filter add dev r1-eth3 ingress pref 9002 protocol ip handle 0x80000ff0 "
        "flower ip_proto tcp action skbedit priority 3 pipe"
    )

    for rname, router in tgen.routers().items():
        router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, rname, "zebra.conf"))
        router.load_config(TopoRouter.RD_PBRD, os.path.join(CWD, rname, "pbrd.conf"))

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def tc_filters(router, ifname):
    out = router.cmd("tc -j filter show dev {} ingress".format(ifname))
    try:
        return [f for f in json.loads(out) if "options" in f]
    except ValueError:
        return []


def filter_by_pref(router, ifname):
    return {f["pref"]: f for f in tc_filters(router, ifname)}


def skbedit(f):
    for a in f["options"].get("actions", []):
        if a.get("kind") == "skbedit":
            return a
    return None


def _check_qos_eth0(router):
    prefs = filter_by_pref(router, "r1-eth0")
    want = {
        80: ("ip", 6),  # seq 10 dscp 46, IPv4
        81: ("ipv6", 6),  # seq 10 dscp 46, IPv6
        160: ("ip", 2),  # seq 20 src 10.10.0.0/24
        240: ("ip", 4),  # seq 30 src 10.30.0.0/24 (+ FIB rule)
    }
    for pref, (proto, tc) in want.items():
        f = prefs.get(pref)
        if not f:
            return "missing pref {}".format(pref)
        if f["protocol"] != proto:
            return "pref {} protocol {}".format(pref, f["protocol"])
        a = skbedit(f)
        if not a or a.get("priority") is None:
            return "pref {} has no skbedit priority".format(pref)
    return None


def test_classify_filters():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    test_func = functools.partial(_check_qos_eth0, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1-eth0 filters: {}".format(result)

    # zebra created the clsact on r1-eth0
    assert "clsact" in r1.cmd("tc qdisc show dev r1-eth0")


def test_classify_only_has_no_fib_rule():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    rules = r1.cmd("ip rule show")
    assert "10.10.0.0/24" not in rules, "classify-only sequence installed an ip rule"

    def _fib_rule():
        return "from 10.30.0.0/24 iif r1-eth0" in r1.cmd("ip rule show")

    _, ok = topotest.run_and_expect(_fib_rule, True, count=30, wait=1)
    assert ok, "seq 30 (nexthop + traffic-class) has no ip rule"


def test_pbr_map_state():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    maps = {m["name"]: m for m in json.loads(r1.vtysh_cmd("show pbr map json"))}
    assert maps["QOS"]["valid"], "QOS map should be valid"

    seqs = {s["sequenceNumber"]: s for s in maps["QOS"]["policies"]}
    assert seqs[10]["classifyOnly"] and seqs[10]["actionSetTrafficClass"] == 6
    assert not seqs[30]["classifyOnly"]

    bad = {s["sequenceNumber"]: s for s in maps["BAD"]["policies"]}
    assert "Match Mark" in bad[10]["installedReason"]
    assert "IP Protocol" in bad[20]["installedReason"]
    assert "Queue-id" in bad[30]["installedReason"]


def _check_l2(router):
    prefs = filter_by_pref(router, "r1-eth2")
    # seq 10 dscp 34: untagged v4/v6 + 802.1Q v4/v6; seq 20 pcp 5: 802.1Q
    for pref, proto in ((80, "ip"), (81, "ipv6"), (82, "802.1Q"), (83, "802.1Q"), (164, "802.1Q")):
        f = prefs.get(pref)
        if not f or f["protocol"] != proto:
            return "pref {}: {}".format(pref, f)
    if prefs[164]["options"]["keys"].get("vlan_prio") != 5:
        return "pref 164 has no vlan_prio 5"
    if prefs[82]["options"]["keys"].get("vlan_ethtype") != "ip":
        return "pref 82 has no vlan_ethtype ip"
    return None


def test_bridge_port_shapes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    test_func = functools.partial(_check_l2, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1-eth2 filters: {}".format(result)


def test_startup_leftover_and_operator_filters():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    def _check():
        prefs = filter_by_pref(r1, "r1-eth3")
        if 9001 in prefs:
            return "leftover zebra filter (pref 9001) not removed"
        if 9000 not in prefs or 9002 not in prefs:
            return "operator filters missing: {}".format(sorted(prefs))
        if 80 not in prefs:
            return "zebra filter not added to the operator clsact"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result

    tc = json.loads(r1.vtysh_cmd("show zebra tc interface r1-eth3 json"))
    assert tc["clsact"][0]["owner"] == "external"


def test_unbind_removes_filters():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf t\ninterface r1-eth0\nno pbr-policy QOS\ninterface r1-eth3\nno pbr-policy QOS")

    def _check():
        if tc_filters(r1, "r1-eth0"):
            return "r1-eth0 still has filters"
        if "clsact" in r1.cmd("tc qdisc show dev r1-eth0"):
            return "zebra-owned clsact not removed from r1-eth0"
        prefs = filter_by_pref(r1, "r1-eth3")
        if 80 in prefs:
            return "zebra filter left on r1-eth3"
        if 9000 not in prefs:
            return "operator filter removed from r1-eth3"
        if "clsact" not in r1.cmd("tc qdisc show dev r1-eth3"):
            return "operator clsact removed from r1-eth3"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result


def test_mark_mask():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf t\npbr traffic-class mark-mask 0x700")

    def _check():
        f = filter_by_pref(r1, "r1-eth2").get(80)
        if not f:
            return "no filter"
        a = skbedit(f)
        # TC 4 << 8.  iproute2 prints the mark as a decimal number and the
        # mask as hex without a "0x" prefix ("700"), so parse them apart.
        mark = int(str(a.get("mark")), 0)
        mask = int(str(a.get("mask")), 16)
        if mark != 0x400 or mask != 0x700:
            return "mark {:#x} mask {:#x}".format(mark, mask)
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result

    out = r1.vtysh_cmd("show pbr traffic-class json")
    assert json.loads(out)["markMask"] == "0x00000700"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
