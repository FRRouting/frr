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
r1-eth4  spare; joins and leaves br0 with policy L2 bound
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


def skbedit_class(a):
    """
    Traffic class set by a skbedit action.  iproute2 prints the priority
    as a tc classid (":6", "0:6") with a hex minor, or as a plain number.
    """
    if not a or a.get("priority") is None:
        return None
    return int(str(a["priority"]).split(":")[-1], 16)


def check_class(f, pref, tc, mark_shift=16):
    """skbedit of filter @f sets class @tc and mark tc << mark_shift."""
    a = skbedit(f)
    got = skbedit_class(a)
    if got != tc:
        return "pref {}: skbedit priority {} (want {})".format(pref, got, tc)
    mark = a.get("mark")
    if mark is not None and int(str(mark), 0) != tc << mark_shift:
        return "pref {}: skbedit mark {} (want {:#x})".format(pref, mark, tc << mark_shift)
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
        err = check_class(f, pref, tc)
        if err:
            return err
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
    assert "Untagged Match" in bad[40]["installedReason"]

    # A classifier rewrites skb->mark before routing, so `match mark` (whole
    # mark compared by the FIB rule) is invalid in a classifying map while
    # the mark carrier is on, whatever its value; with mark-mask 0 it is fine.
    def _mix_seq20():
        m = {x["name"]: x for x in json.loads(r1.vtysh_cmd("show pbr map json"))}
        return {s["sequenceNumber"]: s for s in m["MIX"]["policies"]}[20]["installedReason"]

    assert "Mark Carrier" in _mix_seq20()

    r1.vtysh_cmd("conf t\npbr traffic-class mark-mask 0")
    _, reason = topotest.run_and_expect(_mix_seq20, "Valid", count=10, wait=1)
    assert reason == "Valid", "MIX seq 20 with mark-mask 0: {}".format(reason)

    r1.vtysh_cmd("conf t\nno pbr traffic-class mark-mask")
    _, reason = topotest.run_and_expect(
        lambda: "Mark Carrier" in _mix_seq20(), True, count=10, wait=1
    )
    assert reason, "MIX seq 20 not invalid again after restoring the mask"


def _check_l2(router):
    prefs = filter_by_pref(router, "r1-eth2")
    # seq 10 dscp 34: untagged v4/v6 + 802.1Q v4/v6; seq 20 pcp 5: 802.1Q
    want = (
        (80, "ip", 4),
        (81, "ipv6", 4),
        (82, "802.1Q", 4),
        (83, "802.1Q", 4),
        (164, "802.1Q", 5),
        (244, "802.1Q", 3),
    )
    for pref, proto, tc in want:
        f = prefs.get(pref)
        if not f or f["protocol"] != proto:
            return "pref {}: {}".format(pref, f)
        err = check_class(f, pref, tc)
        if err:
            return err
    if prefs[164]["options"]["keys"].get("vlan_prio") != 5:
        return "pref 164 has no vlan_prio 5"
    # seq 30: pcp 3 + untagged-or-zero must stay on VID 0
    keys = prefs[244]["options"]["keys"]
    if keys.get("vlan_prio") != 3 or keys.get("vlan_id") != 0:
        return "pref 244 keys {} (want vlan_id 0, vlan_prio 3)".format(keys)
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


def test_bridge_join_rebuilds_filters():
    """
    A policy bound before the port joins a bridge gets the 802.1Q shapes
    when the port joins, and loses them again when it leaves.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf t\ninterface r1-eth4\npbr-policy L2")

    def _shapes(want_tagged):
        prefs = filter_by_pref(r1, "r1-eth4")
        if 80 not in prefs or 81 not in prefs:
            return "untagged filters missing: {}".format(sorted(prefs))
        tagged = 82 in prefs and 83 in prefs
        if tagged != want_tagged:
            return "802.1Q shapes {} (want {}): {}".format(
                "present" if tagged else "absent",
                "present" if want_tagged else "absent",
                sorted(prefs),
            )
        if want_tagged:
            return check_class(prefs[82], 82, 4)
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_shapes, False), None, count=30, wait=1
    )
    assert result is None, "before joining br0: {}".format(result)

    r1.cmd_raises("ip link set r1-eth4 master br0")
    _, result = topotest.run_and_expect(
        functools.partial(_shapes, True), None, count=30, wait=1
    )
    assert result is None, "after joining br0: {}".format(result)

    r1.cmd_raises("ip link set r1-eth4 nomaster")
    _, result = topotest.run_and_expect(
        functools.partial(_shapes, False), None, count=30, wait=1
    )
    assert result is None, "after leaving br0: {}".format(result)

    r1.vtysh_cmd("conf t\ninterface r1-eth4\nno pbr-policy L2")


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


def test_clsact_deleted_marks_filters_removed():
    """
    Deleting the clsact qdisc deletes its filters: zebra must show its
    filters there as removed, not installed. Rebinding the policy after the
    operator restores the clsact installs them again.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.cmd_raises("tc qdisc del dev r1-eth3 clsact")

    def _status(want):
        tc = json.loads(r1.vtysh_cmd("show zebra tc interface r1-eth3 json"))
        status = {f["pref"]: f["status"] for f in tc.get("filters", [])}
        if status.get(80) != want:
            return "zebra filter pref 80 on r1-eth3: {} (want {})".format(
                status.get(80), want
            )
        return None

    _, result = topotest.run_and_expect(
        functools.partial(_status, "removed"), None, count=30, wait=1
    )
    assert result is None, result

    # operator restores its clsact and filter, then the policy is rebound
    r1.cmd_raises("tc qdisc add dev r1-eth3 clsact")
    r1.cmd_raises(
        "tc filter add dev r1-eth3 ingress pref 9000 protocol ip handle 0x1 "
        "flower ip_proto icmp action skbedit priority 1 pipe"
    )
    r1.vtysh_cmd("conf t\ninterface r1-eth3\nno pbr-policy QOS\npbr-policy QOS")

    _, result = topotest.run_and_expect(
        functools.partial(_status, "installed"), None, count=30, wait=1
    )
    assert result is None, result
    assert 80 in filter_by_pref(r1, "r1-eth3")
    tc = json.loads(r1.vtysh_cmd("show zebra tc interface r1-eth3 json"))
    assert tc["clsact"][0]["owner"] == "external"


def test_remove_forwarding_keeps_classifier():
    """
    `no set nexthop` on a sequence that also classifies: the FIB rule goes,
    the sequence becomes classify-only and its classifier stays installed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf t\npbr-map QOS seq 30\nno set nexthop 198.51.100.2")

    def _check():
        if "from 10.30.0.0/24 iif r1-eth0" in r1.cmd("ip rule show"):
            return "FIB rule of seq 30 still installed"
        f = filter_by_pref(r1, "r1-eth0").get(240)
        if not f:
            return "classifier of seq 30 (pref 240) missing"
        return check_class(f, 240, 4)

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result

    r1.vtysh_cmd("conf t\npbr-map QOS seq 30\nset nexthop 198.51.100.2")

    def _restored():
        if "from 10.30.0.0/24 iif r1-eth0" not in r1.cmd("ip rule show"):
            return "FIB rule of seq 30 not restored"
        if 240 not in filter_by_pref(r1, "r1-eth0"):
            return "classifier of seq 30 lost"
        return None

    _, result = topotest.run_and_expect(_restored, None, count=30, wait=1)
    assert result is None, result


def test_add_forwarding_to_classify_only():
    """
    Adding `set nexthop` or `set vrf unchanged` to an installed
    classify-only sequence installs its FIB rule (and keeps it); removing
    it again leaves the classifier.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    def _state(want_rule):
        has_rule = "from 10.10.0.0/24 iif r1-eth0" in r1.cmd("ip rule show")
        if has_rule != want_rule:
            return "FIB rule of QOS seq 20 {}".format(
                "present" if has_rule else "missing"
            )
        f = filter_by_pref(r1, "r1-eth0").get(160)
        if not f:
            return "classifier of QOS seq 20 (pref 160) missing"
        return check_class(f, 160, 2)

    for add, remove in (
        ("set nexthop 198.51.100.2", "no set nexthop 198.51.100.2"),
        ("set vrf unchanged", "no set vrf unchanged"),
    ):
        r1.vtysh_cmd("conf t\npbr-map QOS seq 20\n" + add)
        _, result = topotest.run_and_expect(
            functools.partial(_state, True), None, count=30, wait=1
        )
        assert result is None, "after '{}': {}".format(add, result)

        r1.vtysh_cmd("conf t\npbr-map QOS seq 20\n" + remove)
        _, result = topotest.run_and_expect(
            functools.partial(_state, False), None, count=30, wait=1
        )
        assert result is None, "after '{}': {}".format(remove, result)


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
