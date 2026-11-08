#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_igmp_proxy_nat.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#

"""
IGMP proxy on a WAN interface with NAT, PIM passive everywhere.

    h1 ---- LAN ---- r1 ---- WAN ---- u1 ---- s1
    192.168.1.10     |  198.51.100.2   .1     203.0.113.10 (source)
                     |
           masquerade + stateful firewall on r1-eth1 (WAN),
           r1-eth1 is the IGMP proxy interface, default route via u1

    r1-eth2 ---- u2 (10.0.15.2): second uplink, PIM passive, not a proxy

u1 has no route back to the LAN, so anything from the LAN only reaches
it through r1's NAT.

1. Unicast from the LAN is masqueraded (h1 can ping s1).
2. h1's (S,G) join is proxied out of the WAN.  The report leaves with
   r1's WAN address, u1 learns the membership and forwards the stream to
   r1, which installs the (S,G) mroute WAN -> LAN.
3. The stateful firewall (FORWARD policy drop, only LAN->WAN and
   established/related allowed) drops the stream: inbound multicast is
   not an established flow and NAT does not apply to it.
4. An explicit FORWARD rule for the SSM range lets it through to h1,
   with strict rp_filter on the WAN (the source is routed via the WAN).
5. With an equal-cost route to the source over a second, non-proxy PIM
   passive uplink (no PIM neighbor either way), a new channel still gets
   its RPF on the proxy WAN and the stream reaches h1.
6. When h1 leaves, the leave goes out of the WAN and u1 drops the
   membership.
"""

import os
import sys
import json
import time
from functools import partial
import pytest

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.pim import McastTesterHelper

SRC = "203.0.113.10"
GRP = "232.1.1.1"
GRP2 = "232.1.1.2"  # fresh channel for the ECMP case
R1_WAN = "198.51.100.2"

app_helper = McastTesterHelper()


def build_topo(tgen):
    "Build function"

    for rname in ["r1", "u1", "h1", "s1", "u2"]:
        tgen.add_router(rname)

    tgen.add_link(tgen.gears["r1"], tgen.gears["h1"], "r1-eth0", "h1-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["u1"], "r1-eth1", "u1-eth0")
    tgen.add_link(tgen.gears["u1"], tgen.gears["s1"], "u1-eth1", "s1-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["u2"], "r1-eth2", "u2-eth0")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    for cmd in [
        # NAT and a typical stateful firewall on the WAN
        "iptables -t nat -A POSTROUTING -o r1-eth1 -j MASQUERADE",
        "iptables -P FORWARD DROP",
        "iptables -A FORWARD -i r1-eth0 -o r1-eth1 -j ACCEPT",
        "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "sysctl -w net.ipv4.conf.all.rp_filter=1",
        "sysctl -w net.ipv4.conf.r1-eth1.rp_filter=1",
    ]:
        r1.cmd_raises(cmd)

    # Count the stream as delivered to h1, and IGMP from r1's WAN on u1
    for grp in [GRP, GRP2]:
        tgen.gears["h1"].cmd_raises("iptables -A INPUT -d {} -p udp".format(grp))
    tgen.gears["u1"].cmd_raises("iptables -A INPUT -s {} -p igmp".format(R1_WAN))

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()
    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    app_helper.cleanup()
    tgen = get_topogen()
    tgen.stop_topology()


def rule_packets(router, chain, match):
    "Packet count of the first rule in the filter chain whose text has match"
    output = router.cmd("iptables -L {} -v -n -x".format(chain))
    for line in output.splitlines():
        if match in line:
            return int(line.split()[0])
    return 0


def h1_received(grp=GRP):
    return rule_packets(get_topogen().gears["h1"], "INPUT", grp)


def h1_join(no=False, grp=GRP):
    get_topogen().gears["h1"].vtysh_cmd(
        "conf\ninterface h1-eth0\n{}ip igmp join-group {} {}\nend".format(
            "no " if no else "", grp, SRC
        )
    )


def test_nat_unicast():
    "LAN unicast reaches the source network only through the masquerade"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    h1 = tgen.gears["h1"]
    output = h1.cmd("ping -c 3 -W 1 {}".format(SRC))
    assert " 0% packet loss" in output, "h1 cannot reach s1:\n{}".format(output)

    output = tgen.gears["r1"].cmd("conntrack -L 2>/dev/null || true")
    logger.info("r1 conntrack:\n%s", output)


def test_proxy_join_through_nat():
    "The proxied join leaves with the WAN address and pulls the stream to r1"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    u1 = tgen.gears["u1"]

    app_helper.run_traffic("s1", GRP, bind_intf="s1-eth0")
    h1_join()

    # r1 proxies on its WAN
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip igmp proxy json",
        {"r1-eth1": {"groups": [{"source": SRC, "group": GRP}]}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 does not proxy ({},{}) on r1-eth1".format(SRC, GRP)

    # u1 learned it on the WAN link, from r1's WAN address
    test_func = partial(
        topotest.router_json_cmp,
        u1,
        "show ip igmp sources json",
        {"u1-eth0": {GRP: {"sources": [{"source": SRC}]}}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "u1 did not learn ({},{}) on u1-eth0".format(SRC, GRP)
    assert rule_packets(u1, "INPUT", R1_WAN) > 0, "u1 got no IGMP from r1's WAN address"

    # u1 forwards the stream to r1, r1 installs WAN -> LAN
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip mroute json",
        {
            GRP: {
                SRC: {
                    "iif": "r1-eth1",
                    "installed": 1,
                    "oil": {"r1-eth0": {}},
                }
            }
        },
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 mroute not WAN -> LAN: {}".format(result)

    def _r1_receiving(last=[0]):
        output = json.loads(r1.vtysh_cmd("show ip mroute count json"))
        pkts = output.get(GRP, {}).get(SRC, {}).get("packets", 0)
        ok = pkts > last[0] > 0
        last[0] = pkts
        return None if ok else "r1 packets {}".format(pkts)

    _, result = topotest.run_and_expect(_r1_receiving, None, count=20, wait=1)
    assert result is None, "stream not arriving on r1's WAN: {}".format(result)


def test_stateful_firewall_drops_stream():
    "Inbound multicast is not an established flow: the firewall drops it"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    before = h1_received()
    time.sleep(3)
    after = h1_received()
    assert after == before, "h1 received {} packets through the firewall".format(
        after - before
    )


def test_firewall_allows_ssm():
    "An explicit FORWARD rule for the SSM range lets the stream through"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].cmd_raises(
        "iptables -I FORWARD -i r1-eth1 -o r1-eth0 -d 232.0.0.0/8 -j ACCEPT"
    )

    def _h1_receiving(last=[None]):
        pkts = h1_received()
        ok = last[0] is not None and pkts > last[0]
        last[0] = pkts
        return None if ok else "h1 packets {}".format(pkts)

    _, result = topotest.run_and_expect(_h1_receiving, None, count=20, wait=1)
    assert result is None, "stream not reaching h1: {}".format(result)


def test_ecmp_with_non_proxy_path():
    "An equal-cost non-proxy path without a PIM neighbor must not win the RPF"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Two equal-cost paths to the source: the proxy WAN and a PIM passive
    # uplink that is not a proxy interface (sorted first, by gateway).  Neither
    # has a PIM neighbor; only the proxy path can carry the stream.  Set
    # them up before a new channel is joined, so its RPF is chosen from
    # scratch from the cached nexthops (h1 keeps the first channel).
    r1.vtysh_cmd(
        "conf\nip route 203.0.113.0/24 10.0.15.2\n"
        "ip route 203.0.113.0/24 198.51.100.1\nend"
    )
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip route 203.0.113.0/24 json",
        {
            "203.0.113.0/24": [
                {
                    "selected": True,
                    "nexthops": [
                        {"fib": True, "interfaceName": "r1-eth2"},
                        {"fib": True, "interfaceName": "r1-eth1"},
                    ],
                }
            ]
        },
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 has no ECMP route to the source"

    # The RPF must be right as soon as h1 joins, before any data arrives
    # (data on the proxy interface would otherwise be what fixes it up).
    h1_join(grp=GRP2)
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip pim upstream json",
        {GRP2: {SRC: {"inboundInterface": "r1-eth1"}}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 upstream RPF not the proxy path: {}".format(result)

    app_helper.run_traffic("s1", GRP2, bind_intf="s1-eth0")

    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip mroute json",
        {GRP2: {SRC: {"iif": "r1-eth1", "installed": 1, "oil": {"r1-eth0": {}}}}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 mroute not via the proxy path: {}".format(result)

    def _h1_receiving(last=[None]):
        pkts = h1_received(GRP2)
        ok = last[0] is not None and pkts > last[0]
        last[0] = pkts
        return None if ok else "h1 packets {}".format(pkts)

    _, result = topotest.run_and_expect(_h1_receiving, None, count=20, wait=1)
    assert result is None, "stream not reaching h1: {}".format(result)

    h1_join(no=True, grp=GRP2)
    r1.vtysh_cmd(
        "conf\nno ip route 203.0.113.0/24 198.51.100.1\n"
        "no ip route 203.0.113.0/24 10.0.15.2\nend"
    )


def test_leave_through_nat():
    "h1's leave goes out of the WAN and u1 drops the membership"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    u1 = tgen.gears["u1"]

    h1_join(no=True)

    def _gone():
        joins = json.loads(r1.vtysh_cmd("show ip igmp proxy json"))
        groups = joins.get("r1-eth1", {}).get("groups", [])
        if any(g["group"] == GRP for g in groups):
            return "r1 still proxies {}".format(GRP)
        sources = json.loads(u1.vtysh_cmd("show ip igmp sources json"))
        if GRP in sources.get("u1-eth0", {}):
            return "u1 still has {} on u1-eth0".format(GRP)
        return None

    _, result = topotest.run_and_expect(_gone, None, count=60, wait=1)
    assert result is None, result

    before = h1_received()
    time.sleep(3)
    assert h1_received() == before, "h1 still receiving after leaving"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
