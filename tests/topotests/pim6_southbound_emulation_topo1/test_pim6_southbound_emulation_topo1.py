#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim6_southbound_emulation_topo1.py
#
# Copyright (c) 2026 by Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim6_southbound_emulation_topo1.py: PIMv6-SM through the vendor
southbound with `pysbd` emulating the data plane events (`-a`).

        +----+   2001:db8:12::/64  +----+
  h1 ---| r1 |---------------------| r2 | (RP 2001:db8:ffff::2)
        +----+                     +----+
           \\                        /
 2001:db8:13::/64                  / 2001:db8:23::/64
                \\     +----+      /
                 -----| r3 |------
                      +----+
                         |
                        h2 (source 2001:db8:3::10)

The IPv6 version of pim_southbound_emulation_topo1: nothing is typed into
`pysbd`. h1 joins ff05::100 and h2 sends to it: r3 registers the traffic
until the register-stop, r1 switches to the shortest path tree (JOIN_SPT,
then DATA_START on the SPT) and the RP stops forwarding the source to it.
When h2 stops the traffic state goes away (DATA_STOP), and comes back with
the traffic.
"""

import json
import os
import socket
import sys
from functools import partial

import pytest

pytestmark = [pytest.mark.pim6d]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.pim import McastTesterHelper
from lib.pysbd.helper import Pysbd, kernel_mroutes
from lib.topogen import Topogen, get_topogen

GROUP = "ff05::100"
SOURCE = "2001:db8:3::10"
#: Seconds without packets before the data plane considers the traffic gone.
DATA_TIMEOUT = 3

# Added before the daemons start (zebra configures them too) so the IPv6
# addresses skip the duplicate address detection.
ADDRESSES = {
    "r1": [
        ("lo", "2001:db8:ffff::1/128"),
        ("r1-eth0", "2001:db8:12::1/64"),
        ("r1-eth1", "2001:db8:13::1/64"),
        ("r1-eth2", "2001:db8:1::1/64"),
    ],
    "r2": [
        ("lo", "2001:db8:ffff::2/128"),
        ("r2-eth0", "2001:db8:12::2/64"),
        ("r2-eth1", "2001:db8:23::2/64"),
    ],
    "r3": [
        ("lo", "2001:db8:ffff::3/128"),
        ("r3-eth0", "2001:db8:13::3/64"),
        ("r3-eth1", "2001:db8:23::3/64"),
        ("r3-eth2", "2001:db8:3::1/64"),
    ],
}

pysbd = {}
app_helper = McastTesterHelper()


def build_topo(tgen):
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    tgen.add_host("h1", "2001:db8:1::10/64", "via 2001:db8:1::1")
    tgen.add_host("h2", "2001:db8:3::10/64", "via 2001:db8:3::1")

    # r1-eth0 <-> r2-eth0
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-eth1 <-> r3-eth0
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # r2-eth1 <-> r3-eth1
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # r1-eth2 <-> h1-eth0
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    # r3-eth2 <-> h2-eth0
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["h2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        for ifname, address in ADDRESSES[router.name]:
            router.cmd_raises("ip -6 addr add {} dev {} nodad".format(address, ifname))

        pysbd[router.name] = Pysbd(
            router,
            [
                "-a",
                "-t",
                str(DATA_TIMEOUT),
                "-E",
                "-q",
                "ipv6:[::1]",
                "-f",
                "ipv4:127.0.0.1",
            ],
        )
        pysbd[router.name].start()

    for router in tgen.routers().values():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(router.name)),
            daemons=[
                ("zebra", "-M dplane_fpm_nl"),
                "mgmtd",
                "staticd",
                ("pim6d", "-M southbound:ipv6c:[::1]"),
            ],
        )

    tgen.start_router()

    for sbd in pysbd.values():
        sbd.wait_connected("pim6")
        sbd.wait_connected("fpm")

    app_helper.init(tgen)


def teardown_module(mod):
    tgen = get_topogen()

    app_helper.cleanup()
    tgen.stop_topology()

    for sbd in pysbd.values():
        sbd.stop()


def expect_kernel_mroute(router, source, group, iif, oifs):
    "Wait for the kernel route to use `iif` and forward to `oifs`."
    want = {"iif": iif, "oifs": sorted(oifs)}

    def _check():
        route = kernel_mroutes(router, socket.AF_INET6).get((source, group))
        if route is None:
            return "no kernel route ({}, {})".format(source, group)
        got = {"iif": route["iif"], "oifs": route["oifs"]}
        if got != want:
            return "({}, {}) is {}, want {}".format(source, group, got, want)
        return None

    _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
    assert result is None, "{}: {}".format(router.name, result)


def expect_upstream(router, expected, message, count=60):
    test_func = partial(
        topotest.router_json_cmp, router, "show ipv6 pim upstream json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    assert result is None, "{}: {}".format(router.name, message)


def expect_h1_traffic(duration=5):
    "Wait for h1 to receive the source's traffic."

    def _check():
        report = app_helper.collect_receiver_sources(
            "h1", GROUP, "h1-eth0", duration=duration
        )
        received = report["sources"].get(SOURCE, 0)
        if received == 0:
            return "h1 got no packets from {} in {}s".format(SOURCE, duration)
        return received

    _, result = topotest.run_and_expect_type(_check, int, count=12, wait=1)
    assert isinstance(result, int), result


def link_local(router, ifname):
    "Return the link-local address of the router interface `ifname`."
    output = router.cmd_raises("ip -j -6 addr show dev {}".format(ifname))
    for link in json.loads(output):
        for address in link.get("addr_info", []):
            if address.get("scope") == "link":
                return address["local"]
    return None


def test_pim_neighbors():
    "Wait for PIMv6 adjacencies formed over the pysbd encapsulation."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # PIMv6 neighbors are known by their link-local addresses.
    neighbors = {
        "r1": {"r1-eth0": ("r2", "r2-eth0"), "r1-eth1": ("r3", "r3-eth0")},
        "r2": {"r2-eth0": ("r1", "r1-eth0"), "r2-eth1": ("r3", "r3-eth1")},
        "r3": {"r3-eth0": ("r1", "r1-eth1"), "r3-eth1": ("r2", "r2-eth1")},
    }
    for rname, peers in neighbors.items():

        def _check(rname=rname, peers=peers):
            expected = {}
            for ifname, (peer, peer_ifname) in peers.items():
                address = link_local(tgen.gears[peer], peer_ifname)
                if address is None:
                    return "{} has no link-local address".format(peer_ifname)
                expected[ifname] = {address: {"interface": ifname, "neighbor": address}}
            return topotest.router_json_cmp(
                tgen.gears[rname], "show ipv6 pim neighbor json", expected
            )

        _, result = topotest.run_and_expect(_check, None, count=60, wait=1)
        assert result is None, "{}: PIMv6 neighbors did not come up".format(rname)


def test_mld_join():
    "h1 joins the group: r1 joins the RPT towards r2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_join("h1", GROUP, join_intf="h1-eth0")
    expect_upstream(
        tgen.gears["r2"],
        {GROUP: {"*": {"inboundInterface": "lo"}}},
        "(*,{}) join from r1 not received".format(GROUP),
    )


def check_spt():
    "The traffic reaches h1 over the shortest path tree only."
    tgen = get_topogen()
    r1, r2, r3 = tgen.gears["r1"], tgen.gears["r2"], tgen.gears["r3"]

    # The data plane reported JOIN_SPT and then DATA_START on the SPT.
    expect_upstream(
        r1,
        {
            GROUP: {
                SOURCE: {
                    "inboundInterface": "r1-eth1",
                    "joinState": "Joined",
                    "sptBit": 1,
                }
            }
        },
        "(S,G) did not switch to the SPT",
    )
    expect_kernel_mroute(r1, SOURCE, GROUP, "r1-eth1", ["r1-eth2"])

    # The RP no longer forwards the source to r1, r3 only feeds r1.
    expect_kernel_mroute(r2, SOURCE, GROUP, "r2-eth1", [])
    expect_kernel_mroute(r3, SOURCE, GROUP, "r3-eth2", ["r3-eth0"])
    expect_h1_traffic()


def test_traffic_spt_switch():
    "h2 sends: the data plane events move the traffic to the SPT."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_traffic("h2", GROUP, bind_intf="h2-eth0")
    check_spt()


def test_registers():
    "r3 registered the traffic until r2 (RP) sent a register-stop."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    assert pysbd["r3"].show("flows")["registersSent"] > 0, "r3 sent no registers"

    def _register_stopped():
        for route in pysbd["r3"].show("routes"):
            if (route["source"], route["group"]) != (SOURCE, GROUP):
                continue
            if any(oif["name"] == "pimreg" for oif in route["oifs"]):
                return "r3 still registers: {}".format(route)
            return None
        return "r3 has no route ({}, {})".format(SOURCE, GROUP)

    _, result = topotest.run_and_expect(_register_stopped, None, count=60, wait=1)
    assert result is None, result


def test_data_stop():
    "h2 stops: the data plane reports DATA_STOP and the traffic state goes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_traffic_senders()

    # Nothing else holds r1's (S,G): it goes away.
    expect_upstream(
        tgen.gears["r1"],
        {GROUP: {SOURCE: None}},
        "(S,G) not removed after the traffic stopped",
    )

    # r3 releases the traffic reference (the RP may still join the (S,G)
    # until its keepalive timer expires).
    def _source_released():
        output = tgen.gears["r3"].vtysh_cmd("show ipv6 pim upstream json", isjson=True)
        upstream = output.get(GROUP, {}).get(SOURCE)
        if upstream and upstream.get("sourceStream"):
            return "r3 still holds the traffic: {}".format(upstream)
        return None

    _, result = topotest.run_and_expect(_source_released, None, count=30, wait=1)
    assert result is None, result


def test_traffic_restart():
    "h2 sends again: the traffic moves to the SPT again."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_traffic("h2", GROUP, bind_intf="h2-eth0")
    check_spt()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
