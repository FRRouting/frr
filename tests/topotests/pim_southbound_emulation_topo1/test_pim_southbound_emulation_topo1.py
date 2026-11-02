#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_southbound_emulation_topo1.py
#
# Copyright (c) 2026 by Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_southbound_emulation_topo1.py: PIM-SM through the vendor southbound
with `pysbd` emulating the data plane events (`-a`).

        +----+    10.0.12.0/24   +----+
  h1 ---| r1 |-------------------| r2 | (RP 10.254.0.2)
        +----+                   +----+
           \\                      /
 10.0.13.0/24 \\                  / 10.0.23.0/24
                \\    +----+     /
                 ----| r3 |-----
                     +----+
                        |
                       h2 (source 192.168.3.10)

Nothing is typed into `pysbd`: it watches the traffic and reports it the way
a vendor data plane does. h1 joins 224.100.0.1 and h2 sends to it:

- r3 (FHR) sends the traffic in registers to r2 (RP) until it gets a
  register-stop.
- r1 (LHR) reports JOIN_SPT when the RPT traffic arrives and DATA_START once
  it arrives on the shortest path tree: it sets the SPT bit and prunes the
  source off the RPT.
- When h2 stops, the data plane reports DATA_STOP and the (S,G) state goes
  away; when h2 sends again, the same happens all over.

Last, an interface created while `pysbd` runs gets its multicast interfaces
(and loses them when removed).
"""

import os
import sys
from functools import partial

import pytest

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.pim import McastTesterHelper
from lib.pysbd.helper import Pysbd, kernel_mroutes
from lib.topogen import Topogen, get_topogen

GROUP = "224.100.0.1"
SOURCE = "192.168.3.10"
#: Seconds without packets before the data plane considers the traffic gone.
DATA_TIMEOUT = 3

pysbd = {}
app_helper = McastTesterHelper()


def build_topo(tgen):
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    tgen.add_host("h1", "192.168.1.10/24", "via 192.168.1.1")
    tgen.add_host("h2", "192.168.3.10/24", "via 192.168.3.1")

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
        pysbd[router.name] = Pysbd(
            router,
            [
                "-a",
                "-t",
                str(DATA_TIMEOUT),
                "-E",
                "-p",
                "ipv4:127.0.0.1",
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
                ("pimd", "-M southbound:ipv4c:127.0.0.1"),
            ],
        )

    tgen.start_router()

    for sbd in pysbd.values():
        sbd.wait_connected("pim")
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
        route = kernel_mroutes(router).get((source, group))
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
        topotest.router_json_cmp, router, "show ip pim upstream json", expected
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


def test_pim_neighbors():
    "Wait for PIM adjacencies formed over the pysbd encapsulation."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    neighbors = {
        "r1": {"r1-eth0": "10.0.12.2", "r1-eth1": "10.0.13.3"},
        "r2": {"r2-eth0": "10.0.12.1", "r2-eth1": "10.0.23.3"},
        "r3": {"r3-eth0": "10.0.13.1", "r3-eth1": "10.0.23.2"},
    }
    for rname, expected in neighbors.items():
        expected = {
            ifname: {address: {"interface": ifname, "neighbor": address}}
            for ifname, address in expected.items()
        }
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rname],
            "show ip pim neighbor json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "{}: PIM neighbors did not come up".format(rname)


def test_igmp_join():
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

    # r3 releases the traffic reference. The RP keeps its (S,G) until its
    # keepalive timer (restarted by the registers) expires, and joins it
    # meanwhile: r3 may still have the entry for that join.
    def _source_released():
        output = tgen.gears["r3"].vtysh_cmd("show ip pim upstream json", isjson=True)
        upstream = output.get(GROUP, {}).get(SOURCE)
        if upstream and upstream.get("sourceStream"):
            return "r3 still holds the traffic: {}".format(upstream)
        return None

    _, result = topotest.run_and_expect(_source_released, None, count=30, wait=1)
    assert result is None, result

    # The receiver still has its RPT.
    expect_upstream(
        tgen.gears["r1"],
        {GROUP: {"*": {"inboundInterface": "r1-eth0"}}},
        "(*,G) lost",
        count=5,
    )


def test_traffic_restart():
    "h2 sends again: the traffic moves to the SPT again."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.run_traffic("h2", GROUP, bind_intf="h2-eth0")
    check_spt()


def test_interface_after_start():
    "An interface created while pysbd runs gets multicast interfaces."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.cmd_raises("ip link add r1-dummy0 type dummy")
    r1.cmd_raises("ip addr add 10.99.0.1/24 dev r1-dummy0")
    r1.cmd_raises("ip link set r1-dummy0 up")

    def _interface():
        for interface in pysbd["r1"].show("interfaces"):
            if interface["name"] == "r1-dummy0":
                return interface
        return None

    def _enabled():
        interface = _interface()
        if interface is None or not interface["vif"] or not interface["mif"]:
            return "r1-dummy0 not multicast enabled: {}".format(interface)
        return None

    _, result = topotest.run_and_expect(_enabled, None, count=10, wait=1)
    assert result is None, result

    vifs = r1.cmd("cat /proc/net/ip_mr_vif")
    assert "r1-dummy0" in vifs, "r1-dummy0 has no kernel VIF:\n{}".format(vifs)

    r1.cmd_raises("ip link del r1-dummy0")

    def _removed():
        if _interface() is not None:
            return "r1-dummy0 still known"
        return None

    _, result = topotest.run_and_expect(_removed, None, count=10, wait=1)
    assert result is None, result

    # The existing interfaces kept theirs.
    names = [i["name"] for i in pysbd["r1"].show("interfaces") if i["vif"]]
    assert {"lo", "r1-eth0", "r1-eth1", "r1-eth2"} <= set(names), names


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
