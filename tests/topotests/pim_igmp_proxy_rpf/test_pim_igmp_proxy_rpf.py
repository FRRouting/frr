#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_igmp_proxy_rpf.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#

"""
Test IGMP proxy RPF mode ('igmp proxy rpf').

            10.0.10.0/24           10.0.20.0/24
    h1 ------------------- r1 ------------------- u1   10.1.0.0/16 via u1
    (receivers)          / |  \\  (proxy r1-eth1)
                        /  |   \\
          10.0.40.0/24 /   |    \\ 10.0.30.0/24
        (local source LAN) |     ------------------ u2   10.2.0.0/16 via u2
                           |       (proxy r1-eth2)

r1 has two proxy interfaces, r1-eth1 (toward u1) and r1-eth2 (toward u2). h1 plays the downstream receivers, u1 also
plays a downstream proxy that sends its joins to r1 over r1-eth1.

1. (S,G) joins go only to the proxy interface that is RPF toward S;
   (*,G) still goes to every proxy interface.
2. A source on a local LAN (RPF not a proxy interface): no proxy join.
3. No route to S: pending, joined once a route appears.
4. RPF change moves the join to the new proxy interface.
5. Memberships learned on a proxy interface are relayed toward S only,
   and never echoed back out the interface they arrived on.
6. A leave on one downstream keeps the join while another downstream
   still wants the (S,G); the last leave removes it.
7. Disabling PIM on the RPF proxy interface withdraws the join (the RPF
   lookup needs PIM there); re-enabling it restores the join.
8. 'no igmp proxy rpf' restores proxying on every proxy interface, and
   turning it back on returns to RPF-only joins, static groups included.
"""

import os
import sys
import json
from functools import partial
import pytest

pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

S1 = "10.1.0.10"  # via u1, r1-eth1
S2 = "10.2.0.10"  # via u2, r1-eth2
S3 = "10.0.40.10"  # local LAN on r1-eth3
S4 = "10.4.0.10"  # no route until test_pending_join


def build_topo(tgen):
    "Build function"

    for rname in ["r1", "h1", "u1", "u2"]:
        tgen.add_router(rname)

    # r1-eth0 <-> h1-eth0
    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["h1"])

    # r1-eth1 <-> u1-eth0
    sw = tgen.add_switch("sw2")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["u1"])

    # r1-eth2 <-> u2-eth0
    sw = tgen.add_switch("sw3")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["u2"])

    # r1-eth3: local source LAN
    sw = tgen.add_switch("sw4")
    sw.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def proxy_joins(router):
    "Return {(proxy ifname, source, group): [downstream ifnames]}"
    output = json.loads(router.vtysh_cmd("show ip igmp proxy json"))
    joins = {}
    for ifname, data in output.items():
        if not isinstance(data, dict):
            continue
        for grp in data.get("groups", []):
            key = (ifname, grp["source"], grp["group"])
            joins[key] = sorted(grp.get("downstreamInterfaces", []))
    return joins


def _check_joins(router, expected, absent):
    joins = proxy_joins(router)
    errors = []
    for key, downstream in expected.items():
        if key not in joins:
            errors.append("missing {}".format(key))
        elif downstream is not None and joins[key] != sorted(downstream):
            errors.append(
                "{} downstream {} != {}".format(key, joins[key], sorted(downstream))
            )
    for key in absent:
        if key in joins:
            errors.append("unexpected {}".format(key))
    if errors:
        return "{}: {} (have {})".format(router.name, "; ".join(errors), joins)
    return None


def expect_joins(router, expected, absent=(), count=60):
    "Wait until all expected proxy joins exist and no absent one does"
    test_func = partial(_check_joins, router, expected, absent)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    assert result is None, result


def join(router, ifname, group, source=None, no=False):
    router.vtysh_cmd(
        "conf\ninterface {}\n{}ip igmp join-group {}{}\nend".format(
            ifname, "no " if no else "", group, " " + source if source else ""
        )
    )


def everywhere(source, group):
    "All proxy interface keys for (source, group)"
    return [("r1-eth1", source, group), ("r1-eth2", source, group)]


def test_rpf_joins():
    "(S,G) proxied only on the RPF proxy interface, (*,G) on all"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    logger.info("h1 joins (S1,232.1.1.1), (S2,232.1.1.2) and (*,225.1.1.1)")
    join(h1, "h1-eth0", "232.1.1.1", S1)
    join(h1, "h1-eth0", "232.1.1.2", S2)
    join(h1, "h1-eth0", "225.1.1.1")

    expect_joins(
        r1,
        {
            ("r1-eth1", S1, "232.1.1.1"): ["r1-eth0"],
            ("r1-eth2", S2, "232.1.1.2"): ["r1-eth0"],
            ("r1-eth1", "*", "225.1.1.1"): ["r1-eth0"],
            ("r1-eth2", "*", "225.1.1.1"): ["r1-eth0"],
        },
        absent=[("r1-eth2", S1, "232.1.1.1"), ("r1-eth1", S2, "232.1.1.2")],
    )


def test_first_hop():
    "Source on a local LAN: this router is the first hop, no proxy join"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    join(h1, "h1-eth0", "232.1.1.3", S3)

    # wait for r1 to have learned the membership, then check no proxy join
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip igmp sources json",
        {"r1-eth0": {"232.1.1.3": {"sources": [{"source": S3}]}}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not learn (S3,232.1.1.3) on r1-eth0"

    expect_joins(r1, {}, absent=everywhere(S3, "232.1.1.3"), count=5)


def test_pending_join():
    "No route to S: the join is held and sent once a route appears"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    join(h1, "h1-eth0", "232.1.1.4", S4)

    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip igmp sources json",
        {"r1-eth0": {"232.1.1.4": {"sources": [{"source": S4}]}}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not learn (S4,232.1.1.4) on r1-eth0"

    expect_joins(r1, {}, absent=everywhere(S4, "232.1.1.4"), count=5)

    logger.info("add a route to S4 via u2, join must appear on r1-eth2")
    r1.vtysh_cmd("conf\nip route 10.4.0.0/16 10.0.30.2\nend")
    expect_joins(
        r1,
        {("r1-eth2", S4, "232.1.1.4"): ["r1-eth0"]},
        absent=[("r1-eth1", S4, "232.1.1.4")],
    )

    logger.info("withdraw the route, join must go away again")
    r1.vtysh_cmd("conf\nno ip route 10.4.0.0/16 10.0.30.2\nend")
    expect_joins(r1, {}, absent=everywhere(S4, "232.1.1.4"))


def test_rpf_change():
    "RPF change moves the join to the new proxy interface"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("more specific route to S1 via u2")
    r1.vtysh_cmd("conf\nip route 10.1.0.0/24 10.0.30.2\nend")
    expect_joins(
        r1,
        {("r1-eth2", S1, "232.1.1.1"): ["r1-eth0"]},
        absent=[("r1-eth1", S1, "232.1.1.1")],
    )

    logger.info("remove it, S1 is back via u1")
    r1.vtysh_cmd("conf\nno ip route 10.1.0.0/24 10.0.30.2\nend")
    expect_joins(
        r1,
        {("r1-eth1", S1, "232.1.1.1"): ["r1-eth0"]},
        absent=[("r1-eth2", S1, "232.1.1.1")],
    )


def test_relay():
    "Memberships learned on a proxy interface are relayed toward S only"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    u1 = tgen.gears["u1"]

    logger.info("u1 joins (S2,232.1.2.2) and (S1,232.1.2.1) toward r1-eth1")
    join(u1, "u1-eth0", "232.1.2.2", S2)
    join(u1, "u1-eth0", "232.1.2.1", S1)

    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip igmp sources json",
        {"r1-eth1": {"232.1.2.1": {"sources": [{"source": S1}]}}},
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not learn (S1,232.1.2.1) on r1-eth1"

    # (S2,G) relayed to u2; (S1,G) has RPF == arrival interface: no echo
    expect_joins(
        r1,
        {("r1-eth2", S2, "232.1.2.2"): ["r1-eth1"]},
        absent=[("r1-eth1", S2, "232.1.2.2")] + everywhere(S1, "232.1.2.1"),
    )


def test_leave():
    "Prune only when no other downstream still wants the (S,G)"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    u1 = tgen.gears["u1"]

    logger.info("h1 also joins (S2,232.1.2.2)")
    join(h1, "h1-eth0", "232.1.2.2", S2)
    expect_joins(r1, {("r1-eth2", S2, "232.1.2.2"): ["r1-eth0", "r1-eth1"]})

    logger.info("h1 leaves, u1 still wants it")
    join(h1, "h1-eth0", "232.1.2.2", S2, no=True)
    expect_joins(r1, {("r1-eth2", S2, "232.1.2.2"): ["r1-eth1"]})

    logger.info("u1 leaves, join must be pruned")
    join(u1, "u1-eth0", "232.1.2.2", S2, no=True)
    expect_joins(r1, {}, absent=everywhere(S2, "232.1.2.2"))

    logger.info("h1 leaves (S2,232.1.1.2)")
    join(h1, "h1-eth0", "232.1.1.2", S2, no=True)
    expect_joins(
        r1,
        {("r1-eth1", S1, "232.1.1.1"): ["r1-eth0"]},
        absent=everywhere(S2, "232.1.1.2"),
    )


def test_pim_toggle():
    "Disabling PIM on the RPF proxy interface withdraws the join, re-enabling restores it"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # The RPF lookup only accepts interfaces with PIM enabled
    r1.vtysh_cmd("conf\ninterface r1-eth1\nno ip pim\nend")
    expect_joins(r1, {}, absent=everywhere(S1, "232.1.1.1"))

    r1.vtysh_cmd("conf\ninterface r1-eth1\nip pim\nend")
    expect_joins(
        r1,
        {("r1-eth1", S1, "232.1.1.1"): ["r1-eth0"]},
        absent=[("r1-eth2", S1, "232.1.1.1")],
    )


def test_mode_toggle():
    "'no igmp proxy rpf' proxies (S,G) everywhere; re-enable restores RPF"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # A static group must be proxied again after each mode change
    r1.vtysh_cmd(
        "conf\ninterface r1-eth0\nip igmp static-group 232.1.1.5 {}\nend".format(S2)
    )
    expect_joins(
        r1,
        {("r1-eth2", S2, "232.1.1.5"): ["r1-eth0"]},
        absent=[("r1-eth1", S2, "232.1.1.5")],
    )

    output = r1.vtysh_cmd("show running-config")
    assert "igmp proxy rpf" in output, "missing from running-config"

    r1.vtysh_cmd("conf\nrouter pim\nno igmp proxy rpf\nend")
    output = r1.vtysh_cmd("show running-config")
    assert "igmp proxy rpf" not in output, "still in running-config"

    expect_joins(
        r1,
        {
            ("r1-eth1", S1, "232.1.1.1"): None,
            ("r1-eth2", S1, "232.1.1.1"): None,
            ("r1-eth1", S3, "232.1.1.3"): None,
            ("r1-eth2", S3, "232.1.1.3"): None,
            ("r1-eth1", S2, "232.1.1.5"): None,
            ("r1-eth2", S2, "232.1.1.5"): None,
        },
    )

    # Proxy joins echoed back while in the old mode are learned as
    # memberships on the proxy interfaces; they age out once r1 stops
    # reporting them, after which only the real interest remains.
    r1.vtysh_cmd("conf\nrouter pim\nigmp proxy rpf\nend")
    expect_joins(
        r1,
        {
            ("r1-eth1", S1, "232.1.1.1"): ["r1-eth0"],
            ("r1-eth2", S2, "232.1.1.5"): ["r1-eth0"],
            ("r1-eth1", "*", "225.1.1.1"): None,
            ("r1-eth2", "*", "225.1.1.1"): None,
        },
        absent=[("r1-eth2", S1, "232.1.1.1"), ("r1-eth1", S2, "232.1.1.5")]
        + everywhere(S3, "232.1.1.3")
        + everywhere(S1, "232.1.2.1")
        + everywhere(S2, "232.1.1.2")
        + everywhere(S2, "232.1.2.2"),
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
