#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_igmp_proxy_self_report.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#

"""
IGMP proxy must not act as a receiver on its own proxy interface.

    h1 ---------- r1 ---------- u1
     (receivers)  |  r1-eth1 (ip igmp proxy)
                  |
                  s1 (source 10.0.30.10, r1 is its first hop)

The reports r1 sends on its proxy interface loop back to r1.  If r1
learns them as membership on the proxy interface, it forwards any stream
it has (here, from its directly connected source) out of the proxy
interface, as if a static route pointed there.  Check that this does not
happen, while real interest on the proxy interface still pulls the
stream there:

1. h1's joins are proxied on r1-eth1, but r1-eth1 does not become an
   outgoing interface and r1 learns no membership on it.
2. A join from another host on r1-eth1 (u1) does.
3. 'ip igmp join-group' on r1-eth1 does, including for a group r1 also
   proxies there.
4. 'ip igmp static-group' on r1-eth1 does.
5. A (*,G) proxy join plus a local (S,G) join on r1-eth1 only yields the
   local (S,G) membership.
6. Removing a local (*,G) join on r1-eth1 while a proxy (S,G) join for
   the same group remains promptly removes the (*,G) membership.
7. The reports the kernel sends when a proxy (S,G) join is removed do
   not leave a membership behind on r1-eth1.
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
from lib.pim import McastTesterHelper

SRC = "10.0.30.10"
G_EXT = "232.1.1.1"  # h1, then u1 too
G_LOCAL = "232.1.1.2"  # r1 join-group on r1-eth1 only
G_BOTH = "232.1.1.3"  # h1 and r1 join-group on r1-eth1
G_STATIC = "232.1.1.4"  # r1 static-group on r1-eth1
G_ASM = "225.1.1.1"  # h1 (*,G)
G_MIXED = "225.5.5.5"  # h1 (*,G), r1 join-group (S,G) on r1-eth1
G_LOCAL_ANY = "225.6.6.6"  # r1 join-group (*,G) on r1-eth1, static (S,G)
G_LEAVE = "232.1.1.5"  # h1 joins, then leaves
STREAMS = [G_EXT, G_LOCAL, G_BOTH, G_STATIC]

app_helper = McastTesterHelper()


def build_topo(tgen):
    "Build function"

    for rname in ["r1", "h1", "u1", "s1"]:
        tgen.add_router(rname)

    # r1-eth0 <-> h1-eth0
    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["h1"])

    # r1-eth1 <-> u1-eth0 (proxy)
    sw = tgen.add_switch("sw2")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["u1"])

    # r1-eth2 <-> s1-eth0 (source)
    sw = tgen.add_switch("sw3")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["s1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()
    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    app_helper.cleanup()
    tgen = get_topogen()
    tgen.stop_topology()


def join(router, ifname, group, source=None, no=False, static=False):
    router.vtysh_cmd(
        "conf\ninterface {}\n{}ip igmp {} {}{}\nend".format(
            ifname,
            "no " if no else "",
            "static-group" if static else "join-group",
            group,
            " " + source if source else "",
        )
    )


def proxied(router, ifname):
    "{(source, group)} proxied on ifname"
    output = json.loads(router.vtysh_cmd("show ip igmp proxy json"))
    groups = output.get(ifname, {}).get("groups", [])
    return {(g["source"], g["group"]) for g in groups}


def igmp_groups(router, ifname):
    "{group: mode} of the IGMP membership r1 holds on ifname"
    output = json.loads(router.vtysh_cmd("show ip igmp groups json"))
    groups = output.get(ifname, {}).get("groups", [])
    return {g["group"]: g.get("mode") for g in groups}


def _check(r1, oil, proxy, members, nonmembers):
    """
    oil: {group: set of outgoing interfaces} for (SRC, group) mroutes
    proxy: (source, group) that must be proxied on r1-eth1
    members/nonmembers: groups r1 must / must not hold membership for on
    r1-eth1
    """
    errors = []
    mroutes = json.loads(r1.vtysh_cmd("show ip mroute json"))
    for grp, want in oil.items():
        entry = mroutes.get(grp, {}).get(SRC, {})
        have = set(entry.get("oil", {}).keys())
        if have != want:
            errors.append("({},{}) oil {}, want {}".format(SRC, grp, have, want))
        elif not entry.get("installed"):
            errors.append("({},{}) not installed".format(SRC, grp))

    have_proxy = proxied(r1, "r1-eth1")
    for key in proxy:
        if key not in have_proxy:
            errors.append("{} not proxied on r1-eth1".format(key))

    groups = igmp_groups(r1, "r1-eth1")
    for grp in members:
        if grp not in groups:
            errors.append("no membership for {} on r1-eth1".format(grp))
    for grp in nonmembers:
        if grp in groups:
            errors.append("membership for {} on r1-eth1".format(grp))

    return "; ".join(errors) if errors else None


def expect(r1, oil=None, proxy=(), members=(), nonmembers=(), count=60):
    test_func = partial(_check, r1, oil or {}, proxy, members, nonmembers)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    assert result is None, "r1: {}".format(result)


def test_start_streams():
    "s1 sources every stream"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for grp in STREAMS:
        app_helper.run_traffic("s1", grp, bind_intf="s1-eth0")


def test_proxy_join_not_a_receiver():
    "Our own proxy reports must not pull the stream onto the proxy interface"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    join(h1, "h1-eth0", G_EXT, SRC)
    join(h1, "h1-eth0", G_ASM)

    expect(
        r1,
        oil={G_EXT: {"r1-eth0"}},
        proxy=[(SRC, G_EXT), ("*", G_ASM)],
        nonmembers=[G_EXT, G_ASM],
    )

    # and stays that way
    expect(
        r1,
        oil={G_EXT: {"r1-eth0"}},
        proxy=[(SRC, G_EXT), ("*", G_ASM)],
        nonmembers=[G_EXT, G_ASM],
        count=5,
    )


def test_external_join():
    "A join from another host on the proxy interface pulls the stream there"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    u1 = tgen.gears["u1"]

    join(u1, "u1-eth0", G_EXT, SRC)
    expect(r1, oil={G_EXT: {"r1-eth0", "r1-eth1"}}, members=[G_EXT])

    join(u1, "u1-eth0", G_EXT, SRC, no=True)
    expect(r1, oil={G_EXT: {"r1-eth0"}}, nonmembers=[G_EXT])


def test_local_join():
    "'ip igmp join-group' on the proxy interface pulls the stream there"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    logger.info("local join only")
    join(r1, "r1-eth1", G_LOCAL, SRC)
    expect(r1, oil={G_LOCAL: {"r1-eth1"}}, members=[G_LOCAL])

    logger.info("local join for a group r1 also proxies on r1-eth1")
    join(h1, "h1-eth0", G_BOTH, SRC)
    expect(r1, oil={G_BOTH: {"r1-eth0"}}, proxy=[(SRC, G_BOTH)], nonmembers=[G_BOTH])
    join(r1, "r1-eth1", G_BOTH, SRC)
    expect(r1, oil={G_BOTH: {"r1-eth0", "r1-eth1"}}, members=[G_BOTH])

    logger.info("removing the local join stops forwarding, proxy stays")
    join(r1, "r1-eth1", G_BOTH, SRC, no=True)
    expect(
        r1,
        oil={G_BOTH: {"r1-eth0"}},
        proxy=[(SRC, G_BOTH)],
        nonmembers=[G_BOTH],
    )


def test_static_group():
    "'ip igmp static-group' on the proxy interface pulls the stream there"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    join(r1, "r1-eth1", G_STATIC, SRC, static=True)
    expect(r1, oil={G_STATIC: {"r1-eth1"}})


def test_mixed_proxy_asm_local_ssm():
    "(*,G) proxy join plus local (S,G) join: only the local (S,G) is learned"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    join(h1, "h1-eth0", G_MIXED)
    expect(r1, proxy=[("*", G_MIXED)], nonmembers=[G_MIXED])

    # The kernel reports EXCLUDE {} for G on r1-eth1 (the proxy's (*,G)
    # wins); r1 must take only the local (S,G) from it.
    join(r1, "r1-eth1", G_MIXED, SRC)

    def _check_mixed():
        groups = igmp_groups(r1, "r1-eth1")
        if groups.get(G_MIXED) != "INCLUDE":
            return "{} on r1-eth1: {}".format(G_MIXED, groups.get(G_MIXED))
        output = json.loads(r1.vtysh_cmd("show ip igmp sources json"))
        srcs = output.get("r1-eth1", {}).get(G_MIXED, {}).get("sources", [])
        srcs = sorted(s["source"] for s in srcs)
        if srcs != [SRC]:
            return "{} sources on r1-eth1: {}".format(G_MIXED, srcs)
        return None

    _, result = topotest.run_and_expect(_check_mixed, None, count=60, wait=1)
    assert result is None, "r1: {}".format(result)


def test_local_asm_removed_from_proxy_ssm():
    "Removing a local (*,G) while a proxy (S,G) remains leaves the group"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # A local (*,G) needs an ASM group.  IGMP reports do not create PIM
    # state for an ASM (S,G), but a static (S,G) group does, and is proxied.
    join(r1, "r1-eth0", G_LOCAL_ANY, SRC, static=True)
    expect(r1, proxy=[(SRC, G_LOCAL_ANY)], nonmembers=[G_LOCAL_ANY])
    join(r1, "r1-eth1", G_LOCAL_ANY)
    expect(r1, proxy=[(SRC, G_LOCAL_ANY)], members=[G_LOCAL_ANY])

    # The kernel now reports TO_IN {SRC} on r1-eth1, all of it owed to the
    # proxy join; r1 must still take it as a leave for the (*,G) it
    # learned, instead of keeping it until the membership times out.  Stop
    # IGMP on u1 so r1 cannot rely on u1's group-specific queries.
    u1 = tgen.gears["u1"]
    u1.vtysh_cmd("conf\ninterface u1-eth0\nno ip igmp\nend")
    join(r1, "r1-eth1", G_LOCAL_ANY, no=True)
    expect(r1, proxy=[(SRC, G_LOCAL_ANY)], nonmembers=[G_LOCAL_ANY], count=15)

    u1.vtysh_cmd("conf\ninterface u1-eth0\nip igmp\nend")
    join(r1, "r1-eth0", G_LOCAL_ANY, SRC, static=True, no=True)


def test_proxy_leave_no_membership():
    "Removing a proxy (S,G) join leaves no membership on the proxy interface"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]

    join(h1, "h1-eth0", G_LEAVE, SRC)
    expect(r1, proxy=[(SRC, G_LEAVE)], nonmembers=[G_LEAVE])

    # The kernel reports BLOCK {SRC} on r1-eth1, after the proxy join is
    # gone, and repeats it.  It must not create a group on r1-eth1.
    join(h1, "h1-eth0", G_LEAVE, SRC, no=True)

    def _check_gone():
        if (SRC, G_LEAVE) in proxied(r1, "r1-eth1"):
            return "({},{}) still proxied".format(SRC, G_LEAVE)
        return None

    _, result = topotest.run_and_expect(_check_gone, None, count=30, wait=1)
    assert result is None, "r1: {}".format(result)
    # let the repeated reports arrive
    topotest.sleep(5)
    expect(r1, nonmembers=[G_LEAVE], count=1)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
