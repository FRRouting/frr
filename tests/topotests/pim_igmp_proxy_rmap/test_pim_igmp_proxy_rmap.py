#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_igmp_proxy_rmap.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#

"""
Proxy route-map changes recompute joins without cycling the proxy.

    h1 ---- r1-eth0    r1-eth1 (ip igmp proxy) ---- u1

h1 joins 225.1.1.1 before any route-map is attached, so r1 proxies it.
Attaching a denying route-map must withdraw that join, and removing the
deny must install it again. Editing a prefix-list the route-map matches
must do the same.
"""

import os
import sys
import json
import pytest

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

GRP = "225.1.1.1"


def build_topo(tgen):
    "Build function"

    for rname in ["r1", "h1", "u1"]:
        tgen.add_router(rname)

    tgen.add_link(tgen.gears["r1"], tgen.gears["h1"], "r1-eth0", "h1-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["u1"], "r1-eth1", "u1-eth0")

    # Second downstream, so a (*,G) there can cover an (S,G) on r1-eth0.
    r1 = tgen.gears["r1"]
    r1.run("ip link add r1-eth2 type dummy")
    r1.run("ip link set r1-eth2 up")
    r1.run("ip addr add 10.0.3.1/24 dev r1-eth2")


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


def proxy_has(r1, group):
    "True when r1-eth1 proxies group"
    output = json.loads(r1.vtysh_cmd("show ip igmp proxy json"))
    groups = output.get("r1-eth1", {}).get("groups", [])
    return any(g.get("group") == group for g in groups)


def proxy_sg(r1, source, group):
    "True when r1-eth1 proxies this source and group"
    output = json.loads(r1.vtysh_cmd("show ip igmp proxy json"))
    groups = output.get("r1-eth1", {}).get("groups", [])
    return any(g.get("source") == source and g.get("group") == group for g in groups)


def wait_proxied(r1, present):
    "Wait until GRP is proxied on r1-eth1, or absent when present is False"

    def check():
        have = proxy_has(r1, GRP)
        if have != present:
            return "proxied={}, want {}".format(have, present)
        return None

    _, result = topotest.run_and_expect(check, None, count=40, wait=0.5)
    assert result is None, "proxy state for {}: {}".format(GRP, result)


def test_route_map_attach_withdraws_and_restores():
    "Attaching a denying proxy route-map withdraws the join; removing it restores it"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("membership is proxied before any route-map exists")
    wait_proxied(r1, True)

    logger.info("attach a route-map that denies the group")
    r1.vtysh_cmd(
        """
conf
ip prefix-list OTHER seq 5 permit 225.9.9.9/32
route-map PROXY_FILTER permit 10
 match ip multicast-group prefix-list OTHER
interface r1-eth1
 ip igmp proxy route-map PROXY_FILTER
"""
    )
    wait_proxied(r1, False)

    logger.info("remove the deny by permitting the joined group")
    r1.vtysh_cmd(
        """
conf
ip prefix-list OTHER seq 10 permit 225.1.1.1/32
"""
    )
    wait_proxied(r1, True)

    logger.info(
        "tighten the prefix-list again; the join must go without detaching the map"
    )
    r1.vtysh_cmd(
        """
conf
no ip prefix-list OTHER seq 10 permit 225.1.1.1/32
"""
    )
    wait_proxied(r1, False)

    logger.info("detach the route-map; the join must come back")
    r1.vtysh_cmd(
        """
conf
interface r1-eth1
 no ip igmp proxy route-map
"""
    )
    wait_proxied(r1, True)

    logger.info("a permit entry matching another group withdraws the join")
    r1.vtysh_cmd(
        """
conf
route-map PROXY_FILTER permit 10
 no match ip multicast-group prefix-list OTHER
 match ip multicast-group 225.9.9.9
interface r1-eth1
 ip igmp proxy route-map PROXY_FILTER
"""
    )
    wait_proxied(r1, False)

    logger.info("removing that match permits the joined group again")
    r1.vtysh_cmd(
        """
conf
route-map PROXY_FILTER permit 10
 no match ip multicast-group 225.9.9.9
"""
    )
    wait_proxied(r1, True)


def test_route_map_call_removed():
    "Removing a denying 'call' from the proxy route-map restores the join"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    wait_proxied(r1, True)

    logger.info("call a route-map that denies the group")
    r1.vtysh_cmd(
        """
conf
route-map PROXY_CHILD deny 10
route-map PROXY_FILTER permit 10
 call PROXY_CHILD
"""
    )
    wait_proxied(r1, False)

    logger.info("remove the call; the join must come back")
    r1.vtysh_cmd(
        """
conf
route-map PROXY_FILTER permit 10
 no call
"""
    )
    wait_proxied(r1, True)


SRC2 = "10.20.0.10"
GRP_RPF = "232.1.1.20"
GRP_STATIC = "232.1.1.21"


def upstream_iif(r1, group, source):
    "RPF interface of r1's upstream, None if there is no upstream"
    output = json.loads(r1.vtysh_cmd("show ip pim upstream json"))
    grp = output.get(group, {})
    entry = grp.get(source)
    if entry is None and source == "*":
        entry = grp.get("0.0.0.0")
    if not entry:
        return None
    return entry.get("inboundInterface")


def wait_for(check, what):
    _, result = topotest.run_and_expect(check, None, count=40, wait=0.5)
    assert result is None, "{}: {}".format(what, result)


def proxy_unfiltered(r1):
    "Route to SRC2 over the proxy and no proxy route-map"
    r1.vtysh_cmd(
        """
conf
ip route 10.20.0.0/24 10.0.2.2
interface r1-eth1
 no ip igmp proxy route-map
"""
    )


def test_leave_keeps_join_for_static_group():
    "A host leave does not prune a join a static group on that interface needs"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    h1 = tgen.gears["h1"]
    proxy_unfiltered(r1)

    def h1_join(no=False):
        h1.vtysh_cmd(
            "conf\ninterface h1-eth0\n {}ip igmp join {} {}\n".format(
                "no " if no else "", GRP_STATIC, SRC2
            )
        )

    def r1_static(no=False):
        r1.vtysh_cmd(
            "conf\ninterface r1-eth0\n {}ip igmp static-group {} {}\n".format(
                "no " if no else "", GRP_STATIC, SRC2
            )
        )

    def igmp_source(present):
        def check():
            out = json.loads(r1.vtysh_cmd("show ip igmp sources json"))
            have = GRP_STATIC in out.get("r1-eth0", {})
            if have != present:
                return "IGMP has {}: {}".format(GRP_STATIC, have)
            return None

        return check

    def proxied(present):
        def check():
            have = proxy_sg(r1, SRC2, GRP_STATIC)
            if have != present:
                return "proxied {}".format(have)
            return None

        return check

    logger.info("host leaves, static group on the same interface remains")
    h1_join()
    r1_static()
    wait_for(igmp_source(True), "h1 membership")
    wait_for(proxied(True), "joined")
    h1_join(no=True)
    wait_for(igmp_source(False), "h1 left")
    topotest.sleep(2)
    assert proxied(True)() is None, "static group lost its join on host leave"

    logger.info("static group removed, host membership remains")
    h1_join()
    wait_for(igmp_source(True), "h1 membership")
    r1_static(no=True)
    topotest.sleep(2)
    assert proxied(True)() is None, "host lost its join on static removal"

    logger.info("last one leaves")
    h1_join(no=True)
    wait_for(proxied(False), "pruned")


def test_rpf_needs_proxy_route_map_permit():
    "The proxy RPF waiver needs the route-map to permit the receiver's interface"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("route to the source over the proxy, which has no PIM neighbor")
    r1.vtysh_cmd(
        """
conf
ip route 10.20.0.0/24 10.0.2.2
route-map PROXY_IF permit 10
 match multicast-source-interface r1-eth2
interface r1-eth1
 no ip igmp proxy route-map PROXY_SG
 ip igmp proxy route-map PROXY_IF
interface r1-eth0
 ip igmp static-group {grp} {src}
""".format(
            grp=GRP_RPF, src=SRC2
        )
    )

    def denied():
        iif = upstream_iif(r1, GRP_RPF, SRC2)
        if iif is None:
            return "no upstream"
        if iif == "r1-eth1":
            return "RPF on the proxy, which never sends the join"
        if proxy_sg(r1, SRC2, GRP_RPF):
            return "(S,G) proxied despite the route-map"
        return None

    wait_for(denied, "receiver on r1-eth0 is denied")
    topotest.sleep(2)
    assert denied() is None, "after settling: {}".format(denied())

    logger.info("drop the route-map: the join and the proxy RPF must follow")
    r1.vtysh_cmd(
        """
conf
interface r1-eth1
 no ip igmp proxy route-map PROXY_IF
"""
    )

    def permitted():
        if not proxy_sg(r1, SRC2, GRP_RPF):
            return "(S,G) not proxied"
        iif = upstream_iif(r1, GRP_RPF, SRC2)
        if iif != "r1-eth1":
            return "RPF {}".format(iif)
        return None

    wait_for(permitted, "receiver on r1-eth0 is permitted")


def test_no_ip_igmp_on_proxy():
    "Turning IGMP off on the proxy removes its joins and its RPF waiver"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    proxy_unfiltered(r1)
    r1.vtysh_cmd(
        "conf\ninterface r1-eth0\n ip igmp static-group {} {}\n".format(
            GRP_RPF, SRC2
        )
    )

    def joined():
        if not proxy_sg(r1, SRC2, GRP_RPF):
            return "(S,G) not proxied"
        iif = upstream_iif(r1, GRP_RPF, SRC2)
        if iif != "r1-eth1":
            return "RPF {}".format(iif)
        return None

    wait_for(joined, "proxied over r1-eth1")

    r1.vtysh_cmd("conf\ninterface r1-eth1\n no ip igmp\n")

    def gone():
        if proxy_sg(r1, SRC2, GRP_RPF):
            return "(S,G) still proxied"
        joins = r1.vtysh_cmd("show ip igmp join")
        if GRP_RPF in joins:
            return "proxy join still in place"
        iif = upstream_iif(r1, GRP_RPF, SRC2)
        if iif == "r1-eth1":
            return "RPF still on r1-eth1"
        return None

    wait_for(gone, "no ip igmp on the proxy")

    r1.vtysh_cmd("conf\ninterface r1-eth1\n ip igmp\n ip igmp proxy\n")

    def back():
        if not proxy_sg(r1, SRC2, GRP_RPF):
            return "(S,G) not proxied"
        iif = upstream_iif(r1, GRP_RPF, SRC2)
        if iif != "r1-eth1":
            return "RPF {}".format(iif)
        return None

    wait_for(back, "ip igmp on the proxy again")

    r1.vtysh_cmd(
        "conf\ninterface r1-eth0\n no ip igmp static-group {} {}\n".format(
            GRP_RPF, SRC2
        )
    )
    wait_for(
        lambda: "still proxied" if proxy_sg(r1, SRC2, GRP_RPF) else None,
        "static group removed",
    )


def _send_igmpv3(rtype, group, sources):
    "Send one IGMPv3 report from h1"
    cmd = (
        "python3 {cwd}/../lib/packet/igmp/igmp_v3.py"
        " --src_ip=10.0.1.2 --iface=h1-eth0 --maddr={group}"
        " --rtype={rtype} --enable_router_alert"
    ).format(cwd=CWD, group=group, rtype=rtype)
    for source in sources:
        cmd += " --source={}".format(source)
    get_topogen().gears["h1"].run(cmd)


def test_exclude_list_drops_starg_proxy():
    "EXCLUDE {} becoming EXCLUDE {S} drops the proxy (*,G) join"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    group = "225.7.7.7"
    source = "10.9.9.9"

    r1.vtysh_cmd(
        """
conf
interface r1-eth1
 ip igmp
 ip igmp proxy
 no ip igmp proxy route-map
"""
    )

    logger.info("EXCLUDE {} is proxied as (*,G)")
    _send_igmpv3(2, group, [])

    def joined():
        if not proxy_sg(r1, "*", group):
            return "(*,G) not proxied"
        return None

    _, result = topotest.run_and_expect(joined, None, count=40, wait=0.5)
    assert result is None, result

    logger.info("EXCLUDE {S} must drop the proxy (*,G) join")
    _send_igmpv3(2, group, [source])

    def switched():
        out = json.loads(r1.vtysh_cmd("show ip igmp sources json"))
        groups = out.get("r1-eth0", {}).get(group, {})
        sources = groups.get("sources", [])
        if not any(s.get("source") == source for s in sources):
            return "excluded source not installed"
        if proxy_sg(r1, "*", group):
            return "(*,G) proxy still installed"
        return None

    _, result = topotest.run_and_expect(switched, None, count=40, wait=0.5)
    assert result is None, result


def test_starg_rpf_uses_wildcard_source():
    "A (*,G) proxy route-map is matched as 0.0.0.0, not the RP address"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    group = "225.9.8.7"
    rp = "10.30.0.1"

    logger.info("permit only source 0.0.0.0; the RP is reached via the proxy")
    r1.vtysh_cmd(
        """
conf
ip route 10.30.0.0/24 10.0.2.2
ip prefix-list ONLY_STAR seq 5 permit 0.0.0.0/32
route-map PROXY_STAR permit 10
 match ip multicast-source prefix-list ONLY_STAR
router pim
 rp {rp} {group}/32
interface r1-eth1
 ip igmp proxy route-map PROXY_STAR
interface r1-eth0
 ip igmp static-group {group}
""".format(
            rp=rp, group=group
        )
    )

    def on_proxy():
        if not proxy_sg(r1, "*", group):
            return "(*,G) not proxied"
        iif = upstream_iif(r1, group, "*")
        if iif != "r1-eth1":
            return "RPF {}".format(iif)
        return None

    wait_for(on_proxy, "(*,G) RPF on the proxy")

    r1.vtysh_cmd(
        """
conf
interface r1-eth0
 no ip igmp static-group {group}
interface r1-eth1
 no ip igmp proxy route-map PROXY_STAR
router pim
 no rp {rp} {group}/32
no ip route 10.30.0.0/24 10.0.2.2
""".format(
            rp=rp, group=group
        )
    )

def test_permitted_leave_moves_rpf_off_proxy():
    "When the last permitted receiver leaves, RPF must leave the proxy"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    group = "232.1.1.30"
    source = "10.20.0.30"

    logger.info("permitted and denied receivers share an (S,G) reached via the proxy")
    r1.vtysh_cmd(
        """
conf
ip route 10.20.0.0/24 10.0.2.2
interface r1-eth2
 ip address 10.0.3.1/24
 ip pim
 ip igmp
route-map PROXY_LEAVE permit 10
 match multicast-source-interface r1-eth2
interface r1-eth1
 ip igmp proxy route-map PROXY_LEAVE
interface r1-eth2
 ip igmp static-group {group} {source}
interface r1-eth0
 ip igmp static-group {group} {source}
""".format(
            group=group, source=source
        )
    )

    def on_proxy():
        if not proxy_sg(r1, source, group):
            return "(S,G) not proxied"
        iif = upstream_iif(r1, group, source)
        if iif != "r1-eth1":
            return "RPF {}".format(iif)
        return None

    wait_for(on_proxy, "RPF on the proxy while a permitted receiver remains")

    logger.info("permitted receiver leaves; the denied one must not stay on the proxy")
    r1.vtysh_cmd(
        """
conf
interface r1-eth2
 no ip igmp static-group {group} {source}
""".format(
            group=group, source=source
        )
    )

    def moved():
        if proxy_sg(r1, source, group):
            return "proxy join still installed"
        iif = upstream_iif(r1, group, source)
        if iif == "r1-eth1":
            return "RPF still on the proxy"
        return None

    wait_for(moved, "RPF left the proxy")

    r1.vtysh_cmd(
        """
conf
interface r1-eth0
 no ip igmp static-group {group} {source}
interface r1-eth1
 no ip igmp proxy route-map PROXY_LEAVE
""".format(
            group=group, source=source
        )
    )
