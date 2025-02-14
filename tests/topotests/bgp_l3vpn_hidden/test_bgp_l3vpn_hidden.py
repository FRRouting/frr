#!/usr/bin/env python
# SPDX-License-Identifier: ISC


"""
Test BGP hidden
See https://github.com/FRRouting/frr/commit/4d0e7a49cf8d4311a485281fa50bbff6ee8ca6cc
"""

import os
import sys
import re
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topolog import logger
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step


pytestmark = [pytest.mark.bgpd, pytest.mark.bfdd, pytest.mark.isisd, pytest.mark.ldpd]


def build_topo(tgen):
    """
    +---+   +---+   +---+
    |ce1|---|pe1|---|rr1|
    +---+   +---+   +---+"""

    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))
        if "ce" not in right and "ce" not in left:
            tgen.gears[left].cmd(f"sysctl net.mpls.conf.eth-{right}.input=1")
            tgen.gears[right].cmd(f"sysctl net.mpls.conf.eth-{left}.input=1")

    def connect_switchs(tgen, rname, switch):
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

        switch.add_link(tgen.gears[rname], nodeif="eth-{}".format(switch.name))

    def connect_lan(tgen, rname):
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

        # Extra LAN interfaces. Not used for communication with hosts, just to
        # hold an address we use to inject routes
        switch = tgen.add_switch("s-{}".format(rname))
        switch.add_link(tgen.gears[rname], nodeif="eth-lan")

    # directly connected without switch routers
    connect_routers(tgen, "rr1", "pe1")
    connect_routers(tgen, "pe1", "ce1")
    connect_lan(tgen, "ce1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["pe1"]
    pe1.cmd(
        f"""
ip link add RED type vrf table 100
ip link set RED up
ip link set eth-ce1 master RED
"""
    )

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_LDP, None),
                (TopoRouter.RD_ISIS, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_bgp_convergence(step=None):
    """
        out was generated using

    FRRGIT=/path/git/frr

    vtysh -c 'show bgp vrf all summary json' | jq . | egrep -v 'ersion|idType|connections|peerState|pfx|outq|inq|msg|As|rib|Count|Memory|Uptime|vrf|\"as|failedPeers|displayedPeers|dynamicPeers' | awk '/      "bestPath": {/ {c=3; next} c-- > 0 {next} 1' | sed -E 's|"totalPeers": (.+),|"totalPeers": \1|g;s|"Established",|"Established"|g' | jq . >$FRRGIT/tests/topotests/bgp_l3vpn_hidden/$HOSTNAME/show_bgp_summary.json

    vtysh -c 'show bgp ipv4 vpn json' | jq . | egrep -v 'selectionReason|pathFrom|prefix|locPrf|ersion|weight|origin|vrfId|afi|defaultLocPrf|network|nhVrfId|announceNexthopSelf|metric|multipath|linkLocalOnly|length' | jq .   >$FRRGIT/tests/topotests/bgp_l3vpn_hidden/$HOSTNAME/show_bgp_ipv4_vpn_step1.json
    vtysh -c 'show bgp ipv6 vpn json' | jq . | egrep -v 'selectionReason|pathFrom|prefix|locPrf|ersion|weight|origin|vrfId|afi|defaultLocPrf|network|fe80|nhVrfId|announceNexthopSelf|metric|multipath|linkLocalOnly|length' | jq .   >$FRRGIT/tests/topotests/bgp_l3vpn_hidden/$HOSTNAME/show_bgp_ipv6_vpn_step1.json

    vtysh -c 'show bgp ipv4 unicast json' | jq . | egrep -v 'selectionReason|pathFrom|prefix|locPrf|ersion|weight|origin|vrfId|afi|defaultLocPrf|network|nhVrfId|announceNexthopSelf|metric|multipath|linkLocalOnly|length' | jq .   >$FRRGIT/tests/topotests/bgp_l3vpn_hidden/$HOSTNAME/show_bgp_ipv4_unicast.json
    vtysh -c 'show bgp ipv6 unicast json' | jq . | egrep -v 'selectionReason|pathFrom|prefix|locPrf|ersion|weight|origin|vrfId|afi|defaultLocPrf|network|fe80|nhVrfId|announceNexthopSelf|metric|multipath|linkLocalOnly|length' | jq .   >$FRRGIT/tests/topotests/bgp_l3vpn_hidden/$HOSTNAME/show_bgp_ipv6_unicast.json
    """
    tgen = get_topogen()

    logger.info("waiting for bgp convergence")

    step_suffix = f"_step{step}" if step else ""

    if not step:
        logger.info("Check BGP summary")
        for rname, router in tgen.routers().items():
            reffile = os.path.join(CWD, f"{rname}/show_bgp_summary.json")
            expected = json.loads(open(reffile).read())
            cmd = "show bgp vrf all summary json"
            test_func = functools.partial(
                topotest.router_json_cmp, router, cmd, expected
            )
            _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
            assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg

    logger.info("Check BGP IPv4/6 unicast/VPN table")
    for rname, router in tgen.routers().items():
        for ipv in [4, 6]:
            logger.info(f"Check BGP IPv4/6 unicast/VPN table: {rname} IPv{ipv}")
            safi = "unicast" if "ce" in rname else "vpn"
            reffile = os.path.join(
                CWD, f"{rname}/show_bgp_ipv{ipv}_{safi}{step_suffix}.json"
            )
            expected = json.loads(open(reffile).read())
            exact = not expected  # exact match if json is void (ie. {})
            cmd = f"show bgp ipv{ipv} {safi} json"
            test_func = functools.partial(
                topotest.router_json_cmp,
                router,
                cmd,
                expected,
                exact=exact,
            )
            _, res = topotest.run_and_expect(test_func, None, count=120, wait=1)
            assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg


def configure_bgp(vrf=None, router_name="all", activate=False):
    tgen = get_topogen()

    vrf_suffix = f" vrf {vrf}" if vrf else ""
    as_pattern = re.compile(rf"^router bgp (\d+){vrf_suffix}$")

    for rname, router in tgen.routers().items():
        if router_name != "all" and router_name != rname:
            continue

        if "ce" in rname:
            continue

        as_number = ""
        cmds = []
        router_bgp = False
        with open(os.path.join(CWD, f"{rname}/frr.conf"), "r") as f:
            for line in f:
                line = line.strip()
                if "router bgp" in line:
                    match = as_pattern.match(line)
                    if match:
                        as_number = match.group(1)
                        router_bgp = True
                        continue
                    if router_bgp:
                        # If we already hit "router bgp <as_number>" once,
                        # and see another "router bgp" line, break.
                        break
                if not router_bgp:
                    # Only capture lines after we've matched "router bgp"
                    continue
                cmds.append(line)

        cfg = "configure terminal\n"
        if activate:
            cfg += f"router bgp {as_number}{vrf_suffix}\n"
            for cmd in cmds:
                cfg += f"{cmd}\n"
        else:
            cfg += f"no router bgp {as_number}{vrf_suffix}\n"

        router.vtysh_cmd(cfg)


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_bgp_convergence()


def test_bgp_l3vpn_hidden_step1():
    """
    Remove pe1 router bgp blocks
    The Default BGP instance becomes hidden
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for vrf in ["RED", None]:
        configure_bgp(router_name="pe1", vrf=vrf, activate=False)

    check_bgp_convergence(step=1)


def test_bgp_l3vpn_hidden_step2():
    """
    Restore pe1 router bgp blocks
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for vrf in [None, "RED"]:
        configure_bgp(router_name="pe1", vrf=vrf, activate=True)

    # identical to the intitial step
    check_bgp_convergence(step=None)


def test_bgp_l3vpn_hidden_step3():
    """
    Remove pe1 router bgp blocks
    The Default BGP instance becomes hidden
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for vrf in ["RED", None]:
        configure_bgp(router_name="pe1", vrf=vrf, activate=False)

    # identical to the intitial step 1
    check_bgp_convergence(step=1)


def test_bgp_l3vpn_hidden_step4():
    """
    Restore pe1 router bgp blocks
    Reconfigure VRF block first
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for vrf in [None, "RED"]:
        configure_bgp(router_name="pe1", vrf=vrf, activate=True)

    # identical to the intitial step
    check_bgp_convergence(step=None)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
