#!/usr/bin/env python
# SPDX-License-Identifier: ISC


"""
Test BGP EVPN local RT-2 leaking
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
from lib.checkping import check_ping
from lib.common_config import step


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

    connect_routers(tgen, "r1", "r2")
    connect_routers(tgen, "r1", "r3")
    connect_routers(tgen, "r2", "r3")
    connect_routers(tgen, "h1", "r1")
    connect_routers(tgen, "h2", "r2")
    connect_routers(tgen, "h3", "r3")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for hname, host in tgen.routers().items():
        if hname not in ("h2", "h3"):
            continue
        id = hname.replace("h", "")
        host.cmd(
            f"""
ip link set eth-r{id} down
ip link set eth-r{id} address 2:00:00:00:00:{id}{id}
ip link set eth-r{id} up
"""
        )

    for rname, router in tgen.routers().items():
        if rname not in ("r2", "r3"):
            continue
        id = rname.replace("r", "")
        router.cmd(
            f"""
# L3VNI setup
ip link add up vrf10 type vrf table 10
ip link add up br10 type bridge
ip link set br10 master vrf10
ip link add up vni10 type vxlan id 10 local 10.0.0.{id} nolearning dstport 4789
ip link set vni10 master br10
bridge link set dev vni10 learning off

# L2VNI and IRB setup
ip link add up br100 type bridge
ip link set br100 master vrf10
ip link add up vni100 type vxlan id 100 local 10.0.0.{id} nolearning dstport 4789
ip link set vni100 master br100
ip link set eth-h{id} master br100
bridge link set dev vni100 learning off
bridge link set dev eth-h{id} learning off
ip address add 192.168.0.1/24 dev br100

# Mock host setup (to cause type-2 MACIP advertisement)
bridge fdb add 02:00:00:00:00:{id}{id} dev eth-h{id} master static sticky
ip neigh add 192.168.0.{id} lladdr 02:00:00:00:00:{id}{id} dev br100
"""
        )

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        d = [
            (TopoRouter.RD_ZEBRA, None),
            (TopoRouter.RD_MGMTD, None),
        ]
        if rname.startswith("r"):
            d.append((TopoRouter.RD_BGP, None))

        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            d,
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_bgp_convergence(step=None):
    """
    JSON output was generated using

    FRRGIT=<git_frr_path>/frr

    vtysh -c 'show bgp summary json' | jq . | egrep -v 'ersion|idType|connections|peerState|pfx|outq|inq|msg|rib|Count|Memory|Uptime|vrf|failedPeers|displayedPeers|dynamicPeers' | awk '/    "bestPath": {/ {c=2; next} c-- > 0 {next} 1' | sed -E 's|"totalPeers": (.+),|"totalPeers": \1|g;s|"Established",|"Established"|g' | jq . >$FRRGIT/tests/topotests/bgp_evpn_rt2_local_leak/$HOSTNAME/show_bgp_summary.json

    vtysh -c "show bgp ipv4 unicast json" | jq '
    {
      routes: (
        .routes
        | with_entries(select(.key | test("^192\\.168\\.")))
        | with_entries(
            .value |= map(
              (.nexthops // [] | map(with_entries(select(.key | IN("hostname","scope","linkLocalOnly","used","interface"))))) as $nh
              | { valid, bestpath, pathFrom, path, origin, nexthops: $nh }
              | with_entries(select(.value != null))
            )
          )
      )
    }
    ' >$FRRGIT/tests/topotests/bgp_evpn_rt2_local_leak/$HOSTNAME/show_bgp_ipv4_unicast.json

    vtysh -c "show ip route json" | jq '
      with_entries(
        .value |= map(
          . as $r
          | ({ protocol, distance, metric, installed }
             + (if ($r | has("selected")) then {selected} else {} end)
             + (if ($r.protocol == "local" and ($r.selected? // false)) then {table} else {} end)
             + {
                 nexthops: (
                   .nexthops
                   | map(
                       { fib, directlyConnected, interfaceName, active, afi }
                       | with_entries(select(.value != null))
                     )
                 )
               }
            )
        )
      )
    ' >$FRRGIT/tests/topotests/bgp_evpn_rt2_local_leak/$HOSTNAME/show_ip_route.json

    [ "$HOSTNAME" != "r1" ] && vtysh -c "show ip route vrf vrf10 json" | jq '
      with_entries(
        .value |= map(
          . as $r
          | ({ protocol, distance, metric, installed }
             + (if ($r | has("selected")) then {selected} else {} end)
             + (if ($r.protocol == "local" and ($r.selected? // false)) then {table} else {} end)
             + {
                 nexthops: (
                   .nexthops
                   | map(
                       { fib, directlyConnected, interfaceName, active, afi }
                       | with_entries(select(.value != null))
                     )
                 )
               }
            )
        )
      )
    ' >$FRRGIT/tests/topotests/bgp_evpn_rt2_local_leak/$HOSTNAME/show_ip_route_vrf_vrf10.json

    """
    tgen = get_topogen()

    logger.info("waiting for bgp convergence")

    step_suffix = f"_step{step}" if step else ""

    if not step:
        logger.info("Check BGP summary")
        for rname, router in tgen.routers().items():
            if "h" in rname:
                continue
            reffile = os.path.join(CWD, f"{rname}/show_bgp_summary.json")
            expected = json.loads(open(reffile).read())
            cmd = "show bgp summary json"
            test_func = functools.partial(
                topotest.router_json_cmp, router, cmd, expected
            )
            _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
            assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg

    logger.info("Check BGP IPv4 unicast table")
    for rname, router in tgen.routers().items():
        if "h" in rname:
            continue
        logger.info(f"Check BGP IPv4 unicast table: {rname}")
        suffix = f"_step{step}" if step else ""
        reffile = os.path.join(CWD, f"{rname}/show_bgp_ipv4_unicast{suffix}.json")
        expected = json.loads(open(reffile).read())
        cmd = f"show bgp ipv4 unicast json"
        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            cmd,
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
        assert res is None, assertmsg

    logger.info("Check IPv4 routing tables")
    for rname, router in tgen.routers().items():
        if "h" in rname:
            continue
        for vrf in ("default", "vrf10"):
            if vrf != "default" and rname == "r1":
                continue
            suffix_vrf = "" if vrf == "default" else f"_vrf_{vrf}"
            suffix = f"_step{step}" if step else ""
            logger.info(f"Check IPv4 routing table: {rname} vrf {vrf}")
            reffile = os.path.join(CWD, f"{rname}/show_ip_route{suffix_vrf}{suffix}.json")
            expected = json.loads(open(reffile).read())
            if vrf == "default":
                cmd = f"show ip route json"
            else:
                cmd = f"show ip route vrf {vrf} json"
            test_func = functools.partial(
                topotest.router_json_cmp,
                router,
                cmd,
                expected,
            )
            _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assertmsg = f"IPv4 routing table did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg

    if step:
        return

    check_ping("h1", "192.168.0.2", True, 60, 0.5)
    check_ping("h1", "192.168.0.3", True, 60, 0.5)


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_bgp_convergence()


def test_host2_neighbor_delete():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].cmd("ip neigh del 192.168.0.2 lladdr 02:00:00:00:00:22 dev br100")
    check_bgp_convergence(step=2)


def test_host2_neighbor_add():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].cmd("ip neigh add 192.168.0.2 lladdr 02:00:00:00:00:22 dev br100")

    check_bgp_convergence()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
