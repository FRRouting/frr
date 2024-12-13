#!/usr/bin/env python
# SPDX-License-Identifier: ISC


"""
Test BGP route-constraint feature
"""

import os
import sys
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

    def connect_switchs(tgen, rname, switch):
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

        switch.add_link(tgen.gears[rname], nodeif="eth-{}".format(switch.name))

    # sw switch is for interconnecting peers on the same subnet
    sw = tgen.add_switch("sw")
    connect_switchs(tgen, "rr", sw)
    connect_switchs(tgen, "r1", sw)
    connect_switchs(tgen, "r2", sw)
    connect_switchs(tgen, "r3", sw)
    connect_switchs(tgen, "r4", sw)

    # directly connected without switch routers
    connect_routers(tgen, "r1", "h1")
    connect_routers(tgen, "r2", "h2")
    connect_routers(tgen, "r3", "h3")
    connect_routers(tgen, "r4", "h4")
    connect_routers(tgen, "r1", "h5")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    for r in range(1, 5):
        router = tgen.gears[f"r{r}"]
        i = 100 if r in [1, 2] else 200
        router.cmd(
            f"""
ip link add vxlan{i} type vxlan id {i} dstport 4789 local 10.0.1.{r}0 nolearning
ip link add br{i} type bridge stp_state 0
ip link set vxlan{i} master br{i}
ip link set eth-h{r} master br{i}
ip link set vxlan{i} up
ip link set br{i} up
"""
        )


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_bgp_convergence(step=None):
    tgen = get_topogen()

    logger.info("waiting for bgp convergence")

    step_suffix = f"_step{step}" if step else ""

    if os.path.isfile(f"rr/show_bgp_summary{step_suffix}.json"):
        logger.info("Check BGP summary")
        for rname, router in tgen.routers().items():
            if rname.startswith("h"):
                continue

            reffile = os.path.join(CWD, f"{rname}/show_bgp_summary{step_suffix}.json")
            expected = json.loads(open(reffile).read())
            cmd = "show bgp vrf all summary json"
            test_func = functools.partial(
                topotest.router_json_cmp, router, cmd, expected
            )
            _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
            assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg

    logger.info("Check BGP route-target constraint table")
    for rname, router in tgen.routers().items():
        if rname.startswith("h"):
            continue

        reffile = os.path.join(CWD, f"{rname}/show_bgp_ipv4_rtc{step_suffix}.json")
        expected = json.loads(open(reffile).read())
        exact = not expected  # exact match if json is void (ie. {})
        cmd = "show bgp ipv4 rt-constraint json"
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

    logger.info("Check RTC prefix-list")
    for rname, router in tgen.routers().items():
        if rname.startswith("h"):
            continue
        for reffile in os.listdir(os.path.join(CWD, rname)):
            if "show_bgp_neigh_plist_" not in reffile:
                continue
            if not step and "step" in reffile:
                continue
            if step and f"{step_suffix}.json" not in reffile:
                continue

            # show_bgp_neighbor_3fff::192:168:0:101_rt_prefix_list.json
            ip = reffile.replace("show_bgp_neigh_plist_", "").replace(
                f"{step_suffix}.json", ""
            )
            expected = json.loads(open(os.path.join(CWD, rname, reffile)).read())
            exact = not expected  # exact match if json is void (ie. {})
            cmd = f"show bgp neigh {ip} rt-prefix-list json"
            test_func = functools.partial(
                topotest.router_json_cmp,
                router,
                cmd,
                expected,
                exact=exact,
            )
            _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assertmsg = f"RT prefix-list did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg

    logger.info("Check BGP EVPN table")
    for rname, router in tgen.routers().items():
        if rname.startswith("h"):
            continue
        reffile = os.path.join(CWD, f"{rname}/show_bgp_l2vpn_evpn{step_suffix}.json")
        expected = json.loads(open(reffile).read())

        # replace actual MAC addresses in expected
        for r in range(1, 5):
            for k, rd in expected.items():
                if not k.startswith(f"10.0.1.{r}0:"):
                    continue
                mac = ""
                for path in rd.get(f"[2]:[0]:[48]:[xx:xx:xx:xx:xx:xx]").get("paths"):
                    if r == 1 and "RT:65000:200" in path.get("extendedCommunity").get(
                        "string"
                    ):
                        mac = mac_hosts[f"h5"]
                    else:
                        mac = mac_hosts[f"h{r}"]
                    path["mac"] = mac
                rd[f"[2]:[0]:[48]:[{mac}]"] = rd.pop("[2]:[0]:[48]:[xx:xx:xx:xx:xx:xx]")

        exact = not expected  # exact match if json is void (ie. {})
        cmd = f"show bgp l2vpn evpn json"
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


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Force producing EVPN type 2
    tgen.gears["h1"].cmd("ping -c 1 -w 1 10.1.1.20")
    tgen.gears["h3"].cmd("ping -c 1 -w 1 10.1.2.40")

    global mac_hosts
    mac_hosts = {}
    for idx in range(1, 6):
        mac_hosts[f"h{idx}"] = (
            tgen.gears[f"h{idx}"]
            .cmd(f"ip -br l show eth-r{idx if idx < 5 else idx - 4}")
            .split()[2]
        )

    check_bgp_convergence()


def test_bgp_rtc_evpn_step1():
    """
    Link h5 to r1 EVPN
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r = 1
    r1 = tgen.gears[f"r{r}"]
    i = 200  # VNI
    r1.cmd(
        f"""
ip link add vxlan{i} type vxlan id {i} dstport 4789 local 10.0.1.{r}0 nolearning
ip link add br{i} type bridge stp_state 0
ip link set vxlan{i} master br{i}
ip link set eth-h{r + 4} master br{i}
ip link set vxlan{i} up
ip link set br{i} up
"""
    )

    # Force producing EVPN type 2
    tgen.gears["h1"].cmd("ping -c 1 -w 1 10.1.1.20")
    tgen.gears["h3"].cmd("ping -c 1 -w 1 10.1.2.40")
    tgen.gears["h5"].cmd("ping -c 1 -w 1 10.1.2.30")
    tgen.gears["h5"].cmd("ping -c 1 -w 1 10.1.2.40")

    check_bgp_convergence(step=1)


def test_bgp_rtc_evpn_step2():
    """
    Un-link h5 to r1 EVPN
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r = 1
    r1 = tgen.gears[f"r{r}"]
    i = 200  # VNI
    r1.cmd(
        f"""
ip link del br{i}
ip link del vxlan{i}
"""
    )

    # Force producing EVPN type 2
    tgen.gears["h1"].cmd("ping -c 1 -w 1 10.1.1.20")
    tgen.gears["h3"].cmd("ping -c 1 -w 1 10.1.2.40")

    # identical to the initial step
    check_bgp_convergence(step=2)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
