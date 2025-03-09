#!/usr/bin/env python
# SPDX-License-Identifier: ISC


"""
Test BGP route-constraint feature for L3VPN
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
    +---+   +---+   +---+   +---+
    |ce1|   |ce2|   |ce3|   |ce4|
    +---+   +---+   +---+   +---+
       \       |     |        /
         \     |     |      /
           \   |     |   /
________________________________AS6550X____________________________________________
             \ |     | /
             +---+  +---+
             |pe1|  |pe2|                                                |
             +---+  +---+                                                | +----+
                \     /    |                                             |/|ce9 |
                 \   /     |           | AS65203 |         AS65001       / +----+
                 +---+     +---+       | +---+   |          +--+    +---+  +----+
      rr         |rr1|\---*| p1|---------| p3+--------------|rr3|---|pe5|--|ce10|
route-reflector  +---+ \ / +---+       | +---+   |          +---+   +---+  +----+
                   |    *    |         |_________|________  /            \ +----+
                 +---+ / \ +---+       | +---+   | +---+   /             |\|ce11|
  AS65000        |rr2|/---*| p2|-------|-| p4|-----| p5|_/ |             | +----+
                 +---+     +---+       | +---+   | +---+   |             |
                 /  \      | AS65201   | AS65204 | AS65205 |             | AS655XX
                /    \
             +---+  +---+
             |pe3|  |pe4|
             +---+  +---+
             / |     | \
___________________________________________________________________________________
           /   |     |   \      AS6550X
         /     |     |     \
       /       |     |        \
    +---+   +---+   +---+   +---+
    |ce5|   |ce6|   |ce7|   |ce8|
    +---+   +---+   +---+   +---+
"""

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
    connect_routers(tgen, "rr1", "pe2")
    connect_routers(tgen, "pe1", "ce1")
    connect_routers(tgen, "pe1", "ce2")
    connect_routers(tgen, "pe2", "ce3")
    connect_routers(tgen, "pe2", "ce4")
    connect_routers(tgen, "rr1", "rr2")
    connect_routers(tgen, "rr2", "pe3")
    connect_routers(tgen, "rr2", "pe4")
    connect_routers(tgen, "pe3", "ce5")
    connect_routers(tgen, "pe3", "ce6")
    connect_routers(tgen, "pe4", "ce7")
    connect_routers(tgen, "pe4", "ce8")
    connect_routers(tgen, "rr1", "p1")
    connect_routers(tgen, "rr1", "p2")
    connect_routers(tgen, "rr2", "p1")
    connect_routers(tgen, "rr2", "p2")
    connect_routers(tgen, "p1", "p2")
    connect_routers(tgen, "p1", "p3")
    connect_routers(tgen, "p2", "p4")
    connect_routers(tgen, "p4", "p5")
    connect_routers(tgen, "p3", "rr3")
    connect_routers(tgen, "p5", "rr3")
    connect_routers(tgen, "rr3", "pe5")
    connect_routers(tgen, "pe5", "ce9")
    connect_routers(tgen, "pe5", "ce10")
    connect_routers(tgen, "pe5", "ce11")
    for i in range(1, 12):
        connect_lan(tgen, f"ce{i}")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for i in range(1, 6):
        pe = tgen.gears[f"pe{i}"]
        ceidx = (i - 1) * 2 + 1
        pe.cmd(
            f"""
ip link add RED type vrf table 100
ip link set RED up
ip link set eth-ce{ceidx} master RED
"""
        )
        ceidx = i * 2
        if i % 2 == 1:
            pe.cmd(
                f"""
ip link add BLUE type vrf table 101
ip link set BLUE up
ip link set eth-ce{ceidx} master BLUE
"""
            )
        else:
            pe.cmd(
                f"""
ip link add GREEN type vrf table 102
ip link set GREEN up
ip link set eth-ce{ceidx} master GREEN
"""
            )

    pe5 = tgen.gears["pe5"]
    pe5.cmd(
        """
ip link add ORANGE type vrf table 103
ip link set ORANGE up
ip link set eth-ce11 master ORANGE
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
    tgen = get_topogen()

    logger.info("waiting for bgp convergence")

    step_suffix = f"_step{step}" if step else ""

    if os.path.isfile(f"rr1/show_bgp_summary{step_suffix}.json"):
        logger.info("Check BGP summary")
        for rname, router in tgen.routers().items():
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
        if "ce" in rname:
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

    logger.info("Check BGP IPv4/6 unicast/VPN table")
    for rname, router in tgen.routers().items():
        for ipv in [4, 6]:
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


def check_clear(router, neighbor):
    logger.info("Check BGP clearing")

    out = router.vtysh_cmd(f"show bgp neighbors {neighbor} json")
    actual = json.loads(out).get(neighbor, {})

    if actual.get("bgpState") != "Established":
        return False
    time_str = actual.get("bgpTimerUpString")
    if not time_str:
        return False

    hours, minutes, seconds = time_str.split(":")
    if hours == "00" and minutes == "00":
        return True

    return False


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


def configure_bgp_address_family(
    afi, safi, vrf=None, router_name="all", activate=False
):
    tgen = get_topogen()

    vrf_suffix = f" vrf {vrf}" if vrf else ""
    as_pattern = re.compile(rf"^router bgp (\d+){vrf_suffix}$")
    neigh_pattern = re.compile(r"^\s*neighbor (.+) activate$")

    for rname, router in tgen.routers().items():
        if router_name != "all" and router_name != rname:
            continue

        if "ce" in rname:
            continue

        as_number = ""
        neighbors = []
        cmds = []
        addr_family = False
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
                    router_bgp = False
                    continue
                if not router_bgp:
                    continue
                if f"address-family {afi} {safi}" in line:
                    addr_family = True
                    continue
                if not addr_family:
                    continue
                match = neigh_pattern.match(line)
                if match:
                    neighbors.append(match.group(1))
                else:
                    cmds.append(line)

                if "exit" in line:
                    break

        cfg = f"""
        configure
        router bgp {as_number}{vrf_suffix}
         address-family {afi} {safi}
        """
        for neighbor in neighbors:
            if activate:
                cfg += f"  neighbor {neighbor} activate\n"
            else:
                cfg += f"  no neighbor {neighbor} activate\n"

        for cmd in cmds:
            if activate:
                cfg += f"  {cmd}\n"
            else:
                cfg += f"  no {cmd}\n"

        router.vtysh_cmd(cfg)


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_bgp_convergence()


def test_rtc_l3vpn_topo1_step1():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rr3 = tgen.gears["rr3"]

    rr3.cmd("ip link set eth-p3 down")

    check_bgp_convergence(step=1)


def test_rtc_l3vpn_topo1_step2():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rr3 = tgen.gears["rr3"]

    rr3.cmd("ip link set eth-p3 up")

    # identical to the initial state
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step3():
    """
    Add a new VRF import on PE1 and check RTC refresh
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["pe1"]

    pe1.cmd("ip link add ORANGE type vrf table 103")
    pe1.cmd("ip link set dev ORANGE up")

    pe1.vtysh_cmd(
        """
configure
router bgp 65000 vrf ORANGE
 bgp router-id 192.168.0.1
 no bgp ebgp-requires-policy
 no bgp network import-check
 bgp bestpath compare-routerid
 !
 address-family ipv4 unicast
  network 172.20.12.0/24
  label vpn export 103
  rd vpn export 65000:103
  rt vpn both 65000:103
  export vpn
  import vpn
 exit-address-family
exit
"""
    )

    check_bgp_convergence(step=3)


def test_rtc_l3vpn_topo1_step4():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["pe1"]
    pe1.vtysh_cmd(
        """
configure
router bgp 65000 vrf ORANGE
 address-family ipv4 unicast
  no network 172.20.12.0/24
"""
    )

    check_bgp_convergence(step=4)


def test_rtc_l3vpn_topo1_step5():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["pe1"]
    pe1.vtysh_cmd(
        """
configure
no router bgp 65000 vrf ORANGE
"""
    )

    # identical to the initial state
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step6():
    """
    Remove all RTC configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    configure_bgp_address_family("ipv4", "rt", activate=False)
    check_bgp_convergence(step=6)


def test_rtc_l3vpn_topo1_step7():
    """
    Re-add all RTC configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    configure_bgp_address_family("ipv4", "rt", activate=True)

    # identical to the initial state
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step8():
    """
    Change VRF Blue IPv4 VPN Route-Target
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000 vrf BLUE
 address-family ipv6 unicast
  rt vpn export 65000:201 65000:301
  rt vpn import 65000:101
"""
    )
    tgen.gears["pe3"].vtysh_cmd(
        """
configure
router bgp 65000 vrf BLUE
 address-family ipv6 unicast
  rt vpn export 65000:101 65000:301
  rt vpn import 65000:201
"""
    )
    tgen.gears["pe5"].vtysh_cmd(
        """
configure
router bgp 65001 vrf BLUE
 address-family ipv6 unicast
  rt vpn export 65000:101 65000:201
  rt vpn import 65000:301
"""
    )

    check_bgp_convergence(step=8)


def test_rtc_l3vpn_topo1_step9():
    """
    Change VRF Blue IPv4 VPN Route-Target
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000 vrf BLUE
 address-family ipv4 unicast
  rt vpn both 65000:401
"""
    )

    check_bgp_convergence(step=9)


def test_rtc_l3vpn_topo1_step10():
    """
    Change VRF Blue IPv4 VPN Route-Target
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe3"].vtysh_cmd(
        """
configure
router bgp 65000 vrf BLUE
 address-family ipv4 unicast
  rt vpn both 65000:401
"""
    )
    tgen.gears["pe5"].vtysh_cmd(
        """
configure
router bgp 65001 vrf BLUE
 address-family ipv4 unicast
  rt vpn both 65000:401
"""
    )

    check_bgp_convergence(step=10)


def test_rtc_l3vpn_topo1_step11():
    """
    Remove pe1 IPv6 VPN configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    configure_bgp_address_family("ipv6", "vpn", router_name="pe1", activate=False)
    configure_bgp_address_family(
        "ipv6", "unicast", router_name="pe1", vrf="RED", activate=False
    )
    configure_bgp_address_family(
        "ipv6", "unicast", router_name="pe1", vrf="BLUE", activate=False
    )

    check_bgp_convergence(step=11)


def test_rtc_l3vpn_topo1_step12():
    """
    Re-add pe1 IPv6 VPN configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    configure_bgp_address_family("ipv6", "vpn", router_name="pe1", activate=True)
    configure_bgp_address_family(
        "ipv6", "unicast", router_name="pe1", vrf="RED", activate=True
    )
    configure_bgp_address_family(
        "ipv6", "unicast", router_name="pe1", vrf="BLUE", activate=True
    )

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000 vrf BLUE
 address-family ipv6 unicast
  rt vpn export 65000:201 65000:301
  rt vpn import 65000:101
"""
    )

    # identical to step 10
    check_bgp_convergence(step=10)


def test_rtc_l3vpn_topo1_step13():
    """
    Restore all VPN configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for version in [4, 6]:
        for vrf in ["RED", "BLUE", "GREEN", "ORANGE"]:
            configure_bgp_address_family(
                f"ipv{version}", "unicast", router_name="all", vrf=vrf, activate=True
            )

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step14():
    """
    Remove pe1 IPv6 VPN configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    configure_bgp_address_family("ipv6", "vpn", router_name="pe1", activate=False)
    configure_bgp_address_family(
        "ipv6", "unicast", router_name="pe1", vrf="RED", activate=False
    )
    configure_bgp_address_family(
        "ipv6", "unicast", router_name="pe1", vrf="BLUE", activate=False
    )

    # CE output identical to step 11
    check_bgp_convergence(step=14)


def test_rtc_l3vpn_topo1_step15():
    """
    Re-add pe1 IPv6 VPN configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    configure_bgp_address_family("ipv6", "vpn", router_name="pe1", activate=True)
    configure_bgp_address_family(
        "ipv6", "unicast", router_name="pe1", vrf="RED", activate=True
    )
    configure_bgp_address_family(
        "ipv6", "unicast", router_name="pe1", vrf="BLUE", activate=True
    )

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step16():
    """
    Restore all VPN configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    configure_bgp_address_family("ipv6", "vpn", router_name="all", activate=False)
    for vrf in ["RED", "BLUE", "GREEN", "ORANGE"]:
        configure_bgp_address_family(
            "ipv6", "unicast", router_name="all", vrf=vrf, activate=False
        )

    check_bgp_convergence(step=16)


def test_rtc_l3vpn_topo1_step17():
    """
    Restore all VPN configuration
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    configure_bgp_address_family("ipv6", "vpn", router_name="all", activate=True)
    for vrf in ["RED", "BLUE", "GREEN", "ORANGE"]:
        configure_bgp_address_family(
            "ipv6", "unicast", router_name="all", vrf=vrf, activate=True
        )

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step18():
    """
    Remove pe1 router bgp blocks
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for vrf in ["RED", "BLUE", None]:
        configure_bgp(router_name="pe1", vrf=vrf, activate=False)

    check_bgp_convergence(step=18)


def test_rtc_l3vpn_topo1_step19():
    """
    Restore pe1 router bgp blocks
    Reconfigure VRF block first
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for vrf in [None, "RED", "BLUE"]:
        configure_bgp(router_name="pe1", vrf=vrf, activate=True)

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step20():
    """
    Announce default RTC prefix from PE1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000
 address-family ipv4 rt-constraint
  network 0/0
"""
    )

    check_bgp_convergence(step=20)


def test_rtc_l3vpn_topo1_step21():
    """
    Remove default RTC prefix from PE1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000
 address-family ipv4 rt-constraint
  no network 0/0
"""
    )

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step22():
    """
    Announce RTC prefix for all RTs from PE1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000
 address-family ipv4 rt-constraint
  network 65001:RT:0/32
"""
    )

    # identical to the step 20, except for RTC prefix and prefix-list
    check_bgp_convergence(step=22)


def test_rtc_l3vpn_topo1_step23():
    """
    Remove RTC prefix for all RTs from PE1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000
 address-family ipv4 rt-constraint
  no network 65001:RT:0/32
"""
    )

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step24():
    """
    Announce RTC prefix for all RTs from PE1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000
 address-family ipv4 rt-constraint
  network 65001:RT:65000:0/64
"""
    )

    # identical to the step 20, except for RTC prefix and prefix-list
    check_bgp_convergence(step=24)


def test_rtc_l3vpn_topo1_step25():
    """
    Remove RTC prefix for all RTs from PE1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000
 address-family ipv4 rt-constraint
  no network 65001:RT:65000:0/64
"""
    )

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step26():
    """
    Announce RTC prefix for all RTs from PE1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000
 address-family ipv4 rt-constraint
  network 65002:RT:65000:96/93
"""
    )

    # identical to the step 20, except for RTC prefix and prefix-list
    check_bgp_convergence(step=26)


def test_rtc_l3vpn_topo1_step27():
    """
    Remove RTC prefix for all RTs from PE1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe1"].vtysh_cmd(
        """
configure
router bgp 65000
 address-family ipv4 rt-constraint
  no network 65002:RT:65000:96/93
"""
    )

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step28():
    """
    Clear all bgp sessions on rr1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "rr1"
    rr1 = tgen.gears[rname]
    rr1.vtysh_cmd("clear bgp *")

    test_func = functools.partial(check_clear, rr1, "192.168.0.1")
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert res, f"BGP was not cleared. Error on {rname}"

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step29():
    """
    Clear rt-constraint bgp sessions on rr1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "rr1"
    rr1 = tgen.gears[rname]
    rr1.vtysh_cmd("clear bgp ipv4 rt-constraint *")

    test_func = functools.partial(check_clear, rr1, "192.168.0.1")
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert res, f"BGP was not cleared. Error on {rname}"

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step30():
    """
    Clear ipv6 bgp sessions on rr1
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "rr1"
    rr1 = tgen.gears[rname]
    rr1.vtysh_cmd("clear bgp ipv6 unicast *")

    test_func = functools.partial(check_clear, rr1, "3fff::192:168:0:1")
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert res, f"BGP was not cleared. Error on {rname}"

    # identical to the initial step
    check_bgp_convergence(step=None)


def test_rtc_l3vpn_topo1_step31():
    """
    Remove rt-constraint on pe5
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["pe5"].vtysh_cmd(
        """
configure
router bgp 65001
 address-family ipv4 rt-constraint
  no neighbor 192.168.0.103 activate
"""
    )

    check_bgp_convergence(step=31)


def test_rtc_l3vpn_topo1_step32():
    """
    Add static prefix on rr3 to make pe5 receive their routes
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rr3"].vtysh_cmd(
        """
configure
router bgp 65001
 address-family ipv4 rt-constraint
  network 65000:100
  network 65000:101
"""
    )

    check_bgp_convergence(step=32)


def test_rtc_l3vpn_topo1_step33():
    """
    Restore configuration on rr3 and pe5
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["rr3"].vtysh_cmd(
        """
configure
router bgp 65001
 address-family ipv4 rt-constraint
  no network 65000:100
  no network 65000:101
"""
    )

    tgen.gears["pe5"].vtysh_cmd(
        """
configure
router bgp 65001
 address-family ipv4 rt-constraint
  neighbor 192.168.0.103 activate
"""
    )

    # identical to the initial step
    check_bgp_convergence(step=None)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
