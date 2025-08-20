#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2025 6WIND S.A.
# Loïc SANG <loic.sang@6wind.com>
#

"""
test_bgp_srv6_unicast.py: Test BGP SRv6 encapsulation at default VRF
                                +-------+
                                |       |
                                |   R4  |
                                |       |
                                +---+---+
                                    |
                                    |
                                    |
  +----+    +------+            +---+---+           +------+    +----+
  |    |    |      |            |       |           |      |    |    |
  | c1 |----|  R2  |------------|   R1  |-----------|  R3  |----| c2 |
  |    |    |      |            |       |           |      |    |    |
  +----+    +------+            +-------+           +------+    +----+

- R1 <-> R2, R1 sends updates with srv6 attributes to R2.
- R1 <-> R3, exchange updates with srv6 attributes only.
- R1 <-> R4, normal BGP peering, no updates with srv6 attributes exchanged.
- Ping test c1 <--> c2.
"""

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.common_config import retry
from lib import topotest
from lib.topogen import Topogen, get_topogen, TopoRouter
from lib.topolog import logger
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]

r1_unicast_sid = None
r3_unicast_sid = None

def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3"), "s3": ("r1", "r4"),
               "s4": ("c1", "r2"), "s5": ("r3", "c2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    tgen.net["r1"].cmd(
        """
        sysctl -w net.vrf.strict_mode=1
        ip link add vrfdefault type vrf table 254
        ip link set up dev vrfdefault
        ip link add sr0 type dummy
        ip link set up dev sr0
        """
    )
    tgen.net["r3"].cmd(
        """
        sysctl -w net.vrf.strict_mode=1
        ip link add vrfdefault type vrf table 254
        ip link set up dev vrfdefault
        ip link add sr0 type dummy
        ip link set up dev sr0
        """
    )

    for _, (rname, router) in enumerate(router_list.items()):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BGP, "-M bmp")],
        )

    tgen.start_router()

@retry(retry_timeout=10)
def get_unicast_sid(afi):
    global r1_unicast_sid, r3_unicast_sid
    tgen = get_topogen()

    output = tgen.gears["r1"].vtysh_cmd("show bgp segment-routing srv6")
    match = re.search(r"srv6_unicast\[%s\].sid: ([0-9a-fA-F:]+::)" % afi, output)

    if not match:
        return "R1 sid[%s] is null" % afi

    r1_unicast_sid = match.group().split()[-1]

    output = tgen.gears["r3"].vtysh_cmd("show bgp segment-routing srv6")
    match = re.search(r"srv6_unicast\[%s\].sid: ([0-9a-fA-F:]+::)" % afi, output)

    if not match:
        return "R3 sid[%s] is null" % afi

    r3_unicast_sid = match.group().split()[-1]

    return True

@retry(retry_timeout=10)
def check_route(router, cmd, expect_route, expect_sid, expect_installed=True):
    tgen = get_topogen()

    output = json.loads(router.vtysh_cmd(cmd))

    route = output.get(expect_route, None)
    if route is None:
        if not expect_installed:
            return True

        return "route %s is not installed on %s" % (expect_route, router.name)

    if not expect_installed:
        return "route is installed on %s" % router.name

    route = route[0]
    if expect_sid and route["nexthops"][0].get("seg6", {}).get("segs", "") != expect_sid:
        error =  "%s: expecting" % router.name
        if expect_sid:
            error = "%s %s sid" % (error, expect_sid)

        error = "%s on route %s" % (error, expect_route)

        return error

    return True

def test_bgp_srv6_encap():
    """
    For static prefix 10.0.0.1/32:
    - check encapsulation-srv6-relax R1 <-> R2
    - check encapsulation-srv6 R1 <-> R3
    - check no srv6 encap on R4
    """

    tgen = get_topogen()

    res = get_unicast_sid("AFI_IP")
    assert res is True, res
    logger.info("R1 sid[AFI_IP]: %s, R3 sid[AFI_IP]: %s" % (r1_unicast_sid, r3_unicast_sid))

    logger.info("Check prefix 10.0.0.1/32 SRv6 encap on R2")
    res = check_route(tgen.gears["r2"], "show ip route 10.0.0.1/32 json", "10.0.0.1/32", r1_unicast_sid)
    assert res is True, res

    logger.info("Check prefix 10.0.0.1/32 SRv6 encap on R3")
    res = check_route(tgen.gears["r3"], "show ip route 10.0.0.1/32 json", "10.0.0.1/32", r1_unicast_sid)
    assert res is True, res

    logger.info("Check prefix 10.0.0.1/32 no SRv6 encap on R4")
    res = check_route(tgen.gears["r4"], "show ip route 10.0.0.1/32 json", "10.0.0.1/32", "")
    assert res is True, res



def test_bgp_srv6_update1():
    """
    Configure a static prefix 10.0.0.2/32 on R2:
    - check no srv6 encap on R1
    - check srv6 encap R1 <-> R3
    - check no srv6 encap on r4
    """

    tgen = get_topogen()
    tgen.gears["r2"].vtysh_multicmd(
        """
        configure
        router bgp 65002
        address-family ipv4 unicast
        network 10.0.0.2/32
        """
    )

    logger.info("Check prefix 10.0.0.2/32 no SRv6 encap on R1")
    res = check_route(tgen.gears["r1"], "show ip route 10.0.0.2/32 json", "10.0.0.2/32", "")
    assert res is True, res

    logger.info("Check prefix 10.0.0.2/32 SRv6 encap on R3")
    res = check_route(tgen.gears["r3"], "show ip route 10.0.0.2/32 json", "10.0.0.2/32", r1_unicast_sid)
    assert res is True, res

    logger.info("Check prefix 10.0.0.2/32 no SRv6 encap on R4")
    res = check_route(tgen.gears["r4"], "show ip route 10.0.0.2/32 json", "10.0.0.2/32", "")
    assert res is True, res


def test_bgp_srv6_update2():
    """
    Configure a static prefix 10.0.0.3/32 on R3:
    - check srv6 encap R1 <-> R3
    - check srv6 encap R1 <-> R2, using sid from R3
    - check no srv6 encap on R4
    """

    tgen = get_topogen()
    tgen.gears["r3"].vtysh_multicmd(
        """
        configure
        router bgp 65003
        address-family ipv4 unicast
        network 10.0.0.3/32
        """
    )

    logger.info("Check prefix 10.0.0.3/32 SRv6 encap on R1")
    res = check_route(tgen.gears["r1"], "show ip route 10.0.0.3/32 json", "10.0.0.3/32", r3_unicast_sid)
    assert res is True, res

    logger.info("Check prefix 10.0.0.3/32 SRv6 encap on R2")
    res = check_route(tgen.gears["r2"], "show ip route 10.0.0.3/32 json", "10.0.0.3/32", r3_unicast_sid)
    assert res is True, res

    logger.info("Check prefix 10.0.0.3/32 no SRv6 encap on R4")
    res = check_route(tgen.gears["r4"], "show ip route 10.0.0.3/32 json", "10.0.0.3/32", "")
    assert res is True, res

def test_bgp_srv6_sid_rmap():
    """
    Configure prefix 172.16.0.0/24 on r1 and check it is blocked.
    """
    tgen = get_topogen()
    tgen.gears["r1"].vtysh_multicmd(
        """
        configure
        router bgp 65001
        address-family ipv4 unicast
        network 172.16.0.0/24
        """
    )

    logger.info("Check prefix 172.16.0.0/24 no SRv6 encap on R2")
    res = check_route(tgen.gears["r2"], "show ip route 172.16.0.0/24 json",
                      "172.16.0.0/24", "")
    assert res is True, res

    logger.info("Check prefix 172.16.0.0/24 is not installed on R3")
    res = check_route(tgen.gears["r3"], "show ip route 172.16.0.0/24 json",
                      "172.16.0.0/24", "", expect_installed=False)
    assert res is True, res


def test_bgp_srv6_sid_unexport():
    """
    Unconfigure sid export on R1, then check prefixes 10.0.0.1-3/32
    - R2: install routes via R1
    - R3: no prefixes are installed
    - R4: no changes
    """

    tgen = get_topogen()
    tgen.gears["r1"].vtysh_multicmd(
        """
        configure
        router bgp 65001
        address-family ipv4 unicast
        no sid export auto
        """
    )
    prefixes = ["10.0.0.1/32", "10.0.0.3/32"]

    logger.info("Check 10.0.0.1/32 and 10.0.0.3/32 are installed on R2")
    for prefix in prefixes:
        res = check_route(tgen.gears["r2"], "show ip route %s json" % prefix, prefix, "")
        assert res is True, res

    prefixes = ["10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"]
    logger.info("Check 10.0.0.1-3/32 are not installed on R3")
    for prefix in prefixes:
        res = check_route(tgen.gears["r3"], "show ip route %s json" % prefix, prefix,
                          "", expect_installed=False)
        assert res is True, res

def test_bgp_srv6_sid_export():
    """
    Enable sid export explicit on R1 and recheck prefixes 10.0.0.1-3/32 srv6 encap.
    """

    tgen = get_topogen()
    tgen.gears["r1"].vtysh_multicmd(
        """
        configure
        router bgp 65001
        address-family ipv4 unicast
        sid export explicit 2001:db8:1:1:a1::
        """
    )

    res = get_unicast_sid("AFI_IP")
    assert res is True, res
    logger.info("R1 sid[AFI_IP]: %s, R3 sid[AFI_IP]: %s" % (r1_unicast_sid, r3_unicast_sid))

    logger.info("Check 10.0.0.1/32 sid %s installed on R2" % r1_unicast_sid)
    res = check_route(tgen.gears["r2"], "show ip route 10.0.0.1/32 json", "10.0.0.1/32", r1_unicast_sid)
    assert res is True, res

    logger.info("Check 10.0.0.1/32 sid %s installed on R3" % r1_unicast_sid)
    res = check_route(tgen.gears["r3"], "show ip route 10.0.0.1/32 json", "10.0.0.1/32", r1_unicast_sid)
    assert res is True, res


    logger.info("Check 10.0.0.3/32 sid %s installed on R2" % r3_unicast_sid)
    res = check_route(tgen.gears["r2"], "show ip route 10.0.0.3/32 json", "10.0.0.3/32", r3_unicast_sid)
    assert res is True, res

    logger.info("Check 10.0.0.3/32 sid %s installed on R1" % r3_unicast_sid)
    res = check_route(tgen.gears["r1"], "show ip route 10.0.0.3/32 json", "10.0.0.3/32", r3_unicast_sid)
    assert res is True, res


def test_bgp_srv6_sid_v6_update():
    tgen = get_topogen()

    tgen.gears["r1"].vtysh_multicmd(
        """
        configure
        router bgp 65001
        address-family ipv6 unicast
        network fd00:200::/64
        sid export 55
        """
    )

    tgen.gears["r3"].vtysh_multicmd(
        """
        configure
        router bgp 65003
        address-family ipv6 unicast
        network fd00:300::/64
        sid export auto
        """
    )

    res = get_unicast_sid("AFI_IP6")
    assert res is True, res
    logger.info("R1 sid[AFI_IP6]: %s, R3 sid[AFI_IP6]: %s" % (r1_unicast_sid, r3_unicast_sid))

    logger.info("Check fd00:200::/64 sid %s installed on R2" % r1_unicast_sid)
    res = check_route(tgen.gears["r2"], "show ipv6 route fd00:200::/64 json",
                      "fd00:200::/64", r1_unicast_sid)
    assert res is True, res

    logger.info("Check fd00:200::/64 sid %s installed on R3" % r1_unicast_sid)
    res = check_route(tgen.gears["r3"], "show ipv6 route fd00:200::/64 json",
                      "fd00:200::/64", r1_unicast_sid)
    assert res is True, res

    logger.info("Check fd00:300::/64 sid %s installed on R1" % r3_unicast_sid)
    res = check_route(tgen.gears["r1"], "show ipv6 route fd00:300::/64 json",
                      "fd00:300::/64", r3_unicast_sid)
    assert res is True, res

    logger.info("Check fd00:300::/64 sid %s installed on R2" % r3_unicast_sid)
    res = check_route(tgen.gears["r2"], "show ipv6 route fd00:300::/64 json",
                      "fd00:300::/64", r3_unicast_sid)
    assert res is True, res

    logger.info("Check fd00:200::/64 sid %s is not installed on R4" % r1_unicast_sid)

    res = check_route(tgen.gears["r4"], "show ipv6 route fd00:200::/64 json",
                      "fd00:200::/64", "")
    assert res is True, res

    logger.info("Check fd00:300::/64 sid %s is not installed on R4" % r3_unicast_sid)
    res = check_route(tgen.gears["r4"], "show ipv6 route fd00:300::/64 json",
                      "fd00:300::/64", "")
    assert res is True, res


def test_srv6_withdraw():
    """
    Withdraw static prefixes:
    - 10.0.0.1/32, fd00:200::/64 on R1
    - 10.0.0.3/32, fd00:300::/64 on R3
    """

    tgen = get_topogen()

    tgen.gears["r1"].vtysh_multicmd(
        """
        configure
        router bgp 65001
        address-family ipv4 unicast
        no network 10.0.0.1/32
        exit-address-family
        address-family ipv6 unicast
        no network fd00:200::/64
        """
    )
    tgen.gears["r3"].vtysh_multicmd(
        """
        configure
        router bgp 65003
        address-family ipv4 unicast
        no network 10.0.0.3/32
        exit-address-family
        address-family ipv6 unicast
        no network fd00:300::/64
        """
    )

    logger.info("Check 10.0.0.1/32 is withdrawn on R3")
    res = check_route(tgen.gears["r3"], "show ip route 10.0.0.1/32 json",
                      "10.0.0.1/32", r1_unicast_sid, expect_installed=False)
    assert res is True, res

    logger.info("Check 10.0.0.3/32 is withdrawn on R2")
    res = check_route(tgen.gears["r2"], "show ip route 10.0.0.3/32 json",
                      "10.0.0.3/32", r3_unicast_sid, expect_installed=False)
    assert res is True, res

    logger.info("Check fd00:200::/64 is withdrawn on R3")
    res = check_route(tgen.gears["r3"], "show ipv6 route fd00:200::/64 json",
                      "fd00:200::/64", r1_unicast_sid, expect_installed=False)
    assert res is True, res

    logger.info("Check fd00:300::/64 is withdrawn on R2")
    res = check_route(tgen.gears["r2"], "show ipv6 route fd00:300::/64 json",
                      "fd00:300::/64", r3_unicast_sid, expect_installed=False)
    assert res is True, res


def test_ping():
    """
    Check pings C1 <-> R2 <-> R1 <-> R3 <-> C2.
    """
    tgen = get_topogen()
    tgen.gears["r3"].vtysh_multicmd(
        """
        configure
        router bgp 65003
        address-family ipv4 unicast
        redistribute connected
        address-family ipv6 unicast
        redistribute connected
        """
    )
    tgen.gears["r2"].vtysh_multicmd(
        """
        configure
        router bgp 65002
        address-family ipv4 unicast
        redistribute connected
        address-family ipv6 unicast
        redistribute connected
        """
    )

    check_ping("c1", "10.100.3.2", True, 3, 3)
    check_ping("c2", "10.100.1.2", True, 3, 3)
    check_ping("c1", "fd00:300::2", True, 3, 3)
    check_ping("c2", "fd00:100::2", True, 3, 3)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
