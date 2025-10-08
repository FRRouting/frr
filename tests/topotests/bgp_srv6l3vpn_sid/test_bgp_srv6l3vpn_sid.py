#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2023 6WIND S.A.
# Authored by Dmytro Shytyi <dmytro.shytyi@6wind.com>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version, retry
from lib.checkping import check_ping


def build_topo(tgen):
    r"""
     CE1     CE3      CE5     CE7
    (eth0)  (eth0)   (eth0)  (eth0)
      :2      :2      :2      :2
       |       |       |       |
   192.168.1.0 |       |       |
      /24      |       |       |
      2001:   2001:   2001:   2001:
     1::/64  3::/64  5::/64  8::/64
       |       |       |       |
      :1      :1      :1      :1
   +-(eth1)--(eth2)---(eth3)--(eth4)-+
   |     \   /          |       |    |
   |    (vrf10)     (vrf20)  (vrf30) |
   |             R1                  |
   +----------(eth0)-----------------+
                :1
                |
            2001::/64
                |
                :2
              (eth0)
    +----------(eth0)--------------+
    |            R2                |
    |   (vrf10)       (vrf20)      |
    |     /           /     \      |
    +-(eth1)-----(eth2)-----(eth3)-+
        :1         :1          :1
         |          |           |
      +------+   +------+   +------+
     /  2001: \ /  2001: \ /  2001: \
    /  2::/64  \ 4::/64  / \ 6::/64 /
   /192.168.2.0|        /   \      /
   \     /24  / \       |   |      |
      +------+   +------+   +------+
         |           |          |
        :2          :2         :2
      (eth0)      (eth0)      (eth0)
        CE2         CE4         CE6
    """

    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("ce5")
    tgen.add_router("ce6")
    tgen.add_router("ce7")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
    tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["r2"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["r1"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["r2"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["r1"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["r2"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce7"], tgen.gears["r1"], "eth0", "eth4")


def setup_module(mod):
    result = required_linux_kernel_version("5.11")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.gears["r1"].run("modprobe vrf")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link add vrf30 type vrf table 30")
    tgen.gears["r1"].run("ip link set vrf30 up")
    tgen.gears["r1"].run("ip link set eth1 master vrf10")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")
    tgen.gears["r1"].run("ip link set eth4 master vrf30")
    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("sysctl net.ipv4.conf.default.rp_filter=0")
    tgen.gears["r1"].run("sysctl net.ipv4.conf.all.rp_filter=0")
    tgen.gears["r1"].run("sysctl net.ipv4.conf.lo.rp_filter=0")
    tgen.gears["r1"].run("sysctl net.ipv4.conf.eth0.rp_filter=0")
    tgen.gears["r1"].run("sysctl net.ipv4.conf.eth1.rp_filter=0")
    tgen.gears["r1"].run("sysctl net.ipv4.conf.vrf10.rp_filter=0")

    tgen.gears["r2"].run("modprobe vrf")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r2"].run("ip link set vrf20 up")
    tgen.gears["r2"].run("ip link set eth1 master vrf10")
    tgen.gears["r2"].run("ip link set eth2 master vrf20")
    tgen.gears["r2"].run("ip link set eth3 master vrf20")
    tgen.gears["r2"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r2"].run("sysctl net.ipv4.conf.default.rp_filter=0")
    tgen.gears["r2"].run("sysctl net.ipv4.conf.all.rp_filter=0")
    tgen.gears["r2"].run("sysctl net.ipv4.conf.lo.rp_filter=0")
    tgen.gears["r2"].run("sysctl net.ipv4.conf.eth0.rp_filter=0")
    tgen.gears["r2"].run("sysctl net.ipv4.conf.eth1.rp_filter=0")
    tgen.gears["r2"].run("sysctl net.ipv4.conf.vrf10.rp_filter=0")
    tgen.start_router()

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.
    # Example:
    # tgen=get_topogen()
    # tgen.mininet_cli()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_rib(name, cmd, expected_file):
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    func = functools.partial(_check, name, cmd, expected_file)
    _, result = topotest.run_and_expect(func, None, count=15, wait=1)
    assert result is None, "Failed"


def test_rib():
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib.json")
    check_rib("r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_rib.json")
    check_rib("r1", "show ipv6 route vrf vrf20 json", "r1/vrf20_rib.json")
    check_rib("r2", "show ipv6 route vrf vrf10 json", "r2/vrf10_rib.json")
    check_rib("r2", "show ipv6 route vrf vrf20 json", "r2/vrf20_rib.json")
    check_rib("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
    check_rib("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")
    check_rib("ce3", "show ipv6 route json", "ce3/ipv6_rib.json")
    check_rib("ce4", "show ipv6 route json", "ce4/ipv6_rib.json")
    check_rib("ce5", "show ipv6 route json", "ce5/ipv6_rib.json")
    check_rib("ce6", "show ipv6 route json", "ce6/ipv6_rib.json")


def test_ping():
    check_ping("ce1", "2001:2::2", True, 10, 0.5)
    check_ping("ce1", "2001:3::2", True, 10, 0.5)
    check_ping("ce1", "2001:4::2", False, 10, 0.5)
    check_ping("ce1", "2001:5::2", False, 10, 0.5)
    check_ping("ce1", "2001:6::2", False, 10, 0.5)
    check_ping("ce4", "2001:1::2", False, 10, 0.5)
    check_ping("ce4", "2001:2::2", False, 10, 0.5)
    check_ping("ce4", "2001:3::2", False, 10, 0.5)
    check_ping("ce4", "2001:5::2", True, 10, 0.5)
    check_ping("ce4", "2001:6::2", True, 10, 0.5)


def test_sid_per_afv6_auto():
    check_rib("r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_afv6_auto_sid_rib.json")
    check_ping("ce1", "2001:2::2", True, 10, 0.5)
    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv6 unicast
           no sid vpn export auto
        """
    )
    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_afv6_auto_no_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", False, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv6 unicast
           sid vpn export auto
        """
    )
    check_rib("r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_afv6_auto_sid_rib.json")
    check_ping("ce1", "2001:2::2", True, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv6 unicast
           no sid vpn export auto
        """
    )
    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_afv6_auto_no_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", False, 10, 0.5)


def test_sid_per_afv6_manual():
    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_afv6_manual_no_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", False, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv6 unicast
           sid vpn export 8
        """
    )

    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_afv6_manual_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", True, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv6 unicast
           no sid vpn export 8
        """
    )
    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_afv6_manual_no_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", False, 10, 0.5)


def test_sid_per_afv4_auto():
    check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10_afv4_auto_sid_rib.json")
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv4 unicast
           no sid vpn export auto
        """
    )

    check_rib(
        "r1", "show ip route vrf vrf10 json", "r1/vrf10_afv4_auto_no_sid_rib.json"
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv4 unicast
           sid vpn export auto
        """
    )

    check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10_afv4_auto_sid_rib.json")
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv4 unicast
           no sid vpn export auto
        """
    )
    check_rib(
        "r1", "show ip route vrf vrf10 json", "r1/vrf10_afv4_auto_no_sid_rib.json"
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)


def test_sid_per_afv4_manual():
    check_rib(
        "r1", "show ip route vrf vrf10 json", "r1/vrf10_afv4_manual_no_sid_rib.json"
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv4 unicast
           sid vpn export 8
        """
    )

    check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10_afv4_manual_sid_rib.json")
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          address-family ipv4 unicast
           no sid vpn export 8
        """
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_rib(
        "r1", "show ip route vrf vrf10 json", "r1/vrf10_afv4_manual_no_sid_rib.json"
    )


def test_sid_per_vrf_auto():
    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_pervrf_auto_no_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", False, 10, 0.5)
    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          sid vpn per-vrf export auto
        """
    )

    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_pervrf6_auto_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", True, 10, 0.5)
    check_rib(
        "r1", "show ip route vrf vrf10 json", "r1/vrf10_pervrf4_auto_sid_rib.json"
    )
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
           no sid vpn per-vrf export auto
        """
    )

    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_pervrf_auto_no_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", False, 10, 0.5)


def test_sid_per_vrf_manual():
    check_rib(
        "r1", "show ip route vrf vrf10 json", "r1/vrf10_pervrf_manual_no_sid_rib.json"
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
          sid vpn per-vrf export 8
        """
    )

    check_rib(
        "r1", "show ipv6 route vrf vrf10 json", "r1/vrf10_pervrf6_manual_sid_rib.json"
    )
    check_ping("ce1", "2001:2::2", True, 10, 0.5)
    check_rib(
        "r1", "show ip route vrf vrf10 json", "r1/vrf10_pervrf4_manual_sid_rib.json"
    )
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)

    get_topogen().gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf10
           no sid vpn per-vrf export 8
        """
    )

    check_rib(
        "r1", "show ip route vrf vrf10 json", "r1/vrf10_pervrf_manual_no_sid_rib.json"
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)


def test_sid_suppress_locator_vrf20():
    check_rib("r2", "show ipv6 route vrf vrf20 json", "r2/vrf20_rib.json")
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf20
          no segment-routing srv6
        """
    )
    # 2001:5::/64 should be present with SID from vrf20
    check_rib("r2", "show ipv6 route vrf vrf20 json", "r2/vrf20_rib_one_locator.json")


def test_sid_suppress_locator_vrf_default():
    """
    Test that no IPv6 vpn prefixes from R1 can be advertised to R2
    """
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_2.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_2.json")
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          no segment-routing srv6
        """
    )
    # r2 should have 3 entries
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_unselected.json")

    # no vpn prefixes from r1 are exported
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_unselected.json")


def test_sid_add_locator_vrf_10():
    """
    Test that IPv6 vpn prefixes for VRF10 can be advertised to R2 with SRv6 SID
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf10
          segment-routing srv6
           locator loc2
        """
    )
    # 2001:1::/64 and 2001:3::/64 should be present
    check_rib("r2", "show ipv6 route vrf vrf10 json", "r2/vrf10_rib_one_locator.json")


def test_sid_vrf_30_basic_config():
    """
    Test that VPN prefix is valid, after configuring the VRF with no label
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          segment-routing srv6
           no srv6-only
          !
          bgp router-id 192.0.2.1
          no bgp ebgp-requires-policy
          no bgp default ipv4-unicast
          address-family ipv6 unicast
           rd vpn export 1:30
           rt vpn both 55:55
           import vpn
           export vpn
           redistribute connected
          exit-address-family
        """
    )
    # exported vpn prefix is exported and selected with MPLS label set to 3
    check_rib(
        "r1",
        "show bgp ipv6 vpn 2001:8::/64 json",
        "r1/vpnv6_rib_2001_8_valid_with_label_3.json",
    )


def test_sid_vrf_30_mpls():
    """
    Test that VPN prefix is valid, after configuring the MPLS
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          address-family ipv6 unicast
           label vpn export auto
          exit-address-family
        """
    )
    # exported vpn prefix is exported and selected
    check_rib(
        "r1", "show bgp ipv6 vpn 2001:8::/64 json", "r1/vpnv6_rib_2001_8_mpls.json"
    )


def test_sid_add_vrf_30_no_mpls():
    """
    Test that VPN prefix is invalid, after unconfiguring the MPLS
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          address-family ipv6 unicast
           no label vpn export auto
          exit-address-family
        """
    )
    # exported vpn prefix is exported and selected with MPLS label set to 3
    check_rib(
        "r1",
        "show bgp ipv6 vpn 2001:8::/64 json",
        "r1/vpnv6_rib_2001_8_valid_with_label_3.json",
    )


def test_sid_add_vrf_30_srv6():
    """
    Test that VPN prefix is valid, after configuring SRv6
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          segment-routing srv6
           locator loc2
          exit
          address-family ipv6 unicast
           sid vpn export auto
          exit-address-family
        """
    )
    # exported vpn prefix is exported and selected
    # exported vpn prefix has srv6 options
    check_rib(
        "r1", "show bgp ipv6 vpn 2001:8::/64 json", "r1/vpnv6_rib_2001_8_srv6.json"
    )


def test_sid_add_vrf_30_srv6_and_mpls():
    """
    Test that 2 VPN prefixs are present on r1, after configuring SRv6, then MPLS
    Test that MPLS and SRv6 are both present, only MPLS is bestpath
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          address-family ipv6 unicast
           label vpn export auto
          exit-address-family
        """
    )
    check_rib(
        "r1",
        "show bgp ipv6 vpn 2001:8::/64 json",
        "r1/vpnv6_rib_2001_8_srv6_and_mpls.json",
    )


def test_sid_add_vrf_30_remove_srv6_keep_mpls():
    """
    Test that unconfiguring SRv6 will trigger removal of VPN SRv6 prefix
    Test that VPN MPLS prefix is selected
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          address-family ipv6 unicast
           no sid vpn export auto
          exit-address-family
        """
    )
    # exported vpn prefix is exported and selected
    # exported vpn prefix has no srv6 options, and mpls value
    check_rib(
        "r1", "show bgp ipv6 vpn 2001:8::/64 json", "r1/vpnv6_rib_2001_8_mpls.json"
    )


def test_sid_add_vrf_30_readd_srv6_keep_mpls():
    """
    Test that reconfiguring SRv6 will trigger add of VPN SRv6 prefix
    Test that VPN MPLS prefix remains selected
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          address-family ipv6 unicast
           sid vpn export auto
          exit-address-family
        """
    )
    check_rib(
        "r1",
        "show bgp ipv6 vpn 2001:8::/64 json",
        "r1/vpnv6_rib_2001_8_srv6_and_mpls.json",
    )


def test_sid_add_peer_srv6_filtered():
    """
    Configure peer 2001::2 with encapsulation-srv6
    Test that SRv6 prefixes only are sent to r2 (2001::8 will not be present)
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          address-family ipv6 vpn
           neighbor 2001::2 addpath-tx-all-paths
           neighbor 2001::2 encapsulation-srv6
          exit-address-family
        """
    )
    check_rib(
        "r2", "show bgp ipv6 vpn 2001:8::/64 json", "r2/vpnv6_rib_2001_8_srv6.json"
    )


def test_sid_add_peer_srv6_not_filtered():
    """
    Unconfigure peer 2001::2 with encapsulation-srv6
    Test that SRv6 and MPLS prefixes are sent to r2 (2001::8 will be present)
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          address-family ipv6 vpn
           no neighbor 2001::2 encapsulation-srv6
          exit-address-family
        """
    )
    check_rib(
        "r2", "show bgp ipv6 vpn 2001:8::/64 json", "r2/vpnv6_rib_2001_8_mpls_srv6.json"
    )


def test_sid_add_peer_mpls_filtered():
    """
    configure peer 2001::2 with encapsulation-mpls
    Test that MPLS prefixes are sent to r2 (2001::1 and 2001::3 will not be present)
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          address-family ipv6 vpn
           neighbor 2001::2 encapsulation-mpls
          exit-address-family
        """
    )
    check_rib(
        "r2", "show bgp ipv6 vpn 2001:8::/64 json", "r2/vpnv6_rib_2001_8_mpls.json"
    )


def test_sid_add_peer_mpls_not_filtered():
    """
    Unconfigure peer 2001::2 with encapsulation-mpls
    Test that MPLS and SRv6 prefixes are sent to r2 (2001::1 2001::3 will be present)
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          address-family ipv6 vpn
           no neighbor 2001::2 encapsulation-mpls
          exit-address-family
        """
    )
    check_rib(
        "r2", "show bgp ipv6 vpn 2001:8::/64 json", "r2/vpnv6_rib_2001_8_mpls_srv6.json"
    )


def test_sid_add_vrf_30_srv6_only():
    """
    Test that VPN prefix is valid, after unconfiguring MPLS
    Test that SRv6 is the chosen dataplane
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          address-family ipv6 unicast
           no label vpn export auto
          exit-address-family
        """
    )
    # exported vpn prefix is exported and selected
    # exported vpn prefix has srv6 options
    check_rib(
        "r1", "show bgp ipv6 vpn 2001:8::/64 json", "r1/vpnv6_rib_2001_8_srv6.json"
    )


def test_sid_reenable_both_srv6_and_mpls():
    """
    Reenable label vpn export auto to r1
    Test that SRv6 and MPLS prefixes are sent to r2 (2001::8 will be present)
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf30
          address-family ipv6 unicast
           label vpn export auto
          exit-address-family
        """
    )
    check_rib(
        "r2", "show bgp ipv6 vpn 2001:8::/64 json", "r2/vpnv6_rib_2001_8_mpls_srv6.json"
    )


@retry(retry_timeout=10)
def _check_show_bgp_vrf_ipv6_prefix(router, vrf, prefix, mpls, srv6):
    output = json.loads(router.vtysh_cmd(f"show bgp vrf {vrf} ipv6 {prefix} json"))
    found_srv6 = False
    found_mpls = False
    if "paths" not in output.keys():
        if not mpls and not srv6:
            return True
        return "paths key not found"
    paths = output["paths"]
    for path in paths:
        if "remoteSid" in path.keys() and not srv6:
            return f"SRv6 path found for {prefix} unexpected"
        if "remoteSid" in path.keys():
            if not srv6:
                return f"SRv6 path found for {prefix} unexpected"
            valid = path.get("valid", False)
            if valid:
                found_srv6 = True
            else:
                return (
                    f"SRv6 path 'valid' value for {prefix} unexpected, expected {srv6}"
                )
        else:
            if not mpls:
                return f"MPLS path found for {prefix} unexpected"
            valid = path.get("valid", False)
            if valid:
                found_mpls = True
            else:
                return (
                    f"MPLS path 'valid' value for {prefix} unexpected, expected {mpls}"
                )
    if not found_srv6 and not srv6:
        found_srv6 = True
    if not found_mpls and not mpls:
        found_mpls = True
    if found_mpls and found_srv6:
        return True
    return f"only one path has been found : MPLS {found_mpls}, SRv6 {found_srv6}"


@retry(retry_timeout=10)
def _check_show_bgp_ipv6_vpn_selected(router, prefix, mpls, srv6):
    output = json.loads(router.vtysh_cmd(f"show bgp ipv6 vpn {prefix} json"))
    found_srv6 = False
    found_mpls = False
    if "1:30" not in output.keys() or "paths" not in output["1:30"].keys():
        return "RD 1:30 not found, or paths key not found"
    paths = output["1:30"]["paths"]
    for path in paths:
        if "remoteSid" in path.keys():
            valid = path.get("valid", False)
            if srv6 and valid:
                found_srv6 = True
            elif not srv6 and not valid:
                found_srv6 = True
            else:
                return (
                    f"SRv6 path 'valid' value for {prefix} unexpected, expected {srv6}"
                )
        else:
            valid = path.get("valid", False)
            if mpls and valid:
                found_mpls = True
            elif not mpls and not valid:
                found_mpls = True
            else:
                return (
                    f"MPLS path 'valid' value for {prefix} unexpected, expected {mpls}"
                )
    if found_mpls and found_srv6:
        return True
    return f"only one path has been found : MPLS {found_mpls}, SRv6 {found_srv6}"


def test_sid_configure_r2_listener_as_srv6():
    """
    Enable R2 as srv6 receiver
    Test that SRv6 and MPLS prefixes are received, and that r2 only selects SRv6
    """
    tgen = get_topogen()
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2
          address-family ipv6 vpn
           neighbor 2001::1 encapsulation-srv6
          exit-address-family
        """
    )

    success = _check_show_bgp_ipv6_vpn_selected(
        tgen.gears["r2"], "2001:8::/64", mpls=False, srv6=True
    )
    assert (
        success is True
    ), "network 2001:8::/64 selected for SRv6, unselected for MPLS: not found on r2"


def test_sid_configure_r2_listener_as_srv6_and_mpls():
    """
    Enable R2 as MPLS receiver
    Test that SRv6 and MPLS prefixes are received, and that r2 selects both SRv6 and MPLS
    """
    tgen = get_topogen()
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2
          address-family ipv6 vpn
           neighbor 2001::1 encapsulation-mpls
          exit-address-family
        """
    )

    success = _check_show_bgp_ipv6_vpn_selected(
        tgen.gears["r2"], "2001:8::/64", mpls=True, srv6=True
    )
    assert (
        success is True
    ), "network 2001:8::/64 selected for MPLS, selected for SRv6: not found on r2"


def test_sid_configure_r2_listener_as_mpls():
    """
    Disable R2 as SRv6 receiver
    Test that SRv6 and MPLS prefixes are received, and that r2 selects both SRv6 and MPLS
    """
    tgen = get_topogen()
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2
          address-family ipv6 vpn
           no neighbor 2001::1 encapsulation-srv6
          exit-address-family
        """
    )

    success = _check_show_bgp_ipv6_vpn_selected(
        tgen.gears["r2"], "2001:8::/64", mpls=True, srv6=False
    )
    assert (
        success is True
    ), "network 2001:8::/64 selected for MPLS, unselected for SRv6: not found on r2"


def test_sid_configure_r2_listener_as_srv6_and_mpls_again():
    """
    Enable R2 as both MPLS and SRv6 receiver
    Test that SRv6 and MPLS prefixes are received, and that r2 selects both SRv6 and MPLS
    - vrf20 is being added a RT to import the 2001:8:: entries
    - label vpn export auto is added to ensure nexthop validity
    """
    tgen = get_topogen()
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf20
          address-family ipv6 unicast
           label vpn export auto
           rt vpn both 55:55 88:88
          exit-address-family
         exit
         router bgp 2
          address-family ipv6 vpn
           neighbor 2001::1 encapsulation-srv6
          exit-address-family
        """
    )

    logger.info(
        "On r2, check that 2 VPN prefixes MPLS and SRv6 for 2001:8::/64 are received"
    )
    success = _check_show_bgp_ipv6_vpn_selected(
        tgen.gears["r2"], "2001:8::/64", mpls=True, srv6=True
    )
    assert (
        success is True
    ), "VPN path 2001:8::/64 present for MPLS, selected for SRv6: not found on r2"

    logger.info(
        "On r2, check that 2 prefixes MPLS and SRv6 for 2001:8::/64 are imported on vrf20"
    )
    success = _check_show_bgp_vrf_ipv6_prefix(
        tgen.gears["r2"], "vrf20", "2001:8::/64", mpls=True, srv6=True
    )
    assert (
        success is True
    ), "path 2001:8::/64 on vrf20 present for MPLS, present for SRv6: not found on r2"


def test_sid_configure_r2_listener_with_route_map_import_drop_mpls():
    """
    Add a route-map at vrf20 importation with the 'match vpn-dataplane srv6' command
    Test that when VPN prefixes are imported, one can import only the SRv6 prefix
    """
    tgen = get_topogen()
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         router bgp 2 vrf vrf20
          address-family ipv6 unicast
           route-map vpn import rmap
          exit-address-family
         exit
         route-map rmap permit 1
           match vpn dataplane srv6
         exit
        """
    )
    logger.info(
        "On r2, check that with a route-map match vpn dataplane srv6, only SRv6 prefix is imported on vrf20"
    )
    success = _check_show_bgp_vrf_ipv6_prefix(
        tgen.gears["r2"], "vrf20", "2001:8::/64", mpls=False, srv6=True
    )
    assert (
        success is True
    ), "path 2001:8::/64 on vrf20 present for srv6, not present for MPLS: not found on r2"


def test_sid_configure_r2_listener_with_route_map_import_drop_srv6():
    """
    Use previous route-map at vrf20 importation with the 'match vpn-dataplane mpls' command
    Test that when VPN prefixes are imported, one can import only the MPLS prefix
    """
    tgen = get_topogen()
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         route-map rmap permit 1
           match vpn dataplane mpls
         exit
        """
    )
    logger.info(
        "On r2, check that with a route-map match vpn dataplane mpls, only MPLS prefix is imported on vrf20"
    )
    success = _check_show_bgp_vrf_ipv6_prefix(
        tgen.gears["r2"], "vrf20", "2001:8::/64", mpls=True, srv6=False
    )
    assert (
        success is True
    ), "path 2001:8::/64 on vrf20 present for srv6, not present for MPLS: not found on r2"


def test_sid_configure_r2_listener_with_route_map_import_drop_srv6_and_mpls():
    """
    Use previous route-map at vrf20 importation with the 'match vpn-dataplane vxlan' command
    Test that when VPN prefixes are imported, one can import none of the prefixes
    """
    tgen = get_topogen()
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
         route-map rmap permit 1
           match vpn dataplane vxlan
         exit
        """
    )
    logger.info(
        "On r2, check that with a route-map match vpn dataplane vxlan, no prefix is imported on vrf20"
    )
    success = _check_show_bgp_vrf_ipv6_prefix(
        tgen.gears["r2"], "vrf20", "2001:8::/64", mpls=False, srv6=False
    )
    assert (
        success is True
    ), "path 2001:8::/64 on vrf20 present for srv6, not present for MPLS: not found on r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
