#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
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
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("ce5")
    tgen.add_router("ce6")
    tgen.add_router("ce7")
    tgen.add_router("ce8")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
    tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["r2"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["r1"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["r2"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["r1"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["r2"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce7"], tgen.gears["r1"], "eth0", "eth4")
    tgen.add_link(tgen.gears["ce8"], tgen.gears["r2"], "eth0", "eth4")


def setup_module(mod):
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # This topotest sets net.vrf.strict_mode during setup. That sysctl is
    # available only after the VRF module is loaded; if the module is not loaded,
    # the strict_mode command may fail and the test can fail later.
    # Ensure the VRF module is present and loaded before setting strict_mode.
    if not topotest.module_present("vrf"):
        pytest.skip("VRF kernel module is not available")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        if os.path.exists("{}/{}/setup.sh".format(CWD, rname)):
            router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrfdefault type vrf table 254")
    tgen.gears["r1"].run("ip link set vrfdefault up")
    tgen.gears["r1"].run("ip link add sr0 type dummy")
    tgen.gears["r1"].run("ip link set sr0 up")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip route add table 10 unreachable default metric 4278198272")
    tgen.gears["r1"].run(
        "ip -6 route add table 10 unreachable default metric 4278198272"
    )
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip route add table 20 unreachable default metric 4278198272")
    tgen.gears["r1"].run(
        "ip -6 route add table 20 unreachable default metric 4278198272"
    )
    tgen.gears["r1"].run("ip link set eth1 master vrf10")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.gears["r2"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r2"].run("ip link add vrfdefault type vrf table 254")
    tgen.gears["r2"].run("ip link set vrfdefault up")
    tgen.gears["r2"].run("ip link add sr0 type dummy")
    tgen.gears["r2"].run("ip link set sr0 up")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip route add table 10 unreachable default metric 4278198272")
    tgen.gears["r2"].run(
        "ip -6 route add table 10 unreachable default metric 4278198272"
    )
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r2"].run("ip link set vrf20 up")
    tgen.gears["r2"].run("ip route add table 20 unreachable default metric 4278198272")
    tgen.gears["r2"].run(
        "ip -6 route add table 20 unreachable default metric 4278198272"
    )
    tgen.gears["r2"].run("ip link set eth1 master vrf10")
    tgen.gears["r2"].run("ip link set eth2 master vrf20")
    tgen.gears["r2"].run("ip link set eth3 master vrf20")
    tgen.start_router()


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
    def _check(name, dest_addr, match):
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
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib.json")
    check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10_rib.json")
    check_rib("r1", "show ip route vrf vrf20 json", "r1/vrf20_rib.json")
    check_rib("r2", "show ip route vrf vrf10 json", "r2/vrf10_rib.json")
    check_rib("r2", "show ip route vrf vrf20 json", "r2/vrf20_rib.json")
    check_rib("ce1", "show ip route json", "ce1/ip_rib.json")
    check_rib("ce2", "show ip route json", "ce2/ip_rib.json")
    check_rib("ce3", "show ip route json", "ce3/ip_rib.json")
    check_rib("ce4", "show ip route json", "ce4/ip_rib.json")
    check_rib("ce5", "show ip route json", "ce5/ip_rib.json")
    check_rib("ce6", "show ip route json", "ce6/ip_rib.json")


def test_ping():
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "192.168.3.2", True, 10, 0.5)
    check_ping("ce1", "192.168.4.2", False, 10, 0.5)
    check_ping("ce1", "192.168.5.2", False, 10, 0.5)
    check_ping("ce1", "192.168.6.2", False, 10, 0.5)
    check_ping("ce4", "192.168.1.2", False, 10, 0.5)
    check_ping("ce4", "192.168.2.2", False, 10, 0.5)
    check_ping("ce4", "192.168.3.2", False, 10, 0.5)
    check_ping("ce4", "192.168.5.2", True, 10, 0.5)
    check_ping("ce4", "192.168.6.2", True, 10, 0.5)
    check_ping("ce7", "192.168.8.2", True, 10, 0.5)
    check_ping("ce8", "192.168.7.2", True, 10, 0.5)


def check_default_vrf_sid(name, sid, present):
    """
    Check the IPv4 VPN SID of the default BGP instance, in BGP and in zebra.
    """

    def _check():
        tgen = get_topogen()
        router = tgen.gears[name]

        output = json.loads(router.vtysh_cmd("show bgp segment-routing srv6 json"))
        bgp_default = next(
            (b for b in output.get("bgps", []) if b.get("name") == "default"), None
        )
        if bgp_default is None:
            return "bgp: default instance not found"
        bgp_sid = bgp_default.get("vpnPolicyIpv4ToVpnSid")
        expected_bgp_sid = sid if present else None
        if bgp_sid != expected_bgp_sid:
            return "bgp: default vpnPolicyIpv4ToVpnSid is {}, expected {}".format(
                bgp_sid, expected_bgp_sid
            )

        output = json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))
        expected = {sid: {"sid": sid}} if present else {sid: None}
        return topotest.json_cmp(output, expected)

    logger.info(
        "[+] check {} default VRF SID {} {}".format(
            name, sid, "allocated" if present else "released"
        )
    )
    _, result = topotest.run_and_expect(_check, None, count=15, wait=1)
    assert result is None, "Failed: {}".format(result)


def check_vpn_rd_empty(name, rd):
    """
    Check that the VPN routes of a route distinguisher are removed.
    """

    def _check():
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn json"))
        routes = output.get("routes", {}).get("routeDistinguishers", {}).get(rd, {})
        if routes:
            return "{} still has routes: {}".format(rd, list(routes.keys()))
        return None

    logger.info("[+] check {} VPN routes of {} removed".format(name, rd))
    _, result = topotest.run_and_expect(_check, None, count=15, wait=1)
    assert result is None, "Failed: {}".format(result)


def test_bgp_srv6_unset():
    """
    Unset the SRv6 locator of the default BGP instance on r1: the SID of the
    default BGP instance must be released, and its routes no more exported.
    """
    check_default_vrf_sid("r1", "2001:db8:1:1:300::", True)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          no segment-routing srv6
        """
    )
    check_default_vrf_sid("r1", "2001:db8:1:1:300::", False)
    check_vpn_rd_empty("r1", "1:30")
    check_vpn_rd_empty("r2", "1:30")
    check_ping("ce8", "192.168.7.2", False, 10, 0.5)


def test_bgp_srv6_reset():
    """
    Restore the SRv6 locator of the default BGP instance on r1: the SID of
    the default BGP instance must be allocated again, and its routes exported.
    """
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          segment-routing srv6
           locator loc1
        """
    )
    check_default_vrf_sid("r1", "2001:db8:1:1:300::", True)
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib.json")
    check_ping("ce7", "192.168.8.2", True, 10, 0.5)
    check_ping("ce8", "192.168.7.2", True, 10, 0.5)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
