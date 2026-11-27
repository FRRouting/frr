#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022, University of Rome Tor Vergata
# Authored by Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#

import os
import re
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import bgp_vpn_router_json_cmp_exact_filter
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    required_linux_kernel_version,
    shutdown_bringup_interface_in_kernel,
    step,
)
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

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
    tgen.add_link(tgen.gears["ce1"], tgen.gears["r1"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["r2"], "eth0", "eth1")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["r1"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["r2"], "eth0", "eth2")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["r1"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["r2"], "eth0", "eth3")


def setup_module(mod):
    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")

    result = required_linux_kernel_version("5.14")
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
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["r1"].tgen,
        tgen.gears["r1"].name,
        "vrf10",
        True,
    )
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["r1"].tgen,
        tgen.gears["r1"].name,
        "vrf20",
        True,
    )
    tgen.gears["r1"].run("ip link set eth1 master vrf10")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.gears["r2"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["r2"].tgen,
        tgen.gears["r2"].name,
        "vrf10",
        True,
    )
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    shutdown_bringup_interface_in_kernel(
        tgen.gears["r2"].tgen,
        tgen.gears["r2"].name,
        "vrf20",
        True,
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


def check_rib(name, cmd, expected_file, count=15, wait=1):
    def _check(router, cmd, expected):
        logger.info("polling")
        tgen = get_topogen()
        output = json.loads(router.vtysh_cmd(cmd))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    router = tgen.gears[name]
    expected = open_json_file("{}/{}".format(CWD, expected_file))
    if "show bgp" in cmd and "vpn" in cmd:
        func = functools.partial(
            bgp_vpn_router_json_cmp_exact_filter, tgen.gears[name], cmd, expected
        )
    else:
        func = functools.partial(_check, router, cmd, expected)
    _, result = topotest.run_and_expect(func, None, count, wait)
    assert result is None, "Failed"


def test_rib():
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib.json", 10, 1)
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib.json")
    check_rib("r1", "show ip route vrf vrf10 json", "r1/vrf10v4_rib.json")
    check_rib("r1", "show ip route vrf vrf20 json", "r1/vrf20v4_rib.json")
    check_rib("r2", "show ip route vrf vrf10 json", "r2/vrf10v4_rib.json")
    check_rib("r2", "show ip route vrf vrf20 json", "r2/vrf20v4_rib.json")
    check_rib("ce1", "show ip route json", "ce1/ip_rib.json")
    check_rib("ce2", "show ip route json", "ce2/ip_rib.json")
    check_rib("ce3", "show ip route json", "ce3/ip_rib.json")
    check_rib("ce4", "show ip route json", "ce4/ip_rib.json")
    check_rib("ce5", "show ip route json", "ce5/ip_rib.json")
    check_rib("ce6", "show ip route json", "ce6/ip_rib.json")

    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib.json")
    check_rib("r1", "show ipv6 route vrf vrf10 json", "r1/vrf10v6_rib.json")
    check_rib("r1", "show ipv6 route vrf vrf20 json", "r1/vrf20v6_rib.json")
    check_rib("r2", "show ipv6 route vrf vrf10 json", "r2/vrf10v6_rib.json")
    check_rib("r2", "show ipv6 route vrf vrf20 json", "r2/vrf20v6_rib.json")
    check_rib("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
    check_rib("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")
    check_rib("ce3", "show ipv6 route json", "ce3/ipv6_rib.json")
    check_rib("ce4", "show ipv6 route json", "ce4/ipv6_rib.json")
    check_rib("ce5", "show ipv6 route json", "ce5/ipv6_rib.json")
    check_rib("ce6", "show ipv6 route json", "ce6/ipv6_rib.json")


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

    check_ping("ce1", "2001:2::2", True, 10, 1)
    check_ping("ce1", "2001:3::2", True, 10, 1)
    check_ping("ce1", "2001:4::2", False, 10, 1)
    check_ping("ce1", "2001:5::2", False, 10, 1)
    check_ping("ce1", "2001:6::2", False, 10, 1)
    check_ping("ce4", "2001:1::2", False, 10, 1)
    check_ping("ce4", "2001:2::2", False, 10, 1)
    check_ping("ce4", "2001:3::2", False, 10, 1)
    check_ping("ce4", "2001:5::2", True, 10, 1)
    check_ping("ce4", "2001:6::2", True, 10, 1)


def test_bgp_sid_vpn_export_disable():
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf10
          segment-routing srv6
           no sid vpn per-vrf export
        """
    )
    check_rib(
        "r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_sid_vpn_export_disabled.json"
    )
    check_rib(
        "r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_sid_vpn_export_disabled.json"
    )
    check_rib(
        "r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_sid_vpn_export_disabled.json"
    )
    check_rib(
        "r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_sid_vpn_export_disabled.json"
    )
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)


def test_bgp_sid_vpn_export_reenable():
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1 vrf vrf10
          segment-routing srv6
           sid vpn per-vrf export auto
        """
    )
    check_rib(
        "r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_sid_vpn_export_reenabled.json"
    )
    check_rib(
        "r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_sid_vpn_export_reenabled.json"
    )
    check_rib(
        "r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_sid_vpn_export_reenabled.json"
    )
    check_rib(
        "r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_sid_vpn_export_reenabled.json"
    )
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)


def test_locator_delete():
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            no locator loc1
        """
    )
    # expectation is that VPN prefixes are not selected
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_zebra_deleted.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_zebra_deleted.json")
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_zebra_deleted.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_zebra_deleted.json")
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)


def test_locator_recreate():
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix 2001:db8:1:1::/64
        """
    )
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_recreated.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_recreated.json")
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_recreated.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_recreated.json")
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)


def test_bgp_locator_unset():
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          segment-routing srv6
           no locator loc1
        """
    )
    # expectation is that VPN prefixes are still selected, but with a label set to 3
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_deleted.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_deleted.json")
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_deleted.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_deleted.json")
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)


def test_bgp_locator_reset():
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          segment-routing srv6
           locator loc1
        """
    )
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_recreated.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_recreated.json")
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_recreated.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_recreated.json")
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)


def test_bgp_srv6_unset():
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          no segment-routing srv6
        """
    )
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_deleted.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_deleted.json")
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_deleted.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_deleted.json")
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)


def test_bgp_srv6_reset():
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)
    get_topogen().gears["r1"].vtysh_cmd(
        """
        configure terminal
         router bgp 1
          segment-routing srv6
           locator loc1
        """
    )
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_recreated.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib_locator_recreated.json")
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib_locator_recreated.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_recreated.json")
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)


def test_srv6_locator_without_default_bgp_and_restore():
    """Verify configuring an SRv6 locator for a VRF without the default BGP instance
    does not crash bgpd.

    Verify VPN routes and connectivity return after the default BGP instance is
    restored.
    """
    # Keep this destructive default-instance transition last in the module.
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def check_default_instance(present):
        expect = {"vrfs": {"default": {} if present else None}}
        test_func = functools.partial(
            topotest.router_json_cmp, r1, "show bgp vrfs json", expect
        )
        result, diff = topotest.run_and_expect(test_func, None, count=15, wait=1)
        status = r1.check_router_running()
        assert status == "", "r1 daemons stopped running: {}".format(status)
        assert result, "Unexpected default BGP instance state:\n{}".format(diff)

    step("Verify VPN service works with the default BGP instance", reset=True)
    check_default_instance(True)
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)

    step("Restart bgpd with VRF leaks and no default BGP instance")
    vrf_config = []
    include_vrf = True
    with open(os.path.join(CWD, "r1", "bgpd.conf")) as config:
        for line in config:
            if line.startswith("router bgp "):
                include_vrf = " vrf " in line
            if include_vrf:
                vrf_config.append(line)
    assert vrf_config, "Could not find the VRF BGP configuration"
    r1.cmd_raises("cat > /etc/frr/bgpd.conf", stdin="".join(vrf_config))
    r1.killDaemons(["bgpd"], wait=True)
    result = r1.startDaemons(["bgpd"])
    assert result == "", "Could not restart bgpd: {}".format(result)

    check_default_instance(False)
    check_ping("ce1", "192.168.2.2", False, 10, 0.5)
    check_ping("ce1", "2001:2::2", False, 10, 1)

    step("Configure an SRv6 locator and VRF while default BGP is absent")
    r1.cmd_raises("ip link add vrf30 type vrf table 30 && ip link set up dev vrf30")
    r1.vtysh_multicmd(
        """
        configure terminal
        vrf vrf30
        exit-vrf
        segment-routing
         srv6
          locators
           locator LOC
            prefix fcbb:bbbb:1::/48
            format usid-f3216
        """,
        raises=True,
    )
    r1.vtysh_multicmd(
        """
        configure terminal
        router bgp 1 vrf vrf30
         segment-routing srv6
          locator LOC
        """,
        daemon="bgpd",
        raises=True,
    )

    step("Wait for bgpd to receive the SRv6 locator")

    def check_locator_received():
        return "Received SRv6 locator LOC" in r1.net.getLog("log", "bgpd")

    result, _ = topotest.run_and_expect(check_locator_received, True, count=15, wait=1)
    status = r1.check_router_running()
    assert status == "", "r1 daemons stopped running: {}".format(status)
    assert result, "bgpd did not receive the SRv6 locator before default BGP"

    check_default_instance(False)
    output = r1.vtysh_cmd("show bgp vrfs json", isjson=True)
    assert output.get("vrfs", {}).get("default") is None, output
    assert "vrf30" in output.get("vrfs", {}), output

    step("Restore the original default BGP configuration")
    r1.vtysh_multicmd(
        """
        configure terminal
        router bgp 1
         bgp router-id 1.1.1.1
         no bgp ebgp-requires-policy
         neighbor 2001::2 remote-as 2
         neighbor 2001::2 timers 3 10
         neighbor 2001::2 timers connect 1
         neighbor 2001::2 capability extended-nexthop
         address-family ipv4 vpn
          neighbor 2001::2 activate
         exit-address-family
         address-family ipv6 vpn
          neighbor 2001::2 activate
         exit-address-family
         segment-routing srv6
          locator loc1
        """,
        daemon="bgpd",
        raises=True,
    )
    check_default_instance(True)

    step("Wait for VPN routes after restoring default BGP")
    for afi in ("ipv4", "ipv6"):
        cmd = "show bgp {} vpn json".format(afi)

        def check_vpn_rib_initialized():
            output = r1.vtysh_cmd(cmd, isjson=True)
            return None if "tableVersion" in output else output

        result, diff = topotest.run_and_expect(
            check_vpn_rib_initialized, None, count=15, wait=1
        )
        assert result, "r1 {} VPN RIB did not initialize: {}".format(afi, diff)

    step("Verify VPN routes and reachability recover")
    check_rib("r1", "show bgp ipv4 vpn json", "r1/vpnv4_rib.json")
    check_rib("r2", "show bgp ipv4 vpn json", "r2/vpnv4_rib.json")
    check_rib("r1", "show bgp ipv6 vpn json", "r1/vpnv6_rib.json")
    check_rib("r2", "show bgp ipv6 vpn json", "r2/vpnv6_rib.json")
    check_ping("ce1", "192.168.2.2", True, 10, 0.5)
    check_ping("ce1", "2001:2::2", True, 10, 1)

    step("Remove the test VRF and locator configuration")
    r1.vtysh_multicmd(
        "configure terminal\nno router bgp 1 vrf vrf30", daemon="bgpd", raises=True
    )
    r1.vtysh_multicmd(
        """
        configure terminal
        segment-routing
         srv6
          locators
           no locator LOC
        """,
        raises=True,
    )
    r1.cmd_raises("ip link delete vrf30")
    r1.vtysh_multicmd("configure terminal\nno vrf vrf30", raises=True)
    running_config = r1.vtysh_cmd("show running-config")
    assert "vrf30" not in running_config, running_config
    assert "locator LOC" not in running_config, running_config


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
