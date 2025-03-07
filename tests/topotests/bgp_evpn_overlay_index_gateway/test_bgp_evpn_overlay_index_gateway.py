#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#

"""
test_bgp_evpn_overlay_index_gateway.py: Test EVPN gateway IP overlay index functionality
Following functionality is covered:

         +--------+ BGP     +--------+ BGP  +--------+      +--------+
    SN1  |        | IPv4/v6 |        | EVPN |        |      |        |
   ======+ Host1  +---------+   PE1  +------+   PE2  +------+  Host2 +
         |        |         |        |      |        |      |        |
         +--------+         +--------+      +--------+      +--------+

    Host1 is connected to PE1 and host2 is connected to PE2
    Host1 and PE1 have IPv4/v6 BGP sessions.
    PE1 and PE2 gave EVPN session.
    Host1 advertises IPv4/v6 prefixes to PE1.
    PE1 advertises these prefixes to PE2 as EVPN type-5 routes.
    Gateway IP for these EVPN type-5 routes is host1 IP.
    Host1 MAC/IP is advertised by PE1 as EVPN type-2 route

Following testcases are covered:
TC_1:
Check BGP and zebra states for above topology at PE1 and PE2.

TC_2:
Stop advertising prefixes from host1. It should withdraw type-5 routes. Check states at PE1 and PE2
Advertise the prefixes again. Check states.

TC_3:
Shut down VxLAN interface at PE1. This should withdraw type-2 routes. Check states at PE1 and PE2.
Enable VxLAN interface again. Check states.
"""

import os
import sys
import json
from functools import partial
import pytest
import time
import platform

# Current Working Directory
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    step,
    write_test_header,
    write_test_footer,
)

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd]


# Global variables
PES = ["PE1", "PE2"]
HOSTS = ["host1", "host2"]
PE_SUFFIX = {"PE1": "1", "PE2": "2"}
HOST_SUFFIX = {"host1": "1", "host2": "2"}
TRIGGERS = ["base", "no_rt5", "no_rt2"]


def build_topo(tgen):
    # This function only purpose is to define allocation and relationship
    # between routers and add links.

    # Create routers
    for pe in PES:
        tgen.add_router(pe)
    for host in HOSTS:
        tgen.add_router(host)

    krel = platform.release()
    logger.info("Kernel version " + krel)

    # Add links
    tgen.add_link(tgen.gears["PE1"], tgen.gears["PE2"], "PE1-eth0", "PE2-eth0")
    tgen.add_link(tgen.gears["PE1"], tgen.gears["host1"], "PE1-eth1", "host1-eth0")
    tgen.add_link(tgen.gears["PE2"], tgen.gears["host2"], "PE2-eth1", "host2-eth0")


def setup_module(mod):
    "Sets up the pytest environment"

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    kernelv = platform.release()
    if topotest.version_cmp(kernelv, "4.15") < 0:
        logger.info(
            "For EVPN, kernel version should be minimum 4.15. Kernel present {}".format(
                kernelv
            )
        )
        return

    if topotest.version_cmp(kernelv, "4.15") == 0:
        l3mdev_accept = 1
        logger.info("setting net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept))
    else:
        l3mdev_accept = 0

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    tgen.start_topology()

    # Configure MAC address for hosts as these MACs are advertised with EVPN type-2 routes
    for name in tgen.gears:
        if name not in HOSTS:
            continue
        host = tgen.net[name]

        host_mac = "1a:2b:3c:4d:5e:6{}".format(HOST_SUFFIX[name])
        host.cmd_raises("ip link set dev {}-eth0 down".format(name))
        host.cmd_raises("ip link set dev {0}-eth0 address {1}".format(name, host_mac))
        host.cmd_raises("ip link set dev {}-eth0 up".format(name))

    # Configure PE VxLAN and Bridge interfaces
    for name in tgen.gears:
        if name not in PES:
            continue
        pe = tgen.net[name]

        vtep_ip = "10.100.0.{}".format(PE_SUFFIX[name])
        bridge_ip = "50.0.1.{}/24".format(PE_SUFFIX[name])
        bridge_ipv6 = "50:0:1::{}/48".format(PE_SUFFIX[name])

        pe.cmd_raises("ip link add vrf-blue type vrf table 10")
        pe.cmd_raises("ip link set dev vrf-blue up")
        pe.cmd_raises(
            "ip link add vxlan100 type vxlan id 100 dstport 4789 local {}".format(
                vtep_ip
            )
        )
        pe.cmd_raises("ip link add name br100 type bridge stp_state 0")
        pe.cmd_raises("ip link set dev vxlan100 master br100")
        pe.cmd_raises("ip link set dev {}-eth1 master br100".format(name))
        pe.cmd_raises("ip addr add {} dev br100".format(bridge_ip))
        pe.cmd_raises("ip link set up dev br100")
        pe.cmd_raises("ip link set up dev vxlan100")
        pe.cmd_raises("ip link set up dev {}-eth1".format(name))
        pe.cmd_raises("ip link set dev br100 master vrf-blue")
        pe.cmd_raises("ip -6 addr add {} dev br100".format(bridge_ipv6))

        pe.cmd_raises(
            "ip link add vxlan1000 type vxlan id 1000 dstport 4789 local {}".format(
                vtep_ip
            )
        )
        pe.cmd_raises("ip link add name br1000 type bridge stp_state 0")
        pe.cmd_raises("ip link set dev vxlan1000 master br100")
        pe.cmd_raises("ip link set up dev br1000")
        pe.cmd_raises("ip link set up dev vxlan1000")
        pe.cmd_raises("ip link set dev br1000 master vrf-blue")

        pe.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
        pe.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=1")
        pe.cmd_raises("sysctl -w net.ipv4.udp_l3mdev_accept={}".format(l3mdev_accept))
        pe.cmd_raises("sysctl -w net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept))

    # For all registered routers, load the zebra configuration file
    for name, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(name))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(name))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()

    logger.info("Running setup_module() done")

    time.sleep(10)


def teardown_module(mod):
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


def evpn_gateway_ip_show_op_check(trigger=" "):
    """
    This function checks CLI O/P for commands mentioned in show_commands for a given trigger
    :param trigger: Should be a trigger present in TRIGGERS
    :return: Returns a tuple (result: None for success, retmsg: Log message to be printed on failure)
    """
    tgen = get_topogen()

    if trigger not in TRIGGERS:
        return "Unexpected trigger", "Unexpected trigger {}".format(trigger)

    show_commands = {
        "bgp_vni_routes": "show bgp l2vpn evpn route vni 100 json",
        "bgp_vrf_ipv4": "show bgp vrf vrf-blue ipv4 json",
        "bgp_vrf_ipv6": "show bgp vrf vrf-blue ipv6 json",
        "zebra_vrf_ipv4": "show ip route vrf vrf-blue json",
        "zebra_vrf_ipv6": "show ipv6 route vrf vrf-blue json",
    }

    for name, pe in tgen.gears.items():
        if name not in PES:
            continue

        for cmd_key, command in show_commands.items():
            expected_op_file = "{0}/{1}/{2}_{3}.json".format(
                CWD, name, cmd_key, trigger
            )
            expected_op = json.loads(open(expected_op_file).read())

            test_func = partial(topotest.router_json_cmp, pe, command, expected_op)
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assertmsg = '"{0}" JSON output mismatch for {1}'.format(name, command)
            if result is not None:
                return result, assertmsg

    return None, "Pass"


def test_evpn_gateway_ip_basic_topo(request):
    """
    Tets EVPN overlay index gateway IP functionality. VErify show O/Ps on PE1 and PE2
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Temporarily Disabled
    tgen.set_error(
        "%s: Failing under new micronet framework, please debug and re-enable", tc_name
    )

    kernelv = platform.release()
    if topotest.version_cmp(kernelv, "4.15") < 0:
        logger.info("For EVPN, kernel version should be minimum 4.15")
        write_test_footer(tc_name)
        return

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check O/Ps for EVPN gateway IP overlay Index functionality at PE1 and PE2")

    result, assertmsg = evpn_gateway_ip_show_op_check("base")

    assert result is None, assertmsg

    write_test_footer(tc_name)


def test_evpn_gateway_ip_flap_rt5(request):
    """
    Withdraw EVPN type-5 routes and check O/Ps at PE1 and PE2
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    kernelv = platform.release()
    if topotest.version_cmp(kernelv, "4.15") < 0:
        logger.info("For EVPN, kernel version should be minimum 4.15")
        write_test_footer(tc_name)
        return

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    h1 = tgen.gears["host1"]

    step("Withdraw type-5 routes")

    h1.run(
        'vtysh  -c "config t" \
                   -c "router bgp 111" \
                   -c "address-family ipv4" \
                   -c "no network 100.0.0.21/32"'
    )
    h1.run(
        'vtysh  -c "config t" \
                   -c "router bgp 111" \
                   -c "address-family ipv6" \
                   -c "no network 100::21/128"'
    )

    result, assertmsg = evpn_gateway_ip_show_op_check("no_rt5")
    assert result is None, assertmsg

    step("Advertise type-5 routes again")

    h1.run(
        'vtysh  -c "config t" \
                   -c "router bgp 111" \
                   -c "address-family ipv4" \
                   -c "network 100.0.0.21/32"'
    )
    h1.run(
        'vtysh  -c "config t" \
                   -c "router bgp 111" \
                   -c "address-family ipv6" \
                   -c "network 100::21/128"'
    )

    result, assertmsg = evpn_gateway_ip_show_op_check("base")

    assert result is None, assertmsg

    write_test_footer(tc_name)


def test_evpn_gateway_ip_flap_rt2(request):
    """
    Withdraw EVPN type-2 routes and check O/Ps at PE1 and PE2
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    kernelv = platform.release()
    if topotest.version_cmp(kernelv, "4.15") < 0:
        logger.info("For EVPN, kernel version should be minimum 4.15")
        write_test_footer(tc_name)
        return

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shut down VxLAN interface at PE1 which results in withdraw of type-2 routes")

    pe1 = tgen.net["PE1"]

    pe1.cmd_raises("ip link set dev vxlan100 down")

    result, assertmsg = evpn_gateway_ip_show_op_check("no_rt2")
    assert result is None, assertmsg

    step("Bring up VxLAN interface at PE1 and advertise type-2 routes again")

    pe1.cmd_raises("ip link set dev vxlan100 up")

    result, assertmsg = evpn_gateway_ip_show_op_check("base")
    assert result is None, assertmsg

    write_test_footer(tc_name)


def test_memory_leak():
    """Run the memory leak test and report results"""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
