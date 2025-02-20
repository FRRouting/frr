#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_nhrp_topo.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_nhrp_topo.py: Test the FRR/Quagga NHRP daemon
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version, retry

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.nhrpd]
TOPOLOGY = """
                                              192.168.2.0/24
                                             -----+-----
                                                  |
                                                  |
                                                  |
                                             +----------+
                                             |          |
                                             | R2       |
                                             | NHS      |
                                             +----------+
                                                  | .2
                                                  |
                                                  |
                                                  |
            GRE P2MP Between                      + 10.2.1.0/24
            Between Spokes and Hub                |
                                                  |
             10.255.255.x/32                 +----+-----+
                                             |          |
                                             | R3       |
                                             |          |
                                             +----+-----+
                                                  |.3
                                                  |
                                                  |
                             +----------+         |          +---------+
               |             |          |         |          |         |       |
               |             |R1        |         |          | R4      |       |
192.168.1.0/24 +-------------|NHC       +---------+----------| NHC     | ------+ 192.168.4.0/24
               |             |          |.1                .4|         |       |
               |             +----------+      10.1.1.0/24   +---------+       |
"""


def build_topo(tgen):
    "Build function"

    # Create 4 routers.
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r4"])


def _populate_iface():
    tgen = get_topogen()
    cmds_tot_hub = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 10.2.1.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
        "iptables -A FORWARD -i {0}-gre0 -o {0}-gre0 -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1 --hashlimit-mode srcip,dstip --hashlimit-srcmask 24 --hashlimit-dstmask 24 --hashlimit-name loglimit-0 -j NFLOG --nflog-group 1 --nflog-range 128",
    ]

    cmds_tot = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 10.1.1.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
    ]

    for cmd in cmds_tot_hub:
        input = cmd.format("r2", "2")
        logger.info("input: " + input)
        output = tgen.net["r2"].cmd(input)
        logger.info("output: " + output)

    for cmd in cmds_tot:
        input = cmd.format("r1", "1")
        logger.info("input: " + input)
        output = tgen.net["r1"].cmd(input)
        logger.info("output: " + output)

        input = cmd.format("r4", "4")
        logger.info("input: " + input)
        output = tgen.net["r4"].cmd(input)
        logger.info("output: " + output)


def _verify_iptables():
    tgen = get_topogen()
    # Verify iptables is installed
    # This is needed for creating shortcuts
    for rname in ("r1", "r4"):
        rc, _, _ = tgen.net[rname].cmd_status("iptables --version")
        if rc == 127:
            return False
    return True


def setup_module(mod):
    "Sets up the pytest environment"

    logger.info("NHRP Topology : \n {}".format(TOPOLOGY))
    result = required_linux_kernel_version("5.0")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        if rname in ("r1", "r2", "r4"):
            router.load_config(
                TopoRouter.RD_NHRP, os.path.join(CWD, "{}/nhrpd.conf".format(rname))
            )

        # Include sharpd for r1
        if rname == "r1":
            router.load_config(
                TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
            )

    # Initialize all routers.
    logger.info("Launching NHRP")
    for name in router_list:
        router = tgen.gears[name]
        router.start()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged before checking for the NHRP
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv4 routing tables.
    logger.info("Checking NHRP cache and IPv4 routes for convergence")
    router_list = tgen.routers()

    for rname, router in router_list.items():
        if rname == "r3":
            continue

        json_file = "{}/{}/nhrp4_cache.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info("skipping file {}".format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip nhrp cache json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip nhrp cache")
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    for rname, router in router_list.items():
        if rname == "r3":
            continue

        json_file = "{}/{}/nhrp_route4.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info("skipping file {}".format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip route nhrp json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip route nhrp")
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # check that the NOARP flag is removed from rX-gre0 interfaces
    for rname, router in router_list.items():
        if rname == "r3":
            continue

        expected = {
            "{}-gre0".format(rname): {
                "flags": "<UP,LOWER_UP,RUNNING>",
            }
        }
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show interface {}-gre0 json".format(rname),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)

        assertmsg = '"{}-gre0 interface flags incorrect'.format(router.name)
        assert result is None, assertmsg

    for rname, router in router_list.items():
        if rname == "r3":
            continue
        logger.info("Dump neighbor information on {}-gre0".format(rname))
        output = router.run("ip neigh show")
        logger.info(output)


def test_nhrp_connection():
    "Assert that the NHRP peers can find themselves."
    tgen = get_topogen()
    pingrouter = tgen.gears["r1"]
    hubrouter = tgen.gears["r2"]
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def ping_helper():
        output = pingrouter.run("ping 10.255.255.2 -f -c 100")
        logger.info(output)
        return output

    # force session to reinitialize
    def relink_session():
        for r in ["r1", "r2", "r4"]:
            tgen.gears[r].vtysh_cmd("clear ip nhrp cache")
            tgen.net[r].cmd("ip l del {}-gre0".format(r))
        _populate_iface()

    @retry(retry_timeout=40, initial_wait=5)
    def verify_same_password():
        output = ping_helper()
        if "100 packets transmitted, 100 received" not in output:
            assertmsg = "expected ping IPv4 from R1 to R2 should be ok"
            assert 0, assertmsg
        else:
            logger.info("Check Ping IPv4 from R1 to R2 OK")

    @retry(retry_timeout=40, initial_wait=5)
    def verify_mismatched_password():
        output = ping_helper()
        if "Network is unreachable" not in output:
            assertmsg = "expected ping IPv4 from R1 to R2 - should be down"
            assert 0, assertmsg
        else:
            logger.info("Check Ping IPv4 from R1 to R2 missing - OK")

    ### Passwords are the same
    logger.info("Check Ping IPv4 from  R1 to R2 = 10.255.255.2")
    verify_same_password()

    ### Passwords are different
    logger.info("Modify password and send ping again, should drop")
    hubrouter.vtysh_cmd(
        """
        configure
            interface r2-gre0
                ip nhrp authentication secret12
    """
    )
    relink_session()
    verify_mismatched_password()

    ### Passwords are the same - again
    logger.info("Recover password and verify conectivity is back")
    hubrouter.vtysh_cmd(
        """
        configure
            interface r2-gre0
                ip nhrp authentication secret
    """
    )
    relink_session()
    verify_same_password()


def test_route_install():
    "Test use of NHRP routes by other protocols (sharpd here)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing route install over NHRP tunnel")

    # Install sharpd routes over an NHRP route
    r1 = tgen.gears["r1"]

    # Install one recursive and one non-recursive sharpd route
    r1.vtysh_cmd("sharp install route 4.4.4.1 nexthop 10.255.255.2 1")

    r1.vtysh_cmd("sharp install route 5.5.5.1 nexthop 10.255.255.2 1 no-recurse")

    json_file = "{}/{}/sharp_route4.json".format(CWD, "r1")
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route sharp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)

    logger.info("Sharp routes:")
    output = r1.vtysh_cmd("show ip route sharp")
    logger.info(output)

    assertmsg = '"{}" JSON route output mismatches'.format(r1.name)
    assert result is None, assertmsg


# Initial wait of 30 second because that is
# what the default purge time is for nhrp -
# here we are testing that all of the expected
# retries are sent and logged before a
# shortcut is purged
@retry(retry_timeout=10, initial_wait=30)
def check_retry_debug_info(pingspoke=None):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    if pingspoke == None:
        pingspoke = r1
    logger.info(f"Check retries are being sent from {pingspoke.name}")
    output = pingspoke.cmd("grep -c 'Retrying Resolution Request' nhrpd.log")
    # Making sure that we see all expected retries for a 30 second purge time
    assertmsg = f"Did not see all expected retries on {pingspoke.name}"
    assert output.strip() == "6", assertmsg
    logger.info("Check retries are being sent OK")


# Helper function to ping between spokes and
# check for either complete or incomplete shortcut
# based on whichever one you are expecting -
# expect_succesful_shortcut inidcates whether
# you are expecting to find a complete shortcut
# (True) or incomplete shortcut (False) as a
# result of the ping
@retry(retry_timeout=10, initial_wait=10)
def create_shortcut(expect_successful_shortcut=True, pingspoke=None, peer_addr=None):
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    if pingspoke == None:
        pingspoke = r1
    if peer_addr == None:
        peer_addr = "192.168.4.4"
    # Pinging the other spoke in an attempt to create specified type of shortcut
    output = pingspoke.cmd(f"ping -c 10 -i .5 {peer_addr}")
    print(output)
    output = pingspoke.vtysh_cmd("show ip nhrp shortcut")
    if expect_successful_shortcut:
        logger.info(f"Check shortcut creation from {pingspoke.name} to {peer_addr}")
    else:
        logger.info(
            f"Check incomplete shortcut creation from {pingspoke.name} to {peer_addr}"
        )

    output = pingspoke.vtysh_cmd("show ip nhrp shortcut")
    print(output)
    if expect_successful_shortcut:
        json_file = "{}/{}/nhrp_shortcut_present.json".format(CWD, pingspoke.name)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, pingspoke, "show ip nhrp shortcut json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        if result is not None:
            assertmsg = (
                "Shortcut is not being made between spoke {} and peer {}".format(
                    pingspoke.name, peer_addr
                )
            )
            assert 0, assertmsg
        else:
            logger.info("Shortcut creation between spokes OK")
    else:
        # Currentlly, 'show ip nhrp shortcut json' does not show incomplete shortcuts
        # so an explicit check for for the  'incompete' keyword needed here
        if "incomplete" not in output:
            assertmsg = (
                "Incomplete shortcut between spoke {} and peer {} is not seen".format(
                    pingspoke.name, peer_addr
                )
            )
            assert 0, assertmsg
        else:
            logger.info("Incomplete shortcut creation between spokes OK")


# This function tests the NHRP resolution request retries by dropping
# incoming packets (including the NHRP resolution request packets)
# from a receiving spoke in order to stop the NHRP resolution
# responses from ever being sent from that receiving spoke  - and in turn
# resolution responses will not reach the sending spoke.
# This will trigger the NHRP resolution request retries which
# can be viewed through log messages.
def test_nhrp_retry_resolution():
    """ "
    Verify resolution requests are retried when resolution responses
    are not received by a spoke
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # iptables used to create shortcuts
    # and subsequent resolution request retries
    if not _verify_iptables():
        pytest.skip("iptables is not installed")

    r1 = tgen.gears["r1"]
    r4 = tgen.gears["r4"]

    logger.info("Testing retrying resolution request functionality")
    # Make sure that shortcut creation between spokes work
    create_shortcut(expect_successful_shortcut=True)
    # Clearing shortcut information for spokes
    r1.vtysh_cmd("clear ip nhrp shortcut")
    r4.vtysh_cmd("clear ip nhrp shortcut")

    # Setting iptables rules to stop incoming packets on r4
    # This should stop resolution requests from reaching
    # the receiving router (r4) and hence stop the
    # creation of a complete shortcut
    r4.cmd("iptables -A INPUT -i r4-eth0 -j DROP")

    # Make sure that nhrp debugging is enabled to read the retry logs
    r1.vtysh_cmd(
        """
        configure
           debug nhrp all
    """
    )
    create_shortcut(expect_successful_shortcut=False)
    # Look for retry logging output for resolution request retries
    check_retry_debug_info()
    # Undo iptables rule
    r4.cmd("iptables -D INPUT -i r4-eth0 -j DROP")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
