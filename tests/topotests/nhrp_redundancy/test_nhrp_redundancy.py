#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_nhrp_redundancy.py
#
# Copyright 2024, LabN Consulting, L.L.C.
# Dave LeRoy
#

import os
import sys
import json
from functools import partial
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    required_linux_kernel_version,
    shutdown_bringup_interface,
    retry,
)

"""
test_nhrp_redundancy.py: Test NHS redundancy for NHRP
"""

TOPOLOGY = """
+------------+                  +------------+                   +------------+               
|            |                  |            |                   |            |               
|            |                  |            |                   |            |               
|   NHS 1    |                  |   NHS 2    |                   |    NHS 3   |               
|            |                  |            |                   |            |               
+-----+------+                  +-----+------+                   +-----+------+               
      |.1                             |.2                              |.3                    
      |                               |                                |                      
      |                               |            192.168.1.0/24      |                      
------+-------------------------------+------------------+-------------+------                
                                                         |                                    
                                                         |.6                                  
         GRE P2MP between all NHS and NHC          +-----+------+                             
               172.16.1.x/32                       |            |                             
                                                   |            |                             
                                                   |   Router   |                             
                                                   |            |                             
                                                   +-----+------+                             
                                                         |                                    
                                                         |                                    
                               ---------+----------------+-------------+------                
                                        |          192.168.2.0/24      |                      
                                        |                              |                      
                       |                |.4                            |.5                    
+------------+         |        +-------+----+                  +------+-----+     |          
|            |         |        |            |                  |            |     |          
|            |         +--------+            |                  |            |     |          
|    Host    |.7       |        |    NHC 1   |                  |    NHC 2   +-----+10.5.5.0/24
|            +---------+        |            |                  |            |     |          
+------------+         |        +------------+                  +------------+     |          
                       |                                                           |          
                  10.4.4.0/24                                                                  
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.nhrpd]


def build_topo(tgen):
    "Build function"

    # Create 7 routers
    for rname in ["nhs1", "nhs2", "nhs3", "nhc1", "nhc2", "router", "host"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["nhs1"])
    switch.add_link(tgen.gears["nhs2"])
    switch.add_link(tgen.gears["nhs3"])
    switch.add_link(tgen.gears["router"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["nhc1"])
    switch.add_link(tgen.gears["nhc2"])
    switch.add_link(tgen.gears["router"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["nhc1"])
    switch.add_link(tgen.gears["host"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["nhc2"])


def _populate_iface():
    tgen = get_topogen()
    cmds_tot_hub = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 192.168.1.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
        "iptables -A FORWARD -i {0}-gre0 -o {0}-gre0 -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1 --hashlimit-mode srcip,dstip --hashlimit-srcmask 24 --hashlimit-dstmask 24 --hashlimit-name loglimit-0 -j NFLOG --nflog-group 1 --nflog-size 128",
    ]

    cmds_tot = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 192.168.2.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
    ]

    for cmd in cmds_tot_hub:
        input = cmd.format("nhs1", "1")
        logger.info("input: " + input)
        output = tgen.net["nhs1"].cmd(input)
        logger.info("output: " + output)

        input = cmd.format("nhs2", "2")
        logger.info("input: " + input)
        output = tgen.net["nhs2"].cmd(input)
        logger.info("output: " + output)

        input = cmd.format("nhs3", "3")
        logger.info("input: " + input)
        output = tgen.net["nhs3"].cmd(input)
        logger.info("output: " + output)

    for cmd in cmds_tot:
        input = cmd.format("nhc1", "4")
        logger.info("input: " + input)
        output = tgen.net["nhc1"].cmd(input)
        logger.info("output: " + output)

        input = cmd.format("nhc2", "5")
        logger.info("input: " + input)
        output = tgen.net["nhc2"].cmd(input)
        logger.info("output: " + output)


def _verify_iptables():
    tgen = get_topogen()
    # Verify iptables is installed. Required for shortcuts
    rc, _, _ = tgen.net["nhs1"].cmd_status("iptables")
    return False if rc == 127 else True


def setup_module(mod):
    logger.info("NHRP Redundant NHS:\n {}".format(TOPOLOGY))

    result = required_linux_kernel_version("5.0")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()
    _populate_iface()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        if rname in ("nhs1", "nhs2", "nhs3", "nhc1", "nhc2"):
            router.load_config(
                TopoRouter.RD_NHRP, os.path.join(CWD, "{}/nhrpd.conf".format(rname))
            )

    # Initialize all routers.
    tgen.start_router()


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

    logger.info("Checking NHRP cache for convergence")
    router_list = tgen.routers()

    # Check NHRP cache on servers and clients
    for rname, router in router_list.items():
        if "nh" not in rname:
            continue

        json_file = "{}/{}/nhrp_cache.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip nhrp cache json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip nhrp cache")
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # Check NHRP IPV4 routes on servers and clients
    logger.info("Checking IPv4 routes for convergence")
    for rname, router in router_list.items():
        if "nh" not in rname:
            continue

        json_file = "{}/{}/nhrp_route.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip route nhrp json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip route nhrp")
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # Test connectivity from 1 NHRP server to all clients
    nhs1 = tgen.gears["nhs1"]
    logger.info("Check Ping IPv4 from  nhs1 to nhc1 = 172.16.1.4)")
    output = nhs1.run("ping 172.16.1.4 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from nhs1 to nhc1 should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from nhs1 to nhc1 OK")

    logger.info("Check Ping IPv4 from  nhs1 to nhc2 = 172.16.1.5)")
    output = nhs1.run("ping 172.16.1.5 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from nhs1 to nhc2 should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from nhs1 to nhc2 OK")

    # Test connectivity from 1 NHRP client to all servers
    nhc1 = tgen.gears["nhc1"]
    logger.info("Check Ping IPv4 from  nhc1 to nhs1 = 172.16.1.1)")
    output = nhc1.run("ping 172.16.1.1 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from nhc1 to nhs1 should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from nhc1 to nhs1 OK")

    logger.info("Check Ping IPv4 from  nhc1 to nhs2 = 172.16.1.2)")
    output = nhc1.run("ping 172.16.1.2 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from nhc1 to nhs2 should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from nhc1 to nhs2 OK")

    logger.info("Check Ping IPv4 from  nhc1 to nhs3 = 172.16.1.3)")
    output = nhc1.run("ping 172.16.1.3 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from nhc1 to nhs3 should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from nhc1 to nhs3 OK")


@retry(retry_timeout=30, initial_wait=5)
def verify_shortcut_path():
    """
    Verifying that traffic flows through shortcut path
    """
    tgen = get_topogen()
    host = tgen.gears["host"]
    logger.info("Check Ping IPv4 from  host to nhc2 = 10.5.5.5")

    output = host.run("ping 10.5.5.5 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from host to nhc2 should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from host to nhc2 OK")


def test_redundancy_shortcut():
    """
    Assert that if shortcut created and then NHS goes down, there is no traffic disruption
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not _verify_iptables():
        pytest.skip("iptables not installed")

    logger.info("Testing NHRP shortcuts with redundant servers")

    # Verify nhc1 nhrp routes before shortcut creation
    nhc1 = tgen.gears["nhc1"]
    json_file = "{}/{}/nhrp_route.json".format(CWD, nhc1.name)
    assertmsg = "No nhrp_route file found"
    assert os.path.isfile(json_file), assertmsg

    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip route nhrp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip route nhrp")
    logger.info(output)

    assertmsg = '"{}" JSON output mismatches'.format(nhc1.name)
    assert result is None, assertmsg

    # Initiate shortcut by pinging between clients
    host = tgen.gears["host"]
    logger.info("Check Ping IPv4 from  host to nhc2 via shortcut = 10.5.5.5")

    output = host.run("ping 10.5.5.5 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from host to nhc2 via shortcut should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from host to nhc2 via shortcut OK")

    # Now check that NHRP shortcut route installed
    json_file = "{}/{}/nhrp_route_shortcut.json".format(CWD, nhc1.name)
    assertmsg = "No nhrp_route file found"
    assert os.path.isfile(json_file), assertmsg

    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip route nhrp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip route nhrp")
    logger.info(output)

    assertmsg = '"{}" JSON output mismatches'.format(nhc1.name)
    assert result is None, assertmsg

    json_file = "{}/{}/nhrp_shortcut_present.json".format(CWD, nhc1.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip nhrp shortcut json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip nhrp shortcut")
    logger.info(output)

    assertmsg = '"{}" JSON output mismatches'.format(nhc1.name)
    assert result is None, assertmsg

    # check the shortcut disappears because of no traffic
    json_file = "{}/{}/nhrp_shortcut_absent.json".format(CWD, nhc1.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip nhrp shortcut json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip nhrp shortcut")
    logger.info(output)

    assertmsg = '"{}" JSON output mismatches'.format(nhc1.name)
    assert result is None, assertmsg


def test_redundancy_shortcut_backup():
    """
    Stop traffic and verify next time traffic started, shortcut is initiated by backup NHS
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not _verify_iptables():
        pytest.skip("iptables not installed")

    nhc1 = tgen.gears["nhc1"]
    router_list = tgen.routers()

    # Bring down primary GRE interface and verify shortcut is not disturbed
    logger.info("Bringing down nhs1, primary NHRP server.")
    shutdown_bringup_interface(tgen, "nhs1", "nhs1-gre0", False)

    # Check NHRP cache on servers and clients
    for rname, router in router_list.items():
        if "nh" not in rname:
            continue
        if "nhs1" in rname:
            continue

        json_file = "{}/{}/nhrp_cache_nhs1_down.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip nhrp cache json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip nhrp cache")
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # Check NHRP IPV4 routes on servers and clients
    logger.info("Checking IPv4 routes for convergence")
    for rname, router in router_list.items():
        if "nh" not in rname:
            continue
        if "nhs1" in rname:
            continue

        json_file = "{}/{}/nhrp_route_nhs1_down.json".format(CWD, router.name)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip route nhrp json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip route nhrp")
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    # Verify shortcut is still active
    host = tgen.gears["host"]
    logger.info("Check Ping IPv4 from  host to nhc2 via shortcut = 10.5.5.5")

    output = host.run("ping 10.5.5.5 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from host to nhc2 via shortcut should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from host to nhc2 via shortcut OK")

    # Verify shortcut is present in routing table
    json_file = "{}/{}/nhrp_route_shortcut_nhs1_down.json".format(CWD, nhc1.name)
    assertmsg = "No nhrp_route file found"
    assert os.path.isfile(json_file), assertmsg

    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip route nhrp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip route nhrp")
    logger.info(output)

    json_file = "{}/{}/nhrp_shortcut_present.json".format(CWD, nhc1.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip nhrp shortcut json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip nhrp shortcut")
    logger.info(output)

    assertmsg = '"{}" JSON output mismatches'.format(nhc1.name)
    assert result is None, assertmsg

    # Now verify shortcut is purged with lack of traffic
    json_file = "{}/{}/nhrp_route_nhs1_down.json".format(CWD, nhc1.name)
    assertmsg = "No nhrp_route file found"
    assert os.path.isfile(json_file), assertmsg

    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip route nhrp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip route nhrp")
    logger.info(output)

    assertmsg = '"{}" JSON output mismatches'.format(nhc1.name)
    assert result is None, assertmsg

    json_file = "{}/{}/nhrp_shortcut_absent.json".format(CWD, nhc1.name)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip nhrp shortcut json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip nhrp shortcut")
    logger.info(output)

    assertmsg = '"{}" JSON output mismatches'.format(nhc1.name)
    assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
