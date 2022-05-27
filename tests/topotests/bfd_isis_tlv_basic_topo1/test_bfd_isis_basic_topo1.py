#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_isis_basic_topo1.py
#
# Copyright 2023 6WIND S.A.
#

"""
test_bfd_isis_basic_topo1.py:

           +----+----+
           |         |
           |   RT1   |
           | 1.1.1.1 |
           |         |
           +----+----+
        eth-rt2 | (.1)
                |
                |
    10.0.1.0/24 |
                |
                |
        eth-rt1 | (.2)
           +----+----+
           |         |
           |   RT2   |
           | 2.2.2.2 |
           |         |
           +----+----+

"""

import os
import sys
import pytest
import json
import re
from ipaddress import ip_address, IPv4Address, IPv6Address
from time import sleep
from time import time
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd, pytest.mark.isisd]

global_count = 40


def build_topo(tgen):
    "Build function"
    tgen = get_topogen()

    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        router.load_config(TopoRouter.RD_BFD, "/dev/null")

    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def print_cmd_result(rname, command):
    print(get_topogen().gears[rname].vtysh_cmd(command, isjson=False))


def router_compare_json_file_output(
    rname, command, reference, count=global_count, wait=0.5
):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def router_compare_json_output(rname, command, reference, wait=0.5, count=global_count):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    expected = json.loads(reference)

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def check_isis(
    rname,
    state="Up",
    ipv4=None,
    ipv6=None,
    mt=False,
    bfd=None,
    bfd_std_ipv4=False,
    bfd_std_ipv6=False,
    bfd_mt6_ipv6=False,
    wait=0.5,
    count=global_count,
):
    """
    output sample:
     rt1
        Interface: eth-rt1, Level: 1, State: Up, Expires in 7s
        Adjacency flaps: 1, Last: 1m25s ago
        Circuit type: L1, Speaks: IPv4, IPv6
        Topologies:
          ipv4-unicast
          ipv6-unicast
        SNPA: 261d.03dc.3cd3, LAN id: 0000.0000.0002.02
        LAN Priority: 64, is not DIS, DIS flaps: 1, Last: 1m16s ago
        Area Address(es):
          49.0000
        IPv4 Address(es):
          10.0.1.1
        IPv6 Address(es):
          fe80::241d:3ff:fedc:3cd3
        BFD is active, status Up
        RFC6213 (MTID,NLPID):
            Local   : (ipv4-unicast,IPv4), (ipv4-unicast,IPv6)
            Neighbor: (ipv4-unicast,IPv4), (ipv6-unicast,IPv6)
    """

    tgen = get_topogen()

    neigh = "rt2" if rname == "rt1" else "rt1"

    retry = count + 1
    while retry:
        retry -= 1
        result = True
        assertmsg = ""

        output = tgen.gears[rname].vtysh_cmd("show isis neighbor {}".format(neigh))
        lst_out = [s.lstrip().rstrip() for s in output.splitlines()]

        if state:
            state_str = "State: {0},".format(state)
            if not (neigh in output and state_str in output):
                assertmsg = "Expected neighbor {0}".format(state)
                result = False
                sleep(wait)
                continue
            else:
                break

        match = next((x for x in lst_out if "Circuit type:" in x), "")
        if ipv4 and "IPv4" not in match:
            assertmsg = "Circuit does not speak IPv4"
            result = False
            sleep(wait)
            continue

        if ipv6 and "IPv6" not in match:
            assertmsg = "Circuit does not speak IPv4"
            result = False
            sleep(wait)
            continue

        if mt and ipv4 and not "ipv4-unicast" in lst_out:
            assertmsg = "Topology IPv4 not found"
            result = False
            sleep(wait)
            continue

        if mt and ipv6 and not "ipv6-unicast" in lst_out:
            assertmsg = "Topology IPv6 not found"
            result = False
            sleep(wait)
            continue

        match = next((x for x in lst_out if "BFD" in x), "")
        if bfd is None and match != "":
            assertmsg = "Expected no BFD"
            result = False
            sleep(wait)
            continue
        elif not bfd and ("Up" in match or "Unknown" in match):
            assertmsg = "Expected BFD down"
            result = False
            sleep(wait)
            continue
        elif bfd and "Down" in match:
            assertmsg = "Expected BFD up"
            result = False
            sleep(wait)
            continue

        match = next((x for x in lst_out if "Neighbor: " in x), "")
        if bfd_std_ipv4 and "ipv4-unicast,IPv4" not in match:
            assertmsg = "ipv4-unicast,IPv4 MTID, NLPID not found"
            result = False
            sleep(wait)
            continue

        if bfd_std_ipv6 and "ipv4-unicast,IPv6" not in match:
            assertmsg = "ipv4-unicast,IPv6 MTID, NLPID not found"
            result = False
            sleep(wait)
            continue

        if bfd_mt6_ipv6 and "ipv6-unicast,IPv6" not in match:
            assertmsg = "ipv6-unicast,IPv6 MTID, NLPID not found"
            result = False
            sleep(wait)
            continue

        if result:
            break
        sleep(wait)

    assertmsg = "{} - neigh {}: {}".format(rname, neigh, assertmsg)
    assert result, assertmsg


def check_bfd(rname, ipv4=None, ipv6=None, wait=0.5, count=global_count):
    tgen = get_topogen()

    sessions = sum(x is not None for x in [ipv4, ipv6])
    ipv4_status = None if ipv4 is None else "Up" if ipv4 else "Down"
    ipv6_status = None if ipv6 is None else "Up" if ipv6 else "Down"

    retry = count + 1
    while retry:
        retry -= 1
        result = True
        assertmsg = ""

        output = tgen.gears[rname].vtysh_cmd("show bfd peers json")
        js_out = json.loads(output)

        for bfd in js_out:
            ipaddr = ip_address(bfd["peer"])
            version = 4 if type(ipaddr) is IPv4Address else 6
            status = True if bfd["status"] == "up" else False
            if len(js_out) != sessions:
                result = False
                assertmsg = "Expected {} BFD sessions. Got {}".format(
                    sessions, len(js_out)
                )
                break
            if ipv4 is None and version == 4:
                result = False
                assertmsg = "An IPv4 BFD session found. Expect none."
                break
            if ipv6 is None and version == 6:
                result = False
                assertmsg = "An IPv6 BFD session found. Expect none."
                break
            if version == 4 and ipv4 != status:
                result = False
                assertmsg = "An IPv4 status is {}. Expect {}.".format(
                    bfd["peer"], ipv4_status
                )
                break
            if version == 6 and ipv6 != status:
                result = False
                assertmsg = "An IPv6 status is {}. Expect {}.".format(
                    bfd["peer"], ipv6_status
                )
                break

        if result:
            break
        sleep(wait)

    assertmsg = "{}: {}".format(rname, assertmsg)
    assert result, assertmsg


def get_bfd_uptime(rname, ip_ver):
    tgen = get_topogen()

    output = tgen.gears[rname].vtysh_cmd("show bfd peers json")
    js_out = json.loads(output)

    nb_4 = sum(type(ip_address(bfd["peer"])) is IPv4Address for bfd in js_out)
    nb_6 = sum(type(ip_address(bfd["peer"])) is IPv6Address for bfd in js_out)

    assert (
        ip_ver == 4 and nb_4 == 1
    ) or ip_ver == 6, "{}: Expected one IPv4 BFD sessions. Got {}".format(rname, nb_4)
    assert (
        ip_ver == 6 and nb_6 == 1
    ) or ip_ver == 4, "{}: Expected one IPv6 BFD sessions. Got {}".format(rname, nb_6)

    for bfd in js_out:
        ipaddr = ip_address(bfd["peer"])
        version = 4 if type(ipaddr) is IPv4Address else 6
        if version != ip_ver:
            continue
        status = True if bfd["status"] == "up" else False
        assert status, "{}: BFD IPv{} is not up".format(rname, ip_ver)
        assert status, "{}: BFD IPv{} is not up".format(rname, ip_ver)
        return bfd["uptime"]

    return None


def check_no_bfd_flap(rname, ip_ver, reftime, refuptime):
    currtime = time()
    curruptime = get_bfd_uptime(rname, ip_ver)

    difftime = currtime - reftime
    expect_uptime = int(refuptime + difftime) - 0.1

    assert (
        curruptime - expect_uptime
    ) > 0, "{}: BFD IPv{} has flapped {}s ago.".format(rname, ip_ver, curruptime)


## TEST STEPS
def test_isis_bfd_tlv_basic_step1():
    logger.info("Test (step 1): check ISIS and no BFD")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_isis("rt1", ipv4=True, bfd=False)  # BFD configured but down
    check_isis("rt2", ipv4=True, bfd=None)  # BFD not configured

    for rt in ["rt1", "rt2"]:
        check_bfd(rt, ipv4=None, ipv6=None)


def test_isis_bfd_tlv_basic_step2():
    logger.info("Test (step 2): check ISIS and BFD")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "rt2"

    logger.info("Configuring BFD TLV on rt2")
    tgen.net[rname].cmd(
        'vtysh -c "conf t" -c "interface eth-rt1" -c "isis bfd" -c "isis bfd use-tlv-ipv4"  -c "isis bfd use-tlv-ipv6"'
    )

    for rt in ["rt1", "rt2"]:
        check_isis(rt, ipv4=True, bfd=True, bfd_std_ipv4=True, bfd_mt6_ipv6=False)
        check_bfd(rt, ipv4=True, ipv6=None)


def test_isis_bfd_tlv_basic_step3():
    logger.info("Test (step 3): check ISIS and BFD")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # reftime = {}
    # refuptime = {}
    # for rt in ["rt1", "rt2"]:
    #     reftime[rt] = time()
    #     refuptime[rt] = get_bfd_uptime(rt, 4)

    logger.info("Configuring ipv6 ISIS on rt1 and rt2 interfaces")
    for rt in ["rt1", "rt2"]:
        iface = "eth-rt2" if rt == "rt1" else "eth-rt1"
        tgen.net[rt].cmd(
            'vtysh -c "conf t" -c "int {}" -c "ipv6 router isis 1"'.format(iface)
        )
    #
    # # Check there was no flap after one second
    # sleep(1)
    # for rt in ["rt1", "rt2"]:
    #     check_no_bfd_flap(rt, 4, reftime[rt], refuptime[rt])

    for rt in ["rt1", "rt2"]:
        check_isis(
            rt,
            ipv4=True,
            ipv6=True,
            bfd=True,
            bfd_std_ipv4=True,
            bfd_std_ipv6=True,
            bfd_mt6_ipv6=False,
        )
        check_bfd(rt, ipv4=True, ipv6=True)


def test_isis_bfd_tlv_basic_step4():
    logger.info("Test (step 4): check ISIS and BFD")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reftime = {}
    refuptime = {}
    for rt in ["rt1", "rt2"]:
        reftime[rt] = time()
        refuptime[rt] = get_bfd_uptime(rt, 4)

    logger.info("Configuring ipv6 ISIS topology on rt1")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "topology ipv6-unicast"'
    )

    # # Check there was no flap after one second
    # sleep(1)
    # for rt in ["rt1", "rt2"]:
    #     check_no_bfd_flap(rt, 4, reftime[rt], refuptime[rt])

    check_isis(
        "rt1", ipv4=True, ipv6=True, bfd=True, bfd_std_ipv4=True, bfd_mt6_ipv6=False
    )
    check_isis(
        "rt2", ipv4=True, ipv6=True, bfd=True, bfd_std_ipv4=False, bfd_mt6_ipv6=True
    )

    check_bfd("rt1", ipv4=True, ipv6=None)
    check_bfd("rt2", ipv4=True, ipv6=None)


def test_isis_bfd_tlv_basic_step5():
    logger.info("Test (step 5): check ISIS and BFD")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reftime = {}
    refuptime = {}
    for rt in ["rt1", "rt2"]:
        reftime[rt] = time()
        refuptime[rt] = get_bfd_uptime(rt, 4)

    logger.info("Configuring ipv6 ISIS topology on rt2")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "topology ipv6-unicast"'
    )

    # # Check there was no flap after one second
    # sleep(1)
    # for rt in ["rt1", "rt2"]:
    #     check_no_bfd_flap(rt, 4, reftime[rt], refuptime[rt])

    for rt in ["rt1", "rt2"]:
        check_isis(
            rt,
            ipv4=True,
            ipv6=True,
            mt=True,
            bfd=True,
            bfd_std_ipv4=True,
            bfd_mt6_ipv6=True,
        )
        check_bfd(rt, ipv4=True, ipv6=True)


def test_isis_bfd_tlv_basic_step6():
    logger.info("Test (step 6): check ISIS and BFD")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reftime = {}
    refuptime = {}
    for rt in ["rt1", "rt2"]:
        reftime[rt] = time()
        refuptime[rt] = get_bfd_uptime(rt, 6)

    logger.info("Unconfiguring IPv4 on rt1 eth-rt2")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "int eth-rt2" -c "no ip address 10.0.1.1/24"'
    )
    #
    # # Check there was no flap after one second
    # sleep(1)
    # for rt in ["rt1", "rt2"]:
    #     check_no_bfd_flap(rt, 6, reftime[rt], refuptime[rt])

    for rt in ["rt1", "rt2"]:
        check_isis(
            rt,
            ipv4=False,
            ipv6=True,
            mt=True,
            bfd=True,
            bfd_std_ipv4=False,
            bfd_mt6_ipv6=True,
        )
        check_bfd(rt, ipv4=None, ipv6=True)


def test_isis_bfd_tlv_basic_step7():
    logger.info("Test (step 7): check ISIS and BFD")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    reftime = {}
    refuptime = {}
    for rt in ["rt1", "rt2"]:
        reftime[rt] = time()
        refuptime[rt] = get_bfd_uptime(rt, 6)

    logger.info("Reconfiguring IPv4 on rt1 eth-rt2")
    tgen.net["rt1"].cmd(
        'vtysh -c "conf t" -c "int eth-rt2" -c "ip address 10.0.1.1/24"'
    )

    # Check there was no flap after one second
    sleep(1)
    for rt in ["rt1", "rt2"]:
        check_no_bfd_flap(rt, 6, reftime[rt], refuptime[rt])

    for rt in ["rt1", "rt2"]:
        check_isis(
            rt,
            ipv4=True,
            ipv6=True,
            mt=True,
            bfd=True,
            bfd_std_ipv4=True,
            bfd_mt6_ipv6=True,
        )
        check_bfd(rt, ipv4=True, ipv6=True)


def test_isis_bfd_tlv_basic_step8():
    logger.info("Test (step 8): check ISIS and BFD")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Dropping BFD traffic")
    tgen.net["rt1"].cmd("iptables -A OUTPUT -p udp  --dport 3784 -j DROP")
    tgen.net["rt1"].cmd("ip6tables -A OUTPUT -p udp  --dport 3784 -j DROP")

    for rt in ["rt1", "rt2"]:
        check_isis(rt, state="Initializing", ipv4=False, ipv6=False, bfd=False)
        check_bfd(rt, ipv4=False, ipv6=False)

    logger.info("Routing BFD traffic")
    tgen.net["rt1"].cmd("iptables -D OUTPUT -p udp  --dport 3784 -j DROP")
    tgen.net["rt1"].cmd("ip6tables -D OUTPUT -p udp  --dport 3784 -j DROP")

    for rt in ["rt1", "rt2"]:
        check_isis(rt, ipv4=True, ipv6=True, bfd=True)
        check_bfd(rt, ipv4=True, ipv6=True, count=30)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
