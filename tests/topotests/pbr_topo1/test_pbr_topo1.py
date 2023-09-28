#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pbr_topo1.py
#
# Copyright (c) 2020 by
# Cumulus Networks, Inc.
# Donald Sharp
#
# Copyright (c) 2023 LabN Consulting, L.L.C.
#

"""
test_pbr_topo1.py: Testing PBR

"""

import os
import sys
import pytest
import json
import platform
import re
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import shutdown_bringup_interface

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.pbrd]

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    "Build function"

    # Populate routers
    for routern in range(1, 2):
        tgen.add_router("r{}".format(routern))

    # Populate switches
    for switchn in range(1, 6):
        switch = tgen.add_switch("sw{}".format(switchn))
        switch.add_link(tgen.gears["r1"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.10") < 0:
        tgen.errors = "Newer kernel than 4.9 needed for pbr tests"
        pytest.skip(tgen.errors)

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Install vrf into the kernel and slave eth3
        router.run("ip link add vrf-chiyoda type vrf table 1000")
        router.run("ip link set dev {}-eth3 master vrf-chiyoda".format(rname))
        router.run("ip link set vrf-chiyoda up")

        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PBRD, os.path.join(CWD, "{}/pbrd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sleep(5, "Waiting for PBR convergence")


#
# router: r1
# tag: "show pbr interface"
# cmd: "show pbr interface json"
# expfile: "{}/{}/pbr-interface.json".format(CWD, router.name)
#
def runit(router, tag, cmd, expfile):
    logger.info(expfile)

    # Read expected result from file
    expected = json.loads(open(expfile).read())

    # Actual output from router
    test_func = partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" mismatches on {}'.format(tag, router.name)
    if result is not None:
        gather_pbr_data_on_error(router)
        assert result is None, assertmsg


def test_pbr_data():
    "Test PBR"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify PBR Status
    logger.info("Verifying PBR routes")

    router_list = tgen.routers().values()
    for router in router_list:
        runit(
            router,
            "show pbr interface",
            "show pbr interface json",
            "{}/{}/pbr-interface.json".format(CWD, router.name),
        )

        runit(
            router,
            "show pbr map",
            "show pbr map json",
            "{}/{}/pbr-map.json".format(CWD, router.name),
        )

        runit(
            router,
            "show pbr nexthop-groups",
            "show pbr nexthop-groups json",
            "{}/{}/pbr-nexthop-groups.json".format(CWD, router.name),
        )


########################################################################
# 			Field test - START
########################################################################

#
# New fields:
# match ip-protocol (was only tcp|udp, now any value in /etc/protocols)
# match pcp (0-7)
# match vlan (1-4094)
# match vlan (tagged|untagged|untagged-or-zero)
#

#
# c:   command
# cDN: omit default destination IP address (special case)
# tm:  must-match pattern
# tN:  must Not match pattern
#
# Note we are searching amid a bunch of other rules, so these elements
# should be unique.
#
ftest = [
    {"c": "match ip-protocol icmp", "tm": r"IP protocol Match: 1$"},
    {"c": "no match ip-protocol icmp", "tN": r"IP protocol Match:"},
    {"c": "match pcp 6", "tm": r"PCP Match: 6$"},
    {"c": "match pcp 0", "tm": r"PCP Match: 0$"},
    {"c": "no match pcp 0", "tN": r"PCP Match:"},
    {"c": "match vlan 33", "tm": r"VLAN ID Match: 33$"},
    {"c": "no match vlan 33", "tN": r"VLAN ID Match:"},
    {"c": "match vlan tagged", "tm": r"VLAN Flags Match: tagged$"},
    {"c": "match vlan untagged", "tm": r"VLAN Flags Match: untagged$"},
    {"c": "match vlan untagged-or-zero", "tm": r"VLAN Flags Match: untagged-or-zero$"},
    {"c": "no match vlan tagged", "tN": r"VLAN Flags Match:"},
    {"c": "match src-ip 37.49.22.0/24", "tm": r"SRC IP Match: 37.49.22.0/24$"},
    {"c": "no match src-ip 37.49.22.0/24", "tN": r"SRC IP Match: 37.49.22.0/24$"},
    {
        "c": "match dst-ip 38.41.29.0/25",
        "cDN": "foo",
        "tm": r"DST IP Match: 38.41.29.0/25$",
    },
    {"c": "no match dst-ip 38.41.29.0/25", "tN": r"DST IP Match: 38.41.29.0/25$"},
    {"c": "match src-port 117", "tm": r"SRC Port Match: 117$"},
    {"c": "no match src-port 117", "tN": r"SRC Port Match: 117$"},
    {"c": "match dst-port 119", "tm": r"DST Port Match: 119$"},
    {"c": "no match dst-port 119", "tN": r"DST Port Match: 119$"},
    {"c": "match dscp cs3", "tm": r"DSCP Match: 24$"},
    {"c": "no match dscp cs3", "tN": r"DSCP Match: 24$"},
    {"c": "match dscp 5", "tm": r"DSCP Match: 5$"},
    {"c": "no match dscp 5", "tN": r"DSCP Match: 5$"},
    {"c": "match ecn 2", "tm": r"ECN Match: 2$"},
    {"c": "no match ecn 2", "tN": r"ECN Match: 2$"},
    {"c": "match mark 337", "tm": r"MARK Match: 337$"},
    {"c": "no match mark 337", "tN": r"MARK Match: 337$"},
    {"c": "set src-ip 44.100.1.1", "tm": r"Set SRC IP: 44.100.1.1$"},
    {"c": "no set src-ip 44.100.1.1", "tN": r"Set SRC IP: 44.100.1.1$"},
    {"c": "set dst-ip 44.105.1.1", "tm": r"Set DST IP: 44.105.1.1$"},
    {"c": "no set dst-ip 44.105.1.1", "tN": r"Set DST IP: 44.105.1.1$"},
    {"c": "set src-port 41", "tm": r"Set SRC PORT: 41$"},
    {"c": "no set src-port 41", "tN": r"Set SRC PORT: 41$"},
    {"c": "set dst-port 43", "tm": r"Set DST PORT: 43$"},
    {"c": "no set dst-port 43", "tN": r"Set DST PORT: 43$"},
    {"c": "set dscp 24", "tm": r"Set DSCP: 24$"},
    {"c": "no set dscp 24", "tN": r"Set DSCP: 24$"},
    {"c": "set dscp cs7", "tm": r"Set DSCP: 56$"},
    {"c": "no set dscp cs7", "tN": r"Set DSCP: 56$"},
    {"c": "set ecn 1", "tm": r"Set ECN: 1$"},
    {"c": "no set ecn 1", "tN": r"Set ECN: 1$"},
]


# returns None if command output is correct, otherwise returns output
def rtr_field_cmp(rtr, cmd, pat_mustmatch, pat_mustnotmatch):
    outstr = rtr.vtysh_cmd(cmd)
    if pat_mustmatch is not None:
        logger.info("MUSTMATCH: {}".format(pat_mustmatch))
        m = re.search(pat_mustmatch, outstr, flags=re.M)
        if not m:
            logger.info('Missing MUSTMATCH "{}"'.format(pat_mustmatch))
            return "MISSING MUSTMATCH: " + outstr
    if pat_mustnotmatch is not None:
        logger.info("MUSTNOTMATCH: {}".format(pat_mustnotmatch))
        m = re.search(pat_mustnotmatch, outstr, flags=re.M)
        if m:
            logger.info('Has MUSTNOTMATCH "{}"'.format(pat_mustnotmatch))
            return "HAS MUSTNOTMATCH: " + outstr
    return None


#
# This test sets fields in pbrd and looks for them in zebra via "sh pbr map"
#
def test_pbr_fields():
    "Test setting and clearing rule fields"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying PBR rule fields")

    # uncomment for manual interaction
    # tgen.cli()

    tag = "field"

    router_list = tgen.routers().values()
    for router in router_list:
        for t in ftest:
            # send field-setting command
            # always have a match dst-ip to satisfy rule non-empty check
            if "cDN" in t:
                match_dstip = ""
            else:
                match_dstip = "match dst-ip 9.9.9.9/32\n"
            vcmd = "c t\npbr-map ASAKUSA seq 100\n{}\n{}set nexthop-group A\nend\nend".format(
                t["c"], match_dstip
            )
            router.vtysh_multicmd(vcmd)

            # debug
            router.vtysh_cmd("sh pbr map")

            match = None
            notmatch = None

            if "tm" in t:
                match = t["tm"]
                logger.info("MUSTMATCH: {}".format(match))
            if "tN" in t:
                notmatch = t["tN"]
                logger.info("NOTMATCH: {}".format(notmatch))

            test_func = partial(rtr_field_cmp, router, "sh pbr rule", match, notmatch)
            _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
            assertmsg = '"{}" mismatches on {}'.format(tag, router.name)
            if result is not None:
                gather_pbr_data_on_error(router)
                assert result is None, assertmsg

        #
        # clean up
        #
        vcmd = "c t\nno pbr-map ASAKUSA seq 100\nend"
        router.vtysh_multicmd(vcmd)

        match = None
        notmatch = r"Seq 100\w"

        test_func = partial(rtr_field_cmp, router, "sh pbr rule", match, notmatch)
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assertmsg = '"{}" mismatches on {}'.format(tag, router.name)
        if result is not None:
            gather_pbr_data_on_error(router)
            assert result is None, assertmsg


########################################################################
# 			Field test - END
########################################################################


def test_pbr_flap():
    "Test PBR interface flapping"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify PBR Status
    logger.info("Flapping PBR Interfaces")

    router_list = tgen.routers().values()
    for router in router_list:
        # Flap interface to see if route-map properties are intact
        # Shutdown interface

        for i in range(5):
            intf = "r1-eth{}".format(i)

            # Down and back again
            shutdown_bringup_interface(tgen, router.name, intf, False)
            shutdown_bringup_interface(tgen, router.name, intf, True)

        intf_file = "{}/{}/pbr-interface.json".format(CWD, router.name)
        logger.info(intf_file)

        # Read expected result from file
        expected = json.loads(open(intf_file).read())

        # Actual output from router
        test_func = partial(
            topotest.router_json_cmp, router, "show pbr interface json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"show pbr interface" mismatches on {}'.format(router.name)
        if result is not None:
            gather_pbr_data_on_error(router)
            assert result is None, assertmsg


def test_rule_linux_installation():
    "Ensure that rule is installed in the kernel"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking for installed PBR rules in OS")

    def _get_router_rules(router, expected):
        actual = topotest.ip_rules(router)

        logger.info(actual)
        return topotest.json_cmp(actual, expected)

    router_list = tgen.routers().values()
    for router in router_list:
        rules_file = "{}/{}/linux-rules.json".format(CWD, router.name)

        expected = json.loads(open(rules_file).read())

        test_func = partial(_get_router_rules, router, expected)

        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = "Router {} OS rules mismatch".format(router.name)
        assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


#
# EXTRA SAUCE
#
def gather_pbr_data_on_error(router):
    logger.info(router.vtysh_cmd("show ip route"))
    logger.info(router.vtysh_cmd("show ip route vrf vrf-chiyoda"))
    logger.info(router.vtysh_cmd("show ip nht"))
    logger.info(router.vtysh_cmd("show pbr interface"))
    logger.info(router.vtysh_cmd("show pbr map"))
    logger.info(router.vtysh_cmd("show pbr nexthop-groups"))
    logger.info(router.vtysh_cmd("show nexthop-group rib singleton ip"))
    logger.info(router.vtysh_cmd("show nexthop-group rib singleton ipv6"))
    logger.info(router.vtysh_cmd("show nexthop-group rib"))
    logger.info(router.run("ip nexthop show"))
    logger.info(router.run("ip route show"))
    logger.info(router.run("ip route show table 1000"))
    logger.info(router.run("ip route show table 10000"))
    logger.info(router.run("ip -6 route show table 10000"))
    logger.info(router.run("ip route show table 10001"))
    logger.info(router.run("ip -6 route show table 10001"))
    logger.info(router.run("ip route show table 10002"))
    logger.info(router.run("ip -6 route show table 10002"))
    logger.info(router.run("ip route show table 10003"))
    logger.info(router.run("ip -6 route show table 10003"))
    logger.info(router.run("ip route show table 10004"))
    logger.info(router.run("ip -6 route show table 10004"))
    logger.info(router.run("ip route show table 10005"))
    logger.info(router.run("ip -6 route show table 10005"))
    logger.info(router.run("ip rule show"))
