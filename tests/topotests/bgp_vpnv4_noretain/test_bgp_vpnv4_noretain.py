#!/usr/bin/env python

#
# test_bgp_vpnv4_noretain.py
# Part of NetDEF Topology Tests
#
# Copyright 2022 6WIND S.A.
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

"""
 test_bgp_vpnv4_noretain.py: Do not keep the VPNvx entries when no
 VRF matches incoming VPNVx entries
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

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]

def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])

        
def _populate_iface():
    tgen = get_topogen()
    cmds_list = [
        'modprobe mpls_router',
        'echo 100000 > /proc/sys/net/mpls/platform_labels',
        'ip link add vrf1 type vrf table 10',
        'ip link set dev vrf1 up',
        'ip link set dev {0}-eth1 master vrf1',
        'echo 1 > /proc/sys/net/mpls/conf/vrf1/input',
    ]
    cmds_list_extra = [
        'ip link add vrf2 type vrf table 20',
        'ip link set dev vrf2 up',
        'ip link set dev {0}-eth2 master vrf2',
        'echo 1 > /proc/sys/net/mpls/conf/vrf2/input',
    ]
    
    for cmd in cmds_list:
        input = cmd.format('r1', '1', '2')
        logger.info('input: ' + cmd)
        output = tgen.net['r1'].cmd(cmd.format('r1', '1', '2'))
        logger.info('output: ' + output)

    for cmd in cmds_list:
        input = cmd.format('r2', '2', '1')
        logger.info('input: ' + cmd)
        output = tgen.net['r2'].cmd(cmd.format('r2', '2', '1'))
        logger.info('output: ' + output)

    for cmd in cmds_list_extra:
        input = cmd.format('r2', '2', '1')
        logger.info('input: ' + cmd)
        output = tgen.net['r2'].cmd(cmd.format('r2', '2', '1'))
        logger.info('output: ' + output)

def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface() 

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.stop_topology()


def router_json_cmp_exact_filter(router, cmd, expected):
    output = router.vtysh_cmd(cmd)
    logger.info("{}: {}\n{}".format(router.name, cmd, output))

    json_output = json.loads(output)

    # filter out tableVersion, version and nhVrfID
    json_output.pop("tableVersion")
    for rd, data in json_output["routes"]["routeDistinguishers"].items():
        for prefix, attrs in data.items():
            for attr in attrs:
                if "nhVrfId" in attr:
                    attr.pop("nhVrfId")
                if "version" in attr:
                    attr.pop("version")

    return topotest.json_cmp(json_output, expected, exact=True)


def test_bgp_no_retain():
    """
    Check bgp no retain route-target all on r1
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv4 VPN routing tables on r1
    logger.info("Checking VPNv4 routes for convergence on r1")
    router = tgen.gears["r1"]
    json_file = "{}/{}/ipv4_vpn_routes.json".format(CWD, router.name)
    if not os.path.isfile(json_file):
        logger.info("skipping file {}".format(json_file))
        assert 0, "{} file not found".format(json_file)
        return

    expected = json.loads(open(json_file).read())
    test_func = partial(
        router_json_cmp_exact_filter,
        router,
        "show bgp ipv4 vpn json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
    assert result is None, assertmsg


def test_bgp_retain():
    """
    Apply and check bgp retain route-target all on r1
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv4 VPN routing tables on r1
    logger.info("Checking VPNv4 routes on r1 after bgp no retain")
    router = tgen.gears["r1"]
    router.vtysh_cmd(
        "configure\nrouter bgp 65500\naddress-family ipv4 vpn\nbgp retain route-target all\n"
    )
    json_file = "{}/{}/ipv4_vpn_routes_unfiltered.json".format(CWD, router.name)
    if not os.path.isfile(json_file):
        logger.info("skipping file {}".format(json_file))
        assert 0, "{} file not found".format(json_file)
        return

    expected = json.loads(open(json_file).read())
    test_func = partial(
        router_json_cmp_exact_filter,
        router,
        "show bgp ipv4 vpn json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assertmsg = '"{}" JSON output mismatches'.format(router.name)
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
