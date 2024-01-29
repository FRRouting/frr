# SPDX-License-Identifier: ISC
#
# Copyright (c) 2023 by
# Alibaba, Inc. Wenbo Li
#

"""
test_kernel_bypass_reconfig.py: Test kernel bypass route-map reconfig.
"""
from lib.topolog import logger
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib import topotest
import os
import sys
import pytest
import json
from functools import partial
# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
pytestmark = [pytest.mark.bgpd]

def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    switch = tgen.add_switch('s1')
    switch.add_link(tgen.gears['r1'])
    switch.add_link(tgen.gears['r2'])

def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()
    print("topology started")
    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname))
        )
        if rname != "r1":
            router.load_config(
                TopoRouter.RD_STATIC,
                os.path.join(CWD, '{}/staticd.conf'.format(rname))
            )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    # This function tears down the whole topology.
    tgen.stop_topology()


def test_ebgp_peers():
    "Assert that BGP peers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bgp peers to go up')

    for router in tgen.routers().values():
        ref_file = '{}/{}/peers.json'.format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show bgp neighbors json', expected)
        _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assertmsg = '{}: bgp did not established'.format(router.name)
        assert res is None, assertmsg


def test_ebgp_convergence():
    "Assert that BGP is converging."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bgp peers to go up')

    for router in tgen.routers().values():
        ref_file = '{}/{}/ip_route_summary.json'.format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show ip route summary json', expected)
        _, res = topotest.run_and_expect(test_func, None, count=50, wait=1)
        assertmsg = '{}: bgp did not converge'.format(router.name)
        assert res is None, assertmsg


def test_kernel_route():
    "Assert kernel route."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears['r1']
    ref_file = '{}/{}/ref_all_route.json'.format(CWD, router.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(topotest.json_cmp,
                    json.loads(router.cmd("ip -j route")), expected)
    _, res = topotest.run_and_expect(test_func, None, count=50, wait=1)
    router.logger.debug("cmd output {}".format(router.cmd("ip -j route")))
    assert res is None, '{}: kernel route install failed'.format(router.name)

    router.vtysh_cmd(
        """
        configure
        route-map tag-map permit 1
        set tag 9999
        !
        route-map kernel-map permit 1
        set kernel-bypass
        match tag 9999
        !
        ip protocol any route-map kernel-map
        router bgp 100
        address-family ipv4 unicast
            neighbor 192.168.0.2 route-map tag-map in
            neighbor 192.168.0.2 soft-reconfiguration inbound
        """
    )

    ref_file = '{}/{}/ref_bypass_route.json'.format(CWD, router.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(topotest.json_cmp,
            json.loads(router.cmd("ip -j route")), expected)
    _, res = topotest.run_and_expect(test_func, None, count=50, wait=1)
    router.logger.debug("cmd output {}".format(router.cmd("ip -j route")))
    assert res is None, '{}: kernel route bypass failed'.format(router.name)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
