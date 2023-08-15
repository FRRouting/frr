#!/usr/bin/python
# SPDX-License-Identifier: ISC
#
# test_fpmsyncd_ecmp.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

import os
import sys
import pytest
import json
import re
from functools import partial
import pdb
# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))
# ecmp route will be recorded twice for it has two deliver process
ROUTE_NUM = 10 * 2
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    r3 = tgen.add_router("r3")
    switch = tgen.add_switch('s1')
    
    switch.add_link(tgen.gears['r1'])
    switch.add_link(tgen.gears['r2'])

    switch = tgen.add_switch('s2')
    switch.add_link(tgen.gears['r1'])
    switch.add_link(tgen.gears['r3'])

    
def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()
    print("topology started")
    # This is a sample of configuration loading.
    router_list = tgen.routers()
    
    for rname, router in router_list.items():
        print(f"starting fpmsyncd for {rname}")
        router.startFpmsyncd()
    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname)),"-M fpm"
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )
        if rname == "r1":
            continue
        router.load_config(
            TopoRouter.RD_STATIC,
            os.path.join(CWD, '{}/staticd.conf'.format(rname))
        )
    
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
        _, res = topotest.run_and_expect(test_func, None, count=50, wait=1)
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

def test_fpmsyncd():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    json_route_num = 0
    with open("/tmp/topotests/fpmsyncd_ecmp_test.test_fpmsyncd_ecmp/r1/routes.json","r") as f:
        routes = json.loads(f.read())
        for route in routes:
            if route["payload"]["prefix"].startswith("20.10"):
                json_route_num += 1 

    assert json_route_num == ROUTE_NUM , "fpmsyncd failed"


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
