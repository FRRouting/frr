#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_prefix_sid2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by LINE Corporation
# Copyright (c) 2020 by Hiroki Shirokura <slank.dev@gmail.com>
#

"""
test_bgp_prefix_sid2.py: Test BGP topology with EBGP on prefix-sid
"""

import json
import os
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    router = tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(router)

    switch = tgen.gears["s1"]
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.0.0.101", defaultRoute="via 10.0.0.1")
    switch.add_link(peer1)


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_config(
        TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format("r1"))
    )
    router.load_config(
        TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format("r1"))
    )
    router.start()

    logger.info("starting exaBGP")
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        logger.info("starting exaBGP on {}".format(pname))
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, pname, "exabgp.env")
        logger.info("Running ExaBGP peer on {}".format(pname))
        peer.start(peer_dir, env_file)
        logger.info(pname)


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def test_r1_rib():
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    def check(name, cmd, expected_file):
        logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
        tgen = get_topogen()
        func = functools.partial(_check, name, cmd, expected_file)
        _, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
        assert result is None, "Failed"

    check("r1", "show bgp ipv6 vpn 2001:1::/64 json", "r1/vpnv6_rib_entry1.json")
    check("r1", "show bgp ipv6 vpn 2001:2::/64 json", "r1/vpnv6_rib_entry2.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)
    sys.exit(ret)
