#!/usr/bin/env python

#
# test_bgp_prefix_sid.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by LINE Corporation
# Copyright (c) 2020 by Hiroki Shirokura <slank.dev@gmail.com>
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
test_bgp_prefix_sid.py: Test BGP topology with EBGP on prefix-sid
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
    peer2 = tgen.add_exabgp_peer("peer2", ip="10.0.0.102", defaultRoute="via 10.0.0.1")
    switch.add_link(peer1)
    switch.add_link(peer2)


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

    logger.info("starting exaBGP on peer1")
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, "exabgp.env")
        logger.info("Running ExaBGP peer")
        peer.start(peer_dir, env_file)
        logger.info(pname)


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def test_r1_receive_and_advertise_prefix_sid_type1():
    tgen = get_topogen()
    router = tgen.gears["r1"]

    def _check_type1_r1(router, prefix, remoteLabel, labelIndex):
        output = router.vtysh_cmd(
            "show bgp ipv4 labeled-unicast {} json".format(prefix)
        )
        output = json.loads(output)
        expected = {
            "prefix": prefix,
            "advertisedTo": {"10.0.0.101": {}, "10.0.0.102": {}},
            "paths": [
                {
                    "valid": True,
                    "remoteLabel": remoteLabel,
                    "labelIndex": labelIndex,
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_type1_r1, router, "3.0.0.1/32", 800001, 1)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _check_type1_r1 in "{}"'.format(router)

    test_func = functools.partial(_check_type1_r1, router, "3.0.0.2/32", 800002, 2)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _check_type1_r1 in "{}"'.format(router)


def exabgp_get_update_prefix(filename, afi, nexthop, prefix):
    with open(filename) as f:
        for line in f.readlines():
            output = json.loads(line)
            ret = output.get("neighbor")
            if ret is None:
                continue
            ret = ret.get("message")
            if ret is None:
                continue
            ret = ret.get("update")
            if ret is None:
                continue
            ret = ret.get("announce")
            if ret is None:
                continue
            ret = ret.get(afi)
            if ret is None:
                continue
            ret = ret.get(nexthop)
            if ret is None:
                continue
            ret = ret.get(prefix)
            if ret is None:
                continue
            return output
        return "Not found"


def test_peer2_receive_prefix_sid_type1():
    tgen = get_topogen()
    peer2 = tgen.gears["peer2"]
    logfile = "{}/{}-received.log".format(peer2.gearlogdir, peer2.name)

    def _check_type1_peer2(prefix, labelindex):
        output = exabgp_get_update_prefix(
            logfile, "ipv4 nlri-mpls", "10.0.0.101", prefix
        )
        expected = {
            "type": "update",
            "neighbor": {
                "ip": "10.0.0.1",
                "message": {
                    "update": {
                        "attribute": {
                            "attribute-0x28-0xE0": "0x010007000000{:08x}".format(
                                labelindex
                            )
                        },
                        "announce": {"ipv4 nlri-mpls": {"10.0.0.101": {}}},
                    }
                },
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_type1_peer2, "3.0.0.1/32", labelindex=1)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _check_type1_peer2 in "{}"'.format("peer2")

    test_func = functools.partial(_check_type1_peer2, "3.0.0.2/32", labelindex=2)
    success, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, 'Failed _check_type1_peer2 in "{}"'.format("peer2")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)
    sys.exit(ret)
