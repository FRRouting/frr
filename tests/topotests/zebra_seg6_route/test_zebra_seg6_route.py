#!/usr/bin/env python

#
# test_zebra_seg6_route.py
#
# Copyright (c) 2020 by
# LINE Corporation, Hiroki Shirokura <slank.dev@gmail.com>
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
test_zebra_seg6_route.py: Test seg6 route addition with zapi.
"""

import os
import re
import sys
import pytest
import json
import platform
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import shutdown_bringup_interface
from mininet.topo import Topo


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


class TemplateTopo(Topo):
    def build(self, **_opts):
        tgen = get_topogen(self)
        tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        router.run("/bin/bash {}".format(os.path.join(CWD, "{}/setup.sh".format(rname))))
        router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, '{}/zebra.conf'.format(rname)))
        router.load_config(TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname)))
    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_seg6local_routes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Test for seg6local route install via ZAPI was start.")
    r1 = tgen.gears["r1"]

    def check(router, dest, nh, sid, expected):
        router.vtysh_cmd("sharp install routes {} "\
                         "nexthop-seg6 {} encap {} 1".format(dest, nh, sid))
        output = json.loads(router.vtysh_cmd("show ipv6 route {} json".format(dest)))
        output = output.get('{}/128'.format(dest))
        if output is None:
            return False
        return topotest.json_cmp(output, expected)

    manifests = open_json_file(os.path.join(CWD, "{}/routes.json".format("r1")))
    for manifest in manifests:
        logger.info("CHECK {} {} {}".format(manifest['in']['dest'],
                                            manifest['in']['nh'],
                                            manifest['in']['sid']))
        test_func = partial(check, r1,
                            manifest['in']['dest'],
                            manifest['in']['nh'],
                            manifest['in']['sid'],
                            manifest['out'])
        success, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
        assert result is None, 'Failed'


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
