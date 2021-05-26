#!/usr/bin/env python

#
# test_bgp_suppress_fib.py
#
# Copyright (c) 2019 by
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
"""

import os
import sys
import json
import time
import pytest
from functools import partial
from time import sleep

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo


class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)

        for routern in range(1, 4):
            tgen.add_router("r{}".format(routern))

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_route():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    sleep(5)

    json_file = "{}/r3/v4_route.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 40.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=2, wait=0.5)
    assertmsg = '"r3" JSON output mismatches'
    assert result is None, assertmsg

    json_file = "{}/r3/v4_route2.json".format(CWD)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r3,
        "show ip route 50.0.0.0 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=3, wait=0.5)
    assertmsg = '"r3" JSON output mismatches'
    assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
