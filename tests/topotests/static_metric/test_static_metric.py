#!/usr/bin/env python

#
# Copyright (c) 2022
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
import os
import sys
import functools
import pytest
import json

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import apply_raw_config

def setup_module(mod):
    topodef = {"s1": "r1"}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        router.load_config(TopoRouter.RD_STATIC, "staticd.conf")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_static_metric():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def remove_route(nh):
        cmd = "no ip route 10.0.0.0/8 {}".format(nh)
        apply_raw_config(tgen, {"r1": {"raw_config": [cmd]}})

    def test_func(n):
        with open("{}/r1/routes_{}.json".format(CWD, n)) as f:
            expected = json.load(f)
        return functools.partial(
            topotest.router_json_cmp,
            r1,
            "show ip route 10.0.0.0/8 json",
            expected
        )

    _, result = topotest.run_and_expect(test_func(1), None, count=20, wait=0.5)
    assert result is None, "static route mismatches"

    for i in range(2, 7):
        remove_route("192.168.1.{}".format(i))
        _, result = topotest.run_and_expect(test_func(i), None, count=20,
                                            wait=0.5)
        assert result is None, "static route mismatches"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
