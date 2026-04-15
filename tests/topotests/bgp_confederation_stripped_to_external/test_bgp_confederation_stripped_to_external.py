#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_confederation_stripped_to_external():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast 10.0.0.1/32 json"))
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "64512 64512",
                        "segments": [{"type": "as-sequence", "list": [64512, 64512]}],
                        "length": 2,
                    },
                    "origin": "IGP",
                    "peer": {
                        "peerId": "192.168.3.2",
                        "routerId": "192.168.3.2",
                        "hostname": "r2",
                        "type": "external",
                    },
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_bgp_converge, None, count=60, wait=0.5)
    assert result is None, "Can't see 10.0.0.1/32 coming from r1 to r3 via r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
