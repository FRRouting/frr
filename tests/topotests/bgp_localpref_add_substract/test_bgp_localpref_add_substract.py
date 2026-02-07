#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_localpref_add_substract():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "defaultLocPrf": 100,
            "routes": {
                "10.0.0.1/32": [
                    {
                        "locPrf": 110,
                    }
                ],
                "10.0.0.2/32": [
                    {
                        "locPrf": 90,
                    }
                ],
            },
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "10.0.0.1 local-preference SHOULD be 110, and 10.0.0.2 SHOULD be 90"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
