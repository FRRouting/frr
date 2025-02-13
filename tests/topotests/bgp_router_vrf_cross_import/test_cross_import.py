#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import functools, json, os, pytest, re, sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_vrf_cross_import():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_router_vrf_custom():
        output = json.loads(
            r1.vtysh_cmd("show bgp vrf D detail json")
        )
        expected = {
	    "vrfName": "D",
            "localAS": 65001
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_router_vrf_custom,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "bgp router 65001 vrf D failed"

    def _bgp_router_vrf_default():
        output = json.loads(
            r1.vtysh_cmd("show bgp detail json")
        )
        expected = {
	    "vrfName": "default",
            "localAS": 65001
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_router_vrf_default,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "bgp router 65001 failed in default vrf"

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
