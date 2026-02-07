#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
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
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_update_delay_default_originate():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.23.3": {
                        "state": "Established",
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "192.168.23.3 is not established, but it should be"

    def _bgp_update_delay_timer_running():
        output = json.loads(r2.vtysh_cmd("show bgp neighbors 192.168.23.3 json"))
        if (
            "bgpUpdateDelayTimerMsecsRemaining" in output["192.168.23.3"]
            and output["192.168.23.3"]["bgpUpdateDelayTimerMsecsRemaining"] != 0
        ):
            return True
        return False

    def _bgp_check_advertised_routes():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.23.3 advertised-routes json"
            )
        )
        expected = {
            "bgpOriginatingDefaultNetwork": "0.0.0.0/0",
            "totalPrefixCounter": 1,
        }
        return not _bgp_update_delay_timer_running() and topotest.json_cmp(
            output, expected
        )

    test_func = functools.partial(
        _bgp_check_advertised_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "0.0.0.0/0 is not advertised, but it should be"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
