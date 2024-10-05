#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
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


def test_bgp_dynamic_capability_role():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json detail"))
        expected = {
            "routes": {
                "10.10.10.40/32": {
                    "paths": [
                        {
                            "extendedIpv6Community": {
                                "string": "LB:65000:5000000000 (40.000 Gbps)",
                            }
                        }
                    ]
                },
                "10.10.10.100/32": {
                    "paths": [
                        {
                            "extendedIpv6Community": {
                                "string": "LB:65000:12500000000 (100.000 Gbps)",
                            }
                        }
                    ]
                },
                "10.10.10.200/32": {
                    "paths": [
                        {
                            "extendedIpv6Community": {
                                "string": "LB:65000:25000000000 (200.000 Gbps)",
                            }
                        }
                    ]
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see link bandwidths as expected"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
