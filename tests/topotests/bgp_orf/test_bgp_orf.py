#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if BGP ORF filtering is working correctly when modifying
prefix-list.

Initially advertise 10.10.10.1/32 from R1 to R2. Add new prefix
10.10.10.2/32 to r1 prefix list on R2. Test if we updated ORF
prefix-list correctly.
"""

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
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
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


def test_bgp_orf():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge_r1():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.2 advertised-routes json"
            )
        )
        expected = {"advertisedRoutes": {"10.10.10.1/32": {}, "10.10.10.2/32": None}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't apply ORF from R1 to R2"

    def _bgp_converge_r2():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast summary json"))
        expected = {
            "peers": {
                "192.168.1.1": {
                    "pfxRcd": 1,
                    "pfxSnt": 1,
                    "state": "Established",
                    "peerState": "OK",
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "ORF filtering is not working from R1 to R2"

    r2.vtysh_cmd(
        """
        configure terminal
        ip prefix-list r1 seq 10 permit 10.10.10.2/32
    """
    )

    def _bgp_orf_changed_r1():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.2 advertised-routes json"
            )
        )
        expected = {"advertisedRoutes": {"10.10.10.1/32": {}, "10.10.10.2/32": {}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_orf_changed_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't apply new ORF from R1 to R2"

    def _bgp_orf_changed_r2():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "10.10.10.1/32": [{"valid": True}],
                "10.10.10.2/32": [{"valid": True}],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_orf_changed_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "New ORF filtering is not working from R1 to R2"

    r2.vtysh_cmd(
        """
        configure terminal
        no ip prefix-list r1 seq 10 permit 10.10.10.2/32
    """
    )

    test_func = functools.partial(_bgp_converge_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't apply initial ORF from R1 to R2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
