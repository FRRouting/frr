#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>
# Copyright (c) 2026 by Martin Buck
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

pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_static_metrics():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_static_routes(router, ip, reffile):
        reffile_abs = os.path.join(CWD, reffile)
        expected = json.loads(open(reffile_abs).read())

        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            f"show {ip} route json",
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=15, wait=1)
        assertmsg = f"Static routes on R1 don't match expected in {reffile}"
        assert res is None, assertmsg

    _check_static_routes(r1, "ip", "r1/static_ipv4_initial.json")
    _check_static_routes(r1, "ipv6", "r1/static_ipv6_initial.json")

    r1.vtysh_cmd(
        """
        configure terminal
        ! Expecting success
        no ip route 10.0.3.1/32 192.168.1.2
        no ip route 10.0.3.2/32 192.168.1.2 7
        no ip route 10.0.3.3/32 192.168.1.2 metric 10
        no ip route 10.0.3.4/32 192.168.1.2 7 metric 10
        no ip route 10.0.3.5/32 r1-eth0 7 metric 10
        no ip route 10.0.3.6/32 blackhole 7 metric 10
        no ip route 10.0.3.7/32 192.168.1.2 r1-eth0 7 metric 10
        ! Expecting failure
        no ip route 10.0.3.8/32 192.168.1.2 metric 20
        no ip route 10.0.3.8/32 192.168.1.2 8
        no ip route 10.0.3.8/32 192.168.1.2 8 metric 20
        ! Expecting success
        no ipv6 route 2001:db8:3:1::/64 fe80:1::2
        no ipv6 route 2001:db8:3:2::/64 fe80:1::2 7
        no ipv6 route 2001:db8:3:3::/64 fe80:1::2 metric 10
        no ipv6 route 2001:db8:3:4::/64 fe80:1::2 7 metric 10
        no ipv6 route 2001:db8:3:5::/64 r1-eth0 7 metric 10
        no ipv6 route 2001:db8:3:6::/64 blackhole 7 metric 10
        no ipv6 route 2001:db8:3:7::/64 fe80:1::2 r1-eth0 7 metric 10
        ! Expecting failure
        no ipv6 route 2001:db8:3:8::/64 fe80:1::2 metric 20
        no ipv6 route 2001:db8:3:8::/64 fe80:1::2 8
        no ipv6 route 2001:db8:3:8::/64 fe80:1::2 8 metric 20
        """
    )

    _check_static_routes(r1, "ip", "r1/static_ipv4_after_del.json")
    _check_static_routes(r1, "ipv6", "r1/static_ipv6_after_del.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
