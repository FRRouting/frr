#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if TCP MSS is synced with passive neighbor.
"""

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


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_tcp_mss_passive():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_tcp_mss_configured(router, neighbor, mss):
        output = json.loads(router.vtysh_cmd("show bgp neighbors json"))
        expected = {
            neighbor: {
                "bgpTcpMssConfigured": mss,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_tcp_mss_configured, tgen.gears["r1"], "192.168.1.2", 300
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 is not configured with TCP MSS 300"

    test_func = functools.partial(
        _bgp_check_tcp_mss_configured, tgen.gears["r2"], "192.168.1.1", 0
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 is not configured with the default TCP MSS (1500)"

    def _bgp_check_tcp_mss_synced(router, neighbor, mss):
        output = json.loads(router.vtysh_cmd("show bgp neighbors json"))
        expected = {
            neighbor: {
                "bgpTcpMssSynced": mss,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_tcp_mss_synced, tgen.gears["r1"], "192.168.1.2", 288
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 is not synced with TCP MSS 300"

    test_func = functools.partial(
        _bgp_check_tcp_mss_synced, tgen.gears["r2"], "192.168.1.1", 288
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 is not synced with the default TCP MSS (1488)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
