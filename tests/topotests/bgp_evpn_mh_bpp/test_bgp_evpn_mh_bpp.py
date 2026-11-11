#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_mh_bpp.py
#
# Copyright (c) 2026 by
# Cisco Systems, Inc.
# Patrice Brissette
#

"""
EVPN bridge-port protection (L3 multihoming).

Phase 1: the per-ES `evpn mh bridge-port-protection` knob.

    +------+        +--------+
    | tor1 |--------| hostd1 |     hostbond1 = ES-1 on tor1
    +------+        +--------+
"""

import os
import sys
import json
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

ES_IF = "hostbond1"
BPP_XPATH = (
    "/frr-interface:lib/interface[name='%s']/frr-zebra:zebra/evpn-mh" % ES_IF
)


def build_topo(tgen):
    tgen.add_router("tor1")
    tgen.add_router("hostd1")
    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["tor1"])
    sw.add_link(tgen.gears["hostd1"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    tor1 = tgen.gears["tor1"]
    tor1.run("ip link add dev %s type bond mode 802.3ad" % ES_IF)
    tor1.run("ip link set dev tor1-eth0 master %s" % ES_IF)
    tor1.run("ip link set dev %s up" % ES_IF)

    tor1.load_frr_config(os.path.join(CWD, "tor1/frr.conf"))
    tgen.start_router(tor1)


def teardown_module(_mod):
    get_topogen().stop_topology()


def _bpp_in_running_config(router):
    return "evpn mh bridge-port-protection" in router.vtysh_cmd(
        "show running-config"
    )


def _check_bpp(router, expected):
    if _bpp_in_running_config(router) != expected:
        return "running-config: protection %s" % ("missing" if expected else "set")

    output = router.vtysh_cmd(
        "show mgmt get-data %s datastore running only-config json" % BPP_XPATH
    )
    leaf = (
        json.loads(output)
        .get("frr-interface:lib", {})
        .get("interface", [{}])[0]
        .get("frr-zebra:zebra", {})
        .get("evpn-mh", {})
        .get("bridge-port-protection")
    )
    if bool(leaf) != expected:
        return "mgmt running datastore: bridge-port-protection=%s" % leaf
    return None


def _expect_bpp(router, expected):
    test_func = partial(_check_bpp, router, expected)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, result


def test_bpp_config():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tor1 = tgen.gears["tor1"]

    # Off by default.
    _expect_bpp(tor1, False)

    # Add after es-id.
    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nevpn mh bridge-port-protection" % ES_IF
    )
    _expect_bpp(tor1, True)

    # Remove.
    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nno evpn mh bridge-port-protection"
        % ES_IF
    )
    _expect_bpp(tor1, False)

    # Add before es-id: the knob is kept across es-id removal and re-add.
    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nno evpn mh es-id\n"
        "evpn mh bridge-port-protection\nevpn mh es-id 1" % ES_IF
    )
    _expect_bpp(tor1, True)

    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nno evpn mh es-id" % ES_IF
    )
    _expect_bpp(tor1, True)

    tor1.vtysh_cmd(
        "configure terminal\ninterface %s\nevpn mh es-id 1\n"
        "no evpn mh bridge-port-protection" % ES_IF
    )
    _expect_bpp(tor1, False)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
