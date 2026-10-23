#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
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
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd, pytest.mark.mgmtd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_bfd_session():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bfd_session():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        expected = [
            {
                "multihop": True,
                "peer": "192.168.1.2",
                "local": "10.0.0.1",
                "vrf": "default",
                "minimum-ttl": 246,
                "status": "down",
                "diagnostic": "ok",
                "remote-diagnostic": "ok",
                "type": "dynamic",
            },
            {
                "multihop": True,
                "peer": "192.168.1.3",
                "local": "10.0.0.1",
                "vrf": "default",
                "minimum-ttl": 236,
                "status": "down",
                "diagnostic": "ok",
                "remote-diagnostic": "ok",
                "type": "dynamic",
            },
            {
                "multihop": True,
                "peer": "192.168.1.4",
                "local": "10.0.0.1",
                "vrf": "default",
                "minimum-ttl": 241,
                "status": "down",
                "diagnostic": "ok",
                "remote-diagnostic": "ok",
                "type": "dynamic",
            },
            {
                "multihop": True,
                "peer": "192.168.1.5",
                "local": "10.0.0.1",
                "vrf": "default",
                "minimum-ttl": 231,
                "status": "down",
                "diagnostic": "ok",
                "remote-diagnostic": "ok",
                "type": "dynamic",
            },
        ]
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bfd_session)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't see BFD session created"


def test_bgp_bfd_peer_timers_in_running_config():
    "Per-peer BFD timers are written back to running-config."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _neighbor_bfd_lines():
        return [
            line.strip()
            for line in r1.vtysh_cmd("show running-config bgpd").splitlines()
            if line.strip().startswith("neighbor 192.168.1.2 bfd")
        ]

    def _expect_lines(expected):
        def _check():
            lines = _neighbor_bfd_lines()
            return None if lines == expected else lines

        _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
        assert result is None, "running-config has {}, expected {}".format(
            result, expected
        )

    step("Set non-default BFD timers on 192.168.1.2")
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65000
          neighbor 192.168.1.2 bfd 4 400 500
        """)
    _expect_lines(["neighbor 192.168.1.2 bfd 4 400 500"])

    step("Set the default BFD timers back on 192.168.1.2")
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65000
          neighbor 192.168.1.2 bfd 3 300 300
        """)
    _expect_lines(["neighbor 192.168.1.2 bfd"])


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
