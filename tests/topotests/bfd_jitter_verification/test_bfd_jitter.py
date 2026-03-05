#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_jitter.py
#
# Copyright (c) 2024 by
# Sougata Barik
#

"""
Test BFD jitter calculation and application.

Tests verify:
1. BFD sessions establish successfully
2. Jitter values are within RFC 5880 Section 6.8.7 ranges:
   - 75-100% for detect_multiplier > 1
   - 75-90% for detect_multiplier == 1
"""

import os
import sys
import json
import pytest
import functools
import re

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bfdd]


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

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bfd_session_up():
    """Verify BFD sessions come up successfully."""
    tgen = get_topogen()
    
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    
    def _check_bfd_up(router, peer_ip):
        output = json.loads(router.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == peer_ip and peer.get("status") == "up":
                return None
        return "BFD peer {} not up".format(peer_ip)
    
    step("Waiting for BFD sessions to come up")
    
    # Check R1's session to R2
    test_func = functools.partial(_check_bfd_up, r1, "192.168.1.2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BFD session not up on R1"
    
    # Check R2's session to R1
    test_func = functools.partial(_check_bfd_up, r2, "192.168.1.1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BFD session not up on R2"


def test_bfd_jitter_detect_mult_three():
    """
    Verify jitter range with detect_multiplier == 3.

    Per RFC 5880 Section 6.8.7, when detect_mult > 1 the jitter range
    is 75-100%.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify xmt_TO_actual field via show command")

    output = r1.vtysh_cmd("show bfd peers")

    assert "Transmission interval (actual with jitter)" in output, \
        "xmt_TO_actual not displayed in show output"

    match = re.search(r'Transmission interval \(actual with jitter\):\s+(\d+)ms', output)
    assert match is not None, "Could not parse xmt_TO_actual from output"

    actual_interval = int(match.group(1))

    output_json = json.loads(r1.vtysh_cmd("show bfd peers json"))
    nominal = 1000
    for peer in output_json:
        if peer.get("peer") == "192.168.1.2":
            nominal = peer.get("transmit-interval", 1000)
            break

    min_expected = int(nominal * 0.75)
    max_expected = int(nominal * 1.00)

    assert min_expected <= actual_interval <= max_expected, \
        "xmt_TO_actual {}ms outside RFC 5880 jitter range [{}, {}]".format(
            actual_interval, min_expected, max_expected)

    step("xmt_TO_actual field verified: {}ms (within {}-{}ms range)".format(
        actual_interval, min_expected, max_expected))


def test_bfd_jitter_detect_mult_one():
    """
    Verify jitter range with detect_multiplier == 1.

    Per RFC 5880 Section 6.8.7, when detect_mult == 1 the jitter range
    is narrower: 75-90% instead of 75-100%.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Shutdown BFD profile, change detect-multiplier to 1")

    r1.vtysh_cmd("""
    configure terminal
     bfd
      profile jitter-test
       shutdown
      exit
     exit
    exit
    """)

    def _check_bfd_shutdown():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "192.168.1.2" and peer.get("status") == "shutdown":
                return None
        return "BFD peer not in shutdown state after profile shutdown"

    step("Waiting for BFD session to enter shutdown state")
    test_func = functools.partial(_check_bfd_shutdown)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BFD session not in shutdown state after profile shutdown"

    step("Update profile with detect-multiplier 1 and bring session back up")

    r1.vtysh_cmd("""
    configure terminal
     bfd
      profile jitter-test
       detect-multiplier 1
       no shutdown
      exit
     exit
    exit
    """)

    def _check_bfd_up():
        output = json.loads(r1.vtysh_cmd("show bfd peers json"))
        for peer in output:
            if peer.get("peer") == "192.168.1.2" and peer.get("status") == "up":
                return None
        return "BFD peer not up after no shutdown"

    step("Waiting for BFD session to come up with detect_mult=1")
    test_func = functools.partial(_check_bfd_up)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BFD session not up after changing detect-multiplier to 1"

    output = r1.vtysh_cmd("show bfd peers")

    match = re.search(r'Transmission interval \(actual with jitter\):\s+(\d+)ms', output)
    assert match is not None, "Could not parse xmt_TO_actual from output"

    actual_interval = int(match.group(1))

    output_json = json.loads(r1.vtysh_cmd("show bfd peers json"))
    nominal = 1000
    for peer in output_json:
        if peer.get("peer") == "192.168.1.2":
            nominal = peer.get("transmit-interval", 1000)
            break

    min_expected = int(nominal * 0.75)
    max_expected = int(nominal * 0.90)

    assert min_expected <= actual_interval <= max_expected, \
        "xmt_TO_actual {}ms outside RFC 5880 jitter range [{}, {}] for detect_mult=1".format(
            actual_interval, min_expected, max_expected)

    step("detect_mult=1 jitter verified: {}ms (within {}-{}ms range)".format(
        actual_interval, min_expected, max_expected))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

