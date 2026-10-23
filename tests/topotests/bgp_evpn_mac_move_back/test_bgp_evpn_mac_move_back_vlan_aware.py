#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_evpn_mac_move_back_vlan_aware.py
#
# A MAC that moves to the other PE and back: a VLAN-aware bridge.
#
# The MAC moves make-before-break to PE2 and back (see
# common_bgp_evpn_mac_move_back.py for the topology and why), with one VLAN-aware bridge and a vxlan device
# per VNI, each vxlan port untagged in its access VLAN.
#
# 1. After the move back, PE1 holds the MAC as local and the vxlan device holds
#    no entry for it to PE2.
# 2. An FDB re-read on PE1 (advertise-all-vni off/on) keeps the MAC local and
#    PE2 keeps the route to PE1.
# 3. A leftover planted by hand (the state a zebra without the fix leaves
#    behind) is removed as soon as zebra sees it, and the MAC stays local.
# 4. The same leftover in the kernel when zebra and bgpd start: the MAC is
#    local after the restart and PE2 reaches it through PE1.
#
# The move back (1) and the two leftover steps (3, 4) also watch the FDB and
# check that the bridge's local entry on PE1's access port is never deleted.
# Every step checks that the same MAC in VNI 200 keeps its vxlan entry to PE2.
#

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import get_topogen

from .common_bgp_evpn_mac_move_back import (
    setup,
    step_fdb_reread_keeps_local_mac,
    step_leftover_across_restart,
    step_leftover_seen_live_is_removed,
    step_mac_home_on_pe1,
    step_move_to_pe2_and_back,
    teardown,
)

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def setup_module(mod):
    setup(mod, "aware", CWD)


def teardown_module(mod):
    teardown(mod)


def test_mac_home_on_pe1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step_mac_home_on_pe1()


def test_move_to_pe2_and_back():
    step_move_to_pe2_and_back()


def test_fdb_reread_keeps_local_mac():
    step_fdb_reread_keeps_local_mac()


def test_leftover_seen_live_is_removed():
    step_leftover_seen_live_is_removed()


def test_leftover_across_restart():
    step_leftover_across_restart()


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
