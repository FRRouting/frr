#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_evpn_mac_move_back_svd.py
#
# A MAC that moves to the other PE and back: a single vxlan device (SVD).
#
# The MAC moves make-before-break to PE2 and back (see
# common_bgp_evpn_mac_move_back.py for the topology and why), with one
# VLAN-aware bridge and a single vxlan device carrying both VNIs (vlan_tunnel);
# the entries of the two VNIs share one vxlan FDB and differ only in their
# source VNI.
#
# 1. After the move back, PE1 holds the MAC as local and the vxlan device holds
#    no entry for it to PE2.
# 2. An FDB re-read on PE1 (advertise-all-vni off/on) keeps the MAC local and
#    PE2 keeps the route to PE1.
# 3. A leftover planted by hand (the state a zebra without the fix leaves
#    behind) is removed as soon as zebra sees it, and the MAC stays local.
# 4. The same leftover in the kernel when zebra and bgpd start: the MAC is
#    local after the restart and PE2 reaches it through PE1.
# 5. Adding an unrelated VNI preserves the existing mappings' MACs without
#    withdrawing their routes or deleting their FDB entries.
# 6. A mapping refresh restores an access-BD binding cleared by an L3-to-L2
#    transition while a bond member keeps the access-BD alive.
#
# The move back (1), leftover steps (3, 4), and mapping update (5) watch the
# FDB and check that PE1's local access-port entry is never deleted.
# The MAC checks also verify that VNI 200 keeps its vxlan entry to PE2.
#

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import get_topogen  # noqa: E402

from .common_bgp_evpn_mac_move_back import (  # noqa: E402
    setup,
    step_fdb_reread_keeps_local_mac,
    step_leftover_across_restart,
    step_leftover_seen_live_is_removed,
    step_mac_home_on_pe1,
    step_move_to_pe2_and_back,
    step_retained_svd_binding_recovers,
    step_unchanged_svd_mapping_keeps_macs,
    teardown,
)

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def setup_module(mod):
    setup(mod, "svd", CWD)


def teardown_module(mod):
    teardown(mod)


def test_mac_home_on_pe1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    step_mac_home_on_pe1()


def test_move_to_pe2_and_back():
    step_move_to_pe2_and_back()


def test_leftover_seen_live_is_removed():
    step_leftover_seen_live_is_removed()


# The FDB reread rebuilds EVPN state and can queue remote MAC updates.
# Run the live cleanup check before that rebuild to isolate its FDB events.
def test_fdb_reread_keeps_local_mac():
    step_fdb_reread_keeps_local_mac()


def test_leftover_across_restart():
    step_leftover_across_restart()


def test_unchanged_svd_mapping_keeps_macs():
    step_unchanged_svd_mapping_keeps_macs()


def test_retained_svd_binding_recovers():
    step_retained_svd_binding_recovers()


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
