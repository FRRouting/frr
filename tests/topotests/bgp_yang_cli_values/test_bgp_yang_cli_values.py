#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_cli_values.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
Commands that enqueue several numeric leaves must keep each value.
nb_cli_enqueue_change() stores the value pointer.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_dampening_and_maximum_prefix_keep_each_number():
    "Dampening and maximum-prefix store every number, not the last one"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 address-family ipv4 unicast
  bgp dampening 10 750 2000 60
  neighbor 192.0.2.2 maximum-prefix 1000 80 restart 12
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )

    running = r1.vtysh_cmd("show running-config")
    assert "bgp dampening 10 750 2000 60" in running
    assert "neighbor 192.0.2.2 maximum-prefix 1000 80 restart 12" in running

    # Default threshold (75) is omitted from running-config.
    r1.vtysh_multicmd(
        """
router bgp 65000
 address-family ipv4 unicast
  neighbor 192.0.2.2 maximum-prefix 1000 75 restart 12
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.2 maximum-prefix 1000 restart 12" in running


def test_hidden_neighbor_af_emits_address_family():
    """Hidden BGP_NODE neighbor AF commands must emit address-family block (B005)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 neighbor PG_AF peer-group
 neighbor PG_AF remote-as 65002
 neighbor PG_AF route-map PG_RM in
 neighbor 192.0.2.20 remote-as 65002
 neighbor 192.0.2.20 route-map FOO in
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert " address-family ipv4 unicast\n" in running
    assert "  neighbor PG_AF route-map PG_RM in\n" in running
    assert "  neighbor 192.0.2.20 route-map FOO in\n" in running
    assert running.index("neighbor PG_AF route-map PG_RM in") < running.index(
        "neighbor 192.0.2.20 route-map FOO in"
    )


def test_max_med_administrative_default_and_explicit():
    """bgp max-med administrative must set default maxmed value before update (B007)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 bgp max-med administrative
""",
        pretty_output=False,
        raises=True,
    )
    assert " bgp max-med administrative\n" in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd(
        """
router bgp 65000
 bgp max-med administrative 100
""",
        pretty_output=False,
        raises=True,
    )
    assert " bgp max-med administrative 100\n" in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd(
        """
router bgp 65000
 no bgp max-med administrative
""",
        pretty_output=False,
        raises=True,
    )
    assert "max-med administrative" not in r1.vtysh_cmd("show running-config")


def test_no_multipath_relax_when_off():
    """no bgp bestpath as-path multipath-relax must succeed when already off (B009)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 no bgp bestpath as-path multipath-relax
""",
        pretty_output=False,
        raises=True,
    )
    r1.vtysh_multicmd(
        """
router bgp 65000
 bgp bestpath as-path multipath-relax as-set
""",
        pretty_output=False,
        raises=True,
    )
    assert " bgp bestpath as-path multipath-relax as-set\n" in r1.vtysh_cmd(
        "show running-config"
    )
    r1.vtysh_multicmd(
        """
router bgp 65000
 no bgp bestpath as-path multipath-relax
 no bgp bestpath as-path multipath-relax
""",
        pretty_output=False,
        raises=True,
    )
    assert "multipath-relax" not in r1.vtysh_cmd("show running-config")


def test_confederation_identifier_and_peers_pretty():
    """Confederation identifier and peers preserve original text on one line (B012)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 bgp confederation identifier 1.0
 bgp confederation peers 1.1 65002
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert " bgp confederation identifier 1.0\n" in running
    assert " bgp confederation peers 1.1 65002\n" in running

    r1.vtysh_multicmd(
        """
router bgp 65000
 no bgp confederation peers 1.1 65002
 no bgp confederation identifier
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "bgp confederation" not in running


def test_destroy_callbacks_use_candidate():
    "Destroy callbacks must apply from the candidate tree, not running"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Dampening off must disable runtime dampening, not re-enable it from
    # deleted parameter leaves.
    r1.vtysh_multicmd(
        """
router bgp 65000
 address-family ipv4 unicast
  no bgp dampening
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )
    assert "bgp dampening" not in r1.vtysh_cmd("show running-config")
    damp = r1.vtysh_cmd("show bgp ipv4 unicast dampening parameters")
    assert "dampening not enabled" in damp.lower()

    # Distance route ACL removal must clear the ACL.
    r1.vtysh_multicmd(
        """
router bgp 65000
 address-family ipv4 unicast
  distance 50 10.0.0.0/24 MYACL
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )
    assert "distance 50 10.0.0.0/24 MYACL" in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd(
        """
router bgp 65000
 address-family ipv4 unicast
  distance 50 10.0.0.0/24
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "distance 50 10.0.0.0/24\n" in running
    assert "MYACL" not in running

    # TCP keepalive and update-delay unset must clear runtime timers.
    r1.vtysh_multicmd(
        """
router bgp 65000
 bgp tcp-keepalive 10 10 3
 update-delay 60 10
""",
        pretty_output=False,
        raises=True,
    )
    r1.vtysh_multicmd(
        """
router bgp 65000
 no bgp tcp-keepalive
 no update-delay
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "tcp-keepalive" not in running
    assert "update-delay" not in running

    # EVPN DAD freeze + disable must leave both DAD and freeze off.
    r1.vtysh_multicmd(
        """
router bgp 65000
 address-family l2vpn evpn
  advertise-all-vni
  dup-addr-detection freeze 60
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )
    r1.vtysh_multicmd(
        """
router bgp 65000
 address-family l2vpn evpn
  no dup-addr-detection
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "freeze" not in running
    assert "no dup-addr-detection" in running


def test_profile_and_inherited_defaults():
    """Verify profile/inherited defaults are not masked by YANG defaults (B003)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # coalesce-time 1000 must stay explicit; no coalesce-time restores heuristic.
    r1.vtysh_multicmd(
        """
router bgp 65000
 coalesce-time 1000
""",
        pretty_output=False,
        raises=True,
    )
    assert " coalesce-time 1000" in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd(
        """
router bgp 65000
 no coalesce-time
""",
        pretty_output=False,
        raises=True,
    )
    assert "coalesce-time" not in r1.vtysh_cmd("show running-config")

    # Positive defaults matching SAVE_* / daemon defaults must stay suppressed,
    # while per-instance ipv6-auto-ra overrides global no bgp ipv6-auto-ra.
    r1.vtysh_multicmd(
        """
no bgp ipv6-auto-ra
bgp session-dscp 48
bgp input-queue-limit 10000
bgp output-queue-limit 10000
router bgp 65000
 bgp enforce-first-as
 bgp hard-administrative-reset
 bgp graceful-restart notification
 bgp ipv6-auto-ra
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    for suppressed in (
        "bgp session-dscp 48",
        "bgp input-queue-limit 10000",
        "bgp output-queue-limit 10000",
        "bgp enforce-first-as",
        "bgp hard-administrative-reset",
        "bgp graceful-restart notification",
    ):
        assert suppressed not in running
    assert "no bgp ipv6-auto-ra\n" in running
    assert " bgp ipv6-auto-ra\n" in running

    # Per-neighbor overrides against global capability/enforce-first-as defaults.
    r1.vtysh_multicmd(
        """
router bgp 65000
 bgp default dynamic-capability
 bgp default link-local-capability
 no bgp enforce-first-as
 neighbor 192.0.2.10 remote-as 65002
 no neighbor 192.0.2.10 capability dynamic
 no neighbor 192.0.2.10 capability link-local
 neighbor 192.0.2.10 enforce-first-as
 neighbor 192.0.2.10 timers 60 180
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert " no neighbor 192.0.2.10 capability dynamic" in running
    assert " no neighbor 192.0.2.10 capability link-local" in running
    assert " neighbor 192.0.2.10 enforce-first-as" in running
    assert " neighbor 192.0.2.10 timers 60 180" in running

    r1.vtysh_multicmd(
        """
router bgp 65000
 no neighbor 192.0.2.10 timers
""",
        pretty_output=False,
        raises=True,
    )
    assert "neighbor 192.0.2.10 timers" not in r1.vtysh_cmd("show running-config")


def test_timers_clamping_and_minimum_holdtime():
    """timers bgp clamps keepalive to holdtime/3 and minimum-holdtime suppresses default (B013)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    out = r1.vtysh_multicmd(
        """
router bgp 65000
 timers bgp 20 30
""",
        pretty_output=False,
        raises=True,
    )
    assert "larger than 1/3 of the holdtime, setting to 10" in out
    assert " timers bgp 10 30\n" in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd(
        """
router bgp 65000
 bgp minimum-holdtime 180
""",
        pretty_output=False,
        raises=True,
    )
    assert "minimum-holdtime" not in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd(
        """
router bgp 65000
 no timers bgp
 no bgp minimum-holdtime
""",
        pretty_output=False,
        raises=True,
    )


def test_no_neighbor_activate_saved():
    """no neighbor activate must be saved for default-af and active peer-group (B006)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 neighbor 192.0.2.21 remote-as 65002
 neighbor 192.0.2.22 remote-as 65002
 neighbor PG_ACT peer-group
 neighbor PG_ACT remote-as 65002
 neighbor 192.0.2.23 peer-group PG_ACT
 neighbor 192.0.2.24 peer-group PG_ACT
 address-family ipv4 unicast
  no neighbor 192.0.2.21 activate
  neighbor 192.0.2.22 activate
 exit-address-family
 address-family ipv6 unicast
  neighbor PG_ACT activate
  no neighbor 192.0.2.23 activate
  neighbor 192.0.2.24 activate
 exit-address-family
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "  no neighbor 192.0.2.21 activate\n" in running
    assert "  neighbor 192.0.2.22 activate\n" not in running
    assert "  neighbor PG_ACT activate\n" in running
    assert "  no neighbor 192.0.2.23 activate\n" in running
    assert "  neighbor 192.0.2.24 activate\n" not in running


def test_llgr_stale_time_and_gr_restart_time_unset():
    """no bgp long-lived-graceful-restart stale-time and GR restart-time must destroy cleanly (B008)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 bgp long-lived-graceful-restart stale-time 100
 bgp graceful-restart restart-time 60
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert " bgp long-lived-graceful-restart stale-time 100\n" in running
    assert " bgp graceful-restart restart-time 60\n" in running

    r1.vtysh_multicmd(
        """
router bgp 65000
 no bgp long-lived-graceful-restart stale-time
 no bgp graceful-restart restart-time
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "long-lived-graceful-restart stale-time" not in running
    assert "graceful-restart restart-time" not in running


def test_update_delay_zero_and_global_guard():
    """update-delay 0 must succeed and no update-delay must fail when global is set (B010)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 65000
 update-delay 0
""",
        pretty_output=False,
        raises=True,
    )
    assert "update-delay" not in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd(
        """
router bgp 65000
 update-delay 30 10
""",
        pretty_output=False,
        raises=True,
    )
    assert " update-delay 30 10\n" in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd(
        """
router bgp 65000
 no update-delay
""",
        pretty_output=False,
        raises=True,
    )
    assert "update-delay" not in r1.vtysh_cmd("show running-config")

    r1.vtysh_multicmd("bgp update-delay 30\n", pretty_output=False, raises=True)
    out = r1.vtysh_multicmd(
        """
router bgp 65000
 no update-delay
""",
        pretty_output=False,
        raises=False,
    )
    assert "configured globally" in out
    r1.vtysh_multicmd("no bgp update-delay\n", pretty_output=False, raises=True)


def test_router_bgp_identity_view_default_and_as_notation():
    """Verify view default, vrf/view mismatch, as_pretty, and as-notation (B011)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
router bgp 1 view default
 bgp router-id 2.2.2.2
exit
router bgp 65536 view v_dot as-notation dot
exit
router bgp 0.65001 view v_dp
exit
router bgp 1.0 view v_plain as-notation plain
exit
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "\nrouter bgp 1 view default\n" in running
    assert "\nrouter bgp 65536 view v_dot as-notation dot\n" in running
    assert "\nrouter bgp 0.65001 view v_dp\n" in running
    assert "\nrouter bgp 1.0 view v_plain as-notation plain\n" in running

    # Entering existing view as VRF must fail
    out = r1.vtysh_multicmd("router bgp 65536 vrf v_dot\n", pretty_output=False, raises=False)
    assert "mismatch" in out

    # Re-entering existing view with different as-notation must ignore it
    r1.vtysh_multicmd(
        "router bgp 65536 view v_dot as-notation plain\n",
        pretty_output=False,
        raises=True,
    )
    assert "\nrouter bgp 65536 view v_dot as-notation dot\n" in r1.vtysh_cmd(
        "show running-config"
    )

    # Deleting view default must keep default instance intact
    r1.vtysh_multicmd(
        """
no router bgp 1 view default
no router bgp 65536 view v_dot
no router bgp 0.65001 view v_dp
no router bgp 1.0 view v_plain
""",
        pretty_output=False,
        raises=True,
    )
    running = r1.vtysh_cmd("show running-config")
    assert "view default" not in running
    assert "\nrouter bgp 65000\n" in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
