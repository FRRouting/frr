#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Verify P1-03 (A2-03, A2-04, A2-05, B3-03), P2-C5 (A2-11), P3-B4 (A2-12):
sort-dependent and update-source-dependent peer attributes never leave YANG
in a state that fails VALIDATE on bgpd restart.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router = tgen.gears["r1"]
    router.load_config(
        TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf")
    )
    router.load_config(
        TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf")
    )
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _reset_and_reload(router, setup_cmds, mut_cmds, expect_reject=False):
    router.vtysh_cmd("configure terminal\nno router bgp 65001\n")
    out = router.vtysh_cmd("configure terminal\n" + setup_cmds)
    assert "Configuration failed" not in out, out

    out = router.vtysh_cmd("configure terminal\n" + mut_cmds)
    if expect_reject:
        assert "Configuration failed" in out or "validation" in out.lower(), out
    else:
        assert "Configuration failed" not in out, out

    saved = router.vtysh_cmd("show running-config bgpd")
    cfg_file = os.path.join(router.logdir, "reload_bgpd.conf")
    with open(cfg_file, "w") as f:
        f.write(
            "\n".join(
                line
                for line in saved.splitlines()
                if not line.startswith(("Building configuration", "Current configuration"))
            )
            + "\n"
        )

    router.killDaemons(["bgpd"])
    router.load_config(TopoRouter.RD_BGP, cfg_file)
    router.startDaemons(["bgpd"])

    reloaded = router.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65001" in reloaded, reloaded
    return saved, reloaded


def test_group_remote_as_change_clears_member_local_role():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    saved, _ = _reset_and_reload(
        r1,
        """
router bgp 65001
 neighbor PG peer-group
 neighbor PG remote-as external
 neighbor 192.0.2.1 peer-group PG
 neighbor 192.0.2.1 local-role customer
""",
        """
router bgp 65001
 neighbor PG remote-as internal
""",
        expect_reject=False,
    )
    assert "local-role" not in saved


def test_oad_survives_switch_to_ibgp_and_reload():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    _reset_and_reload(
        r1,
        """
router bgp 65001
 neighbor 192.0.2.1 remote-as 65002
 neighbor 192.0.2.1 oad
""",
        """
router bgp 65001
 neighbor 192.0.2.1 remote-as 65001
""",
        expect_reject=False,
    )


def test_confed_member_rejected_with_local_role():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    _reset_and_reload(
        r1,
        """
router bgp 65001
 bgp confederation identifier 65000
 neighbor 192.0.2.1 remote-as 65002
 neighbor 192.0.2.1 local-role customer
""",
        """
router bgp 65001
 bgp confederation peers 65002
""",
        expect_reject=True,
    )


def test_bind_ibgp_member_to_group_with_local_role_rejected():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    _reset_and_reload(
        r1,
        """
router bgp 65001
 neighbor PG peer-group
 neighbor PG local-role customer
 neighbor 192.0.2.1 remote-as internal
""",
        """
router bgp 65001
 neighbor 192.0.2.1 peer-group PG
""",
        expect_reject=True,
    )


def test_ip_transparent_blocks_update_source_destroy():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    _reset_and_reload(
        r1,
        """
router bgp 65001
 neighbor 192.0.2.1 remote-as 65002
 neighbor 192.0.2.1 update-source 192.0.2.10
 neighbor 192.0.2.1 ip-transparent
""",
        """
router bgp 65001
 no neighbor 192.0.2.1 update-source 192.0.2.10
""",
        expect_reject=True,
    )


def test_remote_as_auto_preserves_local_role():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    saved, _ = _reset_and_reload(
        r1,
        """
router bgp 65001
 neighbor 192.0.2.1 remote-as 65002
 neighbor 192.0.2.1 local-role customer
""",
        """
router bgp 65001
 neighbor 192.0.2.1 remote-as auto
""",
        expect_reject=False,
    )
    assert "neighbor 192.0.2.1 local-role customer" in saved
