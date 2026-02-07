#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_mrib.py
#
# Copyright (c) 2024 ATCorp
# Nathan Bahr
#

import os
import sys
import pytest
from functools import partial

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.pim import (
    verify_pim_rp_info,
    verify_upstream_iif,
    McastTesterHelper,
)
from lib.common_config import step, write_test_header

"""
test_pim_mrib.py: Test PIM MRIB overrides and RPF modes
"""

TOPOLOGY = """
   Test PIM MRIB overrides and RPF modes
     Static routes installed that uses R2 to get between R1 and R4.
     Tests will install MRIB override through R3

            +---+---+                      +---+---+
            |       |     10.0.0.0/24      |       |
            +  R1   +----------------------+  R2   |
            |       | .1                .2 |       |
            +---+---+ r1-eth0      r2-eth0 +---+---+
             .1 | r1-eth1              r2-eth1 | .2
                |                              |
   10.0.1.0/24  |                              |  10.0.2.0/24
                |                              |
             .3 | r3-eth0              r4-eth0 | .4
            +---+---+ r3-eth1      r4-eth1 +---+---+
            |       | .3                .4 |       |
            +  R3   +----------------------+  R4   |---r4-dum0 10.10.0.4/24
            |       |      10.0.3.0/24     |       |
            +---+---+                      +---+---+
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.pimd]

GROUP1 = "239.1.1.1"
GROUP2 = "239.2.2.2"


def build_topo(tgen):
    """Build function"""

    # Create routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")

    # Create topology links
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "r1-eth1", "r3-eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r4"], "r2-eth1", "r4-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r4"], "r3-eth1", "r4-eth1")

    tgen.gears["r4"].run("ip link add r4-dum0 type dummy")


def setup_module(mod):
    logger.info("PIM MRIB/RPF functionality:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_pim_mrib_init(request):
    """Test boot in MRIB-than-URIB with the default MRIB"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify rp-info using default URIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth0",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_override(request):
    """Test MRIB override nexthop"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Install a MRIB route that has a shorter prefix length and lower cost.
    # In MRIB-than-URIB mode, it should use this route
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         ip mroute 10.0.0.0/16 10.0.3.3 25
        exit
        """
    )

    step("Verify rp-info using MRIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth1",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_prefix_mode(request):
    """Test longer prefix lookup mode"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch to longer prefix match, should switch back to the URIB route
    # even with the lower cost, the longer prefix match will win because of the mode
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode longer-prefix
         exit
        exit
        """
    )

    step("Verify rp-info using URIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth0",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_dist_mode(request):
    """Test lower distance lookup mode"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch to lower distance match, should switch back to the MRIB route
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode lower-distance
         exit
        exit
        """
    )

    step("Verify rp-info using MRIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth1",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_urib_mode(request):
    """Test URIB only lookup mode"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch to urib only match, should switch back to the URIB route
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode urib-only
         exit
        exit
        """
    )

    step("Verify rp-info using URIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth0",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_mrib_mode(request):
    """Test MRIB only lookup mode"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch to mrib only match, should switch back to the MRIB route
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode mrib-only
         exit
        exit
        """
    )

    step("Verify rp-info using MRIB nexthop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth1",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_mrib_mode_no_route(request):
    """Test MRIB only with no route"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Remove the MRIB route, in mrib-only mode, it should switch to no path for the RP
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         no ip mroute 10.0.0.0/16 10.0.3.3 25
        exit
        """
    )

    step("Verify rp-info with Unknown next hop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "Unknown",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "Unknown",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_source_list_init(request):
    """Test RPF lookup source list with initial setup"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Reset back to mrib then urib mode
    # Also add mode using SRCPLIST(10.0.0.1) and SRCPLIST2(10.0.1.1)
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode mrib-then-urib
          rpf-lookup-mode mrib-then-urib source-list SRCPLIST
          rpf-lookup-mode mrib-then-urib source-list SRCPLIST2
         exit
        exit
        """
    )

    step("Verify rp-info with default next hop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth0",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_source_list_add_mroute(request):
    """Test RPF lookup source list with MRIB route on alternate path"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Add a MRIB route through r4-eth1 that is better distance but worse prefix
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         ip mroute 10.0.0.0/16 10.0.3.3 25
        exit
        """
    )

    step("Verify rp-info with MRIB next hop")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth1",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_source_list_src1_prefix_mode(request):
    """Test RPF lookup source list src1 longer prefix mode"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch just source 1 to longest prefix
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode longer-prefix source-list SRCPLIST
         exit
        exit
        """
    )

    step("Verify rp-info with URIB next hop for source 1 and MRIB for source 2")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth1",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_source_list_src1_dist_src2_prefix_mode(request):
    """Test RPF lookup source list src1 lower distance mode and src2 longer prefix mode"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch source 1 to shortest distance, source 2 to longest prefix
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode lower-distance source-list SRCPLIST
          rpf-lookup-mode longer-prefix source-list SRCPLIST2
         exit
        exit
        """
    )

    step("Verify rp-info with MRIB next hop for source 1 and URIB for source 2")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth0",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_source_list_src1_urib_src2_dist_mode(request):
    """Test RPF lookup source list src1 urib mode and src2 lower distance mode"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch source 1 to urib only, source 2 to shorter distance
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode urib-only source-list SRCPLIST
          rpf-lookup-mode lower-distance source-list SRCPLIST2
         exit
        exit
        """
    )

    step("Verify rp-info with URIB next hop for source 1 and MRIB for source 2")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth1",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_source_list_src1_mrib_src2_urib_mode(request):
    """Test RPF lookup source list src1 mrib mode and src2 urib mode"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch source 1 to mrib only, source 2 to urib only
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          rpf-lookup-mode mrib-only source-list SRCPLIST
          rpf-lookup-mode urib-only source-list SRCPLIST2
         exit
        exit
        """
    )

    step("Verify rp-info with MRIB next hop for source 1 and URIB for source 2")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth0",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_source_list_removed(request):
    """Test RPF lookup source list removed"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Remove both special modes, both should switch to MRIB route
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         router pim
          no rpf-lookup-mode mrib-only source-list SRCPLIST
          no rpf-lookup-mode urib-only source-list SRCPLIST2
         exit
        exit
        """
    )

    step("Verify rp-info with MRIB next hop for both sources")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth1",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth1",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_source_list_del_mroute(request):
    """Test RPF lookup source list delete mroute"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Remove the MRIB route, both should switch to URIB
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf term
         no ip mroute 10.0.0.0/16 10.0.3.3 25
        exit
        """
    )

    step("Verify rp-info with URIB next hop for both sources")
    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "224.0.0.0/4",
        "r4-eth0",
        "10.0.0.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_pim_rp_info(
        tgen,
        None,
        "r4",
        "225.0.0.0/24",
        "r4-eth0",
        "10.0.1.1",
        "Static",
        False,
        "ipv4",
        True,
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)


def test_pim_mrib_rpf_lookup_group_list(request):
    """Test RPF lookup group list"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    with McastTesterHelper(tgen) as apphelper:
        step(
            ("Send multicast traffic from R1 to dense groups {}, {}").format(
                GROUP1, GROUP2
            )
        )
        result = apphelper.run_traffic("r1", [GROUP1, GROUP2], bind_intf="r1-eth1")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Reset back to mrib then urib mode
        # Also add mode using GRPPLIST(239.1.1.1) and GRPPLIST2(239.2.2.2)
        # And do an igmp join to both groups on r4-eth2
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode mrib-then-urib
              rpf-lookup-mode mrib-then-urib group-list GRPPLIST
              rpf-lookup-mode mrib-then-urib group-list GRPPLIST2
             exit
             int r4-dum0
              ip igmp join-group {}
              ip igmp join-group {}
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif with default next hop")
        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Add MRIB route through alternate path")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             ip mroute 10.0.0.0/16 10.0.3.3 25
            exit
            """
        )

        step("Verify upstream iif with alternate next hop")
        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Switch group1 to longer prefix match (URIB)")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode longer-prefix group-list GRPPLIST
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is URIB, group2 is MRIB")
        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Switch group1 to lower distance match (MRIB), and group2 to longer prefix (URIB)"
        )
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode lower-distance group-list GRPPLIST
              rpf-lookup-mode longer-prefix group-list GRPPLIST2
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is MRIB, group2 is URIB")
        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Switch group1 to urib match only, and group2 to lower distance (URIB)")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode urib-only group-list GRPPLIST
              rpf-lookup-mode lower-distance group-list GRPPLIST2
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is URIB, group2 is MRIB")
        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Switch group1 to mrib match only, and group2 to urib match only")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode mrib-only group-list GRPPLIST
              rpf-lookup-mode urib-only group-list GRPPLIST2
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is MRIB, group2 is URIB")
        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Delete MRIB route")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             no ip mroute 10.0.0.0/16 10.0.3.3 25
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is Unknown, group2 is URIB")
        result = verify_upstream_iif(
            tgen, "r4", "Unknown", "10.0.1.1", GROUP1, "NotJoined"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )


def test_pim_mrib_rpf_lookup_source_group_lists(request):
    """Test RPF lookup source and group lists"""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    with McastTesterHelper(tgen) as apphelper:
        step(
            ("Send multicast traffic from R1 to dense groups {}, {}").format(
                GROUP1, GROUP2
            )
        )
        result = apphelper.run_traffic("r1", [GROUP1, GROUP2], bind_intf="r1-eth1")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Reset back to mrib then urib mode
        # Also add mode using GRPPLIST(239.1.1.1) and GRPPLIST2(239.2.2.2), both using SRCPLIST2
        # And do an igmp join to both groups on r4-eth2
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode mrib-then-urib
              rpf-lookup-mode mrib-then-urib group-list GRPPLIST source-list SRCPLIST2
              rpf-lookup-mode mrib-then-urib group-list GRPPLIST2 source-list SRCPLIST2
             exit
             int r4-dum0
              ip igmp join-group {}
              ip igmp join-group {}
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif with default next hop")
        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Add MRIB route through alternate path")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             ip mroute 10.0.0.0/16 10.0.3.3 25
            exit
            """
        )

        step("Verify upstream iif with alternate next hop")
        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Switch group1 to longer prefix match (URIB)")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode longer-prefix group-list GRPPLIST source-list SRCPLIST2
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is URIB, group2 is MRIB")
        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Switch group1 to lower distance match (MRIB), and group2 to longer prefix (URIB)"
        )
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode lower-distance group-list GRPPLIST source-list SRCPLIST2
              rpf-lookup-mode longer-prefix group-list GRPPLIST2 source-list SRCPLIST2
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is MRIB, group2 is URIB")
        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Switch group1 to urib match only, and group2 to lower distance (URIB)")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode urib-only group-list GRPPLIST source-list SRCPLIST2
              rpf-lookup-mode lower-distance group-list GRPPLIST2 source-list SRCPLIST2
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is URIB, group2 is MRIB")
        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Switch group1 to mrib match only, and group2 to urib match only")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             router pim
              rpf-lookup-mode mrib-only group-list GRPPLIST source-list SRCPLIST2
              rpf-lookup-mode urib-only group-list GRPPLIST2 source-list SRCPLIST2
             exit
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is MRIB, group2 is URIB")
        result = verify_upstream_iif(tgen, "r4", "r4-eth1", "10.0.1.1", GROUP1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        step("Delete MRIB route")
        tgen.routers()["r4"].vtysh_cmd(
            """
            conf term
             no ip mroute 10.0.0.0/16 10.0.3.3 25
            exit
            """.format(
                GROUP1, GROUP2
            )
        )

        step("Verify upstream iif of group1 is Unknown, group2 is URIB")
        result = verify_upstream_iif(
            tgen, "r4", "Unknown", "10.0.1.1", GROUP1, "NotJoined"
        )
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_upstream_iif(tgen, "r4", "r4-eth0", "10.0.1.1", GROUP2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
