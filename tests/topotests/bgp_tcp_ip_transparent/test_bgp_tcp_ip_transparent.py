#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025 by Free Mobile, Vincent Jardin

"""
test_bgp_tcp_ip_transparent.py: Test TCP BGP connectiong using ip-transparent
"""

import os
import sys
import time
import json
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
# Required to instantiate the topology builder class.

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.topojson import build_topo_from_json, build_config_from_json
from lib.common_config import retry, run_frr_cmd

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
)
#from lib.bgp import (
#    verify_bgp_convergence
#)

# pytest, bgp only
pytestmark = pytest.mark.bgpd

def build_topo(tgen):
    """Build function"""

    # Create topology acording to topogen input json file.
    build_topo_from_json(tgen, TOPO)


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: %s", testsuite_run_time)
    logger.info("=" * 40)

    topology = """
        r1-----r2
    """
    logger.info("Master Topology: \n %s", topology)

    logger.info("Running setup_module to create topology")

    json_file = "{}/test_bgp_tcp_ip_transparent.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global TOPO
    TOPO = tgen.json_topo

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Create configuration as defined in input json file.
    build_config_from_json(tgen, TOPO)

    # uncomment the following for debug
    #r1.vtysh_cmd(f"""
    #configure terminal
    #debug bgp neighbor-events
    #debug bgp nht
    #""")
    r1.vtysh_cmd(f"""
    configure terminal
    router bgp 20101
      bgp disable-ebgp-connected-route-check
      neighbor 15.20.100.2 remote-as 20102
    """)

    # needed to enforce socket() receive for a transparent IP socket
    # up to the users to use any other method
    r2.run("iptables -t mangle -A PREROUTING -p tcp -j MARK --set-mark 0x100")
    r2.run("ip route add local default dev lo table 100")
    r2.run("ip rule add fwmark 0x100 lookup 100")

    # uncomment the following for debug
    #r2.vtysh_cmd(f"""
    #configure terminal
    #debug bgp neighbor-events
    #debug bgp nht
    #""")
    r2.vtysh_cmd(f"""
    configure terminal
    router bgp 20102
      bgp disable-ebgp-connected-route-check
      neighbor 10.20.100.1 remote-as 20101
      neighbor 10.20.100.1 update-source 15.20.100.2
    """)

    logger.info("Running setup_module() done")


def teardown_module(mod):
    """
    Teardown the pytest environment

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info("Testsuite end time: %s", time.asctime(time.localtime(time.time())))
    logger.info("=" * 40)


@retry(retry_timeout=8)
def verify_bgp_transparent(tgen, topo=None, dut=None):

    if topo is None:
        topo = tgen.json_topo

    result = False
    logger.info("Entering tool API: {}".format(sys._getframe().f_code.co_name))
    tgen = get_topogen()

    no_of_peer = 0
    total_peer = 0
    for router, rnode in tgen.routers().items():
        if "bgp" not in topo["routers"][router]:
            continue

        if dut is not None and dut != router:
            continue
        logger.info("Verifying BGP Convergence on router %s:", router)
        show_bgp_json = run_frr_cmd(rnode, "show bgp vrf all summary json", isjson=True)

        # Verifying output dictionary show_bgp_json is empty or not
        if not bool(show_bgp_json):
            return f"[{router}] BGP is not running"

        for vrf, vrf_blob in show_bgp_json.items():
            peers = vrf_blob.get("ipv4Unicast", {}).get("peers", {})
            for peer_ip, pdata in peers.items():
                nh_state = pdata.get("state")
                logger.debug("  VRF %s peer %s state %s", vrf, peer_ip, nh_state)
                total_peer += 1
                if nh_state == "Established":
                    no_of_peer += 1

        if no_of_peer == total_peer and no_of_peer > 0:
            errormsg = "[DUT: %s] VRF: %s, BGP is Converged" % (router, vrf)
            result = True
        else:
            errormsg = "[DUT: %s] VRF: %s, BGP is not Converged" % (router, vrf)
            result = False

    logger.info("Exiting API: {}, {}".format(sys._getframe().f_code.co_name, errormsg))
    return result


#####################################################
#
#   Testcases
#
#####################################################

def test_bgp_session_not_established(request):
    """Test that the BGP session is not established."""

    tgen = get_topogen()

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Uncomment below to debug
    #tgen.mininet_cli()

    # Api call verify whether BGP is converged
    logger.info("Checking BGP is not connecting\n")
    converged = verify_bgp_transparent(tgen, retry_timeout=9, expected=False)

    assert (
        converged is False
    ), "BGP session did not establish as expected"

    logger.info("BGP TCP did not connect\n")
    write_test_footer(tc_name)


def test_bgp_session_established(request):
    """Test that the BGP session is established."""

    tgen = get_topogen()

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd(f"""
    configure terminal
    router bgp 20102
      neighbor 10.20.100.1 ip-transparent
    """)

    # Uncomment below to debug
    #tgen.mininet_cli()

    # Api call verify whether BGP is converged
    logger.info("Checking BGP is connecting\n")
    converged = verify_bgp_transparent(tgen, retry_timeout=9, expected=True)

    assert (
        converged is True
    ), "test_bgp_convergence failed.. \n" " Error: {}".format(converged)

    logger.info("BGP TCP did connect\n")
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
