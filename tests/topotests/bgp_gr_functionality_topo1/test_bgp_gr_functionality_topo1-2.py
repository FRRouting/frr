#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#

"""
Following tests are covered to test BGP Graceful Restart functionality.
Basic Common Test steps for all the test case below :
- Create topology (setup module)
  Creating 2 routers topology, r1, r2 in IBGP
- Bring up topology
- Verify for bgp to converge
- Configure BGP Garceful Restart on both the routers.

1. Transition from Peer-level helper to Global Restarting
2. Transition from Peer-level helper to Global inherit helper
3. Transition from Peer-level restarting to Global inherit helper
4. Default GR functional mode is Helper.
5. Verify that the restarting node sets "R" bit while sending the
   BGP open messages after the node restart, only if GR is enabled.
6. Verify if restarting node resets R bit in BGP open message
   during normal BGP session flaps as well, even when GR restarting
   mode is enabled. Here link flap happen due to interface UP/DOWN.
7. Verify if restarting node resets R bit in BGP
   open message during normal BGP session flaps when GR is disabled.
8. Verify that restarting nodes set "F" bit while sending
   the BGP open messages after it restarts, only when BGP GR is enabled.
9. Verify that only GR helper routers keep the stale
   route entries, not any GR disabled router.
10. Verify that GR helper routers keeps all the routes received
    from restarting node if both the routers are configured as
    GR restarting node.
11. Verify that GR helper routers delete all the routes
    received from a node if both the routers are configured as GR
    helper node.
12. After BGP neighborship is established and GR capability is exchanged,
    transition restarting router to disabled state and vice versa.
13. After BGP neighborship is established and GR capability is exchanged,
    transition restarting router to disabled state and vice versa.
14. Verify that restarting nodes reset "F" bit while sending
    the BGP open messages after it's restarts, when BGP GR is **NOT** enabled.
15. Verify that only GR helper routers keep the stale
    route entries, not any GR disabled router.
16. Transition from Global Restarting to Disable and then Global
    Disable to Restarting.
17. Transition from Global Helper to Disable and then Global
    Disable to Helper.
18. Transition from Global Restart to Helper and then Global
    Helper to Restart, Global Mode : GR Restarting
    PerPeer Mode :  GR Helper
    GR Mode effective : GR Helper
19. Transition from Peer-level helper to Global Restarting,
    Global Mode : GR Restarting
    PerPeer Mode :  GR Restarting
    GR Mode effective : GR Restarting
20. Transition from Peer-level restart to Global Restart
    Global Mode : GR Restarting
    PerPeer Mode :  GR Restarting
    GR Mode effective : GR Restarting
21. Transition from Peer-level disabled to Global Restart
    Global Mode : GR Restarting
    PerPeer Mode : GR Disabled
    GR Mode effective : GR Disabled
22. Peer-level inherit from Global Restarting
    Global Mode : GR Restart
    PerPeer Mode :  None
    GR Mode effective : GR Restart
23. Transition from Peer-level disable to Global inherit helper
    Global Mode : None
    PerPeer Mode :  GR Disable
    GR Mode effective : GR Disable

These tests have been broken up into 4 sub python scripts because
the totality of this run was fairly significant.
"""

import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

# Import topoJson from lib, to create topology and initial configuration
from lib.topojson import build_config_from_json
from lib.bgp import (
    clear_bgp,
    verify_bgp_rib,
    verify_graceful_restart,
    create_router_bgp,
    verify_r_bit,
    verify_f_bit,
    verify_bgp_convergence,
    verify_bgp_convergence_from_running_config,
)

from lib.common_config import (
    write_test_header,
    reset_config_on_routers,
    start_topology,
    kill_router_daemons,
    start_router_daemons,
    verify_rib,
    check_address_types,
    write_test_footer,
    check_router_status,
    get_frr_ipv6_linklocal,
    required_linux_kernel_version,
)

pytestmark = [pytest.mark.bgpd]


# Global variables
NEXT_HOP_IP = {"ipv4": "192.168.1.10", "ipv6": "fd00:0:0:1::10"}
NEXT_HOP_IP_1 = {"ipv4": "192.168.0.1", "ipv6": "fd00::1"}
NEXT_HOP_IP_2 = {"ipv4": "192.168.0.2", "ipv6": "fd00::2"}
BGP_CONVERGENCE = False
GR_RESTART_TIMER = 20
PREFERRED_NEXT_HOP = "link_local"


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global ADDR_TYPES

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.16")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=4.16")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_gr_topojson_topo1.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    ADDR_TYPES = check_address_types()

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error:" " {}".format(
        BGP_CONVERGENCE
    )

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

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


def configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut, peer):
    """
    This function groups the repetitive function calls into one function.
    """

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        neighbor = topo["routers"][peer]["links"]["r1-link1"][addr_type].split("/")[0]
        clear_bgp(tgen, addr_type, dut, neighbor=neighbor)

    for addr_type in ADDR_TYPES:
        neighbor = topo["routers"][dut]["links"]["r2-link1"][addr_type].split("/")[0]
        clear_bgp(tgen, addr_type, peer, neighbor=neighbor)

    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    return True


def next_hop_per_address_family(
    tgen, dut, peer, addr_type, next_hop_dict, preferred_next_hop=PREFERRED_NEXT_HOP
):
    """
    This function returns link_local or global next_hop per address-family
    """

    intferface = topo["routers"][peer]["links"]["{}-link1".format(dut)]["interface"]
    if addr_type == "ipv6" and "link_local" in preferred_next_hop:
        next_hop = get_frr_ipv6_linklocal(tgen, peer, intf=intferface)
    else:
        next_hop = next_hop_dict[addr_type]

    return next_hop


def test_BGP_GR_TC_8_p1(request):
    """
    Test Objective : Verify that restarting nodes set "F" bit while sending
     the BGP open messages after it restarts, only when BGP GR is enabled.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Check router status
    check_router_status(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    logger.info(
        "[Phase 1] : Test Setup" " [Restart Mode]R1-----R2[Restart Mode] initialized  "
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "graceful-restart": {"preserve-fw-state": True},
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart": True}
                                    }
                                }
                            }
                        }
                    },
                },
            }
        },
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {"graceful-restart": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {"graceful-restart": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        dut = "r1"
        peer = "r2"
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        protocol = "bgp"
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 2] : R1 goes for reload  ")

    kill_router_daemons(tgen, "r1", ["bgpd"])

    logger.info("[Phase 3] : R1 is about to come up now  ")
    start_router_daemons(tgen, "r1", ["bgpd"])

    logger.info("[Phase 4] : R2 is UP now, so time to collect GR stats  ")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(tgen, topo, addr_type, input_dict, dut="r2", peer="r1")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_f_bit(tgen, topo, addr_type, input_dict, dut="r2", peer="r1")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
