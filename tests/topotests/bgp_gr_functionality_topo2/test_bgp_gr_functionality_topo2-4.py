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
  Creating 7 routers topology
- Bring up topology
- Verify for bgp to converge
- Configure BGP Graceful Restart on both the routers.

TC_1_2:
    Verify that EOR message is sent out only after initial convergence
    Verify whether EOR message is received from all the peers after restart
TC_3:
    Verify the selection deferral timer functionality when EOR is not sent
    by the helper router
TC_11:
    Verify that selection-deferral timer sets the maximum time to
    avoid deadlock during which the best-path
TC_10:
    Test Objective : Test GR scenarios on helper router by enabling
    Graceful Restart for multiple address families.
TC_15:
    Test Objective : Test GR scenarios by enabling Graceful Restart
    for multiple address families..
TC_16:
    Test Objective : Verify BGP-GR feature when restarting node
    is a transit router for it's iBGP peers.
TC_18:
    Test Objective : Verify that GR helper router deletes stale routes
    received from restarting node, if GR capability is not present in
TC_19:
    Test Objective : Verify that GR routers keeps all the routes
     received from restarting node if both the routers are
TC_26:
    Test Objective : Test GR scenarios on helper router by enabling
    Graceful Restart for multiple address families.
TC_28:
    Test Objective : Verify if helper node goes down before restarting
    node comes up online, helper node sets the R-bit to avoid dead-lock
TC_29:
    Test Objective : Change timers on the fly, and
    verify if it takes immediate effect.
TC_33:
    Test Objective : Helper router receives same prefixes from two
    different routers (GR-restarting and GR-disabled). Keeps the
TC_34_1:
    Test Objective : Restarting node doesn't preserve forwarding
    state, helper router should not keep the stale entries.
TC_34_2:
    Test Objective : Restarting node doesn't preserve the forwarding
    state verify the behaviour on helper node, if it still keeps the
TC_32:
    Test Objective : Restarting node is connected to multiple helper
    nodes, one of them doesn't send EOR to restarting router. Verify
TC_37:
    Test Objective : Verify if helper node restarts before sending the
    EOR message, restarting node doesn't wait until stale path timer
TC_30:
    Test Objective : Restarting node removes stale routes from Zebra
    after receiving an EOR from helper router.

These tests have been broken up into 4 sub python scripts because
the totality of run time for this script was greater than 10 minutes
"""

import os
import sys
import time
import pytest
from time import sleep

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
    verify_eor,
    verify_bgp_convergence,
    modify_bgp_config_when_bgpd_down,
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
BGP_CONVERGENCE = False
GR_RESTART_TIMER = 5
GR_SELECT_DEFER_TIMER = 5
GR_STALEPATH_TIMER = 5
PREFERRED_NEXT_HOP = "link_local"
NEXT_HOP_4 = ["192.168.1.1", "192.168.4.2"]
NEXT_HOP_6 = ["fd00:0:0:1::1", "fd00:0:0:4::2"]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.16")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=4.16")

    global ADDR_TYPES

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_gr_topojson_topo2.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Api call verify whether BGP is converged
    ADDR_TYPES = check_address_types()

    for _ in ADDR_TYPES:
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

    logger.info("configure_gr_followed_by_clear: dut %s peer %s", dut, peer)

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        neighbor = topo["routers"][peer]["links"][dut][addr_type].split("/")[0]
        clear_bgp(tgen, addr_type, dut, neighbor=neighbor)

    for addr_type in ADDR_TYPES:
        neighbor = topo["routers"][dut]["links"][peer][addr_type].split("/")[0]
        clear_bgp(tgen, addr_type, peer, neighbor=neighbor)

    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    return True


def next_hop_per_address_family(tgen, dut, peer, addr_type, next_hop_dict):
    """
    This function returns link_local or global next_hop per address-family
    """

    intferface = topo["routers"][peer]["links"]["{}-link1".format(dut)]["interface"]
    if addr_type == "ipv6" and "link_local" in PREFERRED_NEXT_HOP:
        next_hop = get_frr_ipv6_linklocal(tgen, peer, intf=intferface)
    else:
        next_hop = next_hop_dict[addr_type]

    return next_hop


def test_BGP_GR_TC_23_p1(request):
    """
    Verify that helper routers are deleting stale routes after stale route
    timer's expiry. If all the routes are not received from restating node
    after restart.
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
        "Verify Stale Routes are deleted on helper: BGP_GR_TC_23 >> "
        "BGP GR [Helper Mode]R1-----R2[Restart Mode] "
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "graceful-restart": {"timer": {"stalepath-time": GR_STALEPATH_TIMER}},
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {"graceful-restart-helper": True}
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
                                        "r1": {"graceful-restart-helper": True}
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
                "graceful-restart": {
                    "graceful-restart": True,
                    "preserve-fw-state": True,
                },
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {"dest_link": {"r2": {"graceful-restart": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {"dest_link": {"r2": {"graceful-restart": True}}}
                            }
                        }
                    },
                },
            }
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes received from router R1
        dut = "r1"
        input_dict_1 = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    logger.info("R2 goes for reload")
    kill_router_daemons(tgen, "r2", ["bgpd"])

    # Modify configuration to delete routes and include disable-eor
    input_dict_3 = {"r2": {"bgp": {"graceful-restart": {"disable-eor": True}}}}

    result = modify_bgp_config_when_bgpd_down(tgen, topo, input_dict_3)

    # Modify configuration to delete routes and include disable-eor
    network = {"ipv4": "102.0.20.1/32", "ipv6": "2::1/128"}
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
            "r2": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": network[addr_type],
                                        "no_of_network": 3,
                                        "delete": True,
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = modify_bgp_config_when_bgpd_down(tgen, topo, input_dict_3)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    logger.info("BGPd comes up for r2")
    start_router_daemons(tgen, "r2", ["bgpd"])

    # Wait for stalepath timer
    logger.info("Waiting for stalepath timer({} sec..)".format(GR_STALEPATH_TIMER))
    sleep(GR_STALEPATH_TIMER)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r2")

    # Verifying RIB routes
    dut = "r1"
    network = {"ipv4": "102.0.20.4/32", "ipv6": "2::4/128"}
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {"network": network[addr_type], "no_of_network": 2}
                                ]
                            }
                        }
                    }
                }
            }
        }

        # Verify EOR on helper router
        result = verify_eor(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2", expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: EOR should not be set to True in r2\n"
            "Found: {}".format(tc_name, result)
        )

        # Verifying BGP RIB routes received from router R1
        dut = "r1"
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_BGP_GR_20_p1(request):
    """
    Test Objective : Verify that GR routers delete all the routes
    received from a node if both the routers are configured as GR
    helper node
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
        "[Step 1] : Test Setup " "[Restart Mode]R3-----R1[Restart Mode] Initialized"
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"graceful-restart-helper": True}
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
                                        "r3": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r3")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r3"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Kill BGPd daemon on R1
    kill_router_daemons(tgen, "r1", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} FIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    # Start BGPd daemon on R1
    start_router_daemons(tgen, "r1", ["bgpd"])

    for addr_type in ADDR_TYPES:
        result = verify_bgp_convergence(tgen, topo)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_BGP_GR_21_p2(request):
    """
    Test Objective : VVerify BGP-GR feature when helper node is
    a transit router for it's eBGP peers.
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
        "[Step 1] : Test Setup " "[Helper Mode]R6-----R1[Restart Mode] Initialized"
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r6": {
                                    "dest_link": {
                                        "r1": {"graceful-restart-disable": True}
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r6": {
                                    "dest_link": {
                                        "r1": {"graceful-restart-disable": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
        "r6": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r6": {"graceful-restart-helper": True}
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
                                        "r6": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r6")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r6"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    logger.info(
        "[Step 2] : Test Setup "
        "[Restart Mode]R2-----[Helper Mode]R1[Disable Mode]"
        "--------R6[Helper Mode] Initialized"
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {"graceful-restart-helper": True}
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
                                        "r1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
        "r2": {
            "bgp": {
                "graceful-restart": {
                    "graceful-restart": True,
                }
            }
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r6"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r6"
        input_dict_2 = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Kill BGPd daemon on R1
    kill_router_daemons(tgen, "r2", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        dut = "r6"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r6"
        input_dict_2 = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Start BGPd daemon on R1
    start_router_daemons(tgen, "r2", ["bgpd"])

    for addr_type in ADDR_TYPES:
        result = verify_bgp_convergence(tgen, topo)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r6"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes after bringing up BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r6"
        input_dict_2 = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_BGP_GR_22_p2(request):
    """
    Test Objective : Verify BGP-GR feature when helper node
    is a transit router for it's iBGP peers.
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
        "[Step 1] : Test Setup " "[Helper Mode]R3-----R1[Restart Mode] Initialized"
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {
                                            "graceful-restart-disable": True,
                                            "next_hop_self": True,
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {
                                            "graceful-restart-disable": True,
                                            "next_hop_self": True,
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {"graceful-restart-helper": True}
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
                                        "r3": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r3")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r3"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    logger.info(
        "[Step 2] : Test Setup "
        "[Restart Mode]R2-----[Helper Mode]R1[Disable Mode]"
        "--------R3[Helper Mode] Initialized"
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {"graceful-restart-helper": True}
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
                                        "r1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
        "r2": {"bgp": {"graceful-restart": {"graceful-restart": True}}},
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_2 = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Kill BGPd daemon on R1
    kill_router_daemons(tgen, "r2", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_2 = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Start BGPd daemon on R1
    start_router_daemons(tgen, "r2", ["bgpd"])

    for addr_type in ADDR_TYPES:
        result = verify_bgp_convergence(tgen, topo)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying BGP RIB routes
        dut = "r3"
        input_dict_2 = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
