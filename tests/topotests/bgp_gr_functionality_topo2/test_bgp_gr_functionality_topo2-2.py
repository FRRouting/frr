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
    verify_r_bit,
    verify_f_bit,
    verify_bgp_convergence,
    verify_gr_address_family,
    modify_bgp_config_when_bgpd_down,
    verify_graceful_restart_timers,
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


def test_BGP_GR_26_p2(request):
    """
    Test Objective : Test GR scenarios on helper router by enabling
    Graceful Restart for multiple address families.
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
        "[Step 1] : Test Setup " "[Helper Mode]R3-----R1[Restart Mode] initialized"
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
                                            "graceful-restart": True,
                                            "next_hop_self": True,
                                            "activate": "ipv6",
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
                                            "graceful-restart": True,
                                            "next_hop_self": True,
                                            "activate": "ipv4",
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
                                        "r3": {
                                            "graceful-restart-helper": True,
                                            "activate": "ipv6",
                                        }
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
                                        "r3": {
                                            "graceful-restart-helper": True,
                                            "activate": "ipv4",
                                        }
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
            tgen, topo, addr_type, input_dict, dut="r3", peer="r1"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        dut = "r3"
        input_topo = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_topo)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    # Kill BGPd daemon on R1
    kill_router_daemons(tgen, "r1", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        input_topo = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_topo)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    # Start BGPd daemon on R1
    start_router_daemons(tgen, "r1", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        input_topo = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_topo)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # verify multi address family
        result = verify_gr_address_family(
            tgen,
            topo,
            addr_type,
            "ipv4Unicast",
            dut="r1",
            peer="r3",
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # verify multi address family
        result = verify_gr_address_family(
            tgen,
            topo,
            addr_type,
            "ipv6Unicast",
            dut="r1",
            peer="r3",
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # verify multi address family
        result = verify_gr_address_family(
            tgen,
            topo,
            addr_type,
            "ipv4Unicast",
            dut="r3",
            peer="r1",
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # verify multi address family
        result = verify_gr_address_family(
            tgen,
            topo,
            addr_type,
            "ipv6Unicast",
            dut="r3",
            peer="r1",
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_chaos_28_p1(request):
    """
    Test Objective : Verify if helper node goes down before restarting
    node comes up online, helper node sets the R-bit to avoid dead-lock
    till SDT expiry.
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
        "Test Case: test_BGP_GR_chaos_28 :"
        "[Helper Mode]R3-----R1[Restart Mode] initialized"
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r1": {"graceful-restart": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r1": {"graceful-restart": True}}}
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
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Step 1] : Kill BGPd daemon on R1..")

    # Kill BGPd daemon on R1
    kill_router_daemons(tgen, "r1", ["bgpd"])

    logger.info("[Step 2] : Kill BGPd daemon on R3..")

    # Kill BGPd daemon on R3
    kill_router_daemons(tgen, "r3", ["bgpd"])

    logger.info("[Step 3] : Start BGPd daemon on R1..")

    # Start BGPd daemon on R1
    start_router_daemons(tgen, "r1", ["bgpd"])

    logger.info("[Step 4] : Start BGPd daemon on R3..")

    # Start BGPd daemon on R3
    start_router_daemons(tgen, "r3", ["bgpd"])

    # Verify r_bit
    for addr_type in ADDR_TYPES:
        result = verify_r_bit(tgen, topo, addr_type, input_dict, dut="r3", peer="r1")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_chaos_29_p1(request):
    """
    Test Objective : Change timers on the fly, and
    verify if it takes immediate effect.
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
        " Test Case : test_BGP_GR_chaos_29"
        " BGP GR [Helper Mode]R3-----R1[Restart Mode]"
        " and [restart-time 150]R1 initialized"
    )

    # Configure graceful-restart and timers
    input_dict = {
        "r1": {
            "bgp": {
                "graceful-restart": {"timer": {"restart-time": GR_RESTART_TIMER}},
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r1": {"graceful-restart": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r1": {"graceful-restart": True}}}
                            }
                        }
                    },
                },
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
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    # Verify graceful-restart timers
    input_dict_2 = {
        "r1": {
            "bgp": {
                "graceful-restart": {"timer": {"restart-time": GR_RESTART_TIMER + 5}}
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r1": {
                "bgp": {
                    "graceful-restart": {"timer": {"restart-time": GR_RESTART_TIMER}}
                }
            }
        }

        result = verify_graceful_restart_timers(
            tgen, topo, addr_type, input_dict_2, dut="r3", peer="r1"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes before shutting down BGPd daemon
        dut = "r3"
        input_dict = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Step 2] : Kill BGPd daemon on R1..")

    # Kill BGPd daemon on R1
    kill_router_daemons(tgen, "r1", ["bgpd"])

    logger.info("[Step 3] : Wait for {} seconds..".format(GR_RESTART_TIMER))

    # Waiting for GR_RESTART_TIMER
    sleep(GR_RESTART_TIMER)

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes before shutting down BGPd daemon
        input_dict = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

        # Verifying RIB routes before shutting down BGPd daemon
        result = verify_rib(tgen, addr_type, dut, input_dict, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} FIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    logger.info("[Step 4] : Start BGPd daemon on R1..")

    # Start BGPd daemon on R1
    start_router_daemons(tgen, "r1", ["bgpd"])

    write_test_footer(tc_name)


def test_BGP_GR_chaos_33_p1(request):
    """
    Test Objective : Helper router receives same prefixes from two
    different routers (GR-restarting and GR-disabled). Keeps the
    stale entry only for GR-restarting node(next-hop is correct).
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
        " Test Case : test_BGP_GR_chaos_33 "
        "BGP GR "
        "[Restart Mode]R1--R3[Helper Mode]--R4[Disabled Mode]"
    )

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r1": {"graceful-restart": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r1": {"graceful-restart": True}}}
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
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r4": {"graceful-restart-disable": True}
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
                                        "r4": {"graceful-restart-disable": True}
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
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Step 2] : Advertise same networks from R1 and R4..")

    # Api call to delete advertised networks
    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.0.20.1/32",
                                    "no_of_network": 2,
                                }
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "2001::1/128", "no_of_network": 2}
                            ]
                        }
                    },
                }
            }
        },
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "200.0.20.1/32", "no_of_network": 2}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "2001::1/128", "no_of_network": 2}
                            ]
                        }
                    },
                }
            }
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        # Verifying RIB routes
        dut = "r3"
        peer1 = "r1"
        peer2 = "r4"
        intf1 = topo["routers"][peer1]["links"][dut]["interface"]
        intf2 = topo["routers"][peer2]["links"][dut]["interface"]

        if addr_type == "ipv4":
            next_hop_4 = NEXT_HOP_4
            result = verify_rib(tgen, addr_type, dut, input_dict_2, next_hop_4)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

        if addr_type == "ipv6":
            if "link_local" in PREFERRED_NEXT_HOP:
                next_hop1 = get_frr_ipv6_linklocal(tgen, peer1, intf=intf1)
                next_hop2 = get_frr_ipv6_linklocal(tgen, peer2, intf=intf2)

                next_hop_6 = [next_hop1, next_hop2]
            else:
                next_hop_6 = NEXT_HOP_6

            result = verify_rib(tgen, addr_type, dut, input_dict_2, next_hop_6)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    logger.info("[Step 3] : Kill BGPd daemon on R1 and R4..")

    # Kill BGPd daemon on R1
    kill_router_daemons(tgen, "r1", ["bgpd"])

    # Kill BGPd daemon on R4
    kill_router_daemons(tgen, "r4", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verifying RIB routes
        next_hop_6 = ["fd00:0:0:1::1"]
        if addr_type == "ipv4":
            next_hop_4 = NEXT_HOP_4[0]

            result = verify_rib(tgen, addr_type, dut, input_dict_2, next_hop_4)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

        if addr_type == "ipv6":
            if "link_local" in PREFERRED_NEXT_HOP:
                next_hop_6 = get_frr_ipv6_linklocal(tgen, peer1, intf=intf1)
            else:
                next_hop_6 = NEXT_HOP_6[0]

            result = verify_rib(tgen, addr_type, dut, input_dict_2, next_hop_6)

        # Verifying RIB routes
        if addr_type == "ipv4":
            next_hop_4 = NEXT_HOP_4[1]
            result = verify_rib(
                tgen, addr_type, dut, input_dict_2, next_hop_4, expected=False
            )
            assert result is not True, (
                "Testcase {} : Failed \n "
                "Expected: Routes should not be present in {} FIB \n "
                "Found: {}".format(tc_name, dut, result)
            )

        if addr_type == "ipv6":
            if "link_local" in PREFERRED_NEXT_HOP:
                next_hop_6 = get_frr_ipv6_linklocal(tgen, peer2, intf=intf2)
            else:
                next_hop_6 = NEXT_HOP_6[1]

            result = verify_rib(
                tgen, addr_type, dut, input_dict_2, next_hop_6, expected=False
            )
            assert result is not True, (
                "Testcase {} : Failed \n "
                "Expected: Routes should not be present in {} FIB \n "
                "Found: {}".format(tc_name, dut, result)
            )

    logger.info("[Step 4] : Start BGPd daemon on R1 and R4..")

    # Start BGPd daemon on R1
    start_router_daemons(tgen, "r1", ["bgpd"])

    # Start BGPd daemon on R4
    start_router_daemons(tgen, "r4", ["bgpd"])

    write_test_footer(tc_name)


def test_BGP_GR_chaos_34_2_p1(request):
    """
    Test Objective : Restarting node doesn't preserve the forwarding
    state verify the behaviour on helper node, if it still keeps the
    stale routes.
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
        " Test Case : test_BGP_GR_chaos_34 "
        "BGP GR "
        "[Restart Mode]R1---R3[Helper Mode]"
    )

    logger.info("[Step 1] : Configure restarting" "  router R1 to prevent ")
    logger.info("[Step 2] : Reset the session" " between R1 and R3..")

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "graceful-restart": {"preserve-fw-state": True, "disable-eor": True},
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r1": {"graceful-restart": True}}}
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {"dest_link": {"r1": {"graceful-restart": True}}}
                            }
                        }
                    },
                },
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
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verify f-bit before killing BGPd daemon
        result = verify_f_bit(tgen, topo, addr_type, input_dict, "r3", "r1")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes after starting BGPd daemon
        dut = "r3"
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Step 3] : Kill BGPd daemon on R1..")

    # Kill BGPd daemon on R1
    kill_router_daemons(tgen, "r1", ["bgpd"])

    logger.info("[Step 4] : Withdraw/delete the prefixes " "originated from R1..")

    # Api call to delete advertised networks
    network = {"ipv4": "101.0.20.1/32", "ipv6": "1::1/128"}
    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": network[addr_type],
                                        "no_of_network": 5,
                                        "delete": True,
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = modify_bgp_config_when_bgpd_down(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Step 5] : Remove the CLI from R1's config to " "set the F-bit..")

    # Modify graceful-restart config not to set f-bit
    # and write to /etc/frr
    input_dict_2 = {"r1": {"bgp": {"graceful-restart": {"preserve-fw-state": False}}}}

    result = modify_bgp_config_when_bgpd_down(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    logger.info("[Step 6] : Bring up the BGPd daemon on R1 again..")

    # Start BGPd daemon on R1
    start_router_daemons(tgen, "r1", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verify f-bit after starting BGPd daemon
        result = verify_f_bit(
            tgen, topo, addr_type, input_dict, "r3", "r1", expected=False
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: F-bit should not be set to True in r3\n"
            "Found: {}".format(tc_name, result)
        )

        # Verifying BGP RIB routes after starting BGPd daemon
        input_dict_1 = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} BGP RIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_dict_1, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} FIB \n "
            "Found: {}".format(tc_name, dut, result)
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
