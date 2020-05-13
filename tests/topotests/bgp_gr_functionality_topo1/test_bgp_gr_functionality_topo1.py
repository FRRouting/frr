#!/usr/bin/env python
#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Following tests are covered to test BGP Gracefull Restart functionality.
Basic Common Test steps for all the test case below :
- Create topology (setup module)
  Creating 2 routers topology, r1, r2 in IBGP
- Bring up topology
- Verify for bgp to converge
- Configure BGP Garceful Restart on both the routers.

1. Helper BGP router R1, mark and unmark IPV4 routes
   as stale as the restarting router R2 come up within the restart time.
2. Helper BGP router R1, mark IPV4 routes as stale and
   deletes them as the restarting router R2 did-not come up within restart
   time.
3. Restart BGP router R1, detects it is connected to R2,
   which is a helper router. Verify the restart capability i.e. R bit
   are sent after R1 reloads and comes back.
4. Verify that the restarting node sets "R" bit while sending the
   BGP open messages after the node restart, only if GR is enabled.
5. Verify if restarting node resets R bit in BGP open message
   during normal BGP session flaps as well, even when GR restarting mode is enabled.
   Here link flap happen due to interface UP/DOWN.
6. Verify if restarting node resets R bit in BGP open message
   during normal BGP session flaps as well, even when GR restarting mode is enabled.
   Here link flap happen due to neigh router restarts
7. Verify if restarting node resets R bit in BGP open message
   during normal BGP session flaps when GR helper mode is enabled.
   Here link flap happen due to interface UP/DOWN.
8. Verify if restarting node resets R bit in BGP open message
   during normal BGP session flaps when GR helper mode is enabled.
   Here link flap happen due to neigh router restarts.
9. Verify that restarting nodes set "F" bit while sending
   the BGP open messages after it restarts, only when BGP GR is enabled.
10. Verify that restarting nodes reset "F" bit while sending
   the BGP open messages after it's restarts, when BGP GR is **NOT** enabled.
11. Verify that only GR helper routers keep the stale
   route entries, not any GR disabled router.
12. Verify that GR helper routers keeps all the routes received
   from restarting node if both the routers are configured as GR restarting node.
13. Verify that GR helper routers delete all the routes
   received from a node if both the routers are configured as GR helper node.
14. Test Objective : After BGP neighborship is established and GR capability
    is exchanged, transition helper router to disabled state.
15.Test Objective : After BGP neighborship is established and GR capability
    is exchanged, transition disabled router to helper state.
16. Verify transition from Global Restarting to Disable and then
    Global Disable to Restarting.
17. Verify transition from Global Helper to Disable and then Global
    Disable to Helper.
18. Verify transition from Global Restart to Helper and then Global
    Helper to Restart.
19. Verify transition from Peer-level helper to Global Restarting.
20. Verify transition from Peer-level restart to Global Restart.
21. Verify transition from Peer-level disabled to Global Restart.
22. Verify Peer-level inherit from Global Restarting mode.
23. Verify transition from Peer-level helper to Global inherit helper.
24. Verify transition from Peer-level restart to Global inherit helper.
25. Verify transition from Peer-level disbale to Global inherit helper.
26. Verify default GR functional mode is Helper.
27. Verify transition from Peer-level Helper to Global Disable.
28. Verify transition from Peer-level Restarting to Global Disable.
29. Verify transition from Peer-level Disable to Global Disable.
30. Verfiy Peer-level inherit from Global Disable mode.

"""

import os
import sys
import json
import time
import inspect
import pytest
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

# Import topoJson from lib, to create topology and initial configuration
from lib.topojson import build_topo_from_json, build_config_from_json
from lib.bgp import (
    clear_bgp,
    verify_bgp_rib,
    verify_graceful_restart,
    create_router_bgp,
    verify_r_bit,
    verify_f_bit,
    verify_bgp_convergence,
    verify_graceful_restart_timers,
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
    shutdown_bringup_interface,
    step,
    kill_mininet_routers_process,
    get_frr_ipv6_linklocal,
    create_route_maps,
)

# Reading the data from JSON File for topology and configuration creation
jsonFile = "{}/bgp_gr_topojson_topo1.json".format(CWD)
try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    logger.info("Could not read file:", jsonFile)


# Global variables
NEXT_HOP_IP = {"ipv4": "192.168.1.10", "ipv6": "fd00:0:0:1::10"}
NEXT_HOP_IP_1 = {"ipv4": "192.168.0.1", "ipv6": "fd00::1"}
NEXT_HOP_IP_2 = {"ipv4": "192.168.0.2", "ipv6": "fd00::2"}
BGP_CONVERGENCE = False
GR_RESTART_TIMER = 20
PREFERRED_NEXT_HOP = "link_local"


class GenerateTopo(Topo):
    """
    Test topology builder

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to create topology
        # as defined in input json file.
        #
        # Create topology (setup module)
        # Creating 2 routers topology, r1, r2in IBGP
        # Bring up topology

        # Building topology from json file
        build_topo_from_json(tgen, topo)


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global ADDR_TYPES

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(GenerateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Kill stale mininet routers and process
    kill_mininet_routers_process(tgen)

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    ADDR_TYPES = check_address_types()

    for addr_type in ADDR_TYPES:
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
        clear_bgp(tgen, addr_type, dut)

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


def test_BGP_GR_TC_46_p1(request):
    """
    Test Objective : transition from Peer-level helper to Global Restarting
    Global Mode : GR Restarting
    PerPeer Mode :  GR Helper
    GR Mode effective : GR Helper

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

    step(
        "Configure R1 and R2 as GR restarting node in global"
        " and helper in per-Peer-level"
    )

    input_dict = {
        "r1": {
            "bgp": {
                "graceful-restart": {"graceful-restart": True,},
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-helper": True}
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
                                        "r1-link1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                },
            }
        },
        "r2": {"bgp": {"graceful-restart": {"graceful-restart": True}}},
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    step("Verify on R2 that R1 advertises GR capabilities as a restarting node")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Kill BGP on R2")

    kill_router_daemons(tgen, "r2", ["bgpd"])

    step(
        "Verify that R1 keeps the stale entries in RIB & FIB and R2 keeps stale entries in FIB using"
    )

    for addr_type in ADDR_TYPES:
        protocol = "bgp"
        next_hop = next_hop_per_address_family(
            tgen, "r2", "r1", addr_type, NEXT_HOP_IP_1
        )
        input_topo = {"r1": topo["routers"]["r1"]}
        result = verify_rib(tgen, addr_type, "r2", input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        next_hop = next_hop_per_address_family(
            tgen, "r1", "r2", addr_type, NEXT_HOP_IP_2
        )
        input_topo = {"r2": topo["routers"]["r2"]}
        result = verify_bgp_rib(tgen, addr_type, "r1", input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Bring up BGP on R1 and remove Peer-level GR config"
        " from R1 following by a session reset"
    )

    start_router_daemons(tgen, "r2", ["bgpd"])

    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-helper": False}
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
                                        "r1-link1": {"graceful-restart-helper": False}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    step("Verify on R2 that R1 advertises GR capabilities as a restarting node")

    input_dict = {
        "r1": {"bgp": {"graceful-restart": {"graceful-restart": True}}},
        "r2": {"bgp": {"graceful-restart": {"graceful-restart": True}}},
    }

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Kill BGP on R1")

    kill_router_daemons(tgen, "r1", ["bgpd"])

    step(
        "Verify that R1 keeps the stale entries in FIB command and R2 keeps stale entries in RIB & FIB"
    )

    for addr_type in ADDR_TYPES:
        protocol = "bgp"
        next_hop = next_hop_per_address_family(
            tgen, "r1", "r2", addr_type, NEXT_HOP_IP_2
        )
        input_topo = {"r2": topo["routers"]["r2"]}
        result = verify_rib(tgen, addr_type, "r1", input_topo, next_hop, protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Routes are still present \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        next_hop = next_hop_per_address_family(
            tgen, "r2", "r1", addr_type, NEXT_HOP_IP_1
        )
        input_topo = {"r1": topo["routers"]["r1"]}
        result = verify_bgp_rib(tgen, addr_type, "r2", input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r2", input_topo, next_hop, protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Routes are still present \n Error {}".format(
            tc_name, result
        )

    step("Start BGP on R1")

    start_router_daemons(tgen, "r1", ["bgpd"])

    write_test_footer(tc_name)


def test_BGP_GR_TC_50_p1(request):
    """
    Test Objective : Transition from Peer-level helper to Global inherit helper
    Global Mode : None
    PerPeer Mode :  Helper
    GR Mode effective : GR Helper

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

    step(
        "Configure R1 as GR helper node at per Peer-level for R2"
        " and configure R2 as global restarting node."
    )

    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-helper": True}
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
                                        "r1-link1": {"graceful-restart-helper": True}
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

    step("Verify on R2 that R1 advertises GR capabilities as a helper node")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Kill BGP on R2")

    kill_router_daemons(tgen, "r2", ["bgpd"])

    step(
        "Verify that R2 keeps the stale entries in FIB & R1 keeps stale entries in RIB & FIB"
    )

    for addr_type in ADDR_TYPES:
        protocol = "bgp"
        next_hop = next_hop_per_address_family(
            tgen, "r2", "r1", addr_type, NEXT_HOP_IP_1
        )
        input_topo = {"r1": topo["routers"]["r1"]}
        result = verify_rib(tgen, addr_type, "r2", input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        next_hop = next_hop_per_address_family(
            tgen, "r1", "r2", addr_type, NEXT_HOP_IP_2
        )
        input_topo = {"r2": topo["routers"]["r2"]}
        result = verify_bgp_rib(tgen, addr_type, "r1", input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Bring up BGP on R2 and remove Peer-level GR config from R1 ")

    start_router_daemons(tgen, "r2", ["bgpd"])

    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-helper": False}
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
                                        "r1-link1": {"graceful-restart-helper": False}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    step("Verify on R2 that R1 still advertises GR capabilities as a helper node")

    input_dict = {
        "r1": {"bgp": {"graceful-restart": {"graceful-restart-helper": True}}},
        "r2": {"bgp": {"graceful-restart": {"graceful-restart": True}}},
    }

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Kill BGP on R2")

    kill_router_daemons(tgen, "r2", ["bgpd"])

    step(
        "Verify that R2 keeps the stale entries in FIB & R1 keeps stale entries in RIB & FIB"
    )

    for addr_type in ADDR_TYPES:
        protocol = "bgp"
        next_hop = next_hop_per_address_family(
            tgen, "r2", "r1", addr_type, NEXT_HOP_IP_1
        )
        input_topo = {"r1": topo["routers"]["r1"]}
        result = verify_rib(tgen, addr_type, "r2", input_topo, next_hop, protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Routes are still present \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        next_hop = next_hop_per_address_family(
            tgen, "r1", "r2", addr_type, NEXT_HOP_IP_2
        )
        input_topo = {"r2": topo["routers"]["r2"]}
        result = verify_bgp_rib(tgen, addr_type, "r1", input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_topo, next_hop, protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Routes are still present \n Error {}".format(
            tc_name, result
        )

    step("Start BGP on R2")

    start_router_daemons(tgen, "r2", ["bgpd"])

    write_test_footer(tc_name)


def test_BGP_GR_TC_51_p1(request):
    """
    Test Objective : Transition from Peer-level restarting to Global inherit helper
    Global Mode : None
    PerPeer Mode :  GR Restart
    GR Mode effective : GR Restart

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

    step("Configure R1 as GR restarting node at per Peer-level for R2")

    input_dict = {
        "r1": {
            "bgp": {
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
                }
            }
        },
        "r2": {"bgp": {"graceful-restart": {"graceful-restart": True}}},
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")
    step("Verify on R2 that R1 advertises GR capabilities as a restarting node")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Kill BGP on R1")

    kill_router_daemons(tgen, "r1", ["bgpd"])

    step(
        "Verify that R1 keeps the stale entries in FIB & R2 keeps stale entries in RIB & FIB"
    )

    for addr_type in ADDR_TYPES:
        protocol = "bgp"
        next_hop = next_hop_per_address_family(
            tgen, "r1", "r2", addr_type, NEXT_HOP_IP_2
        )
        input_topo = {"r2": topo["routers"]["r2"]}
        result = verify_rib(tgen, addr_type, "r1", input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        next_hop = next_hop_per_address_family(
            tgen, "r2", "r1", addr_type, NEXT_HOP_IP_1
        )
        input_topo = {"r1": topo["routers"]["r1"]}
        result = verify_bgp_rib(tgen, addr_type, "r2", input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r2", input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Bring up BGP on R1 and remove Peer-level GR config")

    start_router_daemons(tgen, "r1", ["bgpd"])

    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart": False}
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
                                        "r1-link1": {"graceful-restart": False}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    step("Verify on R2 that R1 advertises GR capabilities as a helper node")

    input_dict = {
        "r1": {"bgp": {"graceful-restart": {"graceful-restart-helper": True}}},
        "r2": {"bgp": {"graceful-restart": {"graceful-restart": True}}},
    }

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Kill BGPd on R2")

    kill_router_daemons(tgen, "r2", ["bgpd"])

    step(
        "Verify that R2 keeps the stale entries in FIB & R1 keeps stale entries in RIB & FIB"
    )

    for addr_type in ADDR_TYPES:
        protocol = "bgp"
        next_hop = next_hop_per_address_family(
            tgen, "r2", "r1", addr_type, NEXT_HOP_IP_1
        )
        input_topo = {"r1": topo["routers"]["r1"]}
        result = verify_rib(tgen, addr_type, "r2", input_topo, next_hop, protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Routes are still present \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        next_hop = next_hop_per_address_family(
            tgen, "r1", "r2", addr_type, NEXT_HOP_IP_2
        )
        input_topo = {"r2": topo["routers"]["r2"]}
        result = verify_bgp_rib(tgen, addr_type, "r1", input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_topo, next_hop, protocol)
        assert (
            result is True
        ), "Testcase {} : Failed \n Routes are still present \n Error {}".format(
            tc_name, result
        )

    step("Start BGP on R2")

    start_router_daemons(tgen, "r2", ["bgpd"])

    write_test_footer(tc_name)


def test_BGP_GR_TC_53_p1(request):
    """
    Test Objective : Default GR functional mode is Helper.
    Global Mode : None
    PerPeer Mode :  None
    GR Mode effective : GR Helper

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

    step("configure R2 as global restarting node")

    input_dict = {"r2": {"bgp": {"graceful-restart": {"graceful-restart": True}}}}

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r1", peer="r2")

    step(
        "Verify on R2 that R1 advertises GR capabilities as a helper node based on inherit"
    )

    input_dict = {
        "r1": {"bgp": {"graceful-restart": {"graceful-restart-helper": True}}},
        "r2": {"bgp": {"graceful-restart": {"graceful-restart": True}}},
    }

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Kill BGPd on R2")

    kill_router_daemons(tgen, "r2", ["bgpd"])

    step(
        "Verify that R2 keeps the stale entries in FIB & R1 keeps stale entries in RIB & FIB"
    )

    for addr_type in ADDR_TYPES:
        protocol = "bgp"
        next_hop = next_hop_per_address_family(
            tgen, "r2", "r1", addr_type, NEXT_HOP_IP_1
        )
        input_topo = {"r1": topo["routers"]["r1"]}
        result = verify_rib(tgen, addr_type, "r2", input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        next_hop = next_hop_per_address_family(
            tgen, "r1", "r2", addr_type, NEXT_HOP_IP_2
        )
        input_topo = {"r2": topo["routers"]["r2"]}
        result = verify_bgp_rib(tgen, addr_type, "r1", input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Start BGP on R2")

    start_router_daemons(tgen, "r2", ["bgpd"])

    write_test_footer(tc_name)


def test_BGP_GR_UTP_1_3_p0(request):
    """
    Test Objective : Helper BGP router R1, mark and unmark IPV4 routes
    as stale as the restarting router R2 come up within the restart time

    Test Objective : Helper BGP router R1, mark IPV4 routes as stale and
    deletes them as the restarting router R2 did-not come up within
    restart time.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Create route-map to prefer global next-hop
    input_dict = {
        "r1": {
            "route_maps": {
                "rmap_global": [
                    {"action": "permit", "set": {"ipv6": {"nexthop": "prefer-global"}}}
                ]
            }
        },
        "r2": {
            "route_maps": {
                "rmap_global": [
                    {"action": "permit", "set": {"ipv6": {"nexthop": "prefer-global"}}}
                ]
            }
        },
    }
    result = create_route_maps(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure neighbor for route map
    input_dict_1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_global",
                                                    "direction": "in",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_global",
                                                    "direction": "in",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

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
                                        "r1-link1": {"graceful-restart-helper": True}
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
                                        "r1-link1": {"graceful-restart-helper": True}
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
                "graceful-restart": {"timer": {"restart-time": GR_RESTART_TIMER}},
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
                },
            }
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r2", peer="r1")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r2", peer="r1"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        dut = "r1"
        peer = "r2"
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2, preferred_next_hop="global"
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, "bgp")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 2] : R2 goes for reload  ")

    kill_router_daemons(tgen, "r2", ["bgpd"])

    logger.info(
        "[Phase 3] : R2 is still down, restart time 120 sec."
        " So time verify the routes are present in BGP RIB"
        " and ZEBRA"
    )

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2, preferred_next_hop="global"
        )
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

    logger.info("[Phase 4] : sleep for {} sec".format(GR_RESTART_TIMER))
    sleep(GR_RESTART_TIMER)

    logger.info("[Phase 5] : Verify the routes from r2  ")

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        next_hop = NEXT_HOP_IP_2[addr_type]
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, expected=False)
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )
        logger.info(" Expected behavior: {}".format(result))

        # Verifying RIB routes
        result = verify_rib(
            tgen, addr_type, dut, input_topo, next_hop, "bgp", expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )
        logger.info(" Expected behavior: {}".format(result))

    logger.info("[Phase 5] : R2 is about to come up now  ")
    start_router_daemons(tgen, "r2", ["bgpd"])

    logger.info("[Phase 5] : R2 is UP Now !  ")

    for addr_type in ADDR_TYPES:
        # Verifying GR stats
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r2", peer="r1"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(tgen, topo, addr_type, input_dict, dut="r1", peer="r2")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2, preferred_next_hop="global"
        )
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_UTP_15_TC_9_p1(request):
    """
    Test Objective : Restart BGP router R1, detects it is connected to R2,
    which is a helper router. Verify the restart capability i.e. R bit
    are sent after R1 reloads and comes back.

    Test Objective : Verify that restarting nodes reset "F" bit while sending
    the BGP open messages after it's restarts, when BGP GR is **NOT** enabled.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Checking router status, starting if not running
    check_router_status(tgen)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    # reset_config_on_routers(tgen)

    # Create route-map to prefer global next-hop
    input_dict = {
        "r1": {
            "route_maps": {
                "rmap_global": [
                    {"action": "permit", "set": {"ipv6": {"nexthop": "prefer-global"}}}
                ]
            }
        },
        "r2": {
            "route_maps": {
                "rmap_global": [
                    {"action": "permit", "set": {"ipv6": {"nexthop": "prefer-global"}}}
                ]
            }
        },
    }
    result = create_route_maps(tgen, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Configure neighbor for route map
    input_dict_1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_global",
                                                    "direction": "in",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {
                                            "route_maps": [
                                                {
                                                    "name": "rmap_global",
                                                    "direction": "in",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    logger.info(
        "[Phase 1] : Test Setup " "[Helper Mode]R1-----R2[Restart Mode] initialized  "
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
                }
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
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
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
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2, preferred_next_hop="global"
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

    logger.info("[Phase 6] : R1 is about to come up now  ")
    start_router_daemons(tgen, "r1", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verifying GR stats
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

        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2, preferred_next_hop="global"
        )
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(tgen, topo, addr_type, input_dict, dut="r1", peer="r2")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_f_bit(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2", expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_UTP_35_p1(request):
    """
    Test Objective : Restart BGP router R1 connected to R2,
    which is a restart router.
    R1 should not send any GR capability in the open message,
    however it would process open message from R2 with GR -restart
    capability, but would not perform any BGP GR functionality.
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
        "[Phase 1] : Test Setup" " [Disable Mode]R1-----R2[Restart Mode] initialized  "
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
                                        "r1-link1": {"graceful-restart-disable": True}
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
                                        "r1-link1": {"graceful-restart-disable": True}
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

        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_TC_4_p0(request):
    """
     Test Objective : Verify that the restarting node sets "R" bit while sending the
     BGP open messages after the node restart, only if GR is enabled.
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
        "[Phase 1] : Test Setup" " [Restart Mode]R1-----R2[Helper Mode] initialized  "
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
                }
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
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
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

    logger.info("[Phase 2] : R2 goes for reload  ")

    kill_router_daemons(tgen, "r2", ["bgpd"])

    logger.info(
        "[Phase 3] : R2 is still down, restart time {} sec."
        "So time verify the routes are present in BGP RIB and ZEBRA ".format(
            GR_RESTART_TIMER
        )
    )

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_topo, next_hop, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )
        logger.info(" Expected behavior: {}".format(result))

        # Verifying RIB routes
        result = verify_rib(
            tgen, addr_type, dut, input_topo, next_hop, protocol, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )
        logger.info(" Expected behavior: {}".format(result))

    logger.info("[Phase 5] : R2 is about to come up now  ")
    start_router_daemons(tgen, "r2", ["bgpd"])

    logger.info("[Phase 4] : R2 is UP now, so time to collect GR stats  ")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(tgen, topo, addr_type, input_dict, dut="r1", peer="r2")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_TC_5_1_2_p1(request):
    """
     Test Objective : Verify if restarting node resets R bit in BGP open message
     during normal BGP session flaps as well, even when GR restarting mode is enabled.
     Here link flap happen due to interface UP/DOWN.

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
                }
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

    logger.info("[Phase 2] : Now flap the link running the BGP session  ")
    # Shutdown interface
    intf = "r2-r1-eth0"
    shutdown_bringup_interface(tgen, "r2", intf)

    # Bring up Interface
    shutdown_bringup_interface(tgen, dut, intf, ifaceaction=True)

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(tgen, topo, addr_type, input_dict, dut="r1", peer="r2")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 2] : Restart BGPd on router R2.  ")
    kill_router_daemons(tgen, "r2", ["bgpd"])

    start_router_daemons(tgen, "r2", ["bgpd"])

    logger.info("[Phase 4] : R2 is UP now, so time to collect GR stats  ")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(tgen, topo, addr_type, input_dict, dut="r1", peer="r2")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_TC_6_1_2_p1(request):
    """
    Test Objective : Verify if restarting node resets R bit in BGP
    open message during normal BGP session flaps when GR is disabled.
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
        "[Phase 1] : Test Setup" "[Restart Mode]R1-----R2[Helper Mode] initialized  "
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
                }
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
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
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

    logger.info("[Phase 1] : Changing mode" "[Disable Mode]R1-----R2[Helper Mode]")

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
                                        "r1-link1": {"graceful-restart-disable": True}
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
                                        "r1-link1": {"graceful-restart-disable": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r1")
        clear_bgp(tgen, addr_type, "r2")

    # Verify GR stats
    input_dict = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-disable": True}
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
                                        "r1-link1": {"graceful-restart-disable": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    }

    # here the verify_graceful_restart fro the neighbor would be
    # "NotReceived" as the latest GR config is not yet applied.
    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 2] : Now flap the link running the BGP session  ")
    # Shutdown interface
    intf = "r2-r1-eth0"
    shutdown_bringup_interface(tgen, "r2", intf)

    # Bring up Interface
    shutdown_bringup_interface(tgen, dut, intf, ifaceaction=True)

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(
            tgen, topo, addr_type, input_dict, dut="r2", peer="r1", expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("Restart BGPd on R2 ")
    kill_router_daemons(tgen, "r2", ["bgpd"])

    start_router_daemons(tgen, "r2", ["bgpd"])

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(
            tgen, topo, addr_type, input_dict, dut="r2", peer="r1", expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


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


def test_BGP_GR_TC_17_p1(request):
    """
      Test Objective : Verify that only GR helper routers keep the stale
       route entries, not any GR disabled router.
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

    logger.info("[Phase 1] : Test Setup [Disable]R1-----R2[Restart] initialized  ")

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "graceful-restart": {
                    "graceful-restart": True,
                    "preserve-fw-state": True,
                },
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-disable": True}
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
                                        "r1-link1": {"graceful-restart-disable": True}
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

    logger.info("[Phase 2] : R2 goes for reload  ")

    kill_router_daemons(tgen, "r2", ["bgpd"])

    logger.info(
        "[Phase 3] : R2 is still down, restart time 120 sec."
        " So time verify the routes are present in BGP RIB and ZEBRA  "
    )

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_topo, next_hop, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )
        logger.info(" Expected behavior: {}".format(result))

        # Verifying RIB routes
        result = verify_rib(
            tgen, addr_type, dut, input_topo, next_hop, protocol, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )
        logger.info(" Expected behavior: {}".format(result))

    logger.info("[Phase 5] : R2 is about to come up now  ")
    start_router_daemons(tgen, "r2", ["bgpd"])

    logger.info("[Phase 4] : R2 is UP now, so time to collect GR stats  ")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_r_bit(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2", expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_TC_19_p1(request):
    """
      Test Objective : Verify that GR helper routers keeps all the routes received
      from restarting node if both the routers are configured as GR restarting node.
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

    logger.info("[Phase 1] : Test Setup [Helper]R1-----R2[Restart] initialized  ")

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "graceful-restart": {
                    "graceful-restart": True,
                    "preserve-fw-state": True,
                },
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-helper": True}
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
                                        "r1-link1": {"graceful-restart-helper": True}
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

    logger.info(
        "[Phase 2] : R1's Gr state cahnge to Graceful"
        " Restart without resetting the session "
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
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    logger.info(
        "[Phase 3] : R2 is still down, restart time 120 sec."
        " So time verify the routes are present in BGP RIB and ZEBRA  "
    )

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_TC_20_p1(request):
    """
      Test Objective : Verify that GR helper routers delete all the routes
       received from a node if both the routers are configured as GR helper node.
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

    logger.info("[Phase 1] : Test Setup [Helper]R1-----R2[Helper] initialized  ")

    # Configure graceful-restart
    input_dict = {
        "r1": {
            "bgp": {
                "graceful-restart": {
                    "graceful-restart": True,
                    "preserve-fw-state": True,
                },
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-helper": True}
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
                                        "r1-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
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

    kill_router_daemons(tgen, "r2", ["bgpd"])

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_topo, next_hop, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )
        logger.info(" Expected behavior: {}".format(result))

        # Verifying RIB routes
        result = verify_rib(
            tgen, addr_type, dut, input_topo, next_hop, protocol, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )
        logger.info(" Expected behavior: {}".format(result))

    logger.info("[Phase 5] : R2 is about to come up now  ")

    start_router_daemons(tgen, "r2", ["bgpd"])

    logger.info("[Phase 4] : R2 is UP now, so time to collect GR stats  ")

    for addr_type in ADDR_TYPES:
        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_TC_31_1_p1(request):
    """
    After BGP neighborship is established and GR capability is exchanged,
    transition restarting router to disabled state and vice versa.
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
        "[Phase 1] : Test Setup" " [Helper Mode]R2-----R1[Restart Mode] initialized  "
    )

    # Configure graceful-restart
    input_dict = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
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
        protocol = "bgp"
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 2] : R1 Goes from Restart to Disable Mode  ")

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
                                        "r1-link1": {"graceful-restart-disable": True}
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
                                        "r1-link1": {"graceful-restart-disable": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r1")
        clear_bgp(tgen, addr_type, "r2")

    # Verify GR stats
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-disable": True}
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
                                        "r1-link1": {"graceful-restart-disable": True}
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
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 2] : R1 goes for reload  ")

    kill_router_daemons(tgen, "r1", ["bgpd"])

    logger.info(
        "[Phase 3] : R1 is still down, restart time 120 sec."
        " So time verify the routes are not present in BGP RIB and ZEBRA"
    )

    for addr_type in ADDR_TYPES:
        # Verifying RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_rib(
            tgen, addr_type, dut, input_topo, next_hop, protocol, expected=False
        )
        assert result is not True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 4] : R1 is about to come up now  ")
    start_router_daemons(tgen, "r1", ["bgpd"])

    logger.info("[Phase 5] : R1 is UP now, so time to collect GR stats  ")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_GR_TC_31_2_p1(request):
    """
    After BGP neighborship is established and GR capability is exchanged,
    transition restarting router to disabled state and vice versa.
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
        "[Phase 1] : Test Setup " "[Disable Mode]R1-----R2[Restart Mode] initialized  "
    )

    # Configure graceful-restart
    input_dict = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1-link1": {"graceful-restart-disable": True}
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
                                        "r1-link1": {"graceful-restart-disable": True}
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

    logger.info("[Phase 2] : R2 Goes from Disable to Restart Mode  ")

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
        }
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r1")
        clear_bgp(tgen, addr_type, "r2")

    # Verify GR stats
    input_dict = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r2-link1": {"graceful-restart-helper": True}
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
                                        "r2-link1": {"graceful-restart-helper": True}
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
        "r1": {
            "bgp": {
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
                }
            }
        },
    }

    # here the verify_graceful_restart fro the neighbor would be
    # "NotReceived" as the latest GR config is not yet applied.
    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 3] : R1 goes for reload  ")

    kill_router_daemons(tgen, "r1", ["bgpd"])

    logger.info(
        "[Phase 4] : R1 is still down, restart time 120 sec."
        " So time verify the routes are present in BGP RIB and ZEBRA  "
    )

    for addr_type in ADDR_TYPES:
        # Verifying RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    logger.info("[Phase 6] : R1 is about to come up now  ")
    start_router_daemons(tgen, "r1", ["bgpd"])

    logger.info("[Phase 4] : R1 is UP now, so time to collect GR stats ")

    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r1", peer="r2"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying BGP RIB routes
        next_hop = next_hop_per_address_family(
            tgen, dut, peer, addr_type, NEXT_HOP_IP_2
        )
        input_topo = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_topo, next_hop)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        # Verifying RIB routes
        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop, protocol)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
