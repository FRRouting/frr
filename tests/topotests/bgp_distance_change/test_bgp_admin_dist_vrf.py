#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

import sys
import time
import pytest
import inspect
import os

"""Following tests are covered to test bgp admin distance functionality.
TC_5:
        Verify bgp admin distance functionality when static route is configured
        same as bgp learnt route in user vrf.

TC_6:   Verify bgp admin distance functionality with ECMP in user vrf.

TC_7:
        Verify bgp admin distance functionality when routes are
        imported between VRFs.
"""

#################################
# TOPOLOGY
#################################
"""

                    +-------+
         +--------- |  R2   |
         |          +-------+
         |iBGP           |
     +-------+           |
     |  R1   |           |iBGP
     +-------+           |
         |               |
         |    iBGP   +-------+   eBGP   +-------+
         +---------- |  R3   |----------|  R4   |
                     +-------+          +-------+
                        |
                        |eBGP
                        |
                    +-------+
                    |  R5   |
                    +-------+


"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

# Required to instantiate the topology builder class.
from lib.common_config import (
    start_topology,
    write_test_header,
    step,
    write_test_footer,
    create_static_routes,
    verify_rib,
    check_address_types,
    reset_config_on_routers,
    check_router_status,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_best_path_as_per_admin_distance,
)

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger

# Global variables
topo = None
bgp_convergence = False
pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

NETWORK = {
    "ipv4": [
        "192.168.20.1/32",
        "192.168.20.2/32",
        "192.168.21.1/32",
        "192.168.21.2/32",
        "192.168.22.1/32",
        "192.168.22.2/32",
    ],
    "ipv6": [
        "fc07:50::1/128",
        "fc07:50::2/128",
        "fc07:150::1/128",
        "fc07:150::2/128",
        "fc07:1::1/128",
        "fc07:1::2/128",
    ],
}
ADDR_TYPES = check_address_types()


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global topo

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_admin_dist_vrf.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Checking BGP convergence
    global bgp_convergence
    global ADDR_TYPES

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence(tgen, topo)
    assert bgp_convergence is True, "setup_module :Failed \n Error:" " {}".format(
        bgp_convergence
    )
    logger.info("Running setup_module() done")


def teardown_module(mod):
    """teardown_module.

    Teardown the pytest environment.
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


#####################################################
# Tests starting
#####################################################


def test_bgp_admin_distance_ebgp_vrf_p0():
    """
    TC: 5
    Verify bgp admin distance functionality when static route is
    configured same as ebgp learnt route
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip("skipping test case because of BGP Convergence failure at setup")

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)

    step("Configure bgp admin distance 200 with CLI in dut.")

    input_dict_1 = {
        "r3": {
            "bgp": [
                {
                    "vrf": "RED",
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200}
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200}
                            }
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp routes have admin distance of 200 in dut.")
    # Verifying best path
    dut = "r3"
    attribute = "admin_distance"

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][0],
                        "admin_distance": 200,
                        "vrf": "RED",
                    },
                    {
                        "network": NETWORK["ipv4"][1],
                        "admin_distance": 200,
                        "vrf": "RED",
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"][0],
                        "admin_distance": 200,
                        "vrf": "RED",
                    },
                    {
                        "network": NETWORK["ipv6"][1],
                        "admin_distance": 200,
                        "vrf": "RED",
                    },
                ]
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute, vrf="RED"
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Modify the admin distance value to 150.")

    input_dict_1 = {
        "r3": {
            "bgp": [
                {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {"ebgp": 150, "ibgp": 150, "local": 150}
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {"ebgp": 150, "ibgp": 150, "local": 150}
                            }
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp routes have admin distance of 150 in dut.")
    # Verifying best path
    dut = "r3"
    attribute = "admin_distance"

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][0],
                        "admin_distance": 150,
                        "vrf": "RED",
                    },
                    {
                        "network": NETWORK["ipv4"][1],
                        "admin_distance": 150,
                        "vrf": "RED",
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"][0],
                        "admin_distance": 150,
                        "vrf": "RED",
                    },
                    {
                        "network": NETWORK["ipv6"][1],
                        "admin_distance": 150,
                        "vrf": "RED",
                    },
                ]
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute, vrf="RED"
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Un configure the admin distance value on DUT")

    input_dict_1 = {
        "r3": {
            "bgp": [
                {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {
                                    "ebgp": 150,
                                    "ibgp": 150,
                                    "local": 150,
                                    "delete": True,
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {
                                    "ebgp": 150,
                                    "ibgp": 150,
                                    "local": 150,
                                    "delete": True,
                                }
                            }
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp routes have default admin distance in dut.")
    # Verifying best path
    dut = "r3"
    attribute = "admin_distance"

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {"network": NETWORK["ipv4"][0], "admin_distance": 20, "vrf": "RED"},
                    {"network": NETWORK["ipv4"][1], "admin_distance": 20, "vrf": "RED"},
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {"network": NETWORK["ipv6"][0], "admin_distance": 20, "vrf": "RED"},
                    {"network": NETWORK["ipv6"][1], "admin_distance": 20, "vrf": "RED"},
                ]
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute, vrf="RED"
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure static route  Without any admin distance")

    for addr_type in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": "Null0", "vrf": "RED"}
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that zebra selects static route.")
    protocol = "static"
    # dual stack changes
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": "Null0", "vrf": "RED"}
                ]
            }
        }
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Configure static route  with admin distance of 253")
    for addr_type in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "admin_distance": 253,
                        "vrf": "RED",
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that zebra selects bgp route.")
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "admin_distance": 253,
                        "vrf": "RED",
                    }
                ]
            }
        }
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Configure admin distance of 254 in bgp for route  .")

    input_dict_1 = {
        "r3": {
            "bgp": [
                {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {"ebgp": 254, "ibgp": 254, "local": 254}
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {"ebgp": 254, "ibgp": 254, "local": 254}
                            }
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that zebra selects static route.")
    protocol = "static"
    # dual stack changes
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "admin_distance": 253,
                        "vrf": "RED",
                    }
                ]
            }
        }

        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Configure admin distance of 255 in bgp for route  in vrf red")

    input_dict_1 = {
        "r3": {
            "bgp": [
                {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {"ebgp": 255, "ibgp": 255, "local": 255}
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {"ebgp": 255, "ibgp": 255, "local": 255}
                            }
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify that zebra selects static route.")
    protocol = "static"
    # dual stack changes
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "admin_distance": 253,
                        "vrf": "RED",
                    }
                ]
            }
        }

        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step("Delete the static route.")
    for addr_type in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "admin_distance": 253,
                        "delete": True,
                        "vrf": "RED",
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that zebra selects bgp route.")
    protocol = "bgp"
    # dual stack changes
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    write_test_footer(tc_name)


def test_bgp_admin_distance_ebgp_with_imported_rtes_vrf_p0():
    """
    TC: 5
    Verify bgp admin distance functionality when static route is configured
    same as bgp learnt route in user vrf.
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip("skipping test case because of BGP Convergence failure at setup")

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configure base config as per the topology")
    reset_config_on_routers(tgen)
    step("Configure bgp admin distance 200 with CLI in dut.")
    step(" Import route from vrf to default vrf")
    input_dict_1 = {
        "r3": {
            "bgp": [
                {
                    "vrf": "RED",
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200}
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200}
                            }
                        },
                    },
                },
                {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200},
                                "import": {"vrf": "RED"},
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200},
                                "import": {
                                    "vrf": "RED",
                                },
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify bgp routes have admin distance of 200 in dut.")
    # Verifying best path
    dut = "r3"
    attribute = "admin_distance"

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][0],
                        "admin_distance": 200,
                        "vrf": "RED",
                    },
                    {
                        "network": NETWORK["ipv4"][1],
                        "admin_distance": 200,
                        "vrf": "RED",
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"][0],
                        "admin_distance": 200,
                        "vrf": "RED",
                    },
                    {
                        "network": NETWORK["ipv6"][1],
                        "admin_distance": 200,
                        "vrf": "RED",
                    },
                ]
            }
        },
    }

    for addr_type in ADDR_TYPES:
        result = verify_best_path_as_per_admin_distance(
            tgen, addr_type, dut, input_dict[addr_type], attribute, vrf="RED"
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that routes are getting imported without any issues and "
        "routes are calculated and installed in rib."
    )

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][0],
                        "admin_distance": 200,
                    },
                    {
                        "network": NETWORK["ipv4"][1],
                        "admin_distance": 200,
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"][0],
                        "admin_distance": 200,
                    },
                    {
                        "network": NETWORK["ipv6"][1],
                        "admin_distance": 200,
                    },
                ]
            }
        },
    }

    step("Verify that zebra selects bgp route.")
    protocol = "bgp"
    # dual stack changes
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result4 is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result4
        )

    step(" Un configure import route vrf red inside default vrf.")
    input_dict_1 = {
        "r3": {
            "bgp": [
                {
                    "vrf": "RED",
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200}
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200}
                            }
                        },
                    },
                },
                {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200},
                                "import": {"vrf": "RED", "delete": True},
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "distance": {"ebgp": 200, "ibgp": 200, "local": 200},
                                "import": {"vrf": "RED", "delete": True},
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict = {
        "ipv4": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv4"][0],
                        "admin_distance": 200,
                    },
                    {
                        "network": NETWORK["ipv4"][1],
                        "admin_distance": 200,
                    },
                ]
            }
        },
        "ipv6": {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK["ipv6"][0],
                        "admin_distance": 200,
                    },
                    {
                        "network": NETWORK["ipv6"][1],
                        "admin_distance": 200,
                    },
                ]
            }
        },
    }

    step("Verify that route withdrawal happens properly.")
    protocol = "bgp"
    # dual stack changes
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict[addr_type],
            protocol=protocol,
            expected=False,
        )
        assert (
            result4 is not True
        ), "Testcase {} : Failed \n Route is not withdrawn. Error: {}".format(
            tc_name, result4
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
