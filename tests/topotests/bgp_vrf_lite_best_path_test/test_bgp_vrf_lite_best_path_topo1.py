#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test BGP VRF Lite:

1. Verify BGP best path selection algorithm works fine when
routes are imported from ISR to default vrf and vice versa.
"""

import os
import sys
import time
import pytest
import platform

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topotest import version_cmp

from lib.common_config import (
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    step,
    create_route_maps,
    create_prefix_lists,
    check_router_status,
    get_frr_ipv6_linklocal,
    shutdown_bringup_interface,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
    verify_best_path_as_per_bgp_attribute,
)
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
NETWORK1_1 = {"ipv4": "11.11.11.1/32", "ipv6": "11:11::1/128"}
NETWORK1_2 = {"ipv4": "11.11.11.11/32", "ipv6": "11:11::11/128"}
NETWORK1_3 = {"ipv4": "10.10.10.10/32", "ipv6": "10:10::10/128"}
NETWORK1_4 = {"ipv4": "10.10.10.100/32", "ipv6": "10:10::100/128"}

NETWORK2_1 = {"ipv4": "22.22.22.2/32", "ipv6": "22:22::2/128"}
NETWORK2_2 = {"ipv4": "22.22.22.22/32", "ipv6": "22:22::22/128"}
NETWORK2_3 = {"ipv4": "20.20.20.20/32", "ipv6": "20:20::20/128"}
NETWORK2_4 = {"ipv4": "20.20.20.200/32", "ipv6": "20:20::200/128"}

NETWORK3_1 = {"ipv4": "30.30.30.3/32", "ipv6": "30:30::3/128"}
NETWORK3_2 = {"ipv4": "30.30.30.30/32", "ipv6": "30:30::30/128"}
NETWORK3_3 = {"ipv4": "50.50.50.5/32", "ipv6": "50:50::5/128"}
NETWORK3_4 = {"ipv4": "50.50.50.50/32", "ipv6": "50:50::50/128"}

NETWORK4_1 = {"ipv4": "40.40.40.4/32", "ipv6": "40:40::4/128"}
NETWORK4_2 = {"ipv4": "40.40.40.40/32", "ipv6": "40:40::40/128"}
NETWORK4_3 = {"ipv4": "50.50.50.5/32", "ipv6": "50:50::5/128"}
NETWORK4_4 = {"ipv4": "50.50.50.50/32", "ipv6": "50:50::50/128"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}
LOOPBACK_1 = {
    "ipv4": "10.0.0.7/24",
    "ipv6": "fd00:0:0:1::7/64",
    "ipv4_mask": "255.255.255.0",
    "ipv6_mask": None,
}
LOOPBACK_2 = {
    "ipv4": "10.0.0.16/24",
    "ipv6": "fd00:0:0:3::5/64",
    "ipv4_mask": "255.255.255.0",
    "ipv6_mask": None,
}
PREFERRED_NEXT_HOP = "global"


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_vrf_lite_best_path_topo1.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Run these tests for kernel version 4.19 or above
    if version_cmp(platform.release(), "4.19") < 0:
        error_msg = (
            "BGP vrf dynamic route leak tests will not run "
            '(have kernel "{}", but it requires >= 4.19)'.format(platform.release())
        )
        pytest.skip(error_msg)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global BGP_CONVERGENCE
    global ADDR_TYPES
    ADDR_TYPES = check_address_types()

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#   Testcases
#
#####################################################


def disable_route_map_to_prefer_global_next_hop(tgen, topo):
    """
    This API is to remove prefer global route-map applied on neighbors

    Parameter:
    ----------
    * `tgen` : Topogen object
    * `topo` : Input JSON data

    Returns:
    --------
    True/errormsg

    """

    logger.info("Remove prefer-global rmap applied on neighbors")
    input_dict = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "ISR",
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
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "100",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "100",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r4": {
                                        "dest_link": {
                                            "r1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
        "r2": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "ISR",
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
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "100",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "100",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r4": {
                                        "dest_link": {
                                            "r2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
        "r3": {
            "bgp": [
                {
                    "local_as": "300",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r3-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "300",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
        "r4": {
            "bgp": [
                {
                    "local_as": "400",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r1": {
                                        "dest_link": {
                                            "r4-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
                {
                    "local_as": "400",
                    "address_family": {
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r4-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_global",
                                                        "direction": "in",
                                                        "delete": True,
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase :Failed \n Error: {}".format(result)

    return True


def test_bgp_best_path_with_dynamic_import_p0(request):
    """
    1.5.6. Verify BGP best path selection algorithm works fine when
    routes are imported from ISR to default vrf and vice versa.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    build_config_from_json(tgen, topo)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    for addr_type in ADDR_TYPES:
        step(
            "Redistribute configured static routes into BGP process" " on R1/R2 and R3"
        )

        input_dict_1 = {}
        DUT = ["r1", "r2", "r3", "r4"]
        VRFS = ["ISR", "ISR", "default", "default"]
        AS_NUM = [100, 100, 300, 400]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_1.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Import from default vrf into vrf ISR on R1 and R2 as below")

        input_dict_vrf = {}
        DUT = ["r1", "r2"]
        VRFS = ["ISR", "ISR"]
        AS_NUM = [100, 100]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_vrf.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {"unicast": {"import": {"vrf": "default"}}}
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_vrf)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_default = {}
        DUT = ["r1", "r2"]
        VRFS = ["default", "default"]
        AS_NUM = [100, 100]

        for dut, vrf, as_num in zip(DUT, VRFS, AS_NUM):
            temp = {dut: {"bgp": []}}
            input_dict_default.update(temp)

            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        addr_type: {"unicast": {"import": {"vrf": "ISR"}}}
                    },
                }
            )

        result = create_router_bgp(tgen, topo, input_dict_default)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify ECMP/Next-hop/Imported routes Vs Locally originated "
        "routes/eBGP routes vs iBGP routes --already covered in almost"
        " all tests"
    )

    for addr_type in ADDR_TYPES:
        step("Verify Pre-emption")

        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_3[addr_type]]}]}
        }

        intf_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"]["interface"]
        intf_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"]["interface"]

        if addr_type == "ipv6" and "link_local" in PREFERRED_NEXT_HOP:
            nh_r3_r1 = get_frr_ipv6_linklocal(tgen, "r3", intf=intf_r3_r1)
            nh_r4_r1 = get_frr_ipv6_linklocal(tgen, "r4", intf=intf_r4_r1)
        else:
            nh_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]
            nh_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]

        result = verify_bgp_rib(
            tgen, addr_type, "r1", input_routes_r3, next_hop=[nh_r4_r1]
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Shutdown interface connected to r1 from r4:")
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, False)

    for addr_type in ADDR_TYPES:
        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_3[addr_type]]}]}
        }

        intf_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"]["interface"]
        intf_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"]["interface"]

        if addr_type == "ipv6" and "link_local" in PREFERRED_NEXT_HOP:
            nh_r3_r1 = get_frr_ipv6_linklocal(tgen, "r3", intf=intf_r3_r1)
            nh_r4_r1 = get_frr_ipv6_linklocal(tgen, "r4", intf=intf_r4_r1)
        else:
            nh_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]
            nh_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]

        step("Verify next-hop is changed")
        result = verify_bgp_rib(
            tgen, addr_type, "r1", input_routes_r3, next_hop=[nh_r3_r1]
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Bringup interface connected to r1 from r4:")
    shutdown_bringup_interface(tgen, "r4", intf_r4_r1, True)

    for addr_type in ADDR_TYPES:
        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_3[addr_type]]}]}
        }

        intf_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"]["interface"]
        intf_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"]["interface"]

        if addr_type == "ipv6" and "link_local" in PREFERRED_NEXT_HOP:
            nh_r3_r1 = get_frr_ipv6_linklocal(tgen, "r3", intf=intf_r3_r1)
            nh_r4_r1 = get_frr_ipv6_linklocal(tgen, "r4", intf=intf_r4_r1)
        else:
            nh_r3_r1 = topo["routers"]["r3"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]
            nh_r4_r1 = topo["routers"]["r4"]["links"]["r1-link1"][addr_type].split("/")[
                0
            ]

        step("Verify next-hop is not chnaged aftr shutdown:")
        result = verify_bgp_rib(
            tgen, addr_type, "r1", input_routes_r3, next_hop=[nh_r3_r1]
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Active-Standby scenario(as-path prepend and Local pref)")

    for addr_type in ADDR_TYPES:
        step("Create prefix-list")

        input_dict_pf = {
            "r1": {
                "prefix_lists": {
                    addr_type: {
                        "pf_ls_{}".format(addr_type): [
                            {
                                "seqid": 10,
                                "network": NETWORK3_4[addr_type],
                                "action": "permit",
                            }
                        ]
                    }
                }
            }
        }
        result = create_prefix_lists(tgen, input_dict_pf)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Create route-map to match prefix-list and set localpref 500")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_PATH1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 10,
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_{}".format(addr_type)
                                }
                            },
                            "set": {"locPrf": 500},
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Create route-map to match prefix-list and set localpref 600")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_PATH2_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 20,
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_{}".format(addr_type)
                                }
                            },
                            "set": {"locPrf": 600},
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_rma = {
            "r1": {
                "bgp": [
                    {
                        "local_as": "100",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r3": {
                                            "dest_link": {
                                                "r1-link1": {
                                                    "route_maps": [
                                                        {
                                                            "name": "rmap_PATH1_{}".format(
                                                                addr_type
                                                            ),
                                                            "direction": "in",
                                                        }
                                                    ]
                                                }
                                            }
                                        },
                                        "r4": {
                                            "dest_link": {
                                                "r1-link1": {
                                                    "route_maps": [
                                                        {
                                                            "name": "rmap_PATH2_{}".format(
                                                                addr_type
                                                            ),
                                                            "direction": "in",
                                                        }
                                                    ]
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_rma)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    dut = "r1"
    attribute = "locPrf"

    for addr_type in ADDR_TYPES:
        step("Verify bestpath is installed as per highest localpref")

        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_4[addr_type]]}]}
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_routes_r3, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Create route-map to match prefix-list and set localpref 700")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_PATH1_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 10,
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_{}".format(addr_type)
                                }
                            },
                            "set": {"locPrf": 700},
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Verify bestpath is changed as per highest localpref")

        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_4[addr_type]]}]}
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_routes_r3, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        step("Create route-map to match prefix-list and set as-path prepend")

        input_dict_rm = {
            "r1": {
                "route_maps": {
                    "rmap_PATH2_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 20,
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_ls_{}".format(addr_type)
                                }
                            },
                            "set": {
                                "localpref": 700,
                                "path": {"as_num": "111", "as_action": "prepend"},
                            },
                        }
                    ]
                }
            }
        }

        result = create_route_maps(tgen, input_dict_rm)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    attribute = "path"

    for addr_type in ADDR_TYPES:
        step("Verify bestpath is changed as per shortest as-path")

        input_routes_r3 = {
            "r3": {"static_routes": [{"network": [NETWORK3_4[addr_type]]}]}
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, dut, input_routes_r3, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
