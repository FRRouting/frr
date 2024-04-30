#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test EVPN-Type5 functionality:

1. RD verification (manual/auto).
2. RT verification(manual)
3. In an active/standby EVPN implementation, if active DCG goes down,
        secondary takes over.
4. EVPN routes are advertised/withdrawn, based on VNFs
        advertising/withdrawing IP prefixes.
5. Route-map operations for EVPN address family.
6. BGP attributes for EVPN address-family.
"""

import os
import sys
import json
import time
import pytest
import platform
from copy import deepcopy


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topotest import version_cmp
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    create_route_maps,
    create_static_routes,
    create_vrf_cfg,
    check_router_status,
    apply_raw_config,
    configure_vxlan,
    configure_brctl,
    create_interface_in_kernel,
    kill_router_daemons,
    start_router_daemons,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_best_path_as_per_bgp_attribute,
    verify_attributes_for_evpn_routes,
    verify_evpn_routes,
)
from lib.topojson import build_topo_from_json, build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
NETWORK1_1 = {"ipv4": "10.1.1.1/32", "ipv6": "10::1/128"}
NETWORK1_2 = {"ipv4": "40.1.1.1/32", "ipv6": "40::1/128"}
NETWORK1_3 = {"ipv4": "40.1.1.2/32", "ipv6": "40::2/128"}
NETWORK1_4 = {"ipv4": "40.1.1.3/32", "ipv6": "40::3/128"}
NETWORK2_1 = {"ipv4": "20.1.1.1/32", "ipv6": "20::1/128"}
NETWORK3_1 = {"ipv4": "30.1.1.1/32", "ipv6": "30::1/128"}
NETWORK4_1 = {"ipv4": "100.1.1.1/32 ", "ipv6": "100::100/128"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}
VNI_1 = 75100
VNI_2 = 75200
VNI_3 = 75300
MAC_1 = "00:80:48:ba:d1:00"
MAC_2 = "00:80:48:ba:d1:01"
MAC_3 = "00:80:48:ba:d1:02"
BRCTL_1 = "br100"
BRCTL_2 = "br200"
BRCTL_3 = "br300"
VXLAN_1 = "vxlan75100"
VXLAN_2 = "vxlan75200"
VXLAN_3 = "vxlan75300"
BRIDGE_INTF1 = "120.0.0.1"
BRIDGE_INTF2 = "120.0.0.2"
BRIDGE_INTF3 = "120.0.0.3"

VXLAN = {
    "vxlan_name": [VXLAN_1, VXLAN_2, VXLAN_3],
    "vxlan_id": [75100, 75200, 75300],
    "dstport": 4789,
    "local_addr": {"e1": BRIDGE_INTF1, "d1": BRIDGE_INTF2, "d2": BRIDGE_INTF3},
    "learning": "no",
}
BRCTL = {
    "brctl_name": [BRCTL_1, BRCTL_2, BRCTL_3],
    "addvxlan": [VXLAN_1, VXLAN_2, VXLAN_3],
    "vrf": ["RED", "BLUE", "GREEN"],
    "stp": [0, 0, 0],
}


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
    json_file = "{}/evpn_type5_topo1.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    topo = tgen.json_topo

    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    if version_cmp(platform.release(), "4.19") < 0:
        error_msg = (
            'EVPN tests will not run (have kernel "{}", '
            "but it requires >= 4.19)".format(platform.release())
        )
        pytest.skip(error_msg)

    global BGP_CONVERGENCE
    global ADDR_TYPES
    ADDR_TYPES = check_address_types()

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Pre-requisite config for testsuite")
    prerequisite_config_for_test_suite(tgen)

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


def prerequisite_config_for_test_suite(tgen):
    """
    API to do prerequisite config for testsuite

    parameters:
    -----------
    * `tgen`: topogen object
    """

    step("Configure vxlan, bridge interface")
    for dut in ["e1", "d1", "d2"]:
        step("[DUT: ]Configure vxlan")
        vxlan_input = {
            dut: {
                "vxlan": [
                    {
                        "vxlan_name": VXLAN["vxlan_name"],
                        "vxlan_id": VXLAN["vxlan_id"],
                        "dstport": VXLAN["dstport"],
                        "local_addr": VXLAN["local_addr"][dut],
                        "learning": VXLAN["learning"],
                    }
                ]
            }
        }

        result = configure_vxlan(tgen, vxlan_input)
        assert result is True, "Testcase :Failed \n Error: {}".format(result)

        step("Configure bridge interface")
        brctl_input = {
            dut: {
                "brctl": [
                    {
                        "brctl_name": BRCTL["brctl_name"],
                        "addvxlan": BRCTL["addvxlan"],
                        "vrf": BRCTL["vrf"],
                        "stp": BRCTL["stp"],
                    }
                ]
            }
        }
        result = configure_brctl(tgen, topo, brctl_input)
        assert result is True, "Testcase :Failed \n Error: {}".format(result)

    step("Configure default routes")
    add_default_routes(tgen)


def add_default_routes(tgen):
    """
    API to do prerequisite config for testsuite

    parameters:
    -----------
    * `tgen`: topogen object
    """

    step("Add default routes..")

    default_routes = {
        "e1": {
            "static_routes": [
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["d1"]),
                    "next_hop": topo["routers"]["d1"]["links"]["e1-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["d2"]),
                    "next_hop": topo["routers"]["d2"]["links"]["e1-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
            ]
        },
        "d1": {
            "static_routes": [
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["e1"]),
                    "next_hop": topo["routers"]["e1"]["links"]["d1-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["d2"]),
                    "next_hop": topo["routers"]["e1"]["links"]["d1-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
            ]
        },
        "d2": {
            "static_routes": [
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["d1"]),
                    "next_hop": topo["routers"]["e1"]["links"]["d2-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
                {
                    "network": "{}/32".format(VXLAN["local_addr"]["e1"]),
                    "next_hop": topo["routers"]["e1"]["links"]["d2-link1"][
                        "ipv4"
                    ].split("/")[0],
                },
            ]
        },
    }

    result = create_static_routes(tgen, default_routes)
    assert result is True, "Testcase :Failed \n Error: {}".format(result)


def test_RD_verification_manual_and_auto_p0(request):
    """
    RD verification (manual/auto).
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Advertise prefixes from VNF routers R1 and R2 in associated "
        "VRFs for both address-family."
    )
    step(
        "Advertise vrf RED's routes in EVPN address family from Edge-1 router"
        ", without manual configuration of RD."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK3_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify on DCG-1 and DCG-2:")
    step("EVPN route for 10.1.1.1/32 has auto-assigned RD value.")

    for dut in ["d1", "d2"]:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_attributes_for_evpn_routes(
            tgen, topo, dut, input_routes, rd="auto", rd_peer="e1"
        )
        assert result is True, "Testcase {} on {} :Failed \n Error: {}".format(
            tc_name, dut, result
        )

    step(
        "Configure RD for vrf RED manually as 50.50.50.50:50 and "
        "advertise vrf RED's routes in EVPN address family from "
        "Edge-1 router."
    )

    input_dict_rd = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {"l2vpn": {"evpn": {"rd": "50.50.50.50:50"}}},
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rd)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("EVPN route for vrf RED has RD value as 50.50.50.50:50")
    for dut in ["d1", "d2"]:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_attributes_for_evpn_routes(
            tgen, topo, dut, input_routes, rd="50.50.50.50:50"
        )
        assert result is True, "Testcase {} on {} :Failed \n Error: {}".format(
            tc_name, dut, result
        )

    step(
        "Configure RD for vrf RED manually as 100.100.100.100:100 and "
        "advertise vrf RED's routes in EVPN address family from Edge-1 "
        "router."
    )
    input_dict_rd = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "l2vpn": {"evpn": {"rd": "100.100.100.100:100"}}
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rd)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "EVPN route for vrf RED is overridden with RD value as " "100.100.100.100:100."
    )

    for dut in ["d1", "d2"]:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_attributes_for_evpn_routes(
            tgen, topo, dut, input_routes, rd="100.100.100.100:100"
        )
        assert result is True, "Testcase {} on {} :Failed \n Error: {}".format(
            tc_name, dut, result
        )

    step(
        "Configure RD for vrf BLUE manually same as vrf RED "
        "(100.100.100.100:100) and advertise vrf RED and BLUE's routes "
        "in EVPN address family from Edge-1 router."
    )

    input_dict_rd = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "BLUE",
                    "address_family": {
                        "l2vpn": {"evpn": {"rd": "100.100.100.100:100"}}
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rd)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Delete manually configured RD and advertise vrf RED's routes "
        "in EVPN address family from Edge-1 router."
    )

    input_dict_rd = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "l2vpn": {"evpn": {"no rd": "100.100.100.100:100"}}
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rd)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Configure same RD value for vrf GREEN, as auto generated RD "
        "value for vrf RED on Edge-1 router."
    )

    input_dict_rd = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "GREEN",
                    "address_family": {"l2vpn": {"evpn": {"rd": "10.0.0.33:1"}}},
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rd)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Delete auto configured RD value from vrf RED in EVPN " "address family.")

    input_dict_rd = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "GREEN",
                    "address_family": {"l2vpn": {"evpn": {"no rd": "10.0.0.33:1"}}},
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rd)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure RD value as 100.100.100:100")

    input_dict_rd = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "GREEN",
                    "address_family": {"l2vpn": {"evpn": {"rd": "100.100.100:100"}}},
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rd)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_RT_verification_manual_p0(request):
    """
    RT verification(manual)
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Advertise prefixes from VNF routers R1 and R2 in associated "
        "VRFs for both address-family."
    )
    step("Advertise VRF routes as in EVPN address family from Edge-1 " "router.")

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK3_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure RT for vrf RED manually as export 100:100 "
        "and advertise vrf RED's routes in EVPN address family"
        " from Edge-1 router."
    )

    input_dict_rt = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"neighbor": {"r1": {"dest_link": {"e1": {}}}}}
                        },
                        "ipv6": {
                            "unicast": {"neighbor": {"r1": {"dest_link": {"e1": {}}}}}
                        },
                        "l2vpn": {
                            "evpn": {"route-target": {"export": [{"value": "100:100"}]}}
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rt)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on dcg-1 and dcg-2, EVPN route for 10.1.1.1/32"
        " and 10::1/128 have RT value as 100:100."
    )

    for dut in ["d1", "d2"]:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_attributes_for_evpn_routes(
            tgen, topo, dut, input_routes, rt="100:100"
        )
        assert result is True, "Testcase {} on {} :Failed \n Error: {}".format(
            tc_name, dut, result
        )

    step(
        "Configure RT for vrf RED manually as export 500:500 and"
        " advertise vrf RED's routes in EVPN address family from"
        " e1 router."
    )

    input_dict_rt = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {"route-target": {"export": [{"value": "500:500"}]}}
                        }
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rt)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on dcg-1 and dcg-2, EVPN route for 10.1.1.1/32"
        " and 10::1/128 have RT value as 500:500."
    )

    for dut in ["d1", "d2"]:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_attributes_for_evpn_routes(
            tgen, topo, dut, input_routes, rt=["100:100", "500:500"]
        )
        assert result is True, "Testcase {} on {} :Failed \n Error: {}".format(
            tc_name, dut, result
        )

    step(
        "Import RT value 100:100 and 500:500 in vrf BLUE manually on"
        " peer router DCG-1 and DCG-2."
    )

    input_dict_rt = {
        "d1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "BLUE",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "route-target": {
                                    "import": [
                                        {"value": "100:100"},
                                        {"value": "500:500"},
                                    ]
                                }
                            }
                        }
                    },
                }
            ]
        },
        "d2": {
            "bgp": [
                {
                    "local_as": "200",
                    "vrf": "BLUE",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "route-target": {
                                    "import": [
                                        {"value": "100:100"},
                                        {"value": "500:500"},
                                    ]
                                }
                            }
                        }
                    },
                }
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_rt)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "EVPN route for 10.1.1.1/32 and 10::1 should be installed "
        "in vrf BLUE on DCG-1 and DCG-2 and further advertised to "
        "VNF router."
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r1": {
                "static_routes": [{"network": [NETWORK1_1[addr_type]], "vrf": "BLUE"}]
            }
        }
        result = verify_rib(tgen, addr_type, "d1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step(
        "Delete import RT value 500:500 in vrf BLUE manually on "
        "peer router DCG-1 and DCG-2."
    )

    input_dict_rt = {
        "d1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "BLUE",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "route-target": {
                                    "import": [{"value": "500:500", "delete": True}]
                                }
                            }
                        }
                    },
                }
            ]
        },
        "d2": {
            "bgp": [
                {
                    "local_as": "200",
                    "vrf": "BLUE",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "route-target": {
                                    "import": [{"value": "500:500", "delete": True}]
                                }
                            }
                        }
                    },
                }
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_rt)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    for dut in ["d1", "d2"]:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_attributes_for_evpn_routes(
            tgen, topo, dut, input_routes, rt=["100:100", "500:500"]
        )
        assert result is True, "Testcase {} on {} :Failed \n Error: {}".format(
            tc_name, dut, result
        )

    step("Delete RT export value 100:100 for vrf RED on Edge-1")

    input_dict_rt = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "route-target": {
                                    "export": [{"value": "100:100", "delete": True}]
                                }
                            }
                        }
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rt)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "EVPN route for 10.1.1.1/32 and 10::1 should be withdrawn "
        "from vrf BLUE on DCG-1,DCG-2 and VNF router."
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r1": {
                "static_routes": [{"network": [NETWORK1_1[addr_type]], "vrf": "BLUE"}]
            }
        }
        result = verify_rib(tgen, addr_type, "d1", input_routes, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, "d1", result)
        )

        result = verify_rib(tgen, addr_type, "d2", input_routes, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, "d2", result)
        )

    step(
        "Configure RT value as 100:100000010000010000101010 to check "
        "the boundary value."
    )

    input_dict_rt = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "route-target": {
                                    "export": [
                                        {"value": "100:100000010000010000101010"}
                                    ]
                                }
                            }
                        }
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_rt)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "CLI error: RT value: 100:100000010000010000101010 should not " "be configured"
    )

    dut = "e1"
    input_routes = {key: topo["routers"][key] for key in ["r1"]}
    result = verify_attributes_for_evpn_routes(
        tgen, topo, dut, input_routes, rt="100:100000010000010000101010", expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: RT value out of boundary error in {} \n "
        "Found: {}".format(tc_name, dut, result)
    )

    write_test_footer(tc_name)


def test_active_standby_evpn_implementation_p1(request):
    """
    In an active/standby EVPN implementation, if active DCG goes down,
    secondary takes over.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Taken care in base config: Configure BGP neighborship for both "
        "address families(IPv4 & IPv6) between DCG-1/DCG-2 and VFN routers"
        "(R3 and R4)."
    )

    step(
        "BGP neighborships come up within defined VRFs. Please use below "
        "command: sh bgp vrf all summary"
    )

    result = verify_bgp_convergence(tgen, topo, "d1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_bgp_convergence(tgen, topo, "d2")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Advertise prefixes from VNF routers R3 and R4 in associated "
        "VRFs for both address-families."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Redistribute static in (IPv4 and IPv6) address-family "
        "on Edge-1 for all VRFs."
    )

    input_dict_2 = {}
    for dut in ["r3", "r4"]:
        temp = {dut: {"bgp": []}}
        input_dict_2.update(temp)

        if dut == "r3":
            VRFS = ["RED"]
            AS_NUM = [3]
        if dut == "r4":
            VRFS = ["BLUE", "GREEN"]
            AS_NUM = [4, 4]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Prefixes are received in respective VRFs on DCG-1/DCG-2.")

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = verify_rib(tgen, addr_type, "d1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Taken care in base config: Advertise VRF routes in EVPN "
        "address-family from DCG-1 and DCG-2 router."
    )

    step("Verify on Edge-1 that EVPN routes are installed via next-hop " "as DCG-2.")

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        if addr_type == "ipv4":
            result = verify_rib(
                tgen, addr_type, "e1", input_routes, next_hop=BRIDGE_INTF2
            )
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )
        else:
            result = verify_rib(tgen, addr_type, "e1", input_routes)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Configure 'next-hop self' on DCG-1 for peer Edge-1 in EVPN " "address-family."
    )

    input_dict_3 = {
        "d1": {
            "bgp": [
                {
                    "local_as": "100",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "neighbor": {
                                    "e1": {
                                        "ipv4": {"d1-link1": {"next_hop_self": True}}
                                    }
                                }
                            }
                        }
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    logger.info(
        "Creating route-map so ipv6 glpbal ip wpuld be preferred " "as next-hop"
    )

    step(
        "Verify on Edge-1 that EVPN routes are now preferred via "
        "next-hop as DCG-1(iBGP) due to shortest AS-Path."
    )

    for addr_type in ADDR_TYPES:

        logger.info("Verifying only ipv4 routes")
        if addr_type != "ipv4":
            continue

        input_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        next_hop = topo["routers"]["d1"]["links"]["e1-link1"]["ipv4"].split("/")[0]

        result = verify_rib(tgen, addr_type, "e1", input_routes, next_hop=next_hop)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_evpn_routes_from_VNFs_p1(request):
    """
    EVPN routes are advertised/withdrawn, based on VNFs
    advertising/withdrawing IP prefixes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Advertise prefixes from VNF routers R1 and R2 in associated "
        "VRFs for both address-family."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK3_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Taken care in base config: Advertise VNFs'(R1 and R2) "
        "originated routes in EVPN address-family from Edge-1 to "
        "DCG-1 and DCG-2 routers."
    )
    step(
        "Taken care in base config: Advertise IPv4 and IPv6 routes "
        "from default vrf in EVPN address-family from Edge-1."
    )

    step(
        "Verify on DCG-2 that VNF routes are received in respective "
        "VRFs along with auto derived RD/RT values 'show bgp l2vpn evpn'"
    )
    for dut in ["d1", "d2"]:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_evpn_routes(tgen, topo, dut, input_routes)
        assert result is True, "Testcase {} on {} :Failed \n Error: {}".format(
            tc_name, dut, result
        )

        input_routes = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_evpn_routes(tgen, topo, dut, input_routes)
        assert result is True, "Testcase {} on {} :Failed \n Error: {}".format(
            tc_name, dut, result
        )

    step(
        "Verify on R3 and R4 that DCG-2 further advertises all EVPN "
        "routes to corresponding VRFs."
    )
    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_rib(tgen, addr_type, "r3", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_rib(tgen, addr_type, "r4", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that DCG-2 receives EVPN routes associated to default "
        "VRF and install in default IP routing table as well."
    )
    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r2"]}
        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Withdraw the IP prefixes from VFN(R1).")
    dut = "r1"
    input_dict_2 = {}
    static_routes = topo["routers"][dut]["static_routes"]
    for static_route in static_routes:
        static_route["delete"] = True
        temp = {dut: {"static_routes": [static_route]}}
        input_dict_2.update(temp)

        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that DCG-2 removes EVPN routes corresponding to vrf RED and "
        "send an withdraw to VNF(R3) as well."
    )
    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_rib(tgen, addr_type, "d2", input_routes, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, "d2", result)
        )

    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_rib(tgen, addr_type, "r3", input_routes, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, "r3", result)
        )

    step("Re-advertise IP prefixes from VFN(R1).")
    step(
        "Advertise prefixes from VNF routers R1 and R2 in associated "
        "VRFs for both address-family."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK3_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that DCG-2 receives EVPN routes corresponding to vrf RED "
        "again and send an update to VNF(R3) as well."
    )
    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_routes = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_rib(tgen, addr_type, "r3", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Delete vrf BLUE from router Edge-1")
    input_dict_3 = {"e1": {"vrfs": [{"name": "BLUE", "id": "2", "delete": True}]}}

    result = create_vrf_cfg(tgen, input_dict_3)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that DCG-2 removes EVPN routes corresponding to "
        "vrf BLUE and send an withdraw to VNF(R4) as well."
    )
    for addr_type in ADDR_TYPES:
        input_routes = {
            "r2": {"static_routes": [{"network": NETWORK2_1[addr_type], "vrf": "BLUE"}]}
        }

        result = verify_rib(tgen, addr_type, "d2", input_routes, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, "d2", result)
        )

        result = verify_rib(tgen, addr_type, "r4", input_routes, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes should not be present in {} RIB \n "
            "Found: {}".format(tc_name, "r4", result)
        )

    step("Add vrf BLUE on router Edge-1 again.")
    interface = topo["routers"]["e1"]["links"]["r2-link1"]["interface"]
    input_dict_3 = {
        "e1": {
            "links": {
                "r2-link1": {
                    "interface": interface,
                    "ipv4": "auto",
                    "ipv6": "auto",
                    "vrf": "BLUE",
                }
            },
            "vrfs": [{"name": "BLUE", "id": "2"}],
        }
    }
    result = create_vrf_cfg(tgen, input_dict_3)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    logger.info(
        "After deleting VRFs ipv6 addresses wil be deleted "
        "from kernel Adding back ipv6 addresses"
    )
    dut = "e1"
    vrfs = ["BLUE"]

    for vrf in vrfs:
        for c_link, c_data in topo["routers"][dut]["links"].items():
            if "vrf" in c_data:
                if c_data["vrf"] != vrf:
                    continue

                intf_name = c_data["interface"]
                intf_ipv6 = c_data["ipv6"]

                create_interface_in_kernel(
                    tgen, dut, intf_name, intf_ipv6, vrf, create=False
                )

    result = verify_bgp_convergence(tgen, topo, dut)
    assert result is True, "Failed to converge on {}".format(dut)

    step(
        "Verify that DCG-2 receives EVPN routes corresponding to "
        "vrf BLUE again and send an update to VNF(R4) as well."
    )
    for addr_type in ADDR_TYPES:
        input_routes = {
            "r2": {"static_routes": [{"network": NETWORK2_1[addr_type], "vrf": "BLUE"}]}
        }

        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r4", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Withdraw IPv6 address-family in EVPN advertisements for " "VRF GREEN")
    addr_type = "ipv6"
    input_dict_4 = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "GREEN",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "advertise": {addr_type: {"unicast": {"delete": True}}}
                            }
                        }
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that EVPN routes (IPv6)associated with vrf GREEN are "
        "withdrawn from DCG-2 and VNF R4."
    )
    input_routes = {
        "r2": {"static_routes": [{"network": NETWORK3_1[addr_type], "vrf": "GREEN"}]}
    }

    result = verify_rib(tgen, addr_type, "d2", input_routes, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} RIB \n "
        "Found: {}".format(tc_name, "d2", result)
    )

    result = verify_rib(tgen, addr_type, "r4", input_routes, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} RIB \n "
        "Found: {}".format(tc_name, "r4", result)
    )

    step("Advertise IPv6 address-family in EVPN advertisements " "for VRF GREEN.")
    addr_type = "ipv6"
    input_dict_4 = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "GREEN",
                    "address_family": {
                        "l2vpn": {"evpn": {"advertise": {addr_type: {"unicast": {}}}}}
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r2": {
                "static_routes": [{"network": NETWORK3_1[addr_type], "vrf": "GREEN"}]
            }
        }

        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r4", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


@pytest.mark.parametrize(
    "attribute", [{"route-type": "prefix"}, {"vni": VNI_1}, {"rt": "300:300"}]
)
def test_route_map_operations_for_evpn_address_family_p1(request, attribute):
    """
    Route-map operations for EVPN address family.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    step(
        "Advertise prefixes from VNF routers R1 and R2 in associated "
        "VRFs for both address-family."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK3_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Advertise VRF routes in EVPN address family from Edge-1 router."
        " Configure a route-map on e1 to filter EVPN routes based on"
        " below keywords: route-type: prefix"
    )

    for key, value in attribute.items():
        if key == "rt":
            logger.info("Creating extcommunity using raw_config")
            raw_config = {
                "d2": {
                    "raw_config": [
                        "bgp extcommunity-list standard ECOMM300 permit {} {}".format(
                            key, value
                        )
                    ]
                }
            }
            result = apply_raw_config(tgen, raw_config)
            assert result is True, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )

            input_dict_1 = {
                "e1": {
                    "route_maps": {
                        "rmap_route_type": [
                            {"action": "permit", "set": {"extcommunity": {key: value}}}
                        ]
                    }
                },
                "d2": {
                    "route_maps": {
                        "rmap_route_type": [
                            {"action": "permit", "match": {"extcommunity": "ECOMM300"}}
                        ]
                    }
                },
            }

        else:
            input_dict_1 = {
                "e1": {
                    "route_maps": {
                        "rmap_route_type": [
                            {"action": "permit", "match": {"evpn": {key: value}}}
                        ]
                    }
                },
                "d2": {
                    "route_maps": {
                        "rmap_route_type": [
                            {"action": "permit", "match": {"evpn": {key: value}}}
                        ]
                    }
                },
            }
        result = create_route_maps(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    input_dict_2 = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "neighbor": {
                                    "d2": {
                                        "ipv4": {
                                            "e1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_route_type",
                                                        "direction": "out",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            ]
        },
        "d2": {
            "bgp": [
                {
                    "local_as": "200",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "neighbor": {
                                    "e1": {
                                        "ipv4": {
                                            "d2-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_route_type",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on router DCG-2 that EVPN routes corresponding to all "
        "VRFs are received. As all EVPN routes are type-5 only."
    )

    input_routes = {key: topo["routers"][key] for key in ["r1"]}
    result = verify_evpn_routes(tgen, topo, "d2", input_routes)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    input_routes = {key: topo["routers"][key] for key in ["r2"]}
    result = verify_evpn_routes(tgen, topo, "d2", input_routes)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_evpn_address_family_with_graceful_restart_p0(request):
    """
    Verify Graceful-restart function for EVPN address-family.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Redistribute static in (IPv4 and IPv6) address-family "
        "on Edge-1 for all VRFs."
    )

    input_dict_2 = {}
    for dut in ["r3", "r4"]:
        temp = {dut: {"bgp": []}}
        input_dict_2.update(temp)

        if dut == "r3":
            VRFS = ["RED"]
            AS_NUM = [3]
        if dut == "r4":
            VRFS = ["BLUE", "GREEN"]
            AS_NUM = [4, 4]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on router Edge-1 that EVPN routes corresponding to "
        "all VRFs are received from both routers DCG-1 and DCG-2"
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = verify_rib(tgen, addr_type, "e1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure DCG-2 as GR restarting node for EVPN session between"
        " DCG-2 and EDGE-1, following by a session reset using 'clear bgp *'"
        " command."
    )

    input_dict_gr = {
        "d2": {
            "bgp": [
                {
                    "local_as": "200",
                    "graceful-restart": {
                        "graceful-restart": True,
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_gr)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that DCG-2 changes it's role to GR-restarting router "
        "and EDGE-1 becomes the GR-helper."
    )

    step("Kill BGPd daemon on DCG-2.")
    kill_router_daemons(tgen, "d2", ["bgpd"])

    step(
        "Verify that EDGE-1 keep stale entries for EVPN RT-5 routes "
        "received from DCG-2 before the restart."
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            }
        }
        result = verify_evpn_routes(tgen, topo, "e1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that DCG-2 keeps BGP routes in Zebra until BGPd "
        "comes up or end of 'rib-stale-time'"
    )

    step("Start BGPd daemon on DCG-2.")
    start_router_daemons(tgen, "d2", ["bgpd"])

    step("Verify that EDGE-1 removed all the stale entries.")
    for addr_type in ADDR_TYPES:
        input_routes = {
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            }
        }
        result = verify_evpn_routes(tgen, topo, "e1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that DCG-2 refresh zebra with EVPN routes. "
        "(no significance of 'rib-stale-time'"
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            }
        }
        result = verify_rib(tgen, addr_type, "d2", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


@pytest.mark.parametrize("attribute", ["locPrf", "weight", "path"])
def test_bgp_attributes_for_evpn_address_family_p1(request, attribute):
    """
    BGP attributes for EVPN address-family.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    check_router_status(tgen)
    reset_config_on_routers(tgen)
    add_default_routes(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Advertise prefixes from VNF routers R1 and R2 in associated "
        "VRFs for both address-family."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK2_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK3_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    topo_local = deepcopy(topo)

    logger.info("Modifying topology b/w e1 and d1 from iBGP to eBGP")
    step("Delete BGP config for vrf RED.")

    if attribute == "locPrf":
        input_dict_vni = {
            "d1": {
                "vrfs": [
                    {"name": "RED", "no_vni": VNI_1},
                    {"name": "BLUE", "no_vni": VNI_2},
                    {"name": "GREEN", "no_vni": VNI_3},
                ]
            }
        }
        result = create_vrf_cfg(tgen, topo, input_dict=input_dict_vni)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_2 = {}
        for dut in ["d1"]:
            temp = {dut: {"bgp": []}}
            input_dict_2.update(temp)

            INDEX = [0, 1, 2, 3]
            VRFS = ["RED", "BLUE", "GREEN", None]
            AS_NUM = [100, 100, 100, 100]

            for index, vrf, as_num in zip(INDEX, VRFS, AS_NUM):
                topo_local["routers"][dut]["bgp"][index]["local_as"] = 200
                if vrf:
                    temp[dut]["bgp"].append(
                        {"local_as": as_num, "vrf": vrf, "delete": True}
                    )
                else:
                    temp[dut]["bgp"].append({"local_as": as_num, "delete": True})

        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} on d1 :Failed \n Error: {}".format(
            tc_name, result
        )

        result = create_router_bgp(tgen, topo_local["routers"])
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Advertise VRF routes in EVPN address-family from DCG-1 " "and DCG-2 routers.")

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Redistribute static in (IPv4 and IPv6) address-family "
        "on Edge-1 for all VRFs."
    )

    input_dict_2 = {}
    for dut in ["r3", "r4"]:
        temp = {dut: {"bgp": []}}
        input_dict_2.update(temp)

        if dut == "r3":
            VRFS = ["RED"]
            AS_NUM = [3]
        if dut == "r4":
            VRFS = ["BLUE", "GREEN"]
            AS_NUM = [4, 4]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on router Edge-1 that EVPN routes corresponding to "
        "all VRFs are received from both routers DCG-1 and DCG-2"
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = verify_rib(tgen, addr_type, "e1", input_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure a route-map on Edge-1 to modify below BGP attributes "
        "for EVPN address-family:"
    )

    if attribute == "path":
        input_dict_1 = {
            "e1": {
                "route_maps": {
                    "rmap_d1": [
                        {
                            "action": "permit",
                            "set": {
                                attribute: {
                                    "as_num": "123 231 321",
                                    "as_action": "prepend",
                                }
                            },
                        }
                    ],
                    "rmap_d2": [
                        {
                            "action": "permit",
                            "set": {
                                attribute: {"as_num": "121", "as_action": "prepend"}
                            },
                        }
                    ],
                }
            }
        }
    else:
        input_dict_1 = {
            "e1": {
                "route_maps": {
                    "rmap_d1": [{"action": "permit", "set": {attribute: 120}}],
                    "rmap_d2": [{"action": "permit", "set": {attribute: 150}}],
                }
            }
        }
    result = create_route_maps(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_2 = {
        "e1": {
            "bgp": [
                {
                    "local_as": "100",
                    "address_family": {
                        "l2vpn": {
                            "evpn": {
                                "neighbor": {
                                    "d1": {
                                        "ipv4": {
                                            "e1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_d1",
                                                        "direction": "in",
                                                    }
                                                ]
                                            }
                                        }
                                    },
                                    "d2": {
                                        "ipv4": {
                                            "e1-link1": {
                                                "route_maps": [
                                                    {
                                                        "name": "rmap_d2",
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

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify on router Edge-1 that EVPN routes are preferred via"
        " DCG-1 or DCG-2 based on best path selection criteria "
        "(according to the configured BGP attribute values in route-map)."
    )

    for addr_type in ADDR_TYPES:
        input_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK1_2[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    }
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": NETWORK1_3[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE",
                    },
                    {
                        "network": NETWORK1_4[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "GREEN",
                    },
                ]
            },
        }

        result = verify_best_path_as_per_bgp_attribute(
            tgen, addr_type, "e1", input_routes, attribute
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
