#!/usr/bin/python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test bgp recursive route and ebgp
multi-hop functionality:

1.  Verify that BGP routes are installed in iBGP peer, only when there
    is a recursive route for next-hop reachability.
2.  Verify that any BGP prefix received with next hop as self-ip is
    not installed in BGP RIB or FIB table.
3.  Verify password authentication for eBGP and iBGP peers.
4.  Verify that for a BGP prefix next-hop information doesn't change
    when same prefix is received from another peer via recursive lookup.
5.  Verify that BGP path attributes are present in CLI outputs and
    JSON format, even if set to default.
6.  Verifying the BGP peering between loopback and physical link's IP
    of 2 peer routers.
7.  Verify that BGP Active/Standby/Pre-emption/ECMP.
"""

import os
import sys
import time
import pytest
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    apply_raw_config,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    check_address_types,
    step,
    create_route_maps,
    create_interface_in_kernel,
    shutdown_bringup_interface,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
    verify_bgp_convergence_from_running_config,
    modify_as_number,
    verify_bgp_attributes,
    clear_bgp,
)
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


# Global variables
BGP_CONVERGENCE = False
KEEP_ALIVE_TIMER = 2
HOLD_DOWN_TIMER = 6
ADDR_TYPES = check_address_types()
NETWORK = {
    "ipv4": ["100.1.1.1/32", "100.1.1.2/32"],
    "ipv6": ["100::1/128", "100::2/128"],
}

RECUR_NEXT_HOP = {
    "N1": {"ipv4": "20.20.20.20/24", "ipv6": "20:20::20:20/120"},
    "N2": {"ipv4": "30.30.30.30/24", "ipv6": "30:30::30:30/120"},
    "N3": {"ipv4": "40.40.40.40/24", "ipv6": "40:40::40:40/120"},
}

CHANGED_NEXT_HOP = {
    "4thOctate": {"ipv4": "10.0.1.250/24", "ipv6": "fd00:0:0:1::100/64"},
    "3rdOctate": {"ipv4": "10.0.10.2/24", "ipv6": "fd00:0:0:10::2/64"},
}

Loopabck_IP = {
    "Lo_R1": {"ipv4": "1.1.1.1/32", "ipv6": "1:1::1:1/128"},
    "Lo_R4": {"ipv4": "4.4.4.4/32", "ipv6": "4:4::4:4/128"},
}


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
    json_file = "{}/bgp_recursive_route_ebgp_multi_hop.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global BGP_CONVERGENCE
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error : {}".format(
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
#   Tests starting
#
#####################################################


def test_recursive_routes_iBGP_peer_p1(request):
    """
    Verify that BGP routes are installed in iBGP peer, only
    when there is a recursive route for next-hop reachability.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Initial config :Configure BGP neighborship between R1 and R3.")
    reset_config_on_routers(tgen)

    dut = "r1"
    protocol = "static"

    step(
        "Configure static routes on R1 pointing next-hop as connected"
        "link between R1 & R3's IP"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": topo["routers"]["r3"]["links"]["r1"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_4)

        step(
            "Verify on router R1 that these static routes are "
            "installed in RIB+FIB of R1"
        )
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Redistribute these static routes in BGP on router R1")
    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_2)

    step(
        "Verify on router R1 that these static routes are installed"
        "in RIB table as well"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": topo["routers"]["r3"]["links"]["r1"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }
        result = verify_bgp_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0],
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    step(
        "Configure a static routes for next hop IP on R2 via multiple"
        "recursive static routes"
    )
    dut = "r2"
    create_interface_in_kernel(
        tgen, dut, "lo10", "40.40.40.50", netmask="255.255.255.0", create=True
    )
    create_interface_in_kernel(
        tgen, dut, "lo10", "40:40::40:50", netmask="120", create=True
    )
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
            "r2": {
                "static_routes": [
                    {
                        "network": topo["routers"]["r3"]["links"]["r1"][addr_type],
                        "next_hop": RECUR_NEXT_HOP["N1"][addr_type].split("/")[0],
                    },
                    {
                        "network": RECUR_NEXT_HOP["N1"][addr_type],
                        "next_hop": RECUR_NEXT_HOP["N2"][addr_type].split("/")[0],
                    },
                    {
                        "network": RECUR_NEXT_HOP["N2"][addr_type],
                        "next_hop": RECUR_NEXT_HOP["N3"][addr_type].split("/")[0],
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_3)
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

        step("verify if redistributed routes are now installed in FIB of R2")
        result = verify_rib(
            tgen,
            addr_type,
            "r2",
            input_dict_4,
            next_hop=topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0],
            protocol="bgp",
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    step("Delete 1 route from static recursive for the next-hop IP")
    dut = "r2"
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
            "r2": {
                "static_routes": [
                    {
                        "network": RECUR_NEXT_HOP["N1"][addr_type],
                        "next_hop": RECUR_NEXT_HOP["N2"][addr_type].split("/")[0],
                        "delete": True,
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_3)
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

        step("Verify that redistributed routes are withdrawn from FIB of R2")
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0],
            protocol="bgp",
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Routes are still present \n Error: {}".format(
            tc_name, result
        )

    step("Reconfigure the same static route on R2 again")
    dut = "r2"
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
            "r2": {
                "static_routes": [
                    {
                        "network": RECUR_NEXT_HOP["N1"][addr_type],
                        "next_hop": RECUR_NEXT_HOP["N2"][addr_type].split("/")[0],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_3)
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

        step("Verify that redistributed routes are again installed" "in FIB of R2")
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0],
            protocol="bgp",
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    step("Configure static route with changed next-hop from same subnet")
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": topo["routers"]["r3"]["links"]["r1"][
                            addr_type
                        ].split("/")[0],
                        "delete": True,
                    },
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": CHANGED_NEXT_HOP["4thOctate"][addr_type].split("/")[
                            0
                        ],
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_dict_4, protocol="static")
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

        step(
            "Verify that redistributed routes are not withdrawn as changed"
            "next-hop IP, belongs to the same subnet"
        )
        result = verify_rib(tgen, addr_type, "r2", input_dict_4, protocol="bgp")
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Configure static route with changed next-hop from different subnet")
    dut = "r1"
    create_interface_in_kernel(
        tgen, dut, "lo10", "10.0.10.10", netmask="255.255.255.0", create=True
    )
    create_interface_in_kernel(
        tgen, dut, "lo10", "fd00:0:0:10::104", netmask="64", create=True
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": CHANGED_NEXT_HOP["4thOctate"][addr_type].split("/")[
                            0
                        ],
                        "delete": True,
                    },
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": CHANGED_NEXT_HOP["3rdOctate"][addr_type].split("/")[
                            0
                        ],
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_dict_4, protocol="static")
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

        step(
            "Verify that redistributed routes are withdrawn as changed "
            "next-hop IP, belongs to different subnet"
        )
        result = verify_rib(
            tgen, addr_type, "r2", input_dict_4, protocol="bgp", expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Routes are still present \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_next_hop_as_self_ip_p1(request):
    """
    Verify that any BGP prefix received with next hop as
    self-ip is not installed in BGP RIB or FIB table.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Initial config :Configure BGP neighborship between R1 and R3.")
    reset_config_on_routers(tgen)

    step(
        "Configure static routes on R1 with a next-hop IP belonging"
        "to the same subnet of R2's link IP."
    )
    dut = "r1"
    create_interface_in_kernel(
        tgen,
        dut,
        "lo10",
        topo["routers"]["r4"]["links"]["r2"]["ipv4"].split("/")[0],
        netmask="255.255.255.0",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        dut,
        "lo10",
        topo["routers"]["r4"]["links"]["r2"]["ipv6"].split("/")[0],
        netmask="64",
        create=True,
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": topo["routers"]["r2"]["links"]["r4"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_4)

        step("Verify that static routes are installed in RIB and FIB of R1")
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
            protocol="static",
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Redistribute static routes into BGP on R1")
    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_2)

    step(
        "Verify that R2 denies the prefixes received in update message,"
        "as next-hop IP belongs to connected interface"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": topo["routers"]["r2"]["links"]["r4"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }
        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            input_dict_4,
            next_hop=topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Routes are still present \n Error: {}".format(
            tc_name, result
        )

    step("Shut interface on R2 that has IP from the subnet as BGP next-hop")
    intf_r2_r4 = topo["routers"]["r2"]["links"]["r4"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r4)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r2")
    step(
        "Verify that redistributed routes now appear only in BGP table,"
        "as next-hop IP is no more active on R2"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": topo["routers"]["r2"]["links"]["r4"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }
        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            input_dict_4,
            next_hop=topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    step("No shutdown interface on R2 which was shut in previous step")
    intf_r2_r4 = topo["routers"]["r2"]["links"]["r4"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r4, ifaceaction=True)

    step(
        "Verify that R2 dosn't install prefixes RIB to FIB as next-hop"
        "interface is up now"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": topo["routers"]["r2"]["links"]["r4"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }
        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r2",
            input_dict_4,
            next_hop=topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )
        result = verify_rib(
            tgen,
            addr_type,
            "r2",
            input_dict_4,
            next_hop=topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Routes are still present \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_next_hop_with_recursive_lookup_p1(request):
    """
    Verify that for a BGP prefix next-hop information doesn't change
    when same prefix is received from another peer via recursive lookup.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Initial config :Configure BGP neighborship between R1 and R3.")
    reset_config_on_routers(tgen)

    step("Verify that BGP peering comes up.")

    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Do redistribute connected on router R3.")
    input_dict_1 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {"redistribute": [{"redist_type": "connected"}]}
                    },
                    "ipv6": {
                        "unicast": {"redistribute": [{"redist_type": "connected"}]}
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify that R1 receives all connected")
    for addr_type in ADDR_TYPES:
        routes = {
            "ipv4": ["1.0.3.17/32", "10.0.1.0/24", "10.0.3.0/24"],
            "ipv6": ["2001:db8:f::3:17/128", "fd00:0:0:1::/64", "fd00:0:0:3::/64"],
        }
        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        result = verify_rib(tgen, addr_type, "r1", input_dict, protocol="bgp")
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step(
        "Configure a BGP neighborship between R1 and R4, directly via "
        "eBGP multi-hop."
    )
    r1_local_as = topo["routers"]["r1"]["bgp"]["local_as"]
    r1_r3_addr = topo["routers"]["r1"]["links"]["r3"]
    r4_local_as = topo["routers"]["r4"]["bgp"]["local_as"]
    r4_r3_addr = topo["routers"]["r4"]["links"]["r3"]
    ebgp_multi_hop = 3

    for addr_type in ADDR_TYPES:
        raw_config = {
            "r1": {
                "raw_config": [
                    "router bgp {}".format(r1_local_as),
                    "neighbor {} remote-as {}".format(
                        r4_r3_addr[addr_type].split("/")[0], r4_local_as
                    ),
                    "neighbor {} timers {} {}".format(
                        r4_r3_addr[addr_type].split("/")[0],
                        KEEP_ALIVE_TIMER,
                        HOLD_DOWN_TIMER,
                    ),
                    "neighbor {} ebgp-multihop {}".format(
                        r4_r3_addr[addr_type].split("/")[0], ebgp_multi_hop
                    ),
                ]
            },
            "r4": {
                "raw_config": [
                    "router bgp {}".format(r4_local_as),
                    "neighbor {} remote-as {}".format(
                        r1_r3_addr[addr_type].split("/")[0], r1_local_as
                    ),
                    "neighbor {} timers {} {}".format(
                        r1_r3_addr[addr_type].split("/")[0],
                        KEEP_ALIVE_TIMER,
                        HOLD_DOWN_TIMER,
                    ),
                    "neighbor {} ebgp-multihop {}".format(
                        r1_r3_addr[addr_type].split("/")[0], ebgp_multi_hop
                    ),
                ]
            },
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error : {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        if addr_type == "ipv4":
            raw_config = {
                "r1": {
                    "raw_config": [
                        "router bgp {}".format(r1_local_as),
                        "address-family {} unicast".format(addr_type),
                        "no neighbor {} activate".format(
                            r4_r3_addr["ipv6"].split("/")[0]
                        ),
                    ]
                },
                "r4": {
                    "raw_config": [
                        "router bgp {}".format(r4_local_as),
                        "address-family {} unicast".format(addr_type),
                        "no neighbor {} activate".format(
                            r1_r3_addr["ipv6"].split("/")[0]
                        ),
                    ]
                },
            }
        else:
            raw_config = {
                "r1": {
                    "raw_config": [
                        "router bgp {}".format(r1_local_as),
                        "address-family {} unicast".format(addr_type),
                        "neighbor {} activate".format(
                            r4_r3_addr[addr_type].split("/")[0]
                        ),
                    ]
                },
                "r4": {
                    "raw_config": [
                        "router bgp {}".format(r4_local_as),
                        "address-family {} unicast".format(addr_type),
                        "neighbor {} activate".format(
                            r1_r3_addr[addr_type].split("/")[0]
                        ),
                    ]
                },
            }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error : {}".format(tc_name, result)

    step("Verify that BGP session between R1 and R4 comes up" "(recursively via R3).")
    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Do redistribute connected on router R4.")
    input_dict_1 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {"redistribute": [{"redist_type": "connected"}]}
                    },
                    "ipv6": {
                        "unicast": {"redistribute": [{"redist_type": "connected"}]}
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step(
        "Verify that R1 now receives BGP prefix of link r3-r4 via 2 "
        "next-hops R3 and R4. however do not install with NHT R4 in FIB."
    )
    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_rib(
            tgen, addr_type, "r1", input_dict, protocol="bgp", next_hop=next_hop
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Clear bgp sessions from R1 using 'clear ip bgp *'")
    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r1")

    step(
        "Verify that prefix of link r3-r4 is again learned via 2 "
        "next-hops (from R3 and R4 directly)"
    )
    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_rib(
            tgen, addr_type, "r1", input_dict, protocol="bgp", next_hop=next_hop
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Remove redistribution from router R3.")
    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": "300",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "connected", "delete": True}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "connected", "delete": True}
                            ]
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step(
        "Verify that peering between R1-R4 goes down and prefix "
        "of link r3-r4, with NHT R4 is withdrawn."
    )

    logger.info("Sleeping for holddowntimer: {}".format(HOLD_DOWN_TIMER))
    sleep(HOLD_DOWN_TIMER + 1)

    result = verify_bgp_convergence_from_running_config(tgen, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n" "BGP is converged \n Error : {}".format(
        tc_name, result
    )
    logger.info("Expected behaviour: {}".format(result))

    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_rib(
            tgen, addr_type, "r1", input_dict, protocol="bgp", next_hop=next_hop
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Re-apply redistribution on R3.")

    input_dict_1 = {
        "r3": {
            "bgp": {
                "local_as": "300",
                "address_family": {
                    "ipv4": {
                        "unicast": {"redistribute": [{"redist_type": "connected"}]}
                    },
                    "ipv6": {
                        "unicast": {"redistribute": [{"redist_type": "connected"}]}
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step(
        "Verify that peering between R1-R4 goes down and prefix "
        "of link r3-r4 with NHT R4 is withdrawn."
    )

    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_rib(
            tgen, addr_type, "r1", input_dict, protocol="bgp", next_hop=next_hop
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Remove redistribution from router R4.")

    input_dict_1 = {
        "r4": {
            "bgp": {
                "local_as": "400",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "connected", "delete": True}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "connected", "delete": True}
                            ]
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step(
        "Verify that peering between R1-R4 doesn't go down but prefix "
        "of link r3-r4 with NHT R4 is withdrawn."
    )

    logger.info("Sleeping for holddowntimer: {}".format(HOLD_DOWN_TIMER))
    sleep(HOLD_DOWN_TIMER + 1)

    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r4"]["links"]["r3"][addr_type].split("/")[0]

        result = verify_rib(
            tgen,
            addr_type,
            "r1",
            input_dict,
            protocol="bgp",
            next_hop=next_hop,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Route is still present \n Error : {}".format(
            tc_name, result
        )

    step("Re-apply redistribution on R4.")

    input_dict_1 = {
        "r4": {
            "bgp": {
                "local_as": "400",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "connected", "delete": True}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "connected", "delete": True}
                            ]
                        }
                    },
                },
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify that prefix of link r3-r4 is re-learned via NHT R4.")

    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_rib(
            tgen, addr_type, "r1", input_dict, protocol="bgp", next_hop=next_hop
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Toggle the interface on R3.")

    intf_r3_r4 = topo["routers"]["r3"]["links"]["r4"]["interface"]
    shutdown_bringup_interface(tgen, "r3", intf_r3_r4)

    step(
        "Verify that peering between R1-R4 goes down and comes up when "
        "interface is toggled. Also prefix of link r3-r4(via both NHTs) is"
        " withdrawn and re-learned accordingly."
    )

    result = verify_bgp_convergence_from_running_config(tgen, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n" "BGP is converged \n Error : {}".format(
        tc_name, result
    )
    logger.info("Expected behaviour: {}".format(result))

    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r4"]["links"]["r3"][addr_type].split("/")[0]

        result = verify_rib(
            tgen,
            addr_type,
            "r1",
            input_dict,
            protocol="bgp",
            next_hop=next_hop,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Route is still present \n Error : {}".format(
            tc_name, result
        )

    shutdown_bringup_interface(tgen, "r3", intf_r3_r4, True)

    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_rib(
            tgen, addr_type, "r1", input_dict, protocol="bgp", next_hop=next_hop
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Toggle the interface on R4.")

    intf_r4_r3 = topo["routers"]["r4"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r4", intf_r4_r3)

    step(
        "Verify that peering between R1-R4 goes down and comes up when"
        "interface is toggled. Also prefix of link r3-r4(via R4)"
        " is withdrawn and re-learned accordingly."
    )

    result = verify_bgp_convergence_from_running_config(tgen, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n" "BGP is converged \n Error : {}".format(
        tc_name, result
    )
    logger.info("Expected behaviour: {}".format(result))

    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r4"]["links"]["r3"][addr_type].split("/")[0]

        result = verify_rib(
            tgen,
            addr_type,
            "r1",
            input_dict,
            protocol="bgp",
            next_hop=next_hop,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Route is still present \n Error : {}".format(
            tc_name, result
        )

    shutdown_bringup_interface(tgen, "r4", intf_r4_r3, True)

    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        routes = {"ipv4": ["10.0.3.0/24"], "ipv6": ["fd00:0:0:3::/64"]}

        input_dict = {"r1": {"static_routes": [{"network": routes[addr_type]}]}}
        next_hop = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]

        result = verify_rib(
            tgen, addr_type, "r1", input_dict, protocol="bgp", next_hop=next_hop
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_path_attributes_default_values_p1(request):
    """
    Verify that BGP path attributes are present in CLI
    outputs and JSON format, even if set to default.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Initial config: Configure BGP neighborship, between R1-R2 & R1-R3")
    reset_config_on_routers(tgen)

    step("Advertise a set of prefixes from R1 to both peers R2 and R3")
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [{"network": NETWORK[addr_type], "next_hop": "null0"}]
            }
        }
        result = create_static_routes(tgen, input_dict_1)

    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_2)

    step(
        "Verify that advertised prefixes are received on R4 and well"
        "known attributes are present in the CLI and JSON outputs with"
        "default values without any route-map config."
    )
    for addr_type in ADDR_TYPES:
        input_dict_3 = {"r4": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r4",
            input_dict_3,
            next_hop=[
                topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
                topo["routers"]["r3"]["links"]["r4"][addr_type].split("/")[0],
            ],
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r4": {
                "route_maps": {
                    "rmap_pf": [{"set": {"origin": "incomplete", "aspath": "300 100"}}]
                }
            }
        }

        result = verify_bgp_attributes(
            tgen,
            addr_type,
            "r4",
            NETWORK[addr_type],
            rmap_name="rmap_pf",
            input_dict=input_dict_4,
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    step(
        "Configure a route-map to set below attribute value as 500"
        "and apply on R4 in an inbound direction"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r4": {
                "route_maps": {
                    "Path_Attribue": [
                        {
                            "action": "permit",
                            "set": {
                                "path": {"as_num": 500, "as_action": "prepend"},
                                "locPrf": 500,
                                "origin": "egp",
                            },
                        }
                    ]
                }
            }
        }
    result = create_route_maps(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    input_dict_5 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [
                                                {
                                                    "name": "Path_Attribue",
                                                    "direction": "in",
                                                }
                                            ]
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
                                        "r4": {
                                            "route_maps": [
                                                {
                                                    "name": "Path_Attribue",
                                                    "direction": "in",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step(
        "Verify that once the route-map is applied all the attributes"
        "part of route-map, changes value to 500"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r4": {
                "route_maps": {
                    "rmap_pf": [
                        {
                            "set": {
                                "locPrf": 500,
                                "aspath": "500 300 100",
                                "origin": "EGP",
                            }
                        }
                    ]
                }
            }
        }
        result = verify_bgp_attributes(
            tgen,
            addr_type,
            "r4",
            NETWORK[addr_type],
            rmap_name="rmap_pf",
            input_dict=input_dict_4,
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    step("Remove the route-map from R4")
    input_dict_5 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r4": {
                                            "route_maps": [
                                                {
                                                    "name": "Path_Attribue",
                                                    "direction": "in",
                                                    "delete": True,
                                                }
                                            ]
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
                                        "r4": {
                                            "route_maps": [
                                                {
                                                    "name": "Path_Attribue",
                                                    "direction": "in",
                                                    "delete": True,
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step(
        "Verify on R4 that well known attributes are present in the CLI &"
        "JSON outputs again with default values without route-map config"
    )
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r4": {
                "route_maps": {
                    "rmap_pf": [{"set": {"aspath": "300 100", "origin": "incomplete"}}]
                }
            }
        }
        result = verify_bgp_attributes(
            tgen,
            addr_type,
            "r4",
            NETWORK[addr_type],
            rmap_name="rmap_pf",
            input_dict=input_dict_4,
            nexthop=None,
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_BGP_peering_bw_loopback_and_physical_p1(request):
    """
    Verifying the BGP peering between loopback and
    physical link's IP of 2 peer routers.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Initial config :Configure BGP neighborship between R1 and R3.")
    reset_config_on_routers(tgen)

    step("Configure a loopback interface on R1")
    dut = "r1"
    create_interface_in_kernel(
        tgen, dut, "lo10", "1.1.1.1", netmask="255.255.255.255", create=True
    )
    create_interface_in_kernel(
        tgen, dut, "lo10", "1:1::1:1", netmask="128", create=True
    )

    step("Configure BGP session between R1's loopbak & R3")
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r3": {
                "static_routes": [
                    {
                        "network": Loopabck_IP["Lo_R1"][addr_type],
                        "next_hop": topo["routers"]["r1"]["links"]["r3"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )
        result = verify_rib(
            tgen,
            addr_type,
            "r3",
            input_dict_1,
            protocol="static",
            next_hop=topo["routers"]["r1"]["links"]["r3"][addr_type].split("/")[0],
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        raw_config = {
            "r1": {
                "raw_config": [
                    "router bgp {}".format(topo["routers"]["r1"]["bgp"]["local_as"]),
                    "address-family {} unicast".format(addr_type),
                    "neighbor {} update-source lo10".format(
                        topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]
                    ),
                    "neighbor {} timers 1 3".format(
                        topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]
                    ),
                ]
            },
            "r3": {
                "raw_config": [
                    "router bgp {}".format(topo["routers"]["r3"]["bgp"]["local_as"]),
                    "address-family {} unicast".format(addr_type),
                    "no neighbor {} remote-as {}".format(
                        topo["routers"]["r1"]["links"]["r3"][addr_type].split("/")[0],
                        topo["routers"]["r1"]["bgp"]["local_as"],
                    ),
                    "neighbor {} remote-as {}".format(
                        Loopabck_IP["Lo_R1"][addr_type].split("/")[0],
                        topo["routers"]["r1"]["bgp"]["local_as"],
                    ),
                    "neighbor {} ebgp-multihop 3".format(
                        Loopabck_IP["Lo_R1"][addr_type].split("/")[0]
                    ),
                ]
            },
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error : {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        if addr_type == "ipv6":
            raw_config = {
                "r3": {
                    "raw_config": [
                        "router bgp {}".format(
                            topo["routers"]["r3"]["bgp"]["local_as"]
                        ),
                        "address-family {} unicast".format(addr_type),
                        "neighbor {} activate".format(
                            Loopabck_IP["Lo_R1"][addr_type].split("/")[0]
                        ),
                    ]
                }
            }
        else:
            raw_config = {
                "r3": {
                    "raw_config": [
                        "router bgp {}".format(
                            topo["routers"]["r3"]["bgp"]["local_as"]
                        ),
                        "address-family {} unicast".format(addr_type),
                        "no neighbor {} activate".format(
                            Loopabck_IP["Lo_R1"]["ipv6"].split("/")[0]
                        ),
                    ]
                }
            }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error : {}".format(tc_name, result)

    step("Verify that BGP neighborship between R1 and R3 comes up")
    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Remove ebgp-multihop command from R3")
    for addr_type in ADDR_TYPES:
        raw_config = {
            "r3": {
                "raw_config": [
                    "router bgp {}".format(topo["routers"]["r3"]["bgp"]["local_as"]),
                    "no neighbor {} ebgp-multihop 3".format(
                        Loopabck_IP["Lo_R1"][addr_type].split("/")[0]
                    ),
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error : {}".format(tc_name, result)

    step("Verify that once eBGP multi-hop is removed, BGP session goes down")
    result = verify_bgp_convergence_from_running_config(tgen, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "BGP is converged \n Error: {}".format(
        tc_name, result
    )

    step("Add ebgp-multihop command on R3 again")
    for addr_type in ADDR_TYPES:
        raw_config = {
            "r3": {
                "raw_config": [
                    "router bgp {}".format(topo["routers"]["r3"]["bgp"]["local_as"]),
                    "neighbor {} ebgp-multihop 3".format(
                        Loopabck_IP["Lo_R1"][addr_type].split("/")[0]
                    ),
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error : {}".format(tc_name, result)

    step("Verify that BGP neighborship between R1 and R3 comes up")
    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Remove update-source command from R1")
    for addr_type in ADDR_TYPES:
        raw_config = {
            "r1": {
                "raw_config": [
                    "router bgp {}".format(topo["routers"]["r1"]["bgp"]["local_as"]),
                    "no neighbor {} update-source lo10".format(
                        topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]
                    ),
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error : {}".format(tc_name, result)

    step("Verify that BGP session goes down, when update-source is removed")
    result = verify_bgp_convergence_from_running_config(tgen, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "BGP is converged \n Error: {}".format(
        tc_name, result
    )

    step("Add update-source command on R1 again")
    for addr_type in ADDR_TYPES:
        raw_config = {
            "r1": {
                "raw_config": [
                    "router bgp {}".format(topo["routers"]["r1"]["bgp"]["local_as"]),
                    "neighbor {} update-source lo10".format(
                        topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]
                    ),
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error : {}".format(tc_name, result)

    step("Verify that BGP neighborship between R1 and R3 comes up")
    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Remove static route from R3")
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r3": {
                "static_routes": [
                    {
                        "network": Loopabck_IP["Lo_R1"][addr_type],
                        "next_hop": topo["routers"]["r1"]["links"]["r3"][
                            addr_type
                        ].split("/")[0],
                        "delete": True,
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )
        result = verify_rib(
            tgen,
            addr_type,
            "r3",
            input_dict_1,
            protocol="static",
            next_hop=topo["routers"]["r1"]["links"]["r3"][addr_type].split("/")[0],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Routes are still present \n Error: {}".format(
            tc_name, result
        )

    sleep(3)
    step("Verify that BGP session goes down, when static route is removed")
    result = verify_bgp_convergence_from_running_config(tgen, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "BGP is converged \n Error: {}".format(
        tc_name, result
    )

    step("Add static route on R3 again")
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r3": {
                "static_routes": [
                    {
                        "network": Loopabck_IP["Lo_R1"][addr_type],
                        "next_hop": topo["routers"]["r1"]["links"]["r3"][
                            addr_type
                        ].split("/")[0],
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )
        result = verify_rib(
            tgen,
            addr_type,
            "r3",
            input_dict_1,
            protocol="static",
            next_hop=topo["routers"]["r1"]["links"]["r3"][addr_type].split("/")[0],
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Verify that BGP neighborship between R1 and R3 comes up")
    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Toggle physical interface on R1")
    intf_r1_r3 = topo["routers"]["r1"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r3)
    sleep(3)
    step("Verify that BGP neighborship between R1 and R3 goes down")
    result = verify_bgp_convergence_from_running_config(tgen, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "BGP is converged \n Error: {}".format(
        tc_name, result
    )

    intf_r1_r3 = topo["routers"]["r1"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r3, True)

    step("Verify that BGP neighborship between R1 and R3 comes up")
    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_BGP_active_standby_preemption_and_ecmp_p1(request):
    """
    Verify that BGP Active/Standby/Pre-emption/ECMP.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Initial config :Configure BGP neighborship between R1 and R3.")
    reset_config_on_routers(tgen)

    step("Change the AS number on R2 as 200")
    input_dict = {"r2": {"bgp": {"local_as": 200}}}
    result = modify_as_number(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify BGP converge after changing the AS number on R2")
    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Advertise a set of prefixes from R1 to both peers R2 & R3")
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r1": {
                "static_routes": [{"network": NETWORK[addr_type], "next_hop": "null0"}]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    input_dict_2 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify that R4 receives BGP prefixes via both peer routers R2 & R3")
    for addr_type in ADDR_TYPES:
        input_dict_3 = {"r4": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(
            tgen,
            addr_type,
            "r4",
            input_dict_3,
            next_hop=[
                topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
                topo["routers"]["r3"]["links"]["r4"][addr_type].split("/")[0],
            ],
        )
        assert result is True, "Testcase {}: Failed \n Error : {}".format(
            tc_name, result
        )

    step(
        "Configure a route-map to set as-path attribute and"
        "apply on R3 in an inbound direction:"
    )

    input_dict_4 = {
        "r3": {
            "route_maps": {
                "Path_Attribue": [
                    {
                        "action": "permit",
                        "set": {"path": {"as_num": 123, "as_action": "prepend"}},
                    }
                ]
            }
        }
    }
    result = create_route_maps(tgen, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    input_dict_5 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {
                                                    "name": "Path_Attribue",
                                                    "direction": "in",
                                                }
                                            ]
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
                                            "route_maps": [
                                                {
                                                    "name": "Path_Attribue",
                                                    "direction": "in",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify on R4, BGP routes with shorter as-path are installed in FIB")
    for addr_type in ADDR_TYPES:
        dut = "r4"
        protocol = "bgp"
        input_dict_6 = {"r4": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_6,
            next_hop=topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Shutdown BGP neighorship between R1-R2")
    dut = "r4"
    intf_r4_r2 = topo["routers"]["r4"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, dut, intf_r4_r2)

    step(
        "Verify that prefixes from next-hop via R2 are withdrawn"
        "and installed via next-hop as R3"
    )
    result = verify_rib(
        tgen,
        addr_type,
        dut,
        input_dict_2,
        next_hop=topo["routers"]["r3"]["links"]["r4"][addr_type].split("/")[0],
        protocol=protocol,
    )
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Do a no shut for BGP neighorship between R2-R4")
    shutdown_bringup_interface(tgen, dut, intf_r4_r2, ifaceaction=True)

    step(
        "Verify that prefixes from next-hop via R3 are withdrawn"
        "from R4 and installed via next-hop as R2 (preemption)"
    )
    result = verify_rib(
        tgen,
        addr_type,
        dut,
        input_dict_2,
        next_hop=topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
        protocol=protocol,
    )
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Remove the route-map from R3's neighbor statement")
    input_dict_5 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {
                                                    "name": "Path_Attribue",
                                                    "direction": "in",
                                                    "delete": True,
                                                }
                                            ]
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
                                            "route_maps": [
                                                {
                                                    "name": "Path_Attribue",
                                                    "direction": "in",
                                                    "delete": True,
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_5)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Configure multipath-relax and maximum-paths 2 on R4 for ECMP")
    input_dict_8 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"maximum_paths": {"ebgp": 2}}},
                    "ipv6": {"unicast": {"maximum_paths": {"ebgp": 2}}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_8)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    maxpath_relax = {
        "r4": {"bgp": {"local_as": "400", "bestpath": {"aspath": "multipath-relax"}}}
    }

    result = create_router_bgp(tgen, topo, maxpath_relax)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify FIB of R4, BGP prefixes with ECMP next-hop via R2 and R3")
    for addr_type in ADDR_TYPES:
        input_dict = {"r4": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_rib(
            tgen,
            addr_type,
            "r4",
            input_dict,
            next_hop=[
                topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
                topo["routers"]["r3"]["links"]["r4"][addr_type].split("/")[0],
            ],
        )
        assert result is True, "Testcase {} : Failed \n Error : {}".format(
            tc_name, result
        )

    step("Remove multipath-relax command from R4")

    del_maxpath_relax = {
        "r4": {
            "bgp": {
                "local_as": "400",
                "bestpath": {"aspath": "multipath-relax", "delete": True},
            }
        }
    }

    result = create_router_bgp(tgen, topo, del_maxpath_relax)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify that ECMP is no longer happening on R4.")
    for addr_type in ADDR_TYPES:
        input_dict = {"r4": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_rib(
            tgen,
            addr_type,
            "r4",
            input_dict,
            next_hop=[
                topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
                topo["routers"]["r3"]["links"]["r4"][addr_type].split("/")[0],
            ],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Routes are still present \n Error: {}".format(
            tc_name, result
        )

    step("Reconfigure multipath-relax command on R4")
    result = create_router_bgp(tgen, topo, maxpath_relax)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify FIB of R4, BGP prefixes with ECMP next-hop via R2 and R3")
    result = verify_rib(
        tgen,
        addr_type,
        "r4",
        input_dict,
        next_hop=[
            topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
            topo["routers"]["r3"]["links"]["r4"][addr_type].split("/")[0],
        ],
    )
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Remove maximum-path 2 command from R4")
    input_dict_8 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "maximum_paths": {
                                "ebgp": 1,
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "maximum_paths": {
                                "ebgp": 1,
                            }
                        }
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_8)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify that ECMP is no longer happening on R4")
    result = verify_rib(
        tgen,
        addr_type,
        "r4",
        input_dict,
        next_hop=[
            topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
            topo["routers"]["r3"]["links"]["r4"][addr_type].split("/")[0],
        ],
        expected=False,
    )
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "Routes are still present \n Error: {}".format(
        tc_name, result
    )

    step("Re-configure maximum-path 2 command on R4")
    input_dict_8 = {
        "r4": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "maximum_paths": {
                                "ebgp": 2,
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "maximum_paths": {
                                "ebgp": 2,
                            }
                        }
                    },
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_8)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Verify FIB of R4, BGP prefixes with ECMP next-hop via R2 and R3")
    result = verify_rib(
        tgen,
        addr_type,
        "r4",
        input_dict,
        next_hop=[
            topo["routers"]["r2"]["links"]["r4"][addr_type].split("/")[0],
            topo["routers"]["r3"]["links"]["r4"][addr_type].split("/")[0],
        ],
    )
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_password_authentication_for_eBGP_and_iBGP_peers_p1(request):
    """
    Verify password authentication for eBGP and iBGP peers.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Initial config :Configure BGP neighborship between R1 and R3.")
    reset_config_on_routers(tgen)

    step(
        "Add a static route on R1 for loopbacks IP's reachability of R2, R3"
        "and on R2 and R3 for loopback IP of R1"
    )
    for addr_type in ADDR_TYPES:
        nh1 = topo["routers"]["r3"]["links"]["r1"][addr_type].split("/")[0]
        nh2 = topo["routers"]["r1"]["links"]["r2"][addr_type].split("/")[0]
        nh3 = topo["routers"]["r1"]["links"]["r3"][addr_type].split("/")[0]
        nh4 = topo["routers"]["r2"]["links"]["r1"][addr_type].split("/")[0]
        input_dict_1 = {
            "r1": {
                "static_routes": [
                    {
                        "network": topo["routers"]["r3"]["links"]["lo"][addr_type],
                        "next_hop": nh1,
                    }
                ]
            }
        }
        input_dict_2 = {
            "r2": {
                "static_routes": [
                    {
                        "network": topo["routers"]["r1"]["links"]["lo"][addr_type],
                        "next_hop": nh2,
                    }
                ]
            }
        }
        input_dict_3 = {
            "r3": {
                "static_routes": [
                    {
                        "network": topo["routers"]["r1"]["links"]["lo"][addr_type],
                        "next_hop": nh3,
                    }
                ]
            }
        }
        input_dict_4 = {
            "r1": {
                "static_routes": [
                    {
                        "network": topo["routers"]["r2"]["links"]["lo"][addr_type],
                        "next_hop": nh4,
                    }
                ]
            }
        }
        dut_list = ["r1", "r2", "r3", "r1"]
        nexthop_list = [nh1, nh2, nh3, nh4]
        input_dict_list = [input_dict_1, input_dict_2, input_dict_3, input_dict_4]
        for dut, next_hop, input_dict in zip(dut_list, nexthop_list, input_dict_list):
            result = create_static_routes(tgen, input_dict)
            assert result is True, "Testcase {} : Failed \n Error : {}".format(
                tc_name, result
            )

            step("Verify that static routes are installed in FIB of routers")
            result = verify_rib(
                tgen, addr_type, dut, input_dict, next_hop=next_hop, protocol="static"
            )
            assert result is True, "Testcase {} : Failed \n Error : {}".format(
                tc_name, result
            )

    step("Configure BGP sessions between R1-R2 and R1-R3 over loopback IPs")
    for routerN in ["r1", "r3"]:
        for addr_type in ADDR_TYPES:
            if routerN == "r1":
                bgp_neighbor = "r3"
            elif routerN == "r3":
                bgp_neighbor = "r1"
            topo["routers"][routerN]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ][bgp_neighbor]["dest_link"] = {
                "lo": {"ebgp_multihop": 2, "source_link": "lo"}
            }
    build_config_from_json(tgen, topo, save_bkup=False)

    for routerN in ["r1", "r2"]:
        for addr_type in ADDR_TYPES:
            if routerN == "r1":
                bgp_neighbor = "r2"
            elif routerN == "r2":
                bgp_neighbor = "r1"
            topo["routers"][routerN]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ][bgp_neighbor]["dest_link"] = {"lo": {"source_link": "lo"}}
    build_config_from_json(tgen, topo, save_bkup=False)

    for routerN in ["r1", "r2", "r3"]:
        for addr_type in ADDR_TYPES:
            for bgp_neighbor in topo["routers"][routerN]["bgp"]["address_family"][
                addr_type
            ]["unicast"]["neighbor"].keys():
                if routerN in ["r1", "r2", "r3"] and bgp_neighbor == "r4":
                    continue
                if addr_type == "ipv4":
                    topo["routers"][routerN]["bgp"]["address_family"][addr_type][
                        "unicast"
                    ]["neighbor"][bgp_neighbor]["dest_link"] = {
                        "lo": {"deactivate": "ipv6"}
                    }
                elif addr_type == "ipv6":
                    topo["routers"][routerN]["bgp"]["address_family"][addr_type][
                        "unicast"
                    ]["neighbor"][bgp_neighbor]["dest_link"] = {
                        "lo": {"deactivate": "ipv4"}
                    }
    build_config_from_json(tgen, topo, save_bkup=False)

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Configure authentication password on R1 for neighbor statements")
    for bgp_neighbor in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            topo["routers"]["r1"]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ][bgp_neighbor]["dest_link"] = {"lo": {"password": "vmware"}}
    build_config_from_json(tgen, topo, save_bkup=False)

    step(
        "Verify that both sessions go down as only R1 has password"
        "configured but not peer routers"
    )
    result = verify_bgp_convergence(tgen, topo, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "BGP is converged \n Error: {}".format(
        tc_name, result
    )

    step("configure same password on R2 and R3")
    for routerN in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            topo["routers"][routerN]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ]["r1"]["dest_link"] = {"lo": {"password": "vmware"}}
    build_config_from_json(tgen, topo, save_bkup=False)

    step("Verify that all BGP sessions come up due to identical passwords")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Configure same password on R2 and R3, but in CAPs.")
    for routerN in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            topo["routers"][routerN]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ]["r1"]["dest_link"] = {"lo": {"password": "VMWARE"}}
    build_config_from_json(tgen, topo, save_bkup=False)

    step(
        "Verify that BGP sessions do not come up as password"
        "strings are in CAPs on R2 and R3"
    )
    result = verify_bgp_convergence(tgen, topo, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "BGP is converged \n Error: {}".format(
        tc_name, result
    )

    step("Configure same password on R2 and R3 without CAPs")
    for routerN in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            topo["routers"][routerN]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ]["r1"]["dest_link"] = {"lo": {"password": "vmware"}}
    build_config_from_json(tgen, topo, save_bkup=False)

    step("Verify all BGP sessions come up again due to identical passwords")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    step("Remove password from R1")
    for bgp_neighbor in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            topo["routers"]["r1"]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ][bgp_neighbor]["dest_link"] = {"lo": {"no_password": "vmware"}}
    build_config_from_json(tgen, topo, save_bkup=False)

    step("Verify if password is removed from R1, both sessions go down again")
    result = verify_bgp_convergence(tgen, topo, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "BGP is converged \n Error: {}".format(
        tc_name, result
    )

    step("Configure alphanumeric password on R1 and peer routers R2,R3")
    for bgp_neighbor in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            topo["routers"]["r1"]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ][bgp_neighbor]["dest_link"] = {"lo": {"password": "Vmware@123"}}
    build_config_from_json(tgen, topo, save_bkup=False)

    for routerN in ["r2", "r3"]:
        for addr_type in ADDR_TYPES:
            topo["routers"][routerN]["bgp"]["address_family"][addr_type]["unicast"][
                "neighbor"
            ]["r1"]["dest_link"] = {"lo": {"password": "Vmware@123"}}
    build_config_from_json(tgen, topo, save_bkup=False)

    step(
        "Verify that sessions Come up irrespective of characters"
        "used in password string"
    )
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error : {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
