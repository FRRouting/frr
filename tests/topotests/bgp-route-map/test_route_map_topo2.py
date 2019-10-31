#!/usr/bin/env python

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
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

"""Following tests are covered to test route-map functionality.
TC_57:
    Create route map to match prefix-list and permit inbound
    and outbound prefixes and set criteria on match
TC_52:
    Test modify set/match clauses in a route-map to see
    if it takes immediate effect.
TC_61:
    Delete the route maps.
TC_50_1:
    Test modify/remove prefix-lists referenced by a
    route-map for match statement.
TC_50_1:
    Remove prefix-list referencec by route-map match cluase
    and verifying it reflecting as intended
TC_51:
    Add and remove community-list referencec by route-map match cluase
    and verifying it reflecting as intended
TC_45:
    Test multiple match statements as part of a route-map's single
    sequence number. (Logical OR-ed of multiple match statements)
TC_44:
    Test multiple match statements as part of a route-map's single
    sequence number. (Logical AND of multiple match statements)
TC_41:
    Test add/remove route-maps to specific neighbor and see if
    it takes effect as intended
TC_56:
    Test clear BGP sessions and interface flaps to see if
    route-map properties are intact.
TC_46:
    Verify if a blank sequence number can be create(without any
    match/set clause) and check if it allows all the traffic/prefixes
TC_48:
    Create route map setting local preference and weight to eBGP peeer
    and metric to ibgp peer and verifying it should not get advertised
TC_43:
    Test multiple set statements as part of a route-map's
    single sequence number.
TC_54:
    Verify route-maps continue clause functionality.
TC_55:
    Verify route-maps goto clause functionality.
TC_53:
    Verify route-maps call clause functionality.
TC_58:
    Create route map deny inbound and outbound prefixes on
    match prefix list and set criteria on match
TC_59:
    Create route map to permit inbound prefixes with filter
    match tag and set criteria
TC_60
    Create route map to deny outbound prefixes with filter match tag,
    and set criteria
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

import sys
import json
import time
import pytest
import inspect
import os
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo

# Required to instantiate the topology builder class.
from lib.common_config import (
    start_topology,  write_test_header,
    write_test_footer, create_static_routes,
    verify_rib, delete_route_maps, create_bgp_community_lists,
    interface_status, create_route_maps, create_prefix_lists,
    verify_route_maps, check_address_types, verify_bgp_community,
    shutdown_bringup_interface, verify_prefix_lists, reset_config_on_routers)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence, create_router_bgp,
    clear_bgp_and_verify, verify_bgp_attributes)
from lib.topojson import build_topo_from_json, build_config_from_json

# Reading the data from JSON File for topology and configuration creation
jsonFile = "{}/bgp_route_map_topo2.json".format(CWD)

try:
    with open(jsonFile, 'r') as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

# Global variables
# Global variables
bgp_convergence = False
NETWORK = {
    "ipv4": ["11.0.20.1/32", "11.0.20.2/32"],
    "ipv6": ["2::1/128", "2::2/128"]
}

bgp_convergence = False
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()


class BGPRmapTopo(Topo):
    """BGPRmapTopo.

    BGPRmap topology 1
    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        """Build function."""
        tgen = get_topogen(self)

        # Building topology and configuration from json file
        build_topo_from_json(tgen, topo)


def setup_module(mod):
    """setup_module.

    Set up the pytest environment
    * `mod`: module name
    """
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("="*40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(BGPRmapTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

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
    assert bgp_convergence is True, ('setup_module :Failed \n Error:'
                                     ' {}'.format(bgp_convergence))
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

    logger.info("Testsuite end time: {}".format(
                    time.asctime(time.localtime(time.time()))))
    logger.info("="*40)


#####################################################
# Tests starting
#####################################################


def test_rmap_match_prefix_list_permit_in_and_outbound_prefixes_p0():
    """
    TC: 57
    Create route map to match prefix-list and permit inbound
    and outbound prefixes and set criteria on match
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                    'pf_list_1_ipv4': [{
                        'seqid': 10,
                        'network': 'any',
                        'action': 'permit',
                    }]
                },
                'ipv6': {
                    'pf_list_1_ipv6': [{
                        'seqid': 10,
                        'network': 'any',
                        'action': 'permit',
                    }]
                }
            }
        }
    }

    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)
    for addr_type in ADDR_TYPES:
    # Create route map
        input_dict_3 = {
            "r3": {
                "route_maps": {
                    "rmap_match_pf_1_{}".format(addr_type): [{
                        "action": "permit",
                        'seq_id': '5',
                        "match": {
                            addr_type: {
                                "prefix_lists": "pf_list_1_" + addr_type
                            }
                        },
                        "set": {
                            "localpref": 150,
                            "weight": 100
                        }
                    },
                    ],
                    "rmap_match_pf_2_{}".format(addr_type): [{
                        "action": "permit",
                        'seq_id': '5',
                        "match": {
                            addr_type: {
                                "prefix_lists": "pf_list_1_" + addr_type
                            }
                        },
                        "set": {
                            "med": 50
                        }
                    },
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r3': {
           "bgp": {
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_1_ipv4",
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               },
                               "r4": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_2_ipv4",
                                                   "direction": 'out'
                                           }]
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
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_1_ipv6",
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               },
                               "r4": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_2_ipv6",
                                                   "direction": 'out'
                                           }]
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           }
       }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]

    # dual stack changes
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result4 is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result4)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    # dual stack changes
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result4 = verify_bgp_attributes(tgen, addr_type, dut, routes[
            addr_type],rmap_name, input_dict_3)
        assert result4 is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result4)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    # dual stack changes
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result4 is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result4)

    # Verifying BGP set attributes
    dut = 'r4'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    # dual stack changes
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_2_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)
    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_modify_set_match_clauses_in_rmap_p0():
    """
    TC_52:
    Test modify set/match clauses in a route-map to see
    if it takes immediate effect.
    """

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list

    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                    'pf_list_1_ipv4': [{
                        'seqid': 10,
                        'network': 'any',
                        'action': 'permit',
                    }],
                    'pf_list_2_ipv4': [{
                        'seqid': 10,
                        'network': 'any',
                        'action': 'permit'
                    }]
                },
                'ipv6': {
                    'pf_list_1_ipv6': [{
                        'seqid': 10,
                        'network': 'any',
                        'action': 'permit',
                    }],
                    'pf_list_2_ipv6': [{
                        'seqid': 10,
                        'network': 'any',
                        'action': 'permit'
                    }]
                }
            }
        }
        }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                    },
                    "set": {
                        "localpref": 150,
                    }
                }],
                "rmap_match_pf_2_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                    },
                    "set": {
                        "med": 50
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r3': {
           "bgp": {
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_1_ipv4",
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               },
                               "r4": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_2_ipv4",
                                                   "direction": 'out'
                                           }]
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
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_1_ipv6",
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               },
                               "r4": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_2_ipv6",
                                                   "direction": 'out'
                                           }]
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           }
       }
   }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    # dual stack changes
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result4 = verify_bgp_attributes(tgen, addr_type, dut, routes[
            addr_type],rmap_name, input_dict_3)
        assert result4 is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result4)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    # dual stack changes
    for addr_type in ADDR_TYPES:
        result4 = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result4 is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result4)

    # Verifying BGP set attributes
    dut = 'r4'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_2_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[
            addr_type],rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Modify set/match clause of in-used route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
        "route_maps": {
            "rmap_match_pf_1_{}".format(addr_type): [{
                "action": "permit",
                'seq_id': '5',
                "match": {
                    addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                },
                "set": {
                    "localpref": 1000,
                }
            }],
            "rmap_match_pf_2_{}".format(addr_type): [{
                "action": "permit",
                'seq_id': '5',
                "match": {
                    addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                },
                "set": {
                    "med": 2000
                }
            }]
        }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying BGP set attributes
    dut = 'r4'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_2_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_delete_route_maps_p1():
    """
    TC_61:
    Delete the route maps.
    """

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_tag_1_{}".format(addr_type): [{
                    "action": "deny",
                    "match": {
                        addr_type: {
                        "tag": "4001"
                    }
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Delete route maps
    for addr_type in ADDR_TYPES:
        input_dict = {
        'r3': {
            'route_maps': ['rmap_match_tag_1_{}'.format(addr_type)]
        }
        }
        result = delete_route_maps(tgen, input_dict)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    result = verify_route_maps(tgen, input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)
    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_modify_prefix_list_referenced_by_rmap_p0():
    """
    TC_50_1:
    Test modify/remove prefix-lists referenced by a
    route-map for match statement.
    """

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                    'pf_list_1_ipv4': [{
                        'seqid': 10,
                        'network': 'any',
                        'action': 'permit',
                    }]
                },
                'ipv6': {
                    'pf_list_1_ipv6': [{
                        'seqid': 100,
                        'network': 'any',
                        'action': 'permit',
                    }]
                }
            }
        }
        }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                    },
                    "set": {
                        "localpref": 150,
                        "weight": 100
                    }
                }],
                "rmap_match_pf_2_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                    },
                    "set": {
                        "med": 50
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r3': {
           "bgp": {
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_1_ipv4",
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               },
                               "r4": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_2_ipv4",
                                                   "direction": 'out'
                                           }]
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
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_1_ipv6",
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               },
                               "r4": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_2_ipv6",
                                                   "direction": 'out'
                                           }]
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           }
       }
   }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r4'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }

    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_2_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Modify ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'deny'
                }]
            },
            'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'deny'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    sleep(5)
    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
                protocol=protocol)
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: routes are not present \n '
        'Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
                protocol=protocol)
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: routes are not present \n '
        'Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_remove_prefix_list_referenced_by_rmap_p0():
    """
    TC_50_1:
    Remove prefix-list referencec by route-map match cluase
    and verifying it reflecting as intended
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
        }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                    },
                    "set": {
                        "localpref": 150,
                    }
                }],
                "rmap_match_pf_2_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                    },
                    "set": {
                        "med": 50
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
       'r3': {
             "bgp": {
                 "address_family": {
                     "ipv4": {
                         "unicast": {
                             "neighbor": {
                                 "r1": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv4",
                                                     "direction": 'in'
                                             }]
                                         }
                                     }
                                 },
                                 "r4": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_2_ipv4",
                                                     "direction": 'out'
                                             }]
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
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv6",
                                                     "direction": 'in'
                                             }]
                                         }
                                     }
                                 },
                                 "r4": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_2_ipv6",
                                                     "direction": 'out'
                                             }]
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
     }
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r4'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_2_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                        rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Remove/Delete prefix list
    input_dict_3 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit',
                    'delete': True
                }]
            },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit',
                    'delete': True
                }]
            }
        }
        }
    }
    result = create_prefix_lists(tgen, input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    result = verify_prefix_lists(tgen, input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = 'r3'
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: routes are not present \n '
        'Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: routes are not present \n '
        'Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_add_and_remove_community_list_referenced_by_rmap_p0():
    """
    TC_51:
    Add and remove community-list referencec by route-map match cluase
    and verifying it reflecting as intended
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Creating configuration from JSON
    # build_config_from_json(tgen, topo)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_5 = {
        "r1": {
            "route_maps": {
                "rm_r1_out_{}".format(addr_type): [{
                    "action": "permit",
                    "set": {
                        "large_community": {"num": "1:1:1 1:2:3 2:1:1 2:2:2"}
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_5)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_6 = {
       'r1': {
           "bgp": {
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r3": {
                                   "dest_link": {
                                       "r1": {
                                           "route_maps": [{
                                                   "name": "rm_r1_out_ipv4",
                                                   "direction": 'out'
                                           }]
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
                                           "route_maps": [{
                                                   "name": "rm_r1_out_ipv6",
                                                   "direction": 'out'
                                           }]
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           }
       }
   }

    result = create_router_bgp(tgen, topo, input_dict_6)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    for addr_type in ADDR_TYPES:
        # Create standard large commumity-list
            input_dict_1 = {
                "r3": {
                    "bgp_community_lists": [
                        {
                            "community_type": "standard",
                            "action": "permit",
                            "name": "rmap_lcomm_{}".format(addr_type),
                            "value": "1:1:1 1:2:3 2:1:1 2:2:2",
                            "large": True
                        }
                    ]
                }
            }
            result = create_bgp_community_lists(tgen, input_dict_1)
            assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
                tc_name, result)

    for addr_type in ADDR_TYPES:
    # Create route map
        input_dict_2 = {
        "r3": {
            "route_maps": {
                "rm_r3_in_{}".format(addr_type): [{
                    "action": "permit",
                    "match": {
                        addr_type : {
                            "large-community-list": {"id": "rmap_lcomm_"+
                            addr_type}
                    }
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_2)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_3 = {
       'r3': {
           "bgp": {
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name": "rm_r3_in_ipv4",
                                                   "direction": 'in'
                                           }]
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
                                           "route_maps": [{
                                                   "name": "rm_r3_in_ipv6",
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           }
       }
   }
    result = create_router_bgp(tgen, topo, input_dict_3)

    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    sleep(5)
    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verify large-community-list
    dut = 'r3'
    networks = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    input_dict_4 = {
        'largeCommunity': '1:1:1 1:2:3 2:1:1 2:2:2'
    }
    for addr_type in ADDR_TYPES:
        result = verify_bgp_community(tgen, addr_type, dut, networks[
            addr_type],input_dict_4)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)
    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_multiple_match_statement_in_route_map_logical_ORed_p0():
    """
    TC_45:
    Test multiple match statements as part of a route-map's single
    sequence number. (Logical OR-ed of multiple match statements)
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict_nw1 = {
            'r1': {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [
                                    {"network": '10.0.30.1/32'}
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "advertise_networks": [
                                    {"network": '1::1/128'}
                                ]
                            }
                        }
                    }
                }
            }
        }

    result = create_router_bgp(tgen, topo, input_dict_nw1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to advertise networks
    input_dict_nw2 = {
            'r1': {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [
                                    {"network": '20.0.30.1/32'}
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "advertise_networks": [
                                    {"network": '2::1/128'}
                                ]
                            }
                        }
                    }
                }
            }
        }

    result = create_router_bgp(tgen, topo, input_dict_nw2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_2_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                'ipv6': {
                'pf_list_2_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    input_dict_3_addr_type ={}
    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                    },
                    "set": {
                        "localpref": 150
                    }
                }]
            }
        }
        }
        input_dict_3_addr_type[addr_type] = input_dict_3
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                    },
                    "set": {
                        "localpref": 200
                    }
                }]
            }
        }
        }
        input_dict_3_addr_type[addr_type] = input_dict_3
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_6 = {
       'r3': {
           "bgp": {
               "address_family": {
                   "ipv4": {
                       "unicast": {
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_1_ipv4",
                                                   "direction": 'in'
                                           }]
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
                                           "route_maps": [{
                                                   "name":
                                                   "rmap_match_pf_1_ipv6",
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           }
       }
   }

    result = create_router_bgp(tgen, topo, input_dict_6)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.30.1/32"],
          "ipv6": ["1::1/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                rmap_name, input_dict_3_addr_type[addr_type])
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    routes = {
          "ipv4": ["20.0.30.1/32"],
          "ipv6": ["2::1/128"]
    }
    for addr_type in ADDR_TYPES:
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_multiple_match_statement_in_route_map_logical_ANDed():
    """
    TC_44:
    Test multiple match statements as part of a route-map's single
    sequence number. (Logical AND of multiple match statements)
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_5 = {
            "r1": {
                "route_maps": {
                    "rm_r1_out_{}".format(addr_type): [{
                        "action": "permit",
                        "set": {
                            "large_community": {
                                "num": "1:1:1 1:2:3 2:1:1 2:2:2"}
                        }
                    }]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_5)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    for addr_type in ADDR_TYPES:
        input_dict_6 = {
        'r1': {
           "bgp": {
               "address_family": {
                addr_type: {
                       "unicast": {
                           "neighbor": {
                               "r3": {
                                   "dest_link": {
                                       "r1": {
                                           "route_maps": [{
                                                   "name":
                                            "rm_r1_out_{}".format(addr_type),
                                                   "direction": 'out'
                                           }]
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           }
        }
        }
        result = create_router_bgp(tgen, topo, input_dict_6)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
                },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)

    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    for addr_type in ADDR_TYPES:
    # Create standard large commumity-list
        input_dict_1 = {
            "r3": {
                "bgp_community_lists": [
                    {
                        "community_type": "standard",
                        "action": "permit",
                        "name": "rmap_lcomm_{}".format(addr_type),
                        "value": "1:1:1 1:2:3 2:1:1 2:2:2",
                        "large": True
                    }
                ]
            }
        }
        result = create_bgp_community_lists(tgen, input_dict_1)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
            "r3": {
                "route_maps": {
                    "rmap_match_pf_1_{}".format(addr_type): [{
                        "action": "permit",
                        'seq_id': '5',
                        "match": {
                            addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                        },
                        "set": {
                            "localpref": 150,
                        }
                    }]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    for addr_type in ADDR_TYPES:
    # Create route map
        input_dict_3 = {
            "r3": {
                "route_maps": {
                    "rmap_match_pf_1_{}".format(addr_type): [{
                        "action": "permit",
                        'seq_id': '5',
                        "match": {
                            addr_type : {
                            "large_community_list": {"id": "rmap_lcomm_"+
                                addr_type}
                        }
                        },
                        "set": {
                            "localpref": 150,
                        }
                    }]
                }
            }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)
    # Configure neighbor for route map
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
       'r3': {
           "bgp": {
               "address_family": {
                addr_type: {
                       "unicast": {
                           "neighbor": {
                               "r1": {
                                   "dest_link": {
                                       "r3": {
                                           "route_maps": [{
                                                   "name":
                                        "rmap_match_pf_1_{}".format(addr_type),
                                                   "direction": 'in'
                                           }]
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
           }
        }
        }
        result = create_router_bgp(tgen, topo, input_dict_4)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)
    # sleep(10)
    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_add_remove_rmap_to_specific_neighbor_p0():
    """
    TC_41:
    Test add/remove route-maps to specific neighbor and see if
    it takes effect as intended
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
            'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'deny'
                }]
            },
            'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'deny'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                    },
                    "set": {
                        "localpref": 150,
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        'r3': {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_1_ipv4",
                                                    "direction": 'in'
                                            }]
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
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_1_ipv6",
                                                    "direction": 'in'
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
         tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
                            protocol=protocol)
        assert result is not True, 'Testcase {} : \n'
        'Expected Behavior: Routes are not present in RIB \n'
        ' Error: {}'.format(
            tc_name, result)

    # Remove applied rmap from neighbor
    input_dict_4 = {
        'r3': {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_1_ipv4",
                                                    "direction": 'in',
                                                    "delete": True
                                            }]
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
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_1_ipv6",
                                                    "direction": 'in',
                                                    "delete": True
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
         tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
             tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_clear_bgp_and_flap_interface_to_verify_rmap_properties_p0():
    """
    TC_56:
    Test clear BGP sessions and interface flaps to see if
    route-map properties are intact.
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                    },
                    "set": {
                        "localpref": 150,
                        "weight": 100
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        'r3': {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_1_ipv4",
                                                    "direction": 'in'
                                            }]
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
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_1_ipv6",
                                                    "direction": 'in'
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
         tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # clear bgp, so config changes would be reflected
    dut = 'r3'
    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                       rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Flap interface to see if route-map properties are intact
    # Shutdown interface
    dut = "r3"
    intf = "r3-r1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, False)

    sleep(5)

    # Bringup interface
    dut = "r3"
    intf = "r3-r1-eth0"
    shutdown_bringup_interface(tgen, dut, intf, True)

    # Verify BGP convergence once interface is up
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, (
        'setup_module :Failed \n Error:' ' {}'.format(result))

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_rmap_without_match_and_set_clause_p0():
    """
    TC_46:
    Verify if a blank sequence number can be create(without any
    match/set clause) and check if it allows all the traffic/prefixes
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_no_match_set_1_{}".format(addr_type): [{
                    "action": "permit",
                    'seq_id': '5'
                }],
                "rmap_no_match_set_2_{}".format(addr_type): [{
                    "action": "deny",
                    'seq_id': '5'
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        'r3': {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_no_match_set_1_ipv4",
                                                    "direction": 'in'
                                            }]
                                        }
                                    }
                                },
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_no_match_set_2_ipv4",
                                                    "direction": 'out'
                                            }]
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
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_no_match_set_1_ipv6",
                                                    "direction": 'in'
                                            }]
                                        }
                                    }
                                },
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_no_match_set_2_ipv6",
                                                    "direction": 'out'
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
         tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: routes are not present \n '
        'Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_set_localpref_weight_to_ebgp_and_med_to_ibgp_peers_p0():
    """
    TC_48:
    Create route map setting local preference and weight to eBGP peeer
    and metric to ibgp peer and verifying it should not get advertised
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                  'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                  'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    input_dict_3_addr_type ={}
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
            "r3": {
                "route_maps": {
                    "rmap_match_pf_1_{}".format(addr_type): [{
                            "action": "permit",
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_list_1_{}".format(
                                        addr_type)
                                }
                            },
                                "set": {
                                    "med": 50
                                }
                            }],
                    "rmap_match_pf_2_{}".format(addr_type): [{
                            "action": "permit",
                            "match": {
                                addr_type: {
                                    "prefix_lists": "pf_list_1_{}".format(
                                            addr_type)
                                    }},
                                    "set": {
                                        "localpref": 150
                                    }
                                }],
                            "rmap_match_pf_3_{}".format(addr_type): [{
                                    "action": "permit",
                                    "match": {
                                        addr_type: {
                                    "prefix_lists": "pf_list_1_{}".format(
                                            addr_type)
                                        }},
                                        "set": {
                                            "weight": 1000
                                        }
                                    }]
                            }
                        }
                    }
        input_dict_3_addr_type[addr_type] = input_dict_3
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        'r3': {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r1": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_1_ipv4",
                                                    "direction": 'in'
                                            }]
                                        }
                                    }
                                },
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_2_ipv4",
                                                    "direction": 'out'
                                            }]
                                        }
                                    }
                                },
                                "r5": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_3_ipv4",
                                                    "direction": 'out'
                                            }]
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
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_1_ipv6",
                                                    "direction": 'in'
                                            }]
                                        }
                                    }
                                },
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_2_ipv6",
                                                    "direction": 'out'
                                            }]
                                        }
                                    }
                                },
                                "r5": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [{
                                                    "name":
                                                    "rmap_match_pf_3_ipv6",
                                                    "direction": 'out'
                                            }]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    rmap_name = "rmap_match_pf_1"
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[
            addr_type],rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r4'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    rmap_name = "rmap_match_pf_2"
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_2_{}".format(addr_type)

        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                rmap_name, input_dict_3_addr_type[addr_type])
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: Attributes are not set \n'
        'Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r5'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)
    # Verifying BGP set attributes
    dut = 'r5'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }

    rmap_name = "rmap_match_pf_3"
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_3_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                rmap_name, input_dict_3_addr_type[addr_type])
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: Attributes are not set \n'
        'Error: {}'.format(
            tc_name, result)

        logger.info("Expected behaviour: {}".format(result))

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_multiple_set_on_single_sequence_in_rmap_p0():
    """
    TC_43:
    Test multiple set statements as part of a route-map's
    single sequence number.
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
                },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
                }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                },
                    "set": {
                        "localpref": 150,
                        "weight": 100,
                        "med": 50
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r3': {
             "bgp": {
                 "address_family": {
                     "ipv4": {
                         "unicast": {
                             "neighbor": {
                                 "r1": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv4",
                                                     "direction": 'in'
                                             }]
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
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv6",
                                                     "direction": 'in'
                                             }]
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
     }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }

    rmap_name = "rmap_match_pf_1"
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_route_maps_with_continue_clause_p0():
    """
    TC_54:
    Verify route-maps continue clause functionality.
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                        "action": "permit",
                        'seq_id': '10',
                        "match": {
                            addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                        },
                        "set": {
                            "localpref": 150
                        },
                        "continue": "30"
                    },
                    {
                        "action": "permit",
                        'seq_id': '20',
                        "match": {
                            addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                        },
                        "set": {
                            "med": 200
                        }
                    },
                    {
                        "action": "permit",
                        'seq_id': '30',
                        "match": {
                            addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                        },
                        "set": {
                            "med": 100
                        }
                    }
                ]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r3': {
             "bgp": {
                 "address_family": {
                     "ipv4": {
                         "unicast": {
                             "neighbor": {
                                 "r1": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv4",
                                                     "direction": 'in'
                                             }]
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
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv6",
                                                     "direction": 'in'
                                             }]
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
     }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
            protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    rmap_name = "rmap_match_pf_1"
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    seq_id = {
          "ipv4": ["10", "30"],
          "ipv6": ["10", "30"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[
            addr_type],rmap_name, input_dict_3, seq_id[addr_type])
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_route_maps_with_goto_clause_p0():
    """
    TC_55:
    Verify route-maps goto clause functionality.
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                        "action": "permit",
                        'seq_id': '10',
                        "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                        },
                        "goto": "30"
                    },
                    {
                        "action": "permit",
                        'seq_id': '20',
                        "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                        },
                        "set": {
                            "med": 100
                        }
                    },
                    {
                        "action": "permit",
                        'seq_id': '30',
                        "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_{}".format(addr_type)
                        }
                        },
                        "set": {
                            "med": 200
                        }
                    }
                ]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r3': {
             "bgp": {
                 "address_family": {
                     "ipv4": {
                         "unicast": {
                             "neighbor": {
                                 "r1": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv4",
                                                     "direction": 'in'
                                             }]
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
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv6",
                                                     "direction": 'in'
                                             }]
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
     }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    rmap_name = "rmap_match_pf_1"
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    seq_id = {
          "ipv4": ["10", "30"],
          "ipv6": ["10", "30"]
    }
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[
            addr_type],rmap_name, input_dict_3, seq_id[addr_type])
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_route_maps_with_call_clause_p0():
    """
    TC_53:
    Verify route-maps call clause functionality.
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "permit",
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                    },
                    "set": {
                        "localpref": 150
                    },
                    "call": "rmap_match_pf_2_{}".format(addr_type)
                }],
                "rmap_match_pf_2_{}".format(addr_type): [{
                    "action": "permit",
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                    },
                    "set": {
                        "med": 200
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r3': {
             "bgp": {
                 "address_family": {
                     "ipv4": {
                         "unicast": {
                             "neighbor": {
                                 "r1": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv4",
                                                     "direction": 'in'
                                             }]
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
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv6",
                                                     "direction": 'in'
                                             }]
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
     }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict, protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Verifying BGP set attributes
    dut = 'r3'
    routes = {
          "ipv4": ["10.0.20.1/32", "10.0.20.2/32"],
          "ipv6": ["1::1/128", "1::2/128"]
    }
    rmap_name = "rmap_match_pf_1"
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_1_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                   rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    rmap_name = "rmap_match_pf_2"
    for addr_type in ADDR_TYPES:
        rmap_name = "rmap_match_pf_2_{}".format(addr_type)
        result = verify_bgp_attributes(tgen, addr_type, dut, routes[addr_type],
                                    rmap_name, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_create_rmap_match_prefix_list_to_deny_in_and_outbound_prefixes_p0():
    """
    TC_58:
    Create route map deny inbound and outbound prefixes on
    match prefix list and set criteria on match
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'ipv4': {
                'pf_list_1_ipv4': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            },
                'ipv6': {
                'pf_list_1_ipv6': [{
                    'seqid': 100,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    for addr_type in ADDR_TYPES:
        input_dict_3 = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_{}".format(addr_type): [{
                    "action": "deny",
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                    },
                    "set": {
                        "localpref": 150,
                    }
                }],
                "rmap_match_pf_2_{}".format(addr_type): [{
                    "action": "deny",
                    "match": {
                        addr_type: {
                        "prefix_lists": "pf_list_1_{}".format(addr_type)
                    }
                    },
                    "set": {
                        "med": 50
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r3': {
             "bgp": {
                 "address_family": {
                     "ipv4": {
                         "unicast": {
                             "neighbor": {
                                 "r1": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv4",
                                                     "direction": 'in'
                                             }]
                                         }
                                     }
                                 },
                                 "r4": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_2_ipv6",
                                                     "direction": 'out'
                                             }]
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
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_1_ipv4",
                                                     "direction": 'in'
                                             }]
                                         }
                                     }
                                 },
                                 "r4": {
                                     "dest_link": {
                                         "r3": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_pf_2_ipv6",
                                                     "direction": 'out'
                                             }]
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
     }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    input_dict = topo["routers"]
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
        protocol=protocol)
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: routes are not present \n '
        'Error: {}'.format(
            tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    for addr_type in ADDR_TYPES:
        result = verify_rib(tgen, addr_type, dut, input_dict,
        protocol=protocol)
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behaviour: routes are not present \n '
        'Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_create_rmap_to_match_tag_permit_inbound_prefixes_p0():
    """
    TC_59:
    Create route map to permit inbound prefixes with filter
    match tag and set criteria
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    for addr_type in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "tag": 4001
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

        # Api call to redistribute static routes
        input_dict_1 = {
            "r1": {
                "bgp": {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"}
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"}
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

        # Create route map
        input_dict_3 = {
        "r1": {
            "route_maps": {
                "rmap_match_tag_1_{}".format(addr_type): [{
                    "action": "permit",
                    "match": {
                        addr_type: {
                        "tag": "4001"
                    }
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r1': {
             "bgp": {
                 "address_family": {
                     "ipv4": {
                         "unicast": {
                             "neighbor": {
                                 "r3": {
                                     "dest_link": {
                                         "r1": {
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_tag_1_ipv4",
                                                     "direction": 'out'
                                             }]
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
                                             "route_maps": [{
                                                     "name":
                                                     "rmap_match_tag_1_ipv6",
                                                     "direction": 'out'
                                             }]
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
     }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "tag": 4001
                    }
                ]
            }
        }
        result = verify_rib(tgen, addr_type, dut, input_dict,
        protocol=protocol)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_create_rmap_to_match_tag_deny_outbound_prefixes_p0():
    """
    TC_60
    Create route map to deny outbound prefixes with filter match tag,
    and set criteria
    """
    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence is not True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    for addr_type in ADDR_TYPES:
        # Create Static routes
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "tag": 4001
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

        # Api call to redistribute static routes
        input_dict_1 = {
            "r1": {
                "bgp": {
                    "local_as": 100,
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"}
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static"},
                                    {"redist_type": "connected"}
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

        # Create route map
        input_dict_3 = {
        "r1": {
            "route_maps": {
                "rmap_match_tag_1_{}".format(addr_type): [{
                    "action": "deny",
                    "match": {
                        addr_type: {
                        "tag": "4001"
                    }
                    }
                }]
            }
        }
        }
        result = create_route_maps(tgen, input_dict_3)
        assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
            tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
       'r1': {
             "bgp": {
                 "address_family": {
                     "ipv4": {
                         "unicast": {
                             "neighbor": {
                                 "r3": {
                                     "dest_link": {
                                         "r1": {
                                             "route_maps": [{
                                                    "name":
                                                    "rmap_match_tag_1_ipv4",
                                                    "direction": 'out'
                                             }]
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
                                             "route_maps": [{
                                                    "name":
                                                    "rmap_match_tag_1_ipv6",
                                                    "direction": 'out'
                                             }]
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
    }
    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'

    for addr_type in ADDR_TYPES:
        input_dict = {
            "r1": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": "Null0",
                        "tag": 4001
                    }
                ]
            }
        }
        result = verify_rib(tgen, addr_type, dut, input_dict,
                            protocol=protocol)
        assert result is not True, 'Testcase {} : Failed \n'
        'Expected behavior: routes are denied \n Error: {}'.format(
            tc_name, result)

    write_test_footer(tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
