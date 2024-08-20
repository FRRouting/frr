#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf6_elsa_legacy.py
#
# The purpose of this test is to check that ospf6d can operate on Legacy LSAs,
# without originating or receiving any of the TLV-based LSAs of RFC 8362.

# It checks for the presence of the Legacy LSAs, and when that passes, it
# checks for the absence of any E-LSAs.
#
# "Absence" means:
# 'not detected during a short time interval following the stable convergence'
# This obviously does not prove that an E-LSA could ever exist...
#
# Based on test_ospf6_gr_topo1.py which claims
# Copyright (c) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
                     ┌─────────┐
                     │   RT1   │
                     │ 1.1.1.1 │
                     └────┬────┘
                          │eth-rt2                    ▲
                          │                           │
                     ┌────┴────┐                      │
                     │   S1    │               area 1 │
                     └────┬────┘                      │
                          │                           │
                          │eth-rt1                    ▼
                     ┌────┴────┐
                     │   RT2   │
                     │ 2.2.2.2 │
                     └────┬────┘
                          │eth-rt3                    ▲
                          │                    area 0 │
                          │eth-rt2                    ▼
                     ┌────┴────┐
                     │   RT3   │
                     │ 3.3.3.3 │
                     └───┬──┬──┘
                  eth-rt4│  │eth-rt6                  ▲
                         │  │                         │
               ┌─────────┘  └────────┐         area 0 │
               │                     │                │
               │eth-rt3              │eth-rt3         ▼
          ┌────┴────┐           ┌────┴────┐
          │   RT4   │           │   RT6   │
          │ 4.4.4.4 │           │ 6.6.6.6 │
          └┬──────┬─┘           └────┬────┘
 ▲ eth-rt5 │      │eth-br9           │eth-rt7         ▲
 │  area2  │      │                  │         area 3 │
 ▼ eth-rt4 │      │                  │eth-rt6         ▼
   ┌───────┴─┐    │             ┌────┴────┐
   │   RT5   │    │             │   RT7   │
   │ 5.5.5.5 │    │             │ 7.7.7.7 │
   └─────────┘    │             └─────────┘
                  │                                   ▲
                  │                                   │
          ┌───────┴─┐                                 │
          │   S9    │                                 │
          └───┬───┬─┘                          area 4 │
              │   │                                   │
              │   └──────────────────┐                │
              │                      │                │
              │eth-br9               │eth-br9         ▼
          ┌───┴─────┐           ┌────┴────┐
          │   RT8   │           │   RT9   │
          │ 8.8.8.8 │           │ 9.9.9.9 │
          └─────────┘           └─────────┘
"""

import os
import sys
import pytest
import json
import time
import functools
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    kill_router_daemons,
    start_router_daemons,
)

pytestmark = [pytest.mark.ospf6d]

# Global multi-dimensional dictionary containing all expected outputs
outputs = {}


def build_topo(tgen):
    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7", "rt8", "rt9"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt1"], nodeif="stub1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt3")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt4")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt3")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt3")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt7")
    switch.add_link(tgen.gears["rt7"], nodeif="eth-rt6")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt7"], nodeif="stub1")

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt4-br9")
    switch.add_link(tgen.gears["rt8"], nodeif="eth-rt8-br9")
    switch.add_link(tgen.gears["rt9"], nodeif="eth-rt9-br9")



def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )

    tgen.start_router()
    #tgen.mininet_cli()

def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def router_compare_json_output(rname, command, reference, tries):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=tries, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def check_routers():
    tries = 100
    for rname in ["rt9", "rt1", "rt2", "rt3", "rt4", "rt5", "rt6", "rt7", "rt8", "rt9"]:
        router_compare_json_output(
            rname, "show ipv6 route ospf json", "show_ipv6_route.json", tries
        )

        router_compare_json_output(
            rname,
            "show ipv6 ospf database json",
            "show_ipv6_ospf_database.json",
            tries,
        )
        router_compare_json_output(
            rname, "show ipv6 ospf route json", "show_ipv6_ospf_route.json", tries
        )


#
# Test initial network convergence
#
def test_initial_convergence():
    logger.info("Test: verify initial network convergence")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_routers()


#
# Define expected parts of LSA database
#

expected_router_lsa_part = {
    "areaScopedLinkStateDb": [
        {
            "areaId": "1",
            "lsa": [
                {
                    "type": "Rtr",
                    "lsId": "0.0.0.0",
                    "advRouter": "2.2.2.2",
                    "payload": "1.1.1.1/0.0.0.2",
                }
            ],
        }
    ]
}

expected_router_lsa_detail_part = {
    "areaScopedLinkStateDb": [
        {
            "areaId": "1",
            "lsa": [
                {
                    "type": "Router",
                    "linkStateId": "0.0.0.0",
                    "advertisingRouter": "2.2.2.2",
                    "lsaDescription":[
                        {
                          "type":"Point-To-Point",
                          "metric":10,
                          "interfaceId":"0.0.0.2",
                          "neighborInterfaceId":"0.0.0.2",
                          "neighborRouterId":"1.1.1.1"
                        }
                    ]
                }
            ],
        }
    ]
}


expected_network_lsa_part = {
    "areaScopedLinkStateDb": [
    {
        "areaId": "4",
        "lsa": [
        {
            "type":"Net",
            "advRouter":"4.4.4.4",
            "payload":"4.4.4.4"
        },
        {
            "type":"Net",
            "advRouter":"4.4.4.4",
            "payload":"8.8.8.8"
        },
        {
            "type":"Net",
            "advRouter":"4.4.4.4",
            "payload":"9.9.9.9"
        }
        ]
    }
    ]
}

expected_network_lsa_detail_part = {
    "areaScopedLinkStateDb":[
    {
        "areaId":"4",
        "lsa":[
        {
            "type":"Network",
            "advertisingRouter":"4.4.4.4",
            "options":"--|-|--|-|-|--|R|-|--|E|V6",
            "attachedRouter":[
                "4.4.4.4",
                "8.8.8.8",
                "9.9.9.9"
            ]
        }
        ]
    }
    ]
}

expected_link_lsa_part = {
    "interfaceScopedLinkStateDb": [
        {
            "areaId": "1",
            "interface": "eth-rt2",
            "lsa": [
                {
                    "type": "Lnk",
                    "lsId": "0.0.0.2",
                    "advRouter": "1.1.1.1",
                },
                {
                    "type": "Lnk",
                    "lsId": "0.0.0.2",
                    "advRouter": "2.2.2.2",
                },
            ],
        }
    ]
}

expected_link_lsa_detail_part = {
    "interfaceScopedLinkStateDb": [
        {
            "areaId": "1",
            "interface": "eth-rt2",
            "lsa": [
                {
                    "type": "Link",
                    "linkStateId": "0.0.0.2",
                    "advertisingRouter": "1.1.1.1",
                },
                {
                    "type": "Link",
                    "linkStateId": "0.0.0.2",
                    "advertisingRouter": "2.2.2.2",
                },
            ],
        }
    ]
}

expected_intra_area_prefix_lsa_part = {
    "areaScopedLinkStateDb": [
        {
            "areaId": "1",
            "lsa": [
                {
                    "type": "INP",
                    "lsId": "0.0.0.0",
                    "advRouter": "1.1.1.1",
                }
            ],
        }
    ]
}

expected_intra_area_prefix_lsa_detail_part = {
    "areaScopedLinkStateDb": [
        {
            "areaId": "1",
            "lsa": [
                {
                    "type": "Intra-Prefix",
                    "linkStateId": "0.0.0.0",
                    "advertisingRouter": "1.1.1.1",
                    "reference": "Router",
                }
            ],
        }
    ]
}

expected_parts = {
    "Router": expected_router_lsa_part,
    "Link": expected_link_lsa_part,
    "Intra-Area_prefix": expected_intra_area_prefix_lsa_part,
}

expected_detail_parts = {
    "Router": expected_router_lsa_detail_part,
    "Link": expected_link_lsa_detail_part,
    "Intra-Area_prefix": expected_intra_area_prefix_lsa_detail_part,
}


expected_area4_parts = {
    "Network": expected_network_lsa_part,
    "Network-Detail": expected_network_lsa_detail_part,
}

#
# Define the parts that must NOT be present:
#
e_router_lsa_part = {
    "areaScopedLinkStateDb": [
        {
            "areaId": "1",
            "lsa": [
                {
                    "type": "ERtr",
                    "lsId": "0.0.0.0",
                    "advRouter": "2.2.2.2",
                    "payload": "1.1.1.1/0.0.0.2",
                }
            ],
        }
    ]
}

e_network_lsa_part = {
    "areaScopedLinkStateDb": [
    {
        "areaId": "4",
        "lsa": [
        {
            "type":"ENet",
            "advRouter":"4.4.4.4",
            "payload":"4.4.4.4"
        },
        {
            "type":"ENet",
            "advRouter":"4.4.4.4",
            "payload":"8.8.8.8"
        },
        {
            "type":"ENet",
            "advRouter":"4.4.4.4",
            "payload":"9.9.9.9"
        }
        ]
    }
    ]
}

e_link_lsa_part = {
    "interfaceScopedLinkStateDb": [
        {
            "areaId": "1",
            "interface": "eth-rt2",
            "lsa": [
                {
                    "type": "ELnk",
                    "lsId": "0.0.0.2",
                    "advRouter": "1.1.1.1",
                },
                {
                    "type": "ELnk",
                    "lsId": "0.0.0.2",
                    "advRouter": "2.2.2.2",
                },
            ],
        }
    ]
}

e_intra_area_prefix_lsa_part = {
    "areaScopedLinkStateDb": [
        {
            "areaId": "1",
            "lsa": [
                {
                    "type": "EINP",
                    "lsId": "0.0.0.0",
                    "advRouter": "1.1.1.1",
                }
            ],
        }
    ]
}

expected_absent_parts = {
    "E-Router" : e_router_lsa_part,
    "E-Link" : e_link_lsa_part,
    "E-Intra-Area-Prefix": e_intra_area_prefix_lsa_part
}

def test_lsa_presence():
    logger.info("Test: verify presence of LSAs in OSPF database")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = "rt1"
    for lsa_name, part in expected_parts.items():
        logger.info('"%s" checking presence of lsa "%s"', router, lsa_name)
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 database json",
            part,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, f'{router} missing LSA {lsa_name}.'


def test_lsa_presence_area4():
    logger.info("Test: verify presence of Network LSAs in OSPF database")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = "rt9"
    lsa_name, part = "Network", expected_network_lsa_part
    logger.info('"%s" checking presence of lsa "%s"', router, lsa_name)
    test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 database json",
            part,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f'{router} missing LSA {lsa_name}.'


def test_network_lsa_detail():
    logger.info("Test: verify detail of Network LSAs in OSPF database")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = "rt9"
    lsa_name, part = "Network", expected_network_lsa_detail_part
    logger.info('"%s" checking presence of lsa "%s"', router, lsa_name)
    test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 database detail json",
            part,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f'{router} missing LSA detail {lsa_name}.'


def test_lsa_detail():
    logger.info("Test: verify detail json output of LSAs in OSPF database")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = "rt1"
    for lsa_name, part in expected_detail_parts.items():
        logger.info('"%s" checking presence of lsa detail "%s"', router, lsa_name)

        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 database detail json",
            part,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, f'{router} missing LSA detail {lsa_name}.'


def run_and_expect_absence(func, what, count=3, wait=1):
    """
    Run `func` and compare the result with `what`. Do it for `count` times
    waiting `wait` seconds between tries.

    Returns (True, func-return) on success or
    (False, func-return) on failure.
    """
    start_time = time.time()
    func_name = "<unknown>"
    if func.__class__ == functools.partial:
        func_name = func.func.__name__
    else:
        func_name = func.__name__

    # Just a safety-check to avoid running topotests with very
    # small wait/count arguments.
    wait_time = wait * count
    if wait_time < 5:
        assert (
            wait_time >= 5
        ), "Waiting time is too small (count={}, wait={}), adjust timer values".format(
            count, wait
        )

    logger.debug(
        "'{}' polling started (interval {} secs, maximum {} tries)".format(
            func_name, wait, count
        )
    )

    while count > 0:
        result = func()
        if result != what:
            time.sleep(wait)
            count -= 1
            continue

        end_time = time.time()
        logger.debug(
            "'{}' succeeded after {:.2f} seconds".format(
                func_name, end_time - start_time
            )
        )
        return (False, result)

    end_time = time.time()
    logger.debug(
        "'{}' needle not found in haystack after {:.2f} seconds".format(func_name, end_time - start_time)
    )
    return (True, result)



# Let the test for absence run after the test for presence,
# with a short timeout.
def test_lsa_absence():
    logger.info("Test: verify absence of LSAs in OSPF database")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = "rt1"
    for lsa_name, part in expected_absent_parts.items():
        logger.info('"%s" checking absence of lsa "%s"', router, lsa_name)
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 database json",
            part,
        )
        _, result = run_and_expect_absence(test_func, None, count=5, wait=1)
        assert result is not None, f'{router} LSDB must not contain E-LSA {lsa_name}.'


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
