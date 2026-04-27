#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_multiple_clusters.py
# Test BGP multiple cluster features in a two route reflector topology
#

r"""
Test BGP multiple clusters feature in a multi-layer route reflector topology.

Topology:

   +------+            +------+
   |  R1--|-          -|--R6  |
   |      | \   R9   / |      |
C1 |      |  \ /  \ /  |      | C3
   |  R2--|---R4--R5---|--R7  |
   +------+  /      \  +------+
   +------+ /        \ +------+
C2 |  R3--|-          -|--R8  | C2
   +------+            +------+

All routers are in AS 100 (IBGP).
R4 and R5 are configured as a route reflector with their neighbors as clients. They form with r9 a full-mesh of non-client peers.
They each oversee two clusters of clients
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """Build the multi-layer RR topology"""

    # Create routers
    for routern in range(1, 10):
        tgen.add_router("r{}".format(routern))

    # Layer 1 connections (r1-r2 to r3-r4)
    # r1 to r4
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    # r2 to r4
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    # r3 to r4
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    # r5 to r6
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r6"])

    # r5 to r7
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r7"])

    # r5 to r8
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r8"])

    # r4 to r5
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])

     # r4 to r9
    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r9"])

    # r5 to r9
    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r9"])


def setup_module(mod):
    """Setup the test environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()


def teardown_module(mod):
    """Teardown the test environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """Test that BGP sessions are established"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP convergence")

    # Expected neighbor counts for each router
    expected_neighbors = {
        "r1": 1,  # r4
        "r2": 1,  # r4
        "r3": 1,  # r4
        "r4": 5,  # r1, r2, r3, r5, r9
        "r5": 5,  # r4, r6, r7, r8, r9
        "r6": 1,  # r5
        "r7": 1,  # r5
        "r8": 1,  # r5
        "r9": 2,  # r4, r5
    }

    for rname, expected_count in expected_neighbors.items():
        router = tgen.gears[rname]

        def check_bgp_session(router, expected_count):
            output = router.vtysh_cmd("show bgp summary json")
            try:
                parsed = json.loads(output)
                ipv4_summary = parsed.get("ipv4Unicast", {})
                peers = ipv4_summary.get("peers", {})
                established_count = sum(
                    1 for peer in peers.values() if peer.get("state") == "Established"
                )

                if established_count == expected_count:
                    logger.info(
                        "{}: {} BGP sessions established".format(
                            router.name, established_count
                        )
                    )
                    return True
                else:
                    logger.info(
                        "{}: {}/{} BGP sessions established (waiting)".format(
                            router.name, established_count, expected_count
                        )
                    )
                    return False
            except (json.JSONDecodeError, KeyError):
                return False
        test_func = functools.partial(check_bgp_session, router, expected_count)
        success, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
        assert success, "{} BGP sessions did not converge".format(rname)


def check_routes_cluster_list(router, prefixes, expected_cluster_lists):
    """Check that router receives a prefix with the correct cluster list"""

    if len(prefixes) != len(expected_cluster_lists):
        logger.info("wrong input for router {}".format(router.name))
        return None

    #Check that there are no unwanted prefix
    output = router.vtysh_cmd("show ip bgp json")
    parsed = json.loads(output)
    totalRoutes = parsed.get("totalRoutes")
    if totalRoutes != len(prefixes) + 1: # we don't check for the loopback address
        logger.info(
            "{}: expected {} prefixes, got {} (waiting)".format(
                router.name,len(prefixes)+1,totalRoutes
            )
        )
        return None

    #Check cluster lists
    for i,prefix in enumerate(prefixes):
        try:
            expected_cluster_list = expected_cluster_lists[i]
            output = router.vtysh_cmd("show ip bgp {} json".format(prefix))
            parsed = json.loads(output)
            paths = parsed.get("paths", [])

            if not paths:
                logger.info(
                    "{}: No paths found for {} (waiting for BGP convergence)".format(
                        router.name, prefix
                    )
                )
                return None

            #Check that there is only one path
            if len(paths) > 1:
                logger.info(
                    "{}: Expected 1 path, got {} (waiting)".format(
                        router.name, len(paths)
                    )
                )
                return None

            #Check that the cluster list is as intended
            cluster_list = paths[0].get("clusterList", [])["list"]
            if cluster_list != expected_cluster_list:
                logger.info(
                    "{}: prefix {} Expected cluster list {}, got {} (waiting)".format(
                        router.name, prefix, expected_cluster_list,cluster_list
                    )
                )
                return None

        except (json.JSONDecodeError, KeyError) as e:
            logger.info("{}: Error parsing BGP output: {}".format(router.name, e))
            return None
    return True


def test_bgp_multiple_cluster_cluster_lists():
    """Test that prefix are correctly reflected between per-neighbor clusters with correct cluster list"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing cluster-lists of prefixes on r1, r2, r3, r6, r7, r8 and r9")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r6 = tgen.gears["r6"]
    r7 = tgen.gears["r7"]
    r8 = tgen.gears["r8"]
    r9 = tgen.gears["r9"]

    expected_results = {
        r1:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        },
        r2:{
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r3:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.6":["20.0.0.2","20.0.0.3"],
            "10.0.0.7":["20.0.0.2","20.0.0.3"],
            "10.0.0.9":["20.0.0.2"],
        },
        r6:{
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.1":["20.0.0.3","20.0.0.1"],
            "10.0.0.2":["20.0.0.3","20.0.0.1"],
            "10.0.0.9":["20.0.0.3"],
        },
        r7:{
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.1":["20.0.0.3","20.0.0.1"],
            "10.0.0.2":["20.0.0.3","20.0.0.1"],
            "10.0.0.9":["20.0.0.3"],
        },
        r8:{
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.2","20.0.0.1"],
            "10.0.0.2":["20.0.0.2","20.0.0.1"],
            "10.0.0.9":["20.0.0.2"],
        },
    }
    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=2)
        assert success, "{}: incorrect cluster lists".format(r.name)


def test_client_to_client_reflection_per_neighbor_cluster():
    """Test that client_to_client_reflection works as intended inside of and between per-neighbor clusters"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r9 = tgen.gears["r9"]

    logger.info("Testing cluster-lists of prefixes on r1, r2, r3 and r9 with no reflection in cluster 20.0.0.1 ")

    r4.vtysh_cmd("configure \n\
                  router bgp 100 \n\
                  bgp cluster-id per-neighbor 20.0.0.1 client-to-client-reflection never\n")

    expected_results = {
        r1:{
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r2:{
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r3:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.6":["20.0.0.2","20.0.0.3"],
            "10.0.0.7":["20.0.0.2","20.0.0.3"],
            "10.0.0.9":["20.0.0.2"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        }
    }

    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=2)
        assert success, "{}: incorrect cluster lists".format(r.name)

    logger.info("Testing cluster-lists of prefixes on r1, r2, r3 and r9 with no reflection in cluster 20.0.0.1 and no client-to-client reflection")

    r4.vtysh_cmd("configure \n\
                  router bgp 100 \n\
                  no bgp client-to-client reflection\n")

    expected_results = {
        r1:{
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r2:{
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r3:{
            "10.0.0.6":["20.0.0.2","20.0.0.3"],
            "10.0.0.7":["20.0.0.2","20.0.0.3"],
            "10.0.0.9":["20.0.0.2"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        }
    }

    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=2)
        assert success, "{}: incorrect cluster lists".format(r.name)

    logger.info("Testing cluster-lists of prefixes on r1, r2, r3 and r9 with reflection in cluster 20.0.0.1 and no client-to-client reflection")

    r4.vtysh_cmd("""
                 configure
                 router bgp 100
                 bgp cluster-id per-neighbor 20.0.0.1 client-to-client-reflection always
                 """)

    expected_results = {
        r1:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r2:{
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r3:{
            "10.0.0.6":["20.0.0.2","20.0.0.3"],
            "10.0.0.7":["20.0.0.2","20.0.0.3"],
            "10.0.0.9":["20.0.0.2"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        }
    }
    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
        assert success, "{}: incorrect cluster lists".format(r.name)

    #reset of the configuration
    r4.vtysh_cmd("""
                  configure
                  router bgp 100
                  no bgp cluster-id per-neighbor 20.0.0.1 client-to-client-reflection
                  bgp client-to-client reflection
                 """ )


def test_client_to_client_reflection_global_cluster():
    """Test that client_to_client_reflection works as intended inside of and between per-neighbor clusters"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r9 = tgen.gears["r9"]

    logger.info("Testing cluster-lists of prefixes on r1, r2, r3 and r9 with no reflection in global cluster")
    r4.vtysh_cmd("""
                  configure
                  router bgp 100
                  bgp cluster-id global client-to-client-reflection never
                  bgp cluster-id 20.0.0.1
                 """)

    expected_results = {
        r1:{
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r2:{
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r3:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.6":["20.0.0.2","20.0.0.3"],
            "10.0.0.7":["20.0.0.2","20.0.0.3"],
            "10.0.0.9":["20.0.0.2"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        }
    }

    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
        assert success, "{}: incorrect cluster lists".format(r.name)

    logger.info("Testing cluster-lists of prefixes on r1, r2, r3 and r9 with no reflection in global cluster and no client-to-client reflection")

    r4.vtysh_cmd("""
                  configure
                  router bgp 100
                  no bgp client-to-client reflection
                 """)

    expected_results = {
        r1:{
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r2:{
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r3:{
            "10.0.0.6":["20.0.0.2","20.0.0.3"],
            "10.0.0.7":["20.0.0.2","20.0.0.3"],
            "10.0.0.9":["20.0.0.2"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        }
    }

    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
        assert success, "{}: incorrect cluster lists".format(r.name)

    logger.info("Testing cluster-lists of prefixes on r1, r2, r3 and r9 with reflection in global cluster and no client-to-client reflection")

    r4.vtysh_cmd("""configure
                 router bgp 100
                 bgp cluster-id global client-to-client-reflection always""")

    expected_results = {
        r1:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r2:{
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r3:{
            "10.0.0.6":["20.0.0.2","20.0.0.3"],
            "10.0.0.7":["20.0.0.2","20.0.0.3"],
            "10.0.0.9":["20.0.0.2"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        }
    }

    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=1)
        assert success, "{}: incorrect cluster lists".format(r.name)

    #reset of the configuration
    r4.vtysh_cmd("""configure
                  router bgp 100
                  no bgp cluster-id global client-to-client-reflection
                  bgp client-to-client reflection
                  bgp cluster-id 10.0.0.4""" )


def test_bgp_multiple_cluster_prefer_global_cluster_configuration():
    """Test that prefix are correctly reflected between per-neighbor clusters with correct cluster list
    whenever non-client-to-client prefer-global-cluster-id is configured"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


    logger.info("Testing cluster-lists of prefixes on r1, r2, r3, r6, r7, r8 and r9")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r5 = tgen.gears["r5"]
    r6 = tgen.gears["r6"]
    r7 = tgen.gears["r7"]
    r8 = tgen.gears["r8"]
    r9 = tgen.gears["r9"]

    r4.vtysh_cmd("""configure
                  router bgp 100
                  bgp cluster-id non-client-to-client prefer-global-cluster-id""")
    r5.vtysh_cmd("""configure
                  router bgp 100
                  bgp cluster-id non-client-to-client prefer-global-cluster-id""")

    expected_results = {
        r1:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.7":["10.0.0.4","20.0.0.3"],
            "10.0.0.6":["10.0.0.4","20.0.0.3"],
            "10.0.0.9":["10.0.0.4"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        },
        r2:{
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.6":["10.0.0.4","20.0.0.3"],
            "10.0.0.7":["10.0.0.4","20.0.0.3"],
            "10.0.0.9":["10.0.0.4"],
        },
        r3:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.6":["10.0.0.4","20.0.0.3"],
            "10.0.0.7":["10.0.0.4","20.0.0.3"],
            "10.0.0.9":["10.0.0.4"],
        },
        r6:{
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.1":["10.0.0.5","20.0.0.1"],
            "10.0.0.2":["10.0.0.5","20.0.0.1"],
            "10.0.0.9":["10.0.0.5"],
        },
        r7:{
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.1":["10.0.0.5","20.0.0.1"],
            "10.0.0.2":["10.0.0.5","20.0.0.1"],
            "10.0.0.9":["10.0.0.5"],
        },
        r8:{
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["10.0.0.5","20.0.0.1"],
            "10.0.0.2":["10.0.0.5","20.0.0.1"],
            "10.0.0.9":["10.0.0.5"],
        },
    }
    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=2)
        assert success, "{}: incorrect cluster lists".format(r.name)

    #reset of the configuration
    r4.vtysh_cmd("""configure
                  router bgp 100
                  no bgp cluster-id non-client-to-client prefer-global-cluster-id""")
    r5.vtysh_cmd("""configure
                  router bgp 100
                  no bgp cluster-id non-client-to-client prefer-global-cluster-id""")


def test_bgp_multiple_cluster_loose_cluster_check_configuration():
    """Test that prefix are correctly reflected between per-neighbor clusters with correct cluster list
    whenever loose-cluster-list-check is configured"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


    logger.info("Testing cluster-lists of prefixes on r1, r2, r3, r6, r7, r8 and r9")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r5 = tgen.gears["r5"]
    r6 = tgen.gears["r6"]
    r7 = tgen.gears["r7"]
    r8 = tgen.gears["r8"]
    r9 = tgen.gears["r9"]

    r4.vtysh_cmd("""configure
                  router bgp 100
                  bgp cluster-id loose-cluster-list-check""")
    r5.vtysh_cmd("""configure
                  router bgp 100
                  bgp cluster-id loose-cluster-list-check""")

    expected_results = {
        r1:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.8":["20.0.0.1","20.0.0.2"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.9":["20.0.0.1"],
        },
        r9:{
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
        },
        r2:{
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.3":["20.0.0.2"],
            "10.0.0.6":["20.0.0.1","20.0.0.3"],
            "10.0.0.7":["20.0.0.1","20.0.0.3"],
            "10.0.0.8":["20.0.0.1","20.0.0.2"],
            "10.0.0.9":["20.0.0.1"],
        },
        r3:{
            "10.0.0.2":["20.0.0.1"],
            "10.0.0.1":["20.0.0.1"],
            "10.0.0.6":["20.0.0.2","20.0.0.3"],
            "10.0.0.7":["20.0.0.2","20.0.0.3"],
            "10.0.0.9":["20.0.0.2"],
        },
        r6:{
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.1":["20.0.0.3","20.0.0.1"],
            "10.0.0.2":["20.0.0.3","20.0.0.1"],
            "10.0.0.3":["20.0.0.3","20.0.0.2"],
            "10.0.0.9":["20.0.0.3"],
        },
        r7:{
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.8":["20.0.0.2"],
            "10.0.0.1":["20.0.0.3","20.0.0.1"],
            "10.0.0.2":["20.0.0.3","20.0.0.1"],
            "10.0.0.3":["20.0.0.3","20.0.0.2"],
            "10.0.0.9":["20.0.0.3"],
        },
        r8:{
            "10.0.0.7":["20.0.0.3"],
            "10.0.0.6":["20.0.0.3"],
            "10.0.0.1":["20.0.0.2","20.0.0.1"],
            "10.0.0.2":["20.0.0.2","20.0.0.1"],
            "10.0.0.9":["20.0.0.2"],
        },
    }
    for r in expected_results.keys():
        logger.info("Checking {} routes".format(r.name))

        test_func = functools.partial(
            check_routes_cluster_list,
            r,
            list(expected_results[r].keys()),
            [expected_results[r][k] for k in expected_results[r].keys()]
        )
        success, result = topotest.run_and_expect(test_func, True, count=20, wait=2)
        assert success, "{}: incorrect cluster lists".format(r.name)

    #reset of the configuration
    r4.vtysh_cmd("""configure
                  router bgp 100
                  no bgp cluster-id loose-cluster-list-check""")
    r5.vtysh_cmd("""configure
                  router bgp 100
                  no bgp cluster-id loose-cluster-list-check""")

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
