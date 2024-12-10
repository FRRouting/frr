#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_isis_tilfa_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_isis_tilfa_topo1.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+
         |         |                     |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |
         |         |eth-rt5       eth-rt4|         |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
"""

import os
import sys
import pytest
import json
<<<<<<< HEAD
import tempfile
from functools import partial
=======
from functools import partial
from time import sleep
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.isisd]

# Global multi-dimensional dictionary containing all expected outputs
outputs = {}


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for router in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        tgen.add_router(router)

    #
    # Define connections
    #
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-1")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-2")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")

<<<<<<< HEAD
    #
    # Populate multi-dimensional dictionary containing all expected outputs
    #
    files = [
        "show_ip_route.ref",
        "show_ipv6_route.ref",
        "show_mpls_table.ref",
        "show_yang_interface_isis_adjacencies.ref",
    ]
    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        outputs[rname] = {}
        for step in range(1, 12 + 1):
            outputs[rname][step] = {}
            for file in files:
                if step == 1:
                    # Get snapshots relative to the expected initial network convergence
                    filename = "{}/{}/step{}/{}".format(CWD, rname, step, file)
                    outputs[rname][step][file] = open(filename).read()
                else:
                    if file == "show_yang_interface_isis_adjacencies.ref":
                        continue

                    # Get diff relative to the previous step
                    filename = "{}/{}/step{}/{}.diff".format(CWD, rname, step, file)

                    # Create temporary files in order to apply the diff
                    f_in = tempfile.NamedTemporaryFile(mode="w")
                    f_in.write(outputs[rname][step - 1][file])
                    f_in.flush()
                    f_out = tempfile.NamedTemporaryFile(mode="r")
                    os.system(
                        "patch -s -o %s %s %s" % (f_out.name, f_in.name, filename)
                    )

                    # Store the updated snapshot and remove the temporary files
                    outputs[rname][step][file] = open(f_out.name).read()
                    f_in.close()
                    f_out.close()

=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

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
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        router.load_config(
<<<<<<< HEAD
            TopoRouter.RD_BFD, os.path.join(CWD, "/dev/null".format(rname))
=======
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )

    tgen.start_router()


<<<<<<< HEAD
def teardown_module(mod):
=======
def teardown_module():
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


<<<<<<< HEAD
def router_compare_json_output(rname, command, reference, count=120, wait=0.5):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
=======
def filter_json(data, keys_to_keep):
    """
    Filters a dictionary, keeping only the specified keys.
    """
    return {k: v for k, v in data.items() if k in keys_to_keep}


def regen_data(rname, command, step, file, wait):
    """
    Regenerates reference data.
    """
    # Sleep enough time to ensure the protocol has converged
    if rname == "rt1":
        sleep(wait)
    if step == 10:
        sleep(10)

    # Get and parse JSON output
    tgen = get_topogen()
    output = json.loads(tgen.gears[rname].vtysh_cmd(command))

    # Default JSON separators
    separators = (",", ":")

    # Process JSON output based on the specified file
    if file == "show_yang_interface_isis_adjacencies.ref":
        # Filter out the loopback interface
        output["frr-interface:lib"]["interface"] = [
            interface
            for interface in output["frr-interface:lib"]["interface"]
            if interface["name"] != "lo"
        ]

        # Filter out unwanted fields
        for interface in output["frr-interface:lib"]["interface"]:
            keys_to_keep = {"name", "vrf", "state"}
            filtered_interface = filter_json(interface, keys_to_keep)
            interface.clear()
            interface.update(filtered_interface)

            keys_to_keep = {"frr-isisd:isis"}
            filtered_state = filter_json(interface["state"], keys_to_keep)
            interface["state"].clear()
            interface["state"].update(filtered_state)

            keys_to_keep = {"adjacencies"}
            filtered_isis = filter_json(
                interface["state"]["frr-isisd:isis"], keys_to_keep
            )
            interface["state"]["frr-isisd:isis"].clear()
            interface["state"]["frr-isisd:isis"].update(filtered_isis)
            if "adjacencies" in interface["state"]["frr-isisd:isis"]:
                for adjacency in interface["state"]["frr-isisd:isis"]["adjacencies"][
                    "adjacency"
                ]:
                    keys_to_keep = {
                        "neighbor-sys-type",
                        "neighbor-sysid",
                        "hold-timer",
                        "neighbor-priority",
                        "state",
                    }
                    filtered_adjacency = filter_json(adjacency, keys_to_keep)
                    adjacency.clear()
                    adjacency.update(filtered_adjacency)
        # Adjust separators to match libyang's output.
        separators = (",", ": ")

    elif file == "show_ip_route.ref" or file == "show_ipv6_route.ref":
        # Filter out unwanted fields
        keys_to_keep_route = {
            "prefix",
            "protocol",
            "selected",
            "destSelected",
            "distance",
            "metric",
            "installed",
            "nexthops",
            "backupNexthops",
        }
        keys_to_keep_nh = {
            "fib",
            "ip",
            "afi",
            "interfaceName",
            "active",
            "backupIndex",
            "labels",
        }
        for prefix_key, prefix_value in output.items():
            filtered_routes = []
            for route in prefix_value:
                if "nexthops" in route:
                    filtered_nhs = []
                    for nh in route["nexthops"]:
                        if nh["ip"].startswith("fe80"):
                            del nh["ip"]
                        filtered_nhs.append(filter_json(nh, keys_to_keep_nh))
                    route["nexthops"] = filtered_nhs
                if "backupNexthops" in route:
                    filtered_nhs = []
                    for nh in route["backupNexthops"]:
                        if nh["ip"].startswith("fe80"):
                            del nh["ip"]
                        filtered_nhs.append(filter_json(nh, keys_to_keep_nh))
                    route["backupNexthops"] = filtered_nhs
                filtered_routes.append(filter_json(route, keys_to_keep_route))
            output[prefix_key] = filtered_routes

    elif file == "show_mpls_table.ref":
        # Filter out Adj-SID labels
        output = {int(key): value for key, value in output.items() if int(key) >= 16000}

        # Filter out unwanted fields
        keys_to_keep_label = {
            "inLabel",
            "installed",
            "nexthops",
            "backupNexthops",
        }
        keys_to_keep_nh = {
            "type",
            "outLabel",
            "installed",
            "interface",
            "nexthop",
            "backupIndex",
        }
        for label_key, label_value in output.items():
            if "nexthops" in label_value:
                filtered_nhs = []
                for nh in label_value["nexthops"]:
                    if nh["nexthop"].startswith("fe80"):
                        del nh["nexthop"]
                    filtered_nhs.append(filter_json(nh, keys_to_keep_nh))
                label_value["nexthops"] = filtered_nhs
            if "backupNexthops" in label_value:
                filtered_nhs = []
                for nh in label_value["backupNexthops"]:
                    if nh["nexthop"].startswith("fe80"):
                        del nh["nexthop"]
                    filtered_nhs.append(filter_json(nh, keys_to_keep_nh))
                label_value["backupNexthops"] = filtered_nhs
            output[label_key] = filter_json(label_value, keys_to_keep_label)

    elif file.startswith("show_bfd_peer"):
        keys_to_keep = ["multihop", "peer", "interface", "status"]
        output = filter_json(output, keys_to_keep)

    # Save the processed output to a file
    filename = "{}/{}/step{}/{}".format(CWD, rname, step, file)
    output = json.dumps(output, separators=separators, indent=2).replace("/", "\\/")
    with open(filename, "w", encoding="ascii") as file:
        file.write(output + "\n")


def router_compare_json_output(rname, command, step, file, count=120, wait=0.5):
    "Compare router JSON output"

    # Regenerate reference data when the REGEN_DATA environment variable is set
    if os.environ.get("REGEN_DATA") is not None:
        regen_data(rname, command, step, file, count * wait)
        return

    tgen = get_topogen()
    logger.info('Comparing router "%s" "%s" output', rname, command)
    reference = open("{}/{}/step{}/{}".format(CWD, rname, step, file)).read()
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    expected = json.loads(reference)

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


#
# Step 1
#
# Test initial network convergence
#
def test_isis_adjacencies_step1():
    logger.info("Test (step 1): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
<<<<<<< HEAD
            outputs[rname][1]["show_yang_interface_isis_adjacencies.ref"],
=======
            1,
            "show_yang_interface_isis_adjacencies.ref",
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv4_step1():
    logger.info("Test (step 1): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][1]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 1, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][1]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 1, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step1():
    logger.info("Test (step 1): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][1]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 1, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 2
#
# Action(s):
# -Disable TI-LFA link protection on rt2's eth-sw1 interface
#
# Expected changes:
# -rt2 should uninstall the backup nexthops from destinations reachable over eth-sw1.
#
def test_rib_ipv4_step2():
    logger.info("Test (step 2): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling TI-LFA link protection on rt2's eth-sw1 interface")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "interface eth-sw1" -c "no isis fast-reroute ti-lfa"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][2]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 2, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step2():
    logger.info("Test (step 2): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][2]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 2, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step2():
    logger.info("Test (step 2): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][2]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 2, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 3
#
# Action(s):
# -Enable TI-LFA link protection on rt2's eth-sw1 interface
#
# Expected changes:
# -rt2 should install backup nexthops for destinations reachable over eth-sw1.
#
def test_rib_ipv4_step3():
    logger.info("Test (step 3): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling TI-LFA link protection on rt2's eth-sw1 interface")
    tgen.net["rt2"].cmd(
        'vtysh -c "conf t" -c "interface eth-sw1" -c "isis fast-reroute ti-lfa"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][3]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 3, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step3():
    logger.info("Test (step 3): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][3]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 3, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step3():
    logger.info("Test (step 3): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][3]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 3, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 4
#
# Action(s):
# -Disable SR on rt4
#
# Expected changes:
# -rt4 should uninstall all Prefix-SIDs from the network
# -rt4 should uninstall all TI-LFA backup nexthops
# -All routers should uninstall rt4's Prefix-SIDs
# -All routers should uninstall all SR labels for destinations whose nexthop is rt4
# -All routers should uninstall all TI-LFA backup nexthops that point to rt4
# -All routers should uninstall all TI-LFA backup nexthops that use rt4's Prefix-SIDs
#
def test_rib_ipv4_step4():
    logger.info("Test (step 4): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling SR on rt4")
    tgen.net["rt4"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no segment-routing on"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][4]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 4, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step4():
    logger.info("Test (step 4): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][4]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 4, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step4():
    logger.info("Test (step 4): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][4]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 4, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 5
#
# Action(s):
# -Enable SR on rt4
#
# Expected changes:
# -Reverse all changes done on the previous step
#
def test_rib_ipv4_step5():
    logger.info("Test (step 5): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling SR on rt4")
    tgen.net["rt4"].cmd('vtysh -c "conf t" -c "router isis 1" -c "segment-routing on"')

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][5]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 5, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step5():
    logger.info("Test (step 5): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][5]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 5, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step5():
    logger.info("Test (step 5): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][5]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 5, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 6
#
# Action(s):
# -Change rt5's SRGB
#
# Expected changes:
# -All routers should update all SR labels for destinations whose primary or backup nexthop is rt5
#
def test_rib_ipv4_step6():
    logger.info("Test (step 6): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Changing rt5's SRGB")
    tgen.net["rt5"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "segment-routing global-block 30000 37999"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][6]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 6, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step6():
    logger.info("Test (step 6): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][6]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 6, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step6():
    logger.info("Test (step 6): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][6]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 6, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 7
#
# Action(s):
# -Delete rt5's Prefix-SIDs
#
# Expected changes:
# -All routers should uninstall rt5's Prefix-SIDs
# -All routers should uninstall all TI-LFA backup nexthops that use rt5's Prefix-SIDs
#
def test_rib_ipv4_step7():
    logger.info("Test (step 7): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Deleting rt5's Prefix-SIDs")
    tgen.net["rt5"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no segment-routing prefix 5.5.5.5/32 index 50"'
    )
    tgen.net["rt5"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "no segment-routing prefix 2001:db8:1000::5/128 index 51"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][7]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 7, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step7():
    logger.info("Test (step 7): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][7]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 7, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step7():
    logger.info("Test (step 7): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][7]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 7, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 8
#
# Action(s):
# -Re-add rt5's Prefix-SIDs
#
# Expected changes:
# -Reverse all changes done on the previous step
#
def test_rib_ipv4_step8():
    logger.info("Test (step 8): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Re-adding rt5's Prefix-SIDs")
    tgen.net["rt5"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "segment-routing prefix 5.5.5.5/32 index 50"'
    )
    tgen.net["rt5"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "segment-routing prefix 2001:db8:1000::5/128 index 51"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][8]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 8, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step8():
    logger.info("Test (step 8): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][8]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 8, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step8():
    logger.info("Test (step 8): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][8]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 8, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 9
#
# Action(s):
# -Change rt5's Prefix-SIDs
#
# Expected changes:
# -All routers should update rt5's Prefix-SIDs
# -All routers should update all TI-LFA backup nexthops that use rt5's Prefix-SIDs
#
def test_rib_ipv4_step9():
    logger.info("Test (step 9): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Re-adding rt5's Prefix-SIDs")
    tgen.net["rt5"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "segment-routing prefix 5.5.5.5/32 index 500"'
    )
    tgen.net["rt5"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "segment-routing prefix 2001:db8:1000::5/128 index 501"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ip route isis json", outputs[rname][9]["show_ip_route.ref"]
=======
            rname, "show ip route isis json", 9, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step9():
    logger.info("Test (step 9): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show ipv6 route isis json", outputs[rname][9]["show_ipv6_route.ref"]
=======
            rname, "show ipv6 route isis json", 9, "show_ipv6_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step9():
    logger.info("Test (step 9): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
<<<<<<< HEAD
            rname, "show mpls table json", outputs[rname][9]["show_mpls_table.ref"]
=======
            rname, "show mpls table json", 9, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


#
# Step 10
#
# Action(s):
<<<<<<< HEAD
# - Setting spf-delay-ietf init-delay of 15s
#
# Expected changes:
# - No routing table change
# - At the end of test, SPF reacts to a failure in 15s
=======
# - Enable ISIS BFD between rt5 and rt6
# - Verify that the BFD session is up
# - Configure an SPF delay-ietf initial delay of 60 seconds on both rt5 and rt6
# - Shut down the eth-rt5 interface on rt6 from the switch side to test fast-reroute
#
# Expected changes:
# - Verify that the BFD session is down
# - Routes should switch over to use alternate paths
#   - On rt5, the switchover should be triggered by the link down event
#   - On rt6, the switchover should be triggered by the BFD down event, since it has
#     link-detect disabled on the eth-rt5 interface
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
#
def test_rib_ipv4_step10():
    logger.info("Test (step 10): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

<<<<<<< HEAD
    logger.info("Setting spf-delay-ietf init-delay of 15s")
    tgen.net["rt6"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "spf-delay-ietf init-delay 15000 short-delay 0 long-delay 0 holddown 0 time-to-learn 0"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][10]["show_ip_route.ref"]
=======
    logger.info("Enabling ISIS BFD between rt5 and rt6")
    tgen.net["rt5"].cmd('vtysh -c "conf t" -c "int eth-rt6" -c "isis bfd"')
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "int eth-rt5" -c "isis bfd"')

    logger.info("Checking if the BFD session is up")
    expect = '{"multihop":false,"peer":"10.0.8.5","interface":"eth-rt5","status":"up"}'
    router_compare_json_output(
        "rt6", "show bfd peer 10.0.8.5 json", 10, "show_bfd_peer_up.ref"
    )

    logger.info("Setting SPF delay-ietf initial delay to 60 seconds")
    for rname in ["rt5", "rt6"]:
        tgen.net[rname].cmd(
            'vtysh -c "conf t" -c "router isis 1" -c "spf-delay-ietf init-delay 60000 short-delay 0 long-delay 0 holddown 0 time-to-learn 0"'
        )

    logger.info(
        "Shutting down rt5 interface to rt6 from the switch side to test fast-reroute"
    )
    tgen.net.cmd_raises("ip link set %s down" % tgen.net["s8"].intfs[0])

    logger.info("Verifying if the BFD session is down")
    expect = (
        '{"multihop":false,"peer":"10.0.8.5","interface":"eth-rt5","status":"down"}'
    )
    router_compare_json_output(
        "rt6", "show bfd peer 10.0.8.5 json", 10, "show_bfd_peer_down.ref"
    )

    for rname in ["rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", 10, "show_ip_route.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_rib_ipv6_step10():
    logger.info("Test (step 10): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

<<<<<<< HEAD
    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][10]["show_ipv6_route.ref"],
=======
    for rname in ["rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            10,
            "show_ipv6_route.ref",
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


def test_mpls_lib_step10():
    logger.info("Test (step 10): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

<<<<<<< HEAD
    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", outputs[rname][10]["show_mpls_table.ref"]
        )


#
# Step 11
#
# Action(s):
# - shut the eth-rt5 interface on rt6
#
# Expected changes:
# - Route switchover of routes via eth-rt5
#
def test_rt6_step11():
    logger.info(
        "Test (step 11): Check IPv4/6 RIB and MPLS table after a LFA switchover"
    )
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Shut a rt6 interface to rt5 from the switch side and check fast-reroute"
    )
    tgen.net.cmd_raises("ip link set %s down" % tgen.net["s8"].intfs[1])

    rname = "rt6"
    router_compare_json_output(
        rname,
        "show ip route isis json",
        outputs[rname][11]["show_ip_route.ref"],
        count=10,
    )
    router_compare_json_output(
        rname,
        "show ipv6 route isis json",
        outputs[rname][11]["show_ipv6_route.ref"],
        count=10,
    )
    router_compare_json_output(
        rname,
        "show mpls table json",
        outputs[rname][11]["show_mpls_table.ref"],
        count=10,
    )


#
# Step 12
#
# Action(s): wait for the convergence and SPF computation on rt6
#
# Expected changes:
# - convergence of IPv4/6 RIB and MPLS table
#
def test_rib_ipv4_step12():
    logger.info("Test (step 12): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check SPF convergence")
    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show ip route isis json",
            outputs[rname][12]["show_ip_route.ref"],
        )


def test_rib_ipv6_step12():
    logger.info("Test (step 12): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][12]["show_ipv6_route.ref"],
        )


def test_mpls_lib_step12():
    logger.info("Test (step 12): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show mpls table json",
            outputs[rname][12]["show_mpls_table.ref"],
        )


#
# Step 13
#
# Action(s):
# - unshut the rt6 to rt5 interface
# - Setup BFD
#
# Expected changes:
# - All route tables go back to previous state situation
# - At the end of test, next SPF is scheduled in approximatively 15s
#
def test_rib_ipv4_step13():
    logger.info("Test (step 13): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Unsetting spf-delay-ietf init-delay of 15s")
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "router isis 1" -c "no spf-delay-ietf"')

    logger.info(
        "Unshut the rt6 interface to rt5 from the switch side and check fast-reroute"
    )
    tgen.net.cmd_raises("ip link set %s up" % tgen.net["s8"].intfs[1])

    logger.info("Setup BFD on rt5 and rt6")
    for rname in ["rt5", "rt6"]:
        conf_file = os.path.join(CWD, "{}/bfdd.conf".format(rname))
        tgen.net[rname].cmd("vtysh -f {}".format(conf_file))

    expect = (
        '[{"multihop":false,"peer":"10.0.8.5","interface":"eth-rt5","status":"up"}]'
    )
    router_compare_json_output("rt6", "show bfd peers json", expect)

    # Unset link detection. We want zebra to consider linkdow as operationaly up
    # in order that BFD triggers LFA instead of the interface down

    # reset spf-interval
    logger.info("Set spf-interval to 15s")
    tgen.net["rt6"].cmd(
        'vtysh -c "conf t" -c "router isis 1" -c "spf-delay-ietf init-delay 15000 short-delay 0 long-delay 0 holddown 0 time-to-learn 0"'
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", outputs[rname][10]["show_ip_route.ref"]
        )

    logger.info("Set ISIS BFD")
    tgen.net["rt5"].cmd('vtysh -c "conf t" -c "int eth-rt6" -c "isis bfd"')
    tgen.net["rt6"].cmd('vtysh -c "conf t" -c "int eth-rt5" -c "isis bfd"')


def test_rib_ipv6_step13():
    logger.info("Test (step 13): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][10]["show_ipv6_route.ref"],
        )


def test_mpls_lib_step13():
    logger.info("Test (step 13): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", outputs[rname][10]["show_mpls_table.ref"]
        )


#
# Step 14
#
# Action(s):
# - drop traffic between rt5 and rt6 by shutting down the bridge between
#   the routers. Interfaces on rt5 and rt6 stay up.
#
# Expected changes:
# - Route switchover of routes via eth-rt5
#
def test_rt6_step14():
    logger.info("Test (step 14): verify IPv4/6 RIB and MPLS table")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Drop traffic between rt5 and rt6")
    tgen.net.cmd_raises("ip link set s8 down")

    rname = "rt6"

    expect = (
        '[{"multihop":false,"peer":"10.0.8.5","interface":"eth-rt5","status":"down"}]'
    )
    router_compare_json_output(
        rname,
        "show bfd peers json",
        expect,
        count=40,
        wait=0.5,
    )

    router_compare_json_output(
        rname,
        "show ip route isis json",
        outputs[rname][11]["show_ip_route.ref"],
        count=10,
    )
    router_compare_json_output(
        rname,
        "show ipv6 route isis json",
        outputs[rname][11]["show_ipv6_route.ref"],
        count=10,
    )
    router_compare_json_output(
        rname,
        "show mpls table json",
        outputs[rname][11]["show_mpls_table.ref"],
        count=10,
    )


#
# Step 15
#
# Action(s): wait for the convergence and SPF computation on rt6
#
# Expected changes:
# - convergence of IPv4/6 RIB and MPLS table
#
def test_rib_ipv4_step15():
    logger.info("Test (step 15): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check SPF convergence")
    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show ip route isis json",
            outputs[rname][12]["show_ip_route.ref"],
        )


def test_rib_ipv6_step15():
    logger.info("Test (step 15): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show ipv6 route isis json",
            outputs[rname][12]["show_ipv6_route.ref"],
        )


def test_mpls_lib_step15():
    logger.info("Test (step 15): verify MPLS LIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show mpls table json",
            outputs[rname][12]["show_mpls_table.ref"],
=======
    for rname in ["rt5", "rt6"]:
        router_compare_json_output(
            rname, "show mpls table json", 10, "show_mpls_table.ref"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
        )


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
