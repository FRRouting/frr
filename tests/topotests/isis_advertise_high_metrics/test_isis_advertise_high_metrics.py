#!/usr/bin/env python

#
# test_isis_advertise_high_metrics.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

r"""
test_isis_advertise_high_metrics.py: Advertise High Metrics FRR ISIS Test
"""

import os
import re
import sys
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.common_config import (
    retry,
    stop_router,
    start_router,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    "Build function"

    # Add ISIS routers:
    #     r2
    #    /  \
    #  r1   r4
    #    \  /
    #     r3

    #
    # Define FRR Routers
    #
    for router in ["r1", "r2", "r3", "r4"]:
        tgen.add_router(router)
    #
    # Define connections
    #
    switch = tgen.add_switch("s0")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r2")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="eth-r3")
    switch.add_link(tgen.gears["r3"], nodeif="eth-r1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"], nodeif="eth-r4")
    switch.add_link(tgen.gears["r4"], nodeif="eth-r2")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"], nodeif="eth-r4")
    switch.add_link(tgen.gears["r4"], nodeif="eth-r3")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


@retry(retry_timeout=60)
def _check_interface_metrics(router, expected_metrics):
    "Verfiy metrics on router's isis interfaces"

    tgen = get_topogen()
    router = tgen.gears[router]
    logger.info(f"check_interface_metrics {router}")
    isis_interface_output = router.vtysh_cmd("show isis interface detail json")

    intf_json = json.loads(isis_interface_output)
    for i in range(len(expected_metrics)):
        metric = intf_json["areas"][0]["circuits"][i]["interface"]["levels"][0][
            "metric"
        ]
        if metric != expected_metrics[i]:
            intf_name = intf_json["areas"][0]["circuits"][i]["interface"]["name"]
            return "{} with expected metric {} on {} got {}".format(
                router.name, expected_metrics[i], intf_name, metric
            )
    return True


def check_interface_metrics(router, expected_metrics):
    "Verfiy metrics on router's isis interfaces"

    assertmsg = _check_interface_metrics(router, expected_metrics)
    assert assertmsg is True, assertmsg


@retry(retry_timeout=60)
def _check_lsp_metrics(router, lsp, expected_metrics):
    "Verfiy metrics on router's lsp"
    tgen = get_topogen()
    router = tgen.gears[router]
    logger.info(f"check_lsp_metrics {router}")
    isis_lsp_output = router.vtysh_cmd("show isis database detail {}".format(lsp))

    metrics_list = [int(i) for i in re.findall(r"Metric: (\d+)", isis_lsp_output)]
    if len(metrics_list) == 0:
        return False
    for metric in metrics_list:
        if metric not in expected_metrics:
            return "{} with expected metrics {} got {}".format(
                router.name, expected_metrics, metrics_list
            )

    return True


def check_lsp_metrics(router, lsp, expected_metrics):
    "Verfiy metrics on router's lsp"

    assertmsg = _check_lsp_metrics(router, lsp, expected_metrics)
    assert assertmsg is True, assertmsg


@retry(retry_timeout=60)
def _check_ip_route(router, destination, expected_interface):
    "Verfiy IS-IS route"

    tgen = get_topogen()
    router = tgen.gears[router]
    logger.info(f"check_ip_route {router}")
    route_output = router.vtysh_cmd("show ip route {} json".format(destination))
    route_json = json.loads(route_output)

    interface = route_json[destination][0]["nexthops"][0]["interfaceName"]

    if interface != expected_interface:
        return "{} with expected route to {} got {} expected {}".format(
            router.name, destination, interface, expected_interface
        )

    return True


def check_ip_route(router, destination, expected_interface):
    "Verfiy IS-IS route"

    assertmsg = _check_ip_route(router, destination, expected_interface)
    assert assertmsg is True, assertmsg


def test_isis_daemon_up():
    "Check isis daemon up before starting test"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in ["r1", "r2", "r3", "r4"]:
        r = tgen.gears[router]
        daemons = r.vtysh_cmd("show daemons")
        assert "isisd" in daemons

    # Verify initial metric values.
    check_lsp_metrics("r1", "r1.00-00", [10, 20])
    check_lsp_metrics("r2", "r2.00-00", [10, 10])
    check_lsp_metrics("r3", "r3.00-00", [20, 20])
    check_lsp_metrics("r4", "r4.00-00", [10, 20])


def test_isis_advertise_high_metrics():
    "Check that advertise high metrics behaves as expected"

    tgen = get_topogen()
    net = get_topogen().net

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing advertise high metrics basic behavior")

    # Confirm low metrics values on each isis interface on r1
    r1 = tgen.gears["r1"]
    check_interface_metrics("r1", [10, 20])

    # Confirm low metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [10, 20])

    # Configure advertise high metrics
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              advertise-high-metrics
        """
    )

    # Confirm high wide metrics values on each isis interface on r1
    check_interface_metrics("r1", [16777215])

    # Confirm high wide metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [16777215])

    # Remove advertise high metrics
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              no advertise-high-metrics
        """
    )

    # Confirm low metrics values on each isis interface on r1
    check_interface_metrics("r1", [10, 20])

    # Confirm low metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [10, 20])


def test_isis_advertise_high_metrics_narrow():
    "Check that advertise high metrics behaves as expected with narrow metrics"

    tgen = get_topogen()
    net = get_topogen().net

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing advertise high metrics with narrow metric style")

    r1 = tgen.gears["r1"]

    # Configure narrow metric-style
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              metric-style narrow
        """
    )

    # Confirm low metrics values on each isis interface on r1
    check_interface_metrics("r1", [10, 20])

    # Confirm low metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [10, 20])

    # Configure advertise high metrics
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              advertise-high-metrics
        """
    )

    # Confirm high narrow metrics values on each isis interface on r1
    check_interface_metrics("r1", [63])

    # Confirm high narrow metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [63])

    # Remove advertise high metrics
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              no advertise-high-metrics
        """
    )

    # Confirm low metrics values on each isis interface on r1
    check_interface_metrics("r1", [10, 20])

    # Confirm low metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [10, 20])

    # Remove narrow metric-style
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              no metric-style narrow
        """
    )


def test_isis_advertise_high_metrics_transition():
    "Check that advertise high metrics behaves as expected with transition metrics"
    tgen = get_topogen()
    net = get_topogen().net

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing advertise high metrics with transition metric style")

    r1 = tgen.gears["r1"]

    # Configure transition metric-style
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              metric-style transition
        """
    )

    # Confirm low metrics values on each isis interface on r1
    check_interface_metrics("r1", [10, 20])

    # Confirm low metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [10, 20])

    # Configure advertise high metrics
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              advertise-high-metrics
        """
    )

    # Confirm high transition metrics values on each isis interface on r1
    check_interface_metrics("r1", [62])

    # Confirm high transition metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [62])

    # Remove advertise high metrics
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              no advertise-high-metrics
        """
    )

    # Confirm low metrics values on each isis interface on r1
    check_interface_metrics("r1", [10, 20])

    # Confirm low metrics values within isis database on r1
    check_lsp_metrics("r1", "r1.00-00", [10, 20])

    # Remove narrow metric-style
    r1.vtysh_cmd(
        f"""
          configure
            router isis 1
              no metric-style transition
        """
    )


def test_isis_advertise_high_metrics_route():
    """
    Topology:
    
         r2
       //  \\
      r1   r4
       \\  //
         r3
    
    Devices are configured with preferred route between r1 and r4:
    r1 -> r2 -> r4
    Configure "advertise-high-metrics" on r2 and check that preferred route is:
    r1 -> r3 -> r4.
    Shut r3 and check that preferred route is:
    r1 -> r2 -> r4.
    """
    tgen = get_topogen()
    net = get_topogen().net

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing advertise high metrics route behavior")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Verify the preferred path from r1 to r4 (192.168.1.6) is currently via 192.168.1.1, eth-r2
    check_ip_route("r1", "192.168.1.6/31", "eth-r2")

    # Configure advertise high metrics on r2
    r2.vtysh_cmd(
        f"""
          configure
            router isis 1
              advertise-high-metrics
        """
    )

    # Verify the preferred path from r1 to r4 (192.168.1.6) is now via 192.168.1.3, eth-r3
    check_ip_route("r1", "192.168.1.6/31", "eth-r3")

    # Shutdown r3
    logger.info("Stop router r3")
    stop_router(tgen, "r3")

    # Verify the preferred path from r1 to r4 (192.168.1.6) is now via 192.168.1.1, eth-r2
    check_ip_route("r1", "192.168.1.6/31", "eth-r2")

    # Start r3
    logger.info("Start router r3")
    start_router(tgen, "r3")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
