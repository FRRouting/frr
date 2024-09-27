#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 Network Education Foundation, Inc. ("NetDEF")
#                    Rafael Zalamena

import os
import sys
import pytest
from functools import partial

from lib import topotest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

from lib.pim import McastTesterHelper

"""
pim_embedded_rp.py: Test PIM embedded RP functionality.
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.pim6d]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    tgen.add_host("h1", "2001:DB8:100::100", "via 2001:DB8:100::1")
    tgen.add_host("h2", "2001:DB8:200::100", "via 2001:DB8:200::1")

    switch = tgen.add_switch("s10")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s20")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["h2"])


app_helper = McastTesterHelper()


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, f"{router.name}/frr.conf"))

    tgen.start_router()
    app_helper.init(tgen)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospfv3_convergence():
    "Wait for OSPFv3 protocol convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_loopback_route(router, iptype, route, proto):
        "Wait until route is present on RIB for protocol."
        logger.info(f"waiting route {route} in {router}")
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            f"show {iptype} route json",
            {route: [{"protocol": proto}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=8)
        assert result is None, f'"{router}" convergence failure'

    # Wait for R1
    expect_loopback_route("r1", "ipv6", "2001:db8:ffff::2/128", "ospf6")
    expect_loopback_route("r1", "ipv6", "2001:db8:ffff::3/128", "ospf6")

    # Wait for R2
    expect_loopback_route("r2", "ipv6", "2001:db8:ffff::1/128", "ospf6")
    expect_loopback_route("r2", "ipv6", "2001:db8:ffff::3/128", "ospf6")

    # Wait for R3
    expect_loopback_route("r3", "ipv6", "2001:db8:ffff::1/128", "ospf6")
    expect_loopback_route("r3", "ipv6", "2001:db8:ffff::2/128", "ospf6")


def expect_pim_rp(router, rp, group, interface=None, missing=False):
    "Wait until RP is present."
    tgen = get_topogen()
    maximum_wait = 15
    log_message = f"waiting RP {rp} for {group} in {router}"
    if missing:
        log_message += \
            f" to be missing ({maximum_wait} seconds maximum)"

    logger.info(log_message)

    expected = {rp: [{"group": f"{group}/128"}]}
    if interface is not None:
        expected[rp][0]["outboundInterface"] = interface

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        f"show ipv6 pim rp-info json",
        expected
    )
    _, result = topotest.run_and_expect(
        test_func, None, count=maximum_wait, wait=1)
    if missing:
        assert result is not None, f'"{router}" convergence failure'
    else:
        assert result is None, f'"{router}" convergence failure'


def test_embedded_rp_mld_join():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    success_group = "ff75:130:2001:db8:ffff::100"
    filtered_group = "ff75:330:2001:db8:ffff::200"
    app_helper.run("h1", [success_group, "h1-eth0"])
    app_helper.run("h1", [filtered_group, "h1-eth0"])

    # Expect first valid join request
    expect_pim_rp("r2", "2001:db8:ffff::1", success_group, interface="r2-eth0")

    # Expect filtered join request
    expect_pim_rp("r2", "2001:db8:ffff::2", filtered_group, missing=True)

    # Send over the limit join request
    groups = [
        "ff75:130:2001:db8:ffff::300",
        "ff75:130:2001:db8:ffff::301",
        "ff75:130:2001:db8:ffff::302",
    ]
    for group in groups:
        app_helper.run("h1", [group, "h1-eth0"])
        topotest.sleep(2, "Waiting MLD join to be sent")

    expect_pim_rp("r2", "2001:db8:ffff::1", groups[0], interface="r2-eth0")
    expect_pim_rp("r2", "2001:db8:ffff::1", groups[1], interface="r2-eth0")
    # Over the limit entry
    expect_pim_rp("r2", "2001:db8:ffff::1", groups[2], missing=True)

    app_helper.stop_all_hosts()

    # Clean up the embedded RPs so we don't cross the limit next phase
    tgen.gears["r2"].vtysh_cmd("clear ipv6 mroute")


def test_embedded_rp_pim_join():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Test sending PIM join with embedded RP information to router R2
    #
    group = "ff75:230:2001:db8:ffff::400"
    app_helper.run("h2", [group, "h2-eth0"])
    expect_pim_rp("r3", "2001:db8:ffff::2", group, interface="r3-eth1")
    expect_pim_rp("r2", "2001:db8:ffff::2", group, interface="lo")

    app_helper.stop_all_hosts()


def test_embedded_rp_spt_switch():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Clean up the embedded RPs so we don't cross the limit next phase
    tgen.gears["r1"].vtysh_cmd("clear ipv6 mroute")
    tgen.gears["r2"].vtysh_cmd("clear ipv6 mroute")
    tgen.gears["r3"].vtysh_cmd("clear ipv6 mroute")

    group = "ff75:130:2001:db8:ffff::500"
    rp = "2001:db8:ffff::1"
    source = "2001:db8:100::100"

    # Join from r3 (host h2)
    app_helper.run("h2", [group, "h2-eth0"])
    # Wait for embedded RP to show up
    expect_pim_rp("r3", rp, group, interface="r3-eth0")

    # Send stream from r2 (host h1)
    app_helper.run("h1", ["--send=0.7", group, "h1-eth0"])

    # Check if R1 has the correct multicast route
    logger.info("Waiting r1 multicast route installation")
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        f"show ipv6 pim state json",
        {group: {"*": {}, source: {}}}
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=8)
    assert result is None, '"r1" convergence failure'

    # Check if R2 has the correct multicast route
    logger.info("Waiting r2 multicast route installation")
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r2"],
        f"show ipv6 pim state json",
        {group: {source: {"r2-eth2": {"r2-eth1": {}}}}}
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=8)
    assert result is None, '"r2" convergence failure'

    # Check if R3 has the correct multicast route
    logger.info("Waiting r3 multicast route installation")
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r3"],
        f"show ipv6 pim state json",
        {group: {source: {"r3-eth1": {"r3-eth2": {}}}}}
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=8)
    assert result is None, '"r3" convergence failure'


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
