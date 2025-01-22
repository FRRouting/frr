#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_features.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_multicast_features.py: Test the FRR PIM multicast features.
"""

import os
import sys
import json
from functools import partial
import re
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

app_helper = McastTesterHelper()


def build_topo(tgen):
    """
    +----+     +----+     +----+     +----+
    | h1 | <-> | r1 | <-> | r2 | <-> | h2 |
    +----+     +----+     +----+     +----+
                 ^
                 |
                 v
               +----+
               | r3 |
               +----+
    """

    # Create 3 routers
    for routern in range(1, 4):
        tgen.add_router(f"r{routern}")

    # R1 interface eth0 and R2 interface eth0
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # R1 interface eth1
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # R1 interface eth2
    switch = tgen.add_switch("s3")
    tgen.add_host("h1", "192.168.100.100/24", "via 192.168.100.1")
    tgen.add_host("h3", "192.168.100.101/24", "via 192.168.100.1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])
    switch.add_link(tgen.gears["h3"])

    # R2 interface eth1
    switch = tgen.add_switch("s4")
    tgen.add_host("h2", "192.168.101.100/24", "via 192.168.101.1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, f"{router.name}/frr.conf"))

    # Initialize all routers.
    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def test_bgp_convergence():
    "Wait for BGP protocol convergence"
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
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for R1
    expect_loopback_route("r1", "ip", "10.254.254.2/32", "bgp")
    expect_loopback_route("r1", "ip", "10.254.254.3/32", "bgp")
    expect_loopback_route("r1", "ipv6", "2001:db8:ffff::2/128", "bgp")
    expect_loopback_route("r1", "ipv6", "2001:db8:ffff::3/128", "bgp")

    # Wait for R2
    expect_loopback_route("r2", "ip", "10.254.254.1/32", "bgp")
    expect_loopback_route("r2", "ip", "10.254.254.3/32", "bgp")
    expect_loopback_route("r2", "ipv6", "2001:db8:ffff::1/128", "bgp")
    expect_loopback_route("r2", "ipv6", "2001:db8:ffff::3/128", "bgp")

    # Wait for R3
    expect_loopback_route("r3", "ip", "10.254.254.1/32", "bgp")
    expect_loopback_route("r3", "ip", "10.254.254.2/32", "bgp")
    expect_loopback_route("r3", "ipv6", "2001:db8:ffff::1/128", "bgp")
    expect_loopback_route("r3", "ipv6", "2001:db8:ffff::2/128", "bgp")


def test_pim_convergence():
    "Wait for PIM peers find each other."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def expect_pim_peer(router, iptype, interface, peer, missing=False):
        "Wait until peer is present."
        if missing:
            logger.info(f"waiting peer {peer} in {router} to disappear")
            expected = {interface: {peer: None}}
        else:
            logger.info(f"waiting peer {peer} in {router}")
            expected = {interface: {peer: {"upTime": "*"}}}

        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            f"show {iptype} pim neighbor json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
        assertmsg = f'"{router}" convergence failure'
        assert result is None, assertmsg

    expect_pim_peer("r1", "ip", "r1-eth0", "192.168.1.2")
    expect_pim_peer("r2", "ip", "r2-eth0", "192.168.1.1")

    # This neighbor is denied by default
    expect_pim_peer("r1", "ip", "r1-eth1", "192.168.2.2", missing=True)
    # Lets configure the prefix list so the above neighbor gets accepted:
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        ip prefix-list pim-eth0-neighbors permit 192.168.2.0/24
    """
    )
    expect_pim_peer("r1", "ip", "r1-eth1", "192.168.2.2", missing=False)

    #
    # IPv6 part
    #
    out = tgen.gears["r1"].vtysh_cmd("show interface r1-eth0 json", True)
    r1_r2_link_address = out["r1-eth0"]["ipAddresses"][1]["address"].split("/")[0]
    out = tgen.gears["r1"].vtysh_cmd("show interface r1-eth1 json", True)
    r1_r3_link_address = out["r1-eth1"]["ipAddresses"][1]["address"].split("/")[0]
    out = tgen.gears["r2"].vtysh_cmd("show interface r2-eth0 json", True)
    r2_link_address = out["r2-eth0"]["ipAddresses"][1]["address"].split("/")[0]
    out = tgen.gears["r3"].vtysh_cmd("show interface r3-eth0 json", True)
    r3_link_address = out["r3-eth0"]["ipAddresses"][1]["address"].split("/")[0]

    expect_pim_peer("r1", "ipv6", "r1-eth0", r2_link_address)
    expect_pim_peer("r2", "ipv6", "r2-eth0", r1_r2_link_address)
    expect_pim_peer("r1", "ipv6", "r1-eth1", r3_link_address, missing=True)

    tgen.gears["r1"].vtysh_cmd(
        f"""
        configure terminal
        ipv6 prefix-list pimv6-eth0-neighbors permit {r3_link_address}/64
    """
    )

    expect_pim_peer("r1", "ipv6", "r1-eth1", r3_link_address, missing=False)


def test_igmp_group_limit():
    "Test IGMP group limits."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         ip igmp max-groups 4
    """
    )
    app_helper.run("h1", ["224.0.100.1", "h1-eth0"])
    app_helper.run("h1", ["224.0.100.2", "h1-eth0"])
    app_helper.run("h1", ["224.0.100.3", "h1-eth0"])
    app_helper.run("h1", ["224.0.100.4", "h1-eth0"])
    app_helper.run("h1", ["224.0.100.5", "h1-eth0"])
    app_helper.run("h1", ["224.0.100.6", "h1-eth0"])

    def expect_igmp_group_count():
        igmp_groups = tgen.gears["r1"].vtysh_cmd(
            "show ip igmp groups json", isjson=True
        )
        try:
            return len(igmp_groups["r1-eth2"]["groups"])
        except KeyError:
            return 0

    topotest.run_and_expect(expect_igmp_group_count, 4, count=10, wait=2)

    # Cleanup
    app_helper.stop_host("h1")
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         no ip igmp max-groups 4
        exit
        clear ip igmp interfaces
    """
    )


def test_igmp_group_source_limit():
    "Test IGMP source limits."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         ip igmp max-sources 4
        exit
    """
    )

    app_helper.run("h1", ["--source=192.168.100.10", "232.0.101.10", "h1-eth0"])
    app_helper.run("h1", ["--source=192.168.100.11", "232.0.101.10", "h1-eth0"])
    app_helper.run("h1", ["--source=192.168.100.12", "232.0.101.10", "h1-eth0"])
    app_helper.run("h1", ["--source=192.168.100.13", "232.0.101.10", "h1-eth0"])
    app_helper.run("h1", ["--source=192.168.100.14", "232.0.101.10", "h1-eth0"])
    app_helper.run("h1", ["--source=192.168.100.15", "232.0.101.10", "h1-eth0"])
    app_helper.run("h1", ["--source=192.168.100.16", "232.0.101.10", "h1-eth0"])

    def expect_igmp_group_source_count():
        igmp_sources = tgen.gears["r1"].vtysh_cmd(
            "show ip igmp sources json", isjson=True
        )
        try:
            return len(igmp_sources["r1-eth2"]["232.0.101.10"]["sources"])
        except KeyError:
            return 0

    topotest.run_and_expect(expect_igmp_group_source_count, 4, count=10, wait=2)

    # Cleanup
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         no ip igmp max-sources 4
        exit
        clear ip igmp interfaces
    """
    )
    app_helper.stop_host("h1")


def test_mld_group_limit():
    "Test MLD group limits."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         ipv6 mld max-groups 14
    """
    )
    app_helper.run("h1", ["FF05::100", "h1-eth0"])
    app_helper.run("h1", ["FF05::101", "h1-eth0"])
    app_helper.run("h1", ["FF05::102", "h1-eth0"])
    app_helper.run("h1", ["FF05::103", "h1-eth0"])
    app_helper.run("h1", ["FF05::104", "h1-eth0"])
    app_helper.run("h1", ["FF05::105", "h1-eth0"])
    app_helper.run("h1", ["FF05::106", "h1-eth0"])
    app_helper.run("h1", ["FF05::107", "h1-eth0"])
    app_helper.run("h1", ["FF05::108", "h1-eth0"])
    app_helper.run("h1", ["FF05::109", "h1-eth0"])
    app_helper.run("h1", ["FF05::110", "h1-eth0"])
    app_helper.run("h1", ["FF05::111", "h1-eth0"])
    app_helper.run("h1", ["FF05::112", "h1-eth0"])
    app_helper.run("h1", ["FF05::113", "h1-eth0"])
    app_helper.run("h1", ["FF05::114", "h1-eth0"])
    app_helper.run("h1", ["FF05::115", "h1-eth0"])

    def expect_mld_group_count():
        mld_groups = tgen.gears["r1"].vtysh_cmd(
            "show ipv6 mld groups json", isjson=True
        )
        try:
            return len(mld_groups["r1-eth2"]["groups"])
        except KeyError:
            return 0

    topotest.run_and_expect(expect_mld_group_count, 14, count=10, wait=2)

    # Cleanup
    app_helper.stop_host("h1")
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         no ipv6 mld max-groups 4
        exit
        clear ipv6 mld interfaces
    """
    )


def test_mld_group_source_limit():
    "Test MLD source limits."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         ipv6 mld max-sources 4
        exit
    """
    )

    app_helper.run("h1", ["--source=2001:db8:1::100", "FF35::100", "h1-eth0"])
    app_helper.run("h1", ["--source=2001:db8:1::101", "FF35::100", "h1-eth0"])
    app_helper.run("h1", ["--source=2001:db8:1::102", "FF35::100", "h1-eth0"])
    app_helper.run("h1", ["--source=2001:db8:1::103", "FF35::100", "h1-eth0"])
    app_helper.run("h1", ["--source=2001:db8:1::104", "FF35::100", "h1-eth0"])
    app_helper.run("h1", ["--source=2001:db8:1::105", "FF35::100", "h1-eth0"])
    app_helper.run("h1", ["--source=2001:db8:1::106", "FF35::100", "h1-eth0"])

    def expect_mld_source_group_count():
        mld_sources = tgen.gears["r1"].vtysh_cmd(
            "show ipv6 mld joins json", isjson=True
        )
        try:
            return len(mld_sources["default"]["r1-eth2"]["ff35::100"].keys())
        except KeyError:
            return 0

    topotest.run_and_expect(expect_mld_source_group_count, 4, count=10, wait=2)

    # Cleanup
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         no ipv6 mld max-sources 4
        exit
        clear ipv6 mld interfaces
    """
    )
    app_helper.stop_host("h1")


def test_igmp_immediate_leave():
    "Test IGMPv2 immediate leave feature."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sysctl_assure(
        tgen.gears["h1"], "net.ipv4.conf.h1-eth0.force_igmp_version", "2"
    )
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         ip igmp immediate-leave
    """
    )

    app_helper.run("h1", ["224.0.110.1", "h1-eth0"])
    app_helper.run("h3", ["224.0.110.1", "h3-eth0"])

    def expect_igmp_group():
        igmp_groups = tgen.gears["r1"].vtysh_cmd(
            "show ip igmp groups json", isjson=True
        )
        try:
            for group in igmp_groups["r1-eth2"]["groups"]:
                if group["group"] == "224.0.110.1":
                    return True

            return False
        except KeyError:
            return False

    topotest.run_and_expect(expect_igmp_group, True, count=10, wait=2)

    # Send leave and expect immediate leave
    app_helper.stop_host("h1")
    topotest.run_and_expect(expect_igmp_group, False, count=10, wait=2)

    # Clean up
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         no ip igmp immediate-leave
    """
    )
    topotest.sysctl_assure(
        tgen.gears["h1"], "net.ipv4.conf.h1-eth0.force_igmp_version", "0"
    )
    app_helper.stop_host("h3")


def test_mldv1_immediate_leave():
    "Test MLDv1 immediate leave feature."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    topotest.sysctl_assure(
        tgen.gears["h1"], "net.ipv6.conf.h1-eth0.force_mld_version", "1"
    )
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         ipv6 mld immediate-leave
    """
    )

    app_helper.run("h1", ["ff05::2000", "h1-eth0"])
    app_helper.run("h3", ["ff05::2000", "h3-eth0"])

    def expect_mld_group():
        igmp_groups = tgen.gears["r1"].vtysh_cmd(
            "show ipv6 mld groups json", isjson=True
        )
        try:
            for group in igmp_groups["r1-eth2"]["groups"]:
                if group["group"] == "ff05::2000":
                    return True

            return False
        except KeyError:
            return False

    topotest.run_and_expect(expect_mld_group, True, count=10, wait=2)

    # Send leave and expect immediate leave
    app_helper.stop_host("h1")
    topotest.run_and_expect(expect_mld_group, False, count=10, wait=2)

    # Clean up
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         no ipv6 mld immediate-leave
    """
    )
    topotest.sysctl_assure(
        tgen.gears["h1"], "net.ipv6.conf.h1-eth0.force_mld_version", "0"
    )
    app_helper.stop_host("h3")


def host_send_igmp_packet(host, script, type, source, group, router_alert=True):
    "Sends packet using specified script from host."
    command = f"python3 {CWD}/../lib/packet/{script}"
    command += f" --src_ip={source} --gaddr={group}"
    command += f" --iface={host}-eth0 --type={type}"
    if router_alert:
        command += f" --enable_router_alert"

    tgen = get_topogen()
    tgen.gears[host].run(command)


def host_send_igmpv3_packet(host, source, group, router_alert=True):
    "Sends packet using specified script from host."
    command = f"python3 {CWD}/../lib/packet/igmp/igmp_v3.py"
    command += f" --src_ip={source} --iface={host}-eth0"
    command += f" --maddr={group} --rtype=2"
    if router_alert:
        command += f" --enable_router_alert"

    tgen = get_topogen()
    tgen.gears[host].run(command)


def expect_igmp_group(router, interface, group, missing=False):
    tgen = get_topogen()

    igmp_groups = tgen.gears[router].vtysh_cmd("show ip igmp groups json", isjson=True)
    try:
        for entry in igmp_groups[interface]["groups"]:
            if entry["group"] == group:
                return True

        return False
    except KeyError:
        return False


def test_igmp_router_alert():
    "Test IGMP router alert check feature."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Test that without require-router-alert we learn IGMP groups
    #
    source = "192.168.100.100"
    group = "224.100.10.10"
    host_send_igmp_packet(
        "h1", "igmp/igmp_v1.py", 0x12, source, group, router_alert=False
    )
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using IGMPv1 without router alert"

    group = "224.100.10.11"
    host_send_igmp_packet(
        "h1", "igmp/igmp_v2.py", 0x16, source, group, router_alert=False
    )
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using IGMPv2 without router alert"

    group = "224.100.10.12"
    host_send_igmpv3_packet("h1", source, group, False)
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using IGMPv3 without router alert"

    #
    # Test that with require-router-alert we don't learn IGMP groups
    #
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         ip igmp require-router-alert
    """
    )

    source = "192.168.100.100"
    group = "224.100.10.20"
    host_send_igmp_packet(
        "h1", "igmp/igmp_v1.py", 0x12, source, group, router_alert=False
    )
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to not learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv == False, "failed to learn group using IGMPv1 without router alert"

    group = "224.100.10.21"
    host_send_igmp_packet(
        "h1", "igmp/igmp_v2.py", 0x16, source, group, router_alert=False
    )
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to not learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv == False, "failed to learn group using IGMPv2 without router alert"

    group = "224.100.10.22"
    host_send_igmpv3_packet("h1", source, group, False)
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to not learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv == False, "failed to learn group using IGMPv3 without router alert"

    #
    # Test that with require-router-alert we learn IGMP groups
    #
    source = "192.168.100.100"
    group = "224.100.10.30"
    host_send_igmp_packet(
        "h1", "igmp/igmp_v1.py", 0x12, source, group, router_alert=True
    )
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using IGMPv1 without router alert"

    group = "224.100.10.31"
    host_send_igmp_packet(
        "h1", "igmp/igmp_v2.py", 0x16, source, group, router_alert=True
    )
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using IGMPv2 without router alert"

    group = "224.100.10.32"
    host_send_igmpv3_packet("h1", source, group, True)
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using IGMPv3 without router alert"

    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         no ip igmp require-router-alert
    """
    )


def host_send_mldv1_packet(host, source, group, router_alert=True):
    "Sends packet using specified script from host."
    command = f"python3 {CWD}/../lib/packet/mld/mld_v1.py"
    command += f" --src_ip={source} --gaddr={group}"
    command += f" --iface={host}-eth0"
    if router_alert:
        command += f" --enable_router_alert"

    tgen = get_topogen()
    tgen.gears[host].run(command)


def host_send_mldv2_packet(host, source, group, router_alert=True):
    "Sends packet using specified script from host."
    command = f"python3 {CWD}/../lib/packet/mld/mld_v2.py"
    command += f" --src_ip={source} --iface={host}-eth0"
    command += f" --maddr={group} --rtype=2"
    if router_alert:
        command += f" --enable_router_alert"

    tgen = get_topogen()
    tgen.gears[host].run(command)


def expect_mld_group(router, interface, group, missing=False):
    tgen = get_topogen()

    igmp_groups = tgen.gears[router].vtysh_cmd("show ipv6 mld groups json", isjson=True)
    try:
        for entry in igmp_groups[interface]["groups"]:
            if entry["group"] == group:
                return True

        return False
    except KeyError:
        return False


def test_mld_router_alert():
    "Test IGMP router alert check feature."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr_out = json.loads(tgen.gears["h1"].run("ip -j addr show dev h1-eth0"))
    source = None
    for address in addr_out[0]["addr_info"]:
        if address["family"] != "inet6":
            continue
        if address["scope"] != "link":
            continue

        source = address["local"]
        break
    assert source is not None, "failed to find link-local address"

    #
    # Test that without require-router-alert we learn MLD groups
    #
    group = "ff05::100"
    host_send_mldv1_packet("h1", source, group, router_alert=False)
    test_func = partial(expect_mld_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using MLDv1 without router alert"

    group = "ff05::101"
    host_send_mldv2_packet("h1", source, group, router_alert=False)
    test_func = partial(expect_mld_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using MLDv2 without router alert"

    #
    # Test that with require-router-alert we don't learn MLD groups
    #
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         ipv6 mld require-router-alert
    """
    )

    group = "ff05::110"
    host_send_mldv1_packet("h1", source, group, router_alert=False)
    test_func = partial(expect_mld_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv == False, "failed to learn group using MLDv1 without router alert"

    group = "ff05::111"
    host_send_mldv2_packet("h1", source, group, router_alert=False)
    test_func = partial(expect_mld_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv == False, "failed to learn group using MLDv2 without router alert"

    #
    # Test that with require-router-alert we learn MLD groups
    #
    group = "ff05::120"
    host_send_mldv1_packet("h1", source, group, router_alert=True)
    test_func = partial(expect_mld_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using MLDv1 without router alert"

    group = "ff05::121"
    host_send_mldv2_packet("h1", source, group, router_alert=True)
    test_func = partial(expect_mld_group, "r1", "r1-eth2", group)
    logger.info(f"Waiting for r1 to learn {group} in interface r1-eth2")
    rv, _ = topotest.run_and_expect(test_func, True, count=10, wait=2)
    assert rv, "failed to learn group using MLDv2 without router alert"

    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth2
         no ipv6 mld require-router-alert
    """
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
