#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_msdp_topo6.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Adriano Marto Reis <adrianomarto@gmail.com>
#

"""
test_msdp_topo6.py: Test the FRR PIM MSDP peer and mesh group.

   ┌────┐                   ┌────┐                     ┌────┐
   │ h1 │                   │ h3 │                     │ h5 │
   └─┬──┘                   └─┬──┘                     └─┬──┘
     │                        │                          │
     │s1                      │s3                        │s5
     │        ................│..................        │
   ┌─┴──┐     : ┌────┐      ┌─┴──┐       ┌────┐ :      ┌─┴──┐
   │ r1 ├───────┤ r2 │      │ r3 │       │ r4 ├────────┤ r5 │
   └────┘  s2 : └─┬──┘      └─┬──┘       └─┬──┘ : s4   └────┘
              :   │           │   mesh1    │    :
              :...│...........│............│....:
                  │           │            │
                  │           │            │
                  └───────────┴────────────┘
                             s6

"""
import os
import sys
import pytest
from functools import partial

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
from lib.tshark import Tshark

pytestmark = [pytest.mark.pimd, pytest.mark.ospfd]

app_helper = McastTesterHelper()


def build_topo(tgen):
    "Build function"
    for router_id in range(1, 6):
        tgen.add_router("r{}".format(router_id))

    tgen.add_host("h1", "192.168.1.101/24", "via 192.168.1.1")
    tgen.add_host("h3", "192.168.3.103/24", "via 192.168.3.3")
    tgen.add_host("h5", "192.168.5.105/24", "via 192.168.5.5")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["h3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["h5"])

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():

        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

        daemon_file = "{}/{}/ospfd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_OSPF, daemon_file)

        daemon_file = "{}/{}/pimd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_PIM, daemon_file)

    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def test_ospf_convergence():
    """
    Wait for OSPF protocol convergence
    All the loopback addresses (10.254.254.x) must be reachable from all
    routers.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    routes = {
        "r1": "10.254.254.1/32",
        "r2": "10.254.254.2/32",
        "r3": "10.254.254.3/32",
        "r4": "10.254.254.4/32",
        "r5": "10.254.254.5/32",
    }

    for router1 in routes.keys():
        for router2, route in routes.items():
            if router1 != router2:
                logger.info("waiting route {} in {}".format(route, router1))
                test_func = partial(
                    topotest.router_json_cmp,
                    tgen.gears[router1],
                    "show ip route json",
                    {route: [{"protocol": "ospf"}]},
                )
                _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
                assertmsg = '"{}" convergence failure'.format(router1)
                assert result is None, assertmsg


def test_msdp_peers():
    """
    Waits for the MSPD peer connections to be established.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected_msdp_peers = {
        "r1": {
            "192.168.2.2": {
                "peer": "192.168.2.2",
                "local": "192.168.2.1",
                "state": "established",
            },
        },
        "r2": {
            "192.168.2.1": {
                "peer": "192.168.2.1",
                "local": "192.168.2.2",
                "state": "established",
            },
            "192.168.6.3": {
                "peer": "192.168.6.3",
                "local": "192.168.6.2",
                "state": "established",
            },
            "192.168.6.4": {
                "peer": "192.168.6.4",
                "local": "192.168.6.2",
                "state": "established",
            },
        },
        "r3": {
            "192.168.6.2": {
                "peer": "192.168.6.2",
                "local": "192.168.6.3",
                "state": "established",
            },
            "192.168.6.4": {
                "peer": "192.168.6.4",
                "local": "192.168.6.3",
                "state": "established",
            },
        },
        "r4": {
            "192.168.4.5": {
                "peer": "192.168.4.5",
                "local": "192.168.4.4",
                "state": "established",
            },
            "192.168.6.2": {
                "peer": "192.168.6.2",
                "local": "192.168.6.4",
                "state": "established",
            },
            "192.168.6.3": {
                "peer": "192.168.6.3",
                "local": "192.168.6.4",
                "state": "established",
            },
        },
        "r5": {
            "192.168.4.4": {
                "peer": "192.168.4.4",
                "local": "192.168.4.5",
                "state": "established",
            },
        },
    }

    for router, peers in expected_msdp_peers.items():
        logger.info(f"Waiting for msdp peers on {router}")
        test_function = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip msdp peer json",
            peers,
        )
        _, val = topotest.run_and_expect(test_function, None, count=30, wait=1)
        assert val is None, "msdp peer failure"


def test_msdp_mesh_group():
    """
    Waits for the MSPD mesh-group member connections to be established.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expected_msdp_mesh_groups = {
        "r2": {
            "mesh1": {
                "name": "mesh1",
                "source": "192.168.6.2",
                "members": {
                    "192.168.6.3": {
                        "member": "192.168.6.3",
                        "state": "established",
                    },
                    "192.168.6.4": {
                        "member": "192.168.6.4",
                        "state": "established",
                    },
                },
            },
        },
        "r3": {
            "mesh1": {
                "name": "mesh1",
                "source": "192.168.6.3",
                "members": {
                    "192.168.6.2": {
                        "member": "192.168.6.2",
                        "state": "established",
                    },
                    "192.168.6.4": {
                        "member": "192.168.6.4",
                        "state": "established",
                    },
                },
            },
        },
        "r4": {
            "mesh1": {
                "name": "mesh1",
                "source": "192.168.6.4",
                "members": {
                    "192.168.6.2": {
                        "member": "192.168.6.2",
                        "state": "established",
                    },
                    "192.168.6.3": {
                        "member": "192.168.6.3",
                        "state": "established",
                    },
                },
            },
        },
    }

    for router, mesh_group in expected_msdp_mesh_groups.items():
        logger.info(f"Waiting for mesh-group members on {router}")
        test_function = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ip msdp mesh-group json",
            mesh_group,
        )
        _, val = topotest.run_and_expect(test_function, None, count=30, wait=1)
        assert val is None, "msdp mesh-group failure"


def test_msdp_sa():
    """
    Waits for the MSDP SA to be propagated.
    The MSDP SA must be present on all routers.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tshark = Tshark("r4", "r4-eth1", "msdp.type==1", 60)

    mcast_info = {
        "h1": {
            "229.1.2.1": {
                "192.168.1.101": {
                    "source": "192.168.1.101",
                    "group": "229.1.2.1",
                },
            },
        },
        "h3": {
            "229.1.2.3": {
                "192.168.3.103": {
                    "source": "192.168.3.103",
                    "group": "229.1.2.3",
                },
            },
        },
        "h5": {
            "229.1.2.5": {
                "192.168.5.105": {
                    "source": "192.168.5.105",
                    "group": "229.1.2.5",
                },
            },
        },
    }

    # start multicast sources on all hosts
    for host, mcast in mcast_info.items():
        for mcast_group in mcast.keys():
            app_helper.run(host, ["--send=0.7", mcast_group, f"{host}-eth0"])

    # start multicast receivers on all hosts (all groups)
    for host in mcast_info.keys():
        for mcast in mcast_info.values():
            for mcast_group in mcast.keys():
                app_helper.run(host, [mcast_group, f"{host}-eth0"])

    # there must be SA for all multicast groups on all routers
    for router_name, router in tgen.routers().items():
        for mcast in mcast_info.values():
            logger.info(f"Waiting for SA on {router_name}")
            test_function = partial(
                topotest.router_json_cmp,
                router,
                "show ip msdp sa json",
                mcast,
            )
            _, val = topotest.run_and_expect(test_function, None, count=30, wait=1)
            assert val is None, f"multicast SA failure on {router_name}"

    packets = tshark.get_packets()

    # r2 should receive the group-1 SA from r1 and forward it to r4 (and r3)
    sa_group1_r2_to_r4 = [
        packet
        for packet in packets
        if packet["msdp.sa.group_addr"] == "229.1.2.1"
        and packet["ip.src"] == "192.168.6.2"
        and packet["ip.dst"] == "192.168.6.4"
    ]
    assert len(sa_group1_r2_to_r4) >= 1, "r2 hasn't forwarded group-1 SA to r4"

    # r3 should not forward group-1 SA to r4
    sa_group1_r3_to_r4 = [
        packet
        for packet in packets
        if packet["msdp.sa.group_addr"] == "229.1.2.1"
        and packet["ip.src"] == "192.168.6.3"
        and packet["ip.dst"] == "192.168.6.4"
    ]
    assert (
        len(sa_group1_r3_to_r4) == 0
    ), "r3 has forwarded group-1 SA to r4 - but shouldn't had"

    # r3 should send group-3 SA to r4 (and r2)
    sa_group3_r3_to_r4 = [
        packet
        for packet in packets
        if packet["msdp.sa.group_addr"] == "229.1.2.3"
        and packet["ip.src"] == "192.168.6.3"
        and packet["ip.dst"] == "192.168.6.4"
    ]
    assert len(sa_group3_r3_to_r4) >= 1, "r3 hasn't sent group-3 SA to r4"

    # r2 should not forward group-3 SA to r4
    sa_group3_r2_to_r4 = [
        packet
        for packet in packets
        if packet["msdp.sa.group_addr"] == "229.1.2.3"
        and packet["ip.src"] == "192.168.6.2"
        and packet["ip.dst"] == "192.168.6.4"
    ]
    assert (
        len(sa_group3_r2_to_r4) == 0
    ), "r2 has forwarded group-3 SA to r4 - but shouldn't had"

    # r4 should receive the group-5 SA from r5 and forward it to r2
    sa_group5_r4_to_r2 = [
        packet
        for packet in packets
        if packet["msdp.sa.group_addr"] == "229.1.2.5"
        and packet["ip.src"] == "192.168.6.4"
        and packet["ip.dst"] == "192.168.6.2"
    ]
    assert len(sa_group5_r4_to_r2) >= 1, "r4 hasn't forwarded group-5 SA to r2"

    # r4 should receive the group-5 SA from r5 and forward it to r3
    sa_group5_r4_to_r3 = [
        packet
        for packet in packets
        if packet["msdp.sa.group_addr"] == "229.1.2.5"
        and packet["ip.src"] == "192.168.6.4"
        and packet["ip.dst"] == "192.168.6.3"
    ]
    assert len(sa_group5_r4_to_r3) >= 1, "r4 hasn't forwarded group-5 SA to r3"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
