#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_ssm_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_multicast_ssm_topo1.py: Test PIM SSM configuration and (S,G) join state.

r3 uses a configured IGMP join-group only to inject local membership; the
test checks that the SSM (S,G) is reflected on all routers on the shared LAN.

Topology:

    h1          h2          h3
    |           |           |
   r1          r2          r3
    +-----------+-----------+
                s1
         (shared LAN)

  s1:  192.168.1.0/24, 2001:db8:1::/64  (r1-eth0, r2-eth0, r3-eth0, OSPFv2 area 0)
  h1:  10.0.1.0/24 via r1-eth1 (.1)
  h2:  10.0.2.0/24 via r2-eth1 (.1)
  h3:  10.0.3.0/24 via r3-eth1 (.1)
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospfd, pytest.mark.pimd]

SSM_GROUP = "230.0.0.100"
SSM_SOURCE = "10.0.1.2"


def expect_igmp_ssm_group(router, interface):
    "Wait until SSM (S,G) IGMP group state is present on interface"
    tgen = get_topogen()
    expected = {
        interface: {
            "groups": [
                {
                    "group": SSM_GROUP,
                    "mode": "INCLUDE",
                    "sources": [
                        {
                            "source": SSM_SOURCE,
                            "forwarded": True,
                        }
                    ],
                }
            ],
        },
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip igmp groups detail json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), f"{router}: missing IGMP group ({SSM_SOURCE}, {SSM_GROUP}) on {interface}"


def expect_pim_sg_join(router, interface, source, group):
    "Wait until (S,G) PIM join state is present on interface"
    tgen = get_topogen()
    expected = {
        interface: {
            group: {
                source: {
                    "source": source,
                    "group": group,
                }
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip pim join json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), f"{router}: missing PIM join ({source}, {group}) on {interface}"


def build_topo(tgen):
    """
    Three routers on a shared LAN, each with a host on a dedicated access link.
    """

    for rname in ("r1", "r2", "r3"):
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    hosts = (
        ("h1", "r1", "10.0.1.2/24", "via 10.0.1.1", "s2"),
        ("h2", "r2", "10.0.2.2/24", "via 10.0.2.1", "s3"),
        ("h3", "r3", "10.0.3.2/24", "via 10.0.3.1", "s4"),
    )
    for hname, rname, hip, hroute, sname in hosts:
        host = tgen.add_host(hname, hip, hroute)
        switch = tgen.add_switch(sname)
        switch.add_link(tgen.gears[rname])
        switch.add_link(host)


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname in ("r1", "r2", "r3"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_multicast_ssm():
    "Test SSM group type on all routers"
    pim_test = [
        {"address": "229.0.0.100", "type": "ASM"},
        {"address": "230.0.0.100", "type": "SSM"}
    ]
    pim6_test = [
        {"address": "FF32::100", "type": "ASM"},
        {"address": "FF35::100", "type": "SSM"}
    ]

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("r1", "r2", "r3"):
        router = tgen.gears[rname]

        for test in pim_test:

            def check_group_type_v4():
                output = router.vtysh_cmd(
                    f"show ip pim group-type {test['address']} json", isjson=True
                )
                return output.get("groupType")

            _, result = topotest.run_and_expect(
                check_group_type_v4, test["type"], count=20, wait=1
            )
            assert result == test["type"], f"{rname}: wrong IPv4 group type"

        for test in pim6_test:

            def check_group_type_v6():
                output = router.vtysh_cmd(
                    f"show ipv6 pim group-type {test['address']} json", isjson=True
                )
                return output.get("groupType")

            _, result = topotest.run_and_expect(
                check_group_type_v6, test["type"], count=20, wait=1
            )
            assert result == test["type"], f"{rname}: wrong IPv6 group type"


def test_ssm_join_state():
    "Verify SSM (S,G) IGMP and PIM join state on all routers"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("r1", "r2", "r3"):
        router = tgen.gears[rname]

        def check_group_type_ssm():
            output = router.vtysh_cmd(
                f"show ip pim group-type {SSM_GROUP} json", isjson=True
            )
            return output.get("groupType")

        _, result = topotest.run_and_expect(
            check_group_type_ssm, "SSM", count=20, wait=1
        )
        assert result == "SSM", f"{rname}: group {SSM_GROUP} is not SSM"

    for rname in ("r1", "r2", "r3"):
        expect_igmp_ssm_group(rname, f"{rname}-eth0")

    for rname in ("r1", "r2", "r3"):
        expect_pim_sg_join(rname, f"{rname}-eth0", SSM_SOURCE, SSM_GROUP)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
