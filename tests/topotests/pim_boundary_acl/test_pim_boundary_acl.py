#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_boundary_acl.py
#
# Copyright (c) 2024 Architecture Technology Corporation
#                    Corey Siltala
#

"""
test_pim_boundary_acl.py: Test multicast boundary commands (access-lists and prefix-lists)
"""

import os
import sys
import pytest
import json
from functools import partial

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

ASM_GROUP = "229.1.1.1"
SSM_GROUP = "232.1.1.1"


def verify_no_igmp_source(router, group, interface=None):
    """Return None when group has no IGMP source entries on router."""
    output = router.vtysh_cmd("show ip igmp sources json", isjson=True)
    if interface:
        iface = output.get(interface, {})
        if group in iface:
            return "Unexpected IGMP source for {} on {}".format(group, interface)
        return None

    for ifname, iface in output.items():
        if isinstance(iface, dict) and group in iface:
            return "Unexpected IGMP source for {} on {}".format(group, ifname)
    return None


def verify_igmp_source(router, group, source, interface):
    """Return None when the expected IGMP source is present on an interface."""
    output = router.vtysh_cmd("show ip igmp sources json", isjson=True)
    iface = output.get(interface, {})
    group_data = iface.get(group, {})
    for entry in group_data.get("sources", []):
        if entry.get("source") == source:
            return None
    return "Expected IGMP source {} for {} on {}".format(source, group, interface)


def verify_router_running(router):
    """Return None when all configured daemons are running."""
    result = router.check_router_running()
    if result:
        return "{} daemons are not running: {}".format(router.name, result)
    return None


def build_topo(tgen):
    "Build function"

    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    tgen.add_router("rp")

    #   rp ------ r1 -------- r2
    #              \
    #               --------- r3
    # r1 -> .1
    # r2 -> .2
    # rp -> .3
    # r3 -> .4
    # loopback network is 10.254.0.X/32
    #
    # r1 <- sw1 -> r2
    # r1-eth0 <-> r2-eth0
    # 10.0.20.0/24
    sw = tgen.add_switch("sw1")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r2"])

    # r1 <- sw2 -> rp
    # r1-eth1 <-> rp-eth0
    # 10.0.30.0/24
    sw = tgen.add_switch("sw2")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["rp"])

    # r1 <- sw3 -> r3
    # r1-eth2 <-> r3-eth0
    # 10.0.40.0/24
    sw = tgen.add_switch("sw3")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for router in tgen.routers().values():
        router.load_frr_config()

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()
    # tgen.mininet_cli()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_pim_rp_setup():
    "Ensure basic routing has come up and the rp has an outgoing interface"
    # Ensure rp and r1 establish pim neighbor ship and bgp has come up
    # Finally ensure that the rp has an outgoing interface on r1
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    expected = {
        "10.254.0.3": [
            {"outboundInterface": "r1-eth1", "group": "224.0.0.0/4", "source": "Static"}
        ]
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim rp-info json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_pim_asm_igmp_join_acl():
    "Test ASM IGMP joins with prefix-list ACLs"
    logger.info("Send IGMP joins from r2 to r1 with ACL enabled and disabled")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r1 = tgen.gears["r1"]

    # No IGMP sources for the ASM test group initially. Interfaces with
    # no sources are omitted from "show ip igmp sources json" output.
    test_func = partial(verify_no_igmp_source, r1, ASM_GROUP)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected no IGMP sources for {}".format(ASM_GROUP)

    # Send IGMP join from r2, check if r1 has IGMP source
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface {}
              ip igmp join {}
        """
        ).format("r2-eth0", ASM_GROUP)
    )
    expected = {
        "r1-eth0": {
            "name": "r1-eth0",
            "229.1.1.1": {
                "group": "229.1.1.1",
                "sources": [
                    {
                        "source": "*",
                        "forwarded": False,
                    }
                ],
            },
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be present but is absent"

    # Test inbound boundary on r1
    # Enable multicast boundary on r1, toggle IGMP join on r2
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
        """
        ).format(ASM_GROUP)
    )
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              ip multicast boundary oil pim-oil-plist
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              ip igmp join {}
        """
        ).format(ASM_GROUP)
    )
    test_func = partial(verify_no_igmp_source, r1, ASM_GROUP, "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected IGMP source to be absent but is present"

    # Test outbound boundary on r2
    # Enable multicast boundary on r2, toggle IGMP join (test outbound)
    # Note: json_cmp treats "*" as wildcard but in this case that's actually what the source is
    expected = {
        "vrf": "default",
        "r2-eth0": {
            "name": "r2-eth0",
            "groups": [
                {
                    "source": "*",
                    "group": "229.1.1.1",
                    "primaryAddr": "10.0.20.2",
                }
            ],
        },
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip igmp join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP join to be present but is absent"

    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
              ip multicast boundary oil pim-oil-plist
              ip igmp join {}
        """
        ).format(ASM_GROUP, ASM_GROUP)
    )
    expected = {"vrf": "default", "r2-eth0": None}
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip igmp join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP join to be absent but is present"

    # Cleanup
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              no ip multicast boundary oil pim-oil-plist
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
              no ip multicast boundary oil pim-oil-plist
        """
        ).format(ASM_GROUP)
    )


def test_pim_ssm_igmp_join_acl():
    "Test SSM IGMP joins with extended ACLs"
    logger.info("Send IGMP joins from r2 to r1 with ACL enabled and disabled")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    r2 = tgen.gears["r2"]
    r1 = tgen.gears["r1"]

    # No IGMP sources for the SSM test group initially.
    test_func = partial(verify_no_igmp_source, r1, SSM_GROUP)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected no IGMP sources for {}".format(SSM_GROUP)

    # Send IGMP join from r2, check if r1 has IGMP source
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
    )
    expected = {
        "r1-eth0": {
            "name": "r1-eth0",
            "232.1.1.1": {
                "group": "232.1.1.1",
                "sources": [
                    {
                        "source": "10.0.20.2",
                        "forwarded": False,
                    }
                ],
            },
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be present but is absent"

    # Test inbound boundary on r1
    # Enable multicast boundary on r1, toggle IGMP join on r2
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
    )
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              ip multicast boundary pim-acl
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
    )
    test_func = partial(verify_no_igmp_source, r1, SSM_GROUP, "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected IGMP source to be absent but is present"

    # Add lower, more-specific permit rule to access-list
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
    )
    r1.vtysh_cmd(
        (
            """
          configure terminal
            access-list pim-acl seq 5 permit ip host 10.0.20.2 {} 0.0.0.128
        """
        ).format(SSM_GROUP)
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
    )
    expected = {
        "r1-eth0": {
            "name": "r1-eth0",
            "232.1.1.1": {
                "group": "232.1.1.1",
                "sources": [
                    {
                        "source": "10.0.20.2",
                        "forwarded": False,
                    }
                ],
            },
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be present but is absent"

    # Test outbound boundary on r2
    # Enable multicast boundary on r2, toggle IGMP join (test outbound)
    expected = {
        "vrf": "default",
        "r2-eth0": {
            "name": "r2-eth0",
            "groups": [
                {
                    "source": "10.0.20.2",
                    "group": "232.1.1.1",
                    "primaryAddr": "10.0.20.2",
                }
            ],
        },
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip igmp join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP join to be present but is absent"

    # Enable boundary ACL, check join is absent
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
              ip multicast boundary pim-acl
              ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP, SSM_GROUP)
    )
    expected = {"vrf": "default", "r2-eth0": None}
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip igmp join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP join to be absent but is present"
    # Check sources on r1 again, should be absent even though we permitted it because r2 is blocking it outbound
    test_func = partial(verify_no_igmp_source, r1, SSM_GROUP)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected IGMP source to be absent but is present"

    # Send IGMP join from r3 with different source, should show up on r1
    # Add lower, more-specific permit rule to access-list
    r3.vtysh_cmd(
        (
            """
          configure terminal
            interface r3-eth0
              ip igmp join {} 10.0.40.4
        """
        ).format(SSM_GROUP)
    )

    test_func = partial(verify_no_igmp_source, r1, SSM_GROUP, "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected IGMP source to be absent on r1-eth0"

    expected = {
        "r1-eth2": {
            "name": "r1-eth2",
            "232.1.1.1": {
                "group": "232.1.1.1",
                "sources": [
                    {
                        "source": "10.0.40.4",
                        "forwarded": False,
                    }
                ],
            },
        },
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected IGMP source to be present on r1-eth2"

    # PIM join
    # PIM-DM forwarding


def test_pim_boundary_list_deletion_and_mixed_acl():
    "Test boundary behavior after list deletion and mixed ACL first-match order"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Leave prior tests in a known state.
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              no ip multicast boundary pim-acl
              no ip multicast boundary oil pim-oil-plist
            no access-list pim-acl seq 5 permit ip host 10.0.20.2 232.1.1.0 0.0.0.128
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
              no ip igmp join {} 10.0.20.2
              no ip multicast boundary pim-acl
              no ip multicast boundary oil pim-oil-plist
        """
        ).format(ASM_GROUP, SSM_GROUP)
    )
    r3.vtysh_cmd(
        (
            """
          configure terminal
            interface r3-eth0
              no ip igmp join {} 10.0.40.4
        """
        ).format(SSM_GROUP)
    )

    # Deleting a prefix-list while boundary oil remains configured must not
    # crash pimd; filtering should stop once the list is gone.
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              ip multicast boundary oil pim-oil-plist
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              ip igmp join {}
        """
        ).format(ASM_GROUP)
    )
    test_func = partial(verify_no_igmp_source, r1, ASM_GROUP, "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected IGMP source to be absent but is present"

    r1.vtysh_cmd(
        """
          configure terminal
            no ip prefix-list pim-oil-plist
        """
    )
    test_func = partial(verify_router_running, r1)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, result

    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
              ip igmp join {}
        """
        ).format(ASM_GROUP, ASM_GROUP)
    )
    test_func = partial(verify_igmp_source, r1, ASM_GROUP, "*", "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert (
        result is None
    ), "Expected IGMP source to be present after prefix-list deletion"

    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              no ip multicast boundary oil pim-oil-plist
            ip prefix-list pim-oil-plist seq 10 deny 229.1.1.0/24
            ip prefix-list pim-oil-plist seq 20 permit any
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
        """
        ).format(ASM_GROUP)
    )

    # Same for access-lists referenced by ip multicast boundary.
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              ip multicast boundary pim-acl
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
    )
    test_func = partial(verify_no_igmp_source, r1, SSM_GROUP, "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected IGMP source to be absent but is present"

    r1.vtysh_cmd(
        """
          configure terminal
            no access-list pim-acl
        """
    )
    test_func = partial(verify_router_running, r1)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, result

    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
              ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP, SSM_GROUP)
    )
    test_func = partial(verify_igmp_source, r1, SSM_GROUP, "10.0.20.2", "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert (
        result is None
    ), "Expected IGMP source to be present after access-list deletion"

    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              no ip multicast boundary pim-acl
            access-list pim-acl seq 10 deny ip host 10.0.20.2 232.1.1.0 0.0.0.255
            access-list pim-acl seq 20 permit ip any any
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
    )

    # Mixed standard + extended ACL entries must honor first-match order.
    r1.vtysh_cmd(
        """
          configure terminal
            access-list pim-mixed-acl seq 10 permit 232.1.1.0/24
            access-list pim-mixed-acl seq 20 deny ip host 10.0.20.2 232.1.1.0 0.0.0.255
            interface r1-eth0
              ip multicast boundary pim-mixed-acl
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
    )
    test_func = partial(verify_igmp_source, r1, SSM_GROUP, "10.0.20.2", "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "Expected mixed ACL permit rule to win over later deny"

    # Cleanup
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              no ip multicast boundary pim-mixed-acl
            no access-list pim-mixed-acl
        """
    )
    r2.vtysh_cmd(
        (
            """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
        """
        ).format(SSM_GROUP)
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
