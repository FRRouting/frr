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

ASM_GROUP="229.1.1.1"
SSM_GROUP="232.1.1.1"

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
    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

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
        "10.254.0.3":[
            {
                "outboundInterface":"r1-eth1",
                "group":"224.0.0.0/4",
                "source":"Static"
            }
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

    # No IGMP sources other than from self for AutoRP Discovery group initially
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "224.0.1.40":"*",
            "229.1.1.1":None
        },
        "r1-eth2":{
            "name":"r1-eth2",
            "224.0.1.40":"*",
            "229.1.1.1":None
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected no IGMP sources other than for AutoRP Discovery"

    # Send IGMP join from r2, check if r1 has IGMP source
    r2.vtysh_cmd((
        """
          configure terminal
            interface {}
              ip igmp join {}
        """
    ).format("r2-eth0", ASM_GROUP))
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "229.1.1.1":{
                "group":"229.1.1.1",
                "sources":[
                    {
                        "source":"*",
                        "timer":"--:--",
                        "forwarded":False,
                        "uptime":"*"
                    }
                ]
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be present but is absent"

    # Test inbound boundary on r1
    # Enable multicast boundary on r1, toggle IGMP join on r2
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
        """
    ).format(ASM_GROUP))
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              ip multicast boundary oil pim-oil-plist
        """
    )
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              ip igmp join {}
        """
    ).format(ASM_GROUP))
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "229.1.1.1":None
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be absent but is present"

    # Test outbound boundary on r2
    # Enable multicast boundary on r2, toggle IGMP join (test outbound)
    # Note: json_cmp treats "*" as wildcard but in this case that's actually what the source is
    expected = {
        "vrf":"default",
        "r2-eth0":{
            "name":"r2-eth0",
            "groups":[
                {
                    "source":"*",
                    "group":"229.1.1.1",
                    "primaryAddr":"10.0.20.2",
                    "sockFd":"*",
                    "upTime":"*"
                }
            ]
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip igmp join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP join to be present but is absent"

    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
              ip multicast boundary oil pim-oil-plist
              ip igmp join {}
        """
    ).format(ASM_GROUP, ASM_GROUP))
    expected = {
        "vrf":"default",
        "r2-eth0":None
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip igmp join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP join to be absent but is present"

    # Cleanup
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              no ip igmp join {}
              no ip multicast boundary oil pim-oil-plist
        """
    ).format(ASM_GROUP))


def test_pim_ssm_igmp_join_acl():
    "Test SSM IGMP joins with extended ACLs"
    logger.info("Send IGMP joins from r2 to r1 with ACL enabled and disabled")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    r2 = tgen.gears["r2"]
    r1 = tgen.gears["r1"]

    # No IGMP sources other than from self for AutoRP Discovery group initially
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "224.0.1.40":"*",
            "229.1.1.1":None,
            "232.1.1.1":None
        },
        "r1-eth2":{
            "name":"r1-eth2",
            "224.0.1.40":"*",
            "229.1.1.1":None,
            "232.1.1.1":None
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", {}
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected no IGMP sources other than from AutoRP Discovery"

    # Send IGMP join from r2, check if r1 has IGMP source
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              ip igmp join {} 10.0.20.2
        """
    ).format(SSM_GROUP))
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "232.1.1.1":{
                "group":"232.1.1.1",
                "sources":[
                    {
                        "source":"10.0.20.2",
                        "timer":"*",
                        "forwarded":False,
                        "uptime":"*"
                    }
                ]
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be present but is absent"

    # Test inbound boundary on r1
    # Enable multicast boundary on r1, toggle IGMP join on r2
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
        """
    ).format(SSM_GROUP))
    r1.vtysh_cmd(
        """
          configure terminal
            interface r1-eth0
              ip multicast boundary pim-acl
        """
    )
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              ip igmp join {} 10.0.20.2
        """
    ).format(SSM_GROUP))
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "232.1.1.1":None
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be absent but is present"

    # Add lower, more-specific permit rule to access-list
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
        """
    ).format(SSM_GROUP))
    r1.vtysh_cmd((
        """
          configure terminal
            access-list pim-acl seq 5 permit ip host 10.0.20.2 {} 0.0.0.128
        """
    ).format(SSM_GROUP))
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              ip igmp join {} 10.0.20.2
        """
    ).format(SSM_GROUP))
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "232.1.1.1":{
                "group":"232.1.1.1",
                "sources":[
                    {
                        "source":"10.0.20.2",
                        "timer":"*",
                        "forwarded":False,
                        "uptime":"*"
                    }
                ]
            }
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
        "vrf":"default",
        "r2-eth0":{
            "name":"r2-eth0",
            "groups":[
                {
                    "source":"10.0.20.2",
                    "group":"232.1.1.1",
                    "primaryAddr":"10.0.20.2",
                    "sockFd":"*",
                    "upTime":"*"
                }
            ]
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip igmp join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP join to be present but is absent"

    # Enable boundary ACL, check join is absent
    r2.vtysh_cmd((
        """
          configure terminal
            interface r2-eth0
              no ip igmp join {} 10.0.20.2
              ip multicast boundary pim-acl
              ip igmp join {} 10.0.20.2
        """
    ).format(SSM_GROUP, SSM_GROUP))
    expected = {
        "vrf":"default",
        "r2-eth0":None
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip igmp join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP join to be absent but is present"
    # Check sources on r1 again, should be absent even though we permitted it because r2 is blocking it outbound
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "232.1.1.1":None
        },
        "r1-eth2":{
            "name":"r1-eth2",
            "232.1.1.1":None
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be absent but is present"

    # Send IGMP join from r3 with different source, should show up on r1
    # Add lower, more-specific permit rule to access-list
    r3.vtysh_cmd((
        """
          configure terminal
            interface r3-eth0
              ip igmp join {} 10.0.40.4
        """
    ).format(SSM_GROUP))
    expected = {
        "r1-eth0":{
            "name":"r1-eth0",
            "232.1.1.1":None
        },
        "r1-eth2":{
            "name":"r1-eth2",
            "232.1.1.1":{
                "group":"232.1.1.1",
                "sources":[
                    {
                        "source":"10.0.40.4",
                        "timer":"*",
                        "forwarded":False,
                        "uptime":"*"
                    }
                ]
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp sources json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "Expected IGMP source to be present but is absent"

    # PIM join
    # PIM-DM forwarding


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
