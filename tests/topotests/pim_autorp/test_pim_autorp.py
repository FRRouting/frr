#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_autorp.py
#
# Copyright (c) 2024 ATCorp
# Nathan Bahr
#

import os
import sys
import pytest
import json
from functools import partial

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, topotest, get_topogen
from lib.topolog import logger
from lib.pim import verify_pim_rp_info
from lib.common_config import step, write_test_header

from time import sleep

"""
test_pim_autorp.py: Test general PIM AutoRP functionality
"""

TOPOLOGY = """
   Test PIM AutoRP functionality:
    AutoRP candidate RP announcements
    Mapping agent announcement receive and send discovery
    AutoRP discovery to active RP info

            +---+---+                      +---+---+
            |       |     10.0.0.0/24      |       |
            +  R1   +----------------------+  R2   |
            |       | .1                .2 |       |
            +---+---+ r1-eth0      r2-eth0 +---+---+
             .1 | r1-eth1              r2-eth1 | .2
                |                              |
   10.0.1.0/24  |                              |  10.0.2.0/24
                |                              |
             .3 | r3-eth0              r4-eth0 | .4
            +---+---+ r3-eth1      r4-eth1 +---+---+
            |       | .3                .4 |       |
            +  R3   +----------------------+  R4   |
            |       |      10.0.3.0/24     |       |
            +---+---+                      +---+---+
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.pimd]


def build_topo(tgen):
    "Build function"

    # Create routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")

    # Create topology links
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "r1-eth1", "r3-eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r4"], "r2-eth1", "r4-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r4"], "r3-eth1", "r4-eth1")


def setup_module(mod):
    logger.info("PIM AutoRP basic functionality:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_pim_autorp_init(request):
    "Test PIM AutoRP startup with only the static RP"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify start-up with no extra RP configuration")
    expected = json.loads(
        """
        {
          "10.0.3.4":[
            {
              "rpAddress":"10.0.3.4",
              "group":"224.0.1.0/24",
              "source":"Static"
            }
          ]
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim rp-info json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct rp-info".format(rtr)

    step("Verify start-up with AutoRP only discovery enabled")
    expected = json.loads(
        """
        {
          "discovery":{
            "enabled": true
          },
          "announce": {
            "enabled":false
          },
          "mapping-agent": {
            "enabled":false
          }
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim autorp json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct autorp configuration".format(
            rtr
        )


def test_pim_autorp_no_mapping_agent_rp(request):
    "Test PIM AutoRP candidate with no mapping agent"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Start a candidate RP on r2
    tgen.routers()["r2"].vtysh_cmd(
        """
        conf
         router pim
          autorp announce 10.0.0.2 224.0.0.0/4
          autorp announce scope 31 interval 1 holdtime 5
        """
    )

    # Without a mapping agent, we should still have no RP
    step("Verify no RP without mapping agent")
    expected = json.loads(
        """
        {
          "10.0.3.4":[
            {
              "rpAddress":"10.0.3.4",
              "group":"224.0.1.0/24",
              "source":"Static"
            }
          ]
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim rp-info json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct rp-info".format(rtr)

    step("Verify candidate RP in AutoRP on R2")
    expected = json.loads(
        """
        {
          "discovery":{
            "enabled": true
          },
          "announce": {
              "enabled":true,
              "scope":31,
              "interval":1,
              "holdtime":5,
              "rpList":[
                {
                  "rpAddress":"10.0.0.2",
                  "groupRange":"224.0.0.0/4",
                  "prefixList":"-"
                }
              ]
          },
          "mapping-agent": {
            "enabled":false
          }
        }"""
    )
    test_func = partial(
        topotest.router_json_cmp, tgen.gears["r2"], "show ip pim autorp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, "{} does not have correct autorp configuration".format("r2")


def test_pim_autorp_discovery_rp(request):
    "Test PIM AutoRP candidate advertised by mapping agent"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Start the mapping agent on R1
    tgen.routers()["r1"].vtysh_cmd(
        """
        conf
         router pim
          autorp send-rp-discovery source interface r1-eth0
          autorp send-rp-discovery scope 31 interval 1 holdtime 5
        """
    )

    step("Verify rp-info of the only candidate RP")
    expected = json.loads(
        """
        {
          "10.0.3.4":[
            {
              "rpAddress":"10.0.3.4",
              "group":"224.0.1.0/24",
              "source":"Static"
            }
          ],
          "10.0.0.2":[
            {
              "rpAddress":"10.0.0.2",
              "group":"224.0.0.0/4",
              "source":"AutoRP"
            }
          ]
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim rp-info json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct rp-info".format(rtr)

    step("Verify mapping-agent in AutoRP on R1")
    expected = json.loads(
        """
        {
          "announce": {
            "enabled":false
          },
          "mapping-agent": {
            "enabled":true,
            "active":true,
            "scope":31,
            "interval":1,
            "holdtime":5,
            "source":"interface",
            "interface":"r1-eth0",
            "address":"10.0.0.1",
            "rpList":{
              "10.0.0.2":{
                "rpAddress":"10.0.0.2",
                "groupRanges":[
                  {
                    "negative":false,
                    "prefix":"224.0.0.0/4"
                  }
                ]
              }
            }
          }
        }"""
    )
    test_func = partial(
        topotest.router_json_cmp, tgen.gears["r1"], "show ip pim autorp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None)
    assert result is None, "{} does not have correct autorp configuration".format("r1")

    step("Verify AutoRP discovery RP's")
    expected = json.loads(
        """
        {
          "discovery":{
            "enabled": true,
            "rpList":{
              "10.0.0.2":{
                "rpAddress":"10.0.0.2",
                "holdtime":5,
                "groupRanges":[
                  {
                    "negative":false,
                    "prefix":"224.0.0.0/4"
                  }
                ]
              }
            }
          }
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim autorp json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct autorp configuration".format(
            rtr
        )


def test_pim_autorp_discovery_multiple_rp_same(request):
    "Test PIM AutoRP Discovery with multiple RP's for same group prefix"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Start a candidate RP on r3
    tgen.routers()["r3"].vtysh_cmd(
        """
        conf
         router pim
          autorp announce 10.0.1.3 224.0.0.0/4
          autorp announce scope 31 interval 1 holdtime 5
        """
    )

    # The new candidate RP has the same group range but a higher IP, they should all
    # switch to this RP
    step("Verify rp-info of the candidate RP with the higher IP")
    expected = json.loads(
        """
        {
          "10.0.3.4":[
            {
              "rpAddress":"10.0.3.4",
              "group":"224.0.1.0/24",
              "source":"Static"
            }
          ],
          "10.0.1.3":[
            {
              "rpAddress":"10.0.1.3",
              "group":"224.0.0.0/4",
              "source":"AutoRP"
            }
          ]
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim rp-info json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct rp-info".format(rtr)

    step("Verify AutoRP discovery RP's")
    expected = json.loads(
        """
        {
          "discovery":{
            "enabled": true,
            "rpList":{
              "10.0.0.2":{
                "rpAddress":"10.0.0.2",
                "holdtime":5,
                "groupRanges":[
                  {
                    "negative":false,
                    "prefix":"224.0.0.0/4"
                  }
                ]
              },
              "10.0.1.3":{
                "rpAddress":"10.0.1.3",
                "holdtime":5,
                "groupRanges":[
                  {
                    "negative":false,
                    "prefix":"224.0.0.0/4"
                  }
                ]
              }
            }
          }
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim autorp json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct autorp configuration".format(
            rtr
        )


def test_pim_autorp_discovery_multiple_rp_different(request):
    "Test PIM AutoRP Discovery with multiple RP's for different group prefixes"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Switch R3 candidate to prefix list with different groups
    step("Change R3 candidate to a prefix list")
    tgen.routers()["r3"].vtysh_cmd(
        """
        conf
         ip prefix-list MYLIST permit 225.0.0.0/8
         ip prefix-list MYLIST permit 226.0.0.0/8
         router pim
          autorp announce 10.0.1.3 group-list MYLIST
        """
    )

    # Now that R3 doesn't conflict, we should see both RP's
    step("Verify rp-info of both candidate RP's")
    expected = json.loads(
        """
        {
          "10.0.3.4":[
            {
              "rpAddress":"10.0.3.4",
              "group":"224.0.1.0/24",
              "source":"Static"
            }
          ],
          "10.0.0.2":[
            {
              "rpAddress":"10.0.0.2",
              "group":"224.0.0.0/4",
              "source":"AutoRP"
            }
          ],
          "10.0.1.3":[
            {
              "rpAddress":"10.0.1.3",
              "prefixList":"__AUTORP_10.0.1.3__",
              "source":"AutoRP"
            }
          ]
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim rp-info json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct rp-info".format(rtr)

    step("Verify AutoRP discovery RP's")
    expected = json.loads(
        """
        {
          "discovery":{
            "enabled": true,
            "rpList":{
              "10.0.0.2":{
                "rpAddress":"10.0.0.2",
                "holdtime":5,
                "groupRanges":[
                  {
                    "negative":false,
                    "prefix":"224.0.0.0/4"
                  }
                ]
              },
              "10.0.1.3":{
                "rpAddress":"10.0.1.3",
                "holdtime":5,
                "groupRanges":[
                  {
                    "negative":false,
                    "prefix":"225.0.0.0/8"
                  },
                  {
                    "negative":false,
                    "prefix":"226.0.0.0/8"
                  }
                ]
              }
            }
          }
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim autorp json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct autorp configuration".format(
            rtr
        )


def test_pim_autorp_discovery_neg_prefixes(request):
    "Test PIM AutoRP Discovery with negative prefixes"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Add negative prefixes to the R3 candidate prefix list
    step("Change R3 candidate prefix list to include overlapping negative prefixes")
    tgen.routers()["r3"].vtysh_cmd(
        """
        conf
         ip prefix-list MYLIST deny 225.1.0.0/16
         ip prefix-list MYLIST deny 226.1.0.0/16
        """
    )

    step("Verify rp-info stays the same")
    expected = json.loads(
        """
        {
          "10.0.3.4":[
            {
              "rpAddress":"10.0.3.4",
              "group":"224.0.1.0/24",
              "source":"Static"
            }
          ],
          "10.0.0.2":[
            {
              "rpAddress":"10.0.0.2",
              "group":"224.0.0.0/4",
              "source":"AutoRP"
            }
          ],
          "10.0.1.3":[
            {
              "rpAddress":"10.0.1.3",
              "prefixList":"__AUTORP_10.0.1.3__",
              "source":"AutoRP"
            }
          ]
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim rp-info json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct rp-info".format(rtr)

    step("Verify AutoRP discovery RP's")
    expected = json.loads(
        """
        {
          "discovery":{
            "enabled": true,
            "rpList":{
              "10.0.0.2":{
                "rpAddress":"10.0.0.2",
                "holdtime":5,
                "groupRanges":[
                  {
                    "negative":false,
                    "prefix":"224.0.0.0/4"
                  }
                ]
              },
              "10.0.1.3":{
                "rpAddress":"10.0.1.3",
                "holdtime":5,
                "groupRanges":[
                  {
                    "negative":false,
                    "prefix":"225.0.0.0/8"
                  },
                  {
                    "negative":false,
                    "prefix":"226.0.0.0/8"
                  },
                  {
                    "negative":true,
                    "prefix":"225.1.0.0/16"
                  },
                  {
                    "negative":true,
                    "prefix":"226.1.0.0/16"
                  }
                ]
              }
            }
          }
        }"""
    )
    for rtr in ["r1", "r2", "r3", "r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim autorp json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct autorp configuration".format(
            rtr
        )


def test_pim_autorp_discovery_static(request):
    "Test PIM AutoRP Discovery with Static RP"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Add in a static RP with a specific range and make sure both are used
    step("Add static RP configuration to r4")
    tgen.routers()["r4"].vtysh_cmd(
        """
        conf t
         router pim
          rp 10.0.2.2 239.0.0.0/24
        """
    )

    step("Verify static rp-info from r4")
    expected = json.loads(
        """
        {
          "10.0.3.4":[
            {
              "rpAddress":"10.0.3.4",
              "group":"224.0.1.0/24",
              "source":"Static"
            }
          ],
          "10.0.0.2":[
            {
              "rpAddress":"10.0.0.2",
              "group":"224.0.0.0/4",
              "source":"AutoRP"
            }
          ],
          "10.0.1.3":[
            {
              "rpAddress":"10.0.1.3",
              "prefixList":"__AUTORP_10.0.1.3__",
              "source":"AutoRP"
            }
          ],
          "10.0.2.2":[
            {
              "rpAddress":"10.0.2.2",
              "group":"239.0.0.0/24",
              "source":"Static"
            }
          ]
        }"""
    )

    for rtr in ["r4"]:
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rtr],
            "show ip pim rp-info json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None)
        assert result is None, "{} does not have correct rp-info".format(rtr)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
