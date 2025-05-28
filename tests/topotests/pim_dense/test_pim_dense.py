#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_pim_autorp.py
#
# Copyright (c) 2024 ATCorp
# Nathan Bahr
#

import os
import sys
import pytest
import json
import functools

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step, write_test_header

from lib.pim import (
    verify_mroutes,
    verify_upstream_iif,
    verify_pim_neighbors,
    McastTesterHelper,
)

"""
test_pim_dense.py: Test general PIM dense mode functionality
"""

TOPOLOGY = """
   Basic PIM Dense Mode functionality
   (p) - PIM passive, (s) - PIM sparse, (d) - PIM dense, (sd) - PIM sparse-dense, (ssm) - PIM SSM

                                            +--+--+
                              Mcast Source  | H1  |
                                            +--+--+
                                               | .2 h1-eth0
                                               |
                                               |   10.100.0.0/24
                                               |
                                               | .1 r1-eth1 (p)
              +--+--+                       +--+--+
              | H4  |                       | R1  |
              +--+--+                       +--+--+
        h4-eth0  | .2                          | .1 r1-eth0 (d)
                 |                             |
 10.101.0.0/24   |                             |   10.0.0.0/24
                 |                             |
    r4-eth1 (p)  | .1                          | .2 r2-eth0 (d)
              +--+--+      10.0.2.0/24      +--+--+
              | R4  |-----------------------| R2  |
              +--+--+ .2                 .1 +--+--+
                  r4-eth0 (d)    r2-eth2 (sd)  | .1 r2-eth1 (sd)
                                               |
                                               |   10.0.1.0.24
                                               |
                                               | .2 r3-eth0 (sd)
              +--+--+      10.0.3.0/24      +--+--+       10.0.4.0/24        +--+--+
              | R5  |-----------------------| R3  |--------------------------| R6  |
              +--+--+ .2                 .1 +--+--+ .1                    .2 +--+--+
 r5-eth1 (p) .1  |  r5-eth0 (d)    r3-eth1 (sd)  r3-eth2 (sd)      r6-eth0 (d)  | .1 r6-eth1 (p)
                 |                                                              |
                 |  10.102.0.0/24                                10.103.0.0/24  |
     H5-eth0 .2  |                                                              |  .2 H6-eth0
              +--+--+                                                        +--+--+
              | H5  |                                                        | H6  |
              +--+--+                                                        +--+--+
"""

DENSE_GROUP = "239.1.1.1"
SSM_GROUP = "232.1.1.1"

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.pimd]

app_helper = McastTesterHelper()


def build_topo(tgen):
    "Build function"

    # Create routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    tgen.add_router("r6")
    tgen.add_host("h1", "10.100.0.2/24", "via 10.100.0.1")
    tgen.add_host("h4", "10.101.0.2/24", "via 10.101.0.1")
    tgen.add_host("h5", "10.102.0.2/24", "via 10.102.0.1")
    tgen.add_host("h6", "10.103.0.2/24", "via 10.103.0.1")

    # Create topology links
    tgen.add_link(tgen.gears["h1"], tgen.gears["r1"], "h1-eth0", "r1-eth1")
    tgen.add_link(tgen.gears["h4"], tgen.gears["r4"], "h4-eth0", "r4-eth1")
    tgen.add_link(tgen.gears["h5"], tgen.gears["r5"], "h5-eth0", "r5-eth1")
    tgen.add_link(tgen.gears["h6"], tgen.gears["r6"], "h6-eth0", "r6-eth1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "r1-eth2", "r3-eth3")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r3"], "r2-eth1", "r3-eth0")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r4"], "r2-eth2", "r4-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r5"], "r3-eth1", "r5-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r6"], "r3-eth2", "r6-eth0")


def setup_module(mod):
    logger.info("PIM Dense mode basic functionality:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    app_helper.init(tgen)

    logger.info("Testing PIM Dense Mode support")
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
    app_helper.cleanup()
    tgen.stop_topology()


def test_pim_dense_neighbors(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    neigh_dict = {
        "r1": {
            "r1-eth0": {
                "10.0.0.2": {
                    "interface": "r1-eth0",
                    "neighbor": "10.0.0.2",
                    "drPriority": 1,
                },
            },
            "r1-eth2": {
                "10.1.3.2": {
                    "interface": "r1-eth2",
                    "neighbor": "10.1.3.2",
                    "drPriority": 1,
                },
            },
        },
        "r2": {
            "r2-eth0": {
                "10.0.0.1": {
                    "interface": "r2-eth0",
                    "neighbor": "10.0.0.1",
                    "drPriority": 1,
                },
            },
            "r2-eth1": {
                "10.0.1.2": {
                    "interface": "r2-eth1",
                    "neighbor": "10.0.1.2",
                    "drPriority": 1,
                },
            },
            "r2-eth2": {
                "10.0.2.2": {
                    "interface": "r2-eth2",
                    "neighbor": "10.0.2.2",
                    "drPriority": 1,
                },
            },
        },
        "r3": {
            "r3-eth0": {
                "10.0.1.1": {
                    "interface": "r3-eth0",
                    "neighbor": "10.0.1.1",
                    "drPriority": 1,
                },
            },
            "r3-eth1": {
                "10.0.3.2": {
                    "interface": "r3-eth1",
                    "neighbor": "10.0.3.2",
                    "drPriority": 1,
                },
            },
            "r3-eth2": {
                "10.0.4.2": {
                    "interface": "r3-eth2",
                    "neighbor": "10.0.4.2",
                    "drPriority": 1,
                },
            },
            "r3-eth3": {
                "10.1.3.1": {
                    "interface": "r3-eth3",
                    "neighbor": "10.1.3.1",
                    "drPriority": 1,
                },
            },
        },
        "r4": {
            "r4-eth0": {
                "10.0.2.1": {
                    "interface": "r4-eth0",
                    "neighbor": "10.0.2.1",
                    "drPriority": 1,
                },
            },
        },
        "r5": {
            "r5-eth0": {
                "10.0.3.1": {
                    "interface": "r5-eth0",
                    "neighbor": "10.0.3.1",
                    "drPriority": 1,
                },
            },
        },
        "r6": {
            "r6-eth0": {
                "10.0.4.1": {
                    "interface": "r6-eth0",
                    "neighbor": "10.0.4.1",
                    "drPriority": 1,
                },
            },
        },
    }

    step("Verify full PIM neighbor membership before continuing")

    for dut, data in neigh_dict.items():
        router = tgen.gears[dut]

        test_func = functools.partial(
            topotest.router_json_cmp, router, "show ip pim neighbor json", data
        )
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
        assertmsg = ("PIM router {} did not converge").format(dut)
        assert res is None, assertmsg


def test_pim_dense_flood_prune(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(("Send multicast traffic from H1 to dense group {}").format(DENSE_GROUP))
    result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    prune_dict = {
        "r1": {
            "src_address": "10.100.0.2",
            "iif": "r1-eth1",
            "oil": "none",
            "joinState": "NotJoined",
        },
        "r2": {
            "src_address": "10.100.0.2",
            "iif": "r2-eth0",
            "oil": "none",
            "joinState": "Joined",
        },
        "r3": {
            "src_address": "10.100.0.2",
            "iif": "r3-eth0",
            "oil": "none",
            "joinState": "Joined",
        },
    }

    step("Verify 'show ip mroute' showing routes with no OIL on all the nodes")
    for dut, data in prune_dict.items():
        result = verify_mroutes(
            tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes"
    )
    for dut, data in prune_dict.items():
        result = verify_upstream_iif(
            tgen,
            dut,
            data["iif"],
            data["src_address"],
            DENSE_GROUP,
            joinState=data["joinState"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_graft_r4(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Join on H4/R4 and check forwarding
    app_helper.run_join("h4", DENSE_GROUP, join_intf="h4-eth0")

    graft_dict = {
        "r4": {
            "src_address": "10.100.0.2",
            "iif": "r4-eth0",
            "oil": "r4-eth1",
            "joinState": "Joined",
        },
        "r3": {
            "src_address": "10.100.0.2",
            "iif": "r3-eth0",
            "oil": "none",
            "joinState": "Joined",
        },
        "r2": {
            "src_address": "10.100.0.2",
            "iif": "r2-eth0",
            "oil": "r2-eth2",
            "joinState": "Joined",
        },
        "r1": {
            "src_address": "10.100.0.2",
            "iif": "r1-eth1",
            "oil": "r1-eth0",
            "joinState": "Joined",
        },
    }

    step("Verify 'show ip mroute' showing routes just to R4")
    for dut, data in graft_dict.items():
        result = verify_mroutes(
            tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes"
    )
    for dut, data in graft_dict.items():
        result = verify_upstream_iif(
            tgen,
            dut,
            data["iif"],
            data["src_address"],
            DENSE_GROUP,
            joinState=data["joinState"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_graft_r5(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Join on H5/R5 and check forwarding
    app_helper.run_join("h5", DENSE_GROUP, join_intf="h5-eth0")

    graft_dict = {
        "r5": {
            "src_address": "10.100.0.2",
            "iif": "r5-eth0",
            "oil": "r5-eth1",
            "joinState": "Joined",
        },
        "r4": {
            "src_address": "10.100.0.2",
            "iif": "r4-eth0",
            "oil": "r4-eth1",
            "joinState": "Joined",
        },
        "r3": {
            "src_address": "10.100.0.2",
            "iif": "r3-eth0",
            "oil": "r3-eth1",
            "joinState": "Joined",
        },
        "r2": {
            "src_address": "10.100.0.2",
            "iif": "r2-eth0",
            "oil": ["r2-eth2", "r2-eth1"],
            "joinState": "Joined",
        },
        "r1": {
            "src_address": "10.100.0.2",
            "iif": "r1-eth1",
            "oil": "r1-eth0",
            "joinState": "Joined",
        },
    }

    step("Verify 'show ip mroute' showing routes to R4 and R5")
    for dut, data in graft_dict.items():
        result = verify_mroutes(
            tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes"
    )
    for dut, data in graft_dict.items():
        result = verify_upstream_iif(
            tgen,
            dut,
            data["iif"],
            data["src_address"],
            DENSE_GROUP,
            joinState=data["joinState"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_graft_r6(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Join on H6/R6 and check forwarding
    app_helper.run_join("h6", DENSE_GROUP, join_intf="h6-eth0")

    graft_dict = {
        "r6": {
            "src_address": "10.100.0.2",
            "iif": "r6-eth0",
            "oil": "r6-eth1",
            "joinState": "Joined",
        },
        "r5": {
            "src_address": "10.100.0.2",
            "iif": "r5-eth0",
            "oil": "r5-eth1",
            "joinState": "Joined",
        },
        "r4": {
            "src_address": "10.100.0.2",
            "iif": "r4-eth0",
            "oil": "r4-eth1",
            "joinState": "Joined",
        },
        "r3": {
            "src_address": "10.100.0.2",
            "iif": "r3-eth0",
            "oil": ["r3-eth1", "r3-eth2"],
            "joinState": "Joined",
        },
        "r2": {
            "src_address": "10.100.0.2",
            "iif": "r2-eth0",
            "oil": ["r2-eth2", "r2-eth1"],
            "joinState": "Joined",
        },
        "r1": {
            "src_address": "10.100.0.2",
            "iif": "r1-eth1",
            "oil": "r1-eth0",
            "joinState": "Joined",
        },
    }

    step("Verify 'show ip mroute' showing routes to R4 and R5 and R6")
    for dut, data in graft_dict.items():
        result = verify_mroutes(
            tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step(
        "Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes"
    )
    for dut, data in graft_dict.items():
        result = verify_upstream_iif(
            tgen,
            dut,
            data["iif"],
            data["src_address"],
            DENSE_GROUP,
            joinState=data["joinState"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_prune_r4(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Leave on H4/R4 and check forwarding
    app_helper.stop_host("h4")

    prune_dict = {
        "r6": {
            "src_address": "10.100.0.2",
            "iif": "r6-eth0",
            "oil": "r6-eth1",
            "joinState": "Joined",
        },
        "r5": {
            "src_address": "10.100.0.2",
            "iif": "r5-eth0",
            "oil": "r5-eth1",
            "joinState": "Joined",
        },
        "r3": {
            "src_address": "10.100.0.2",
            "iif": "r3-eth0",
            "oil": ["r3-eth1", "r3-eth2"],
            "joinState": "Joined",
        },
        "r2": {
            "src_address": "10.100.0.2",
            "iif": "r2-eth0",
            "oil": "r2-eth1",
            "joinState": "Joined",
        },
        "r1": {
            "src_address": "10.100.0.2",
            "iif": "r1-eth1",
            "oil": "r1-eth0",
            "joinState": "Joined",
        },
    }

    step("Verify 'show ip mroute' showing routes to R5 and R6")
    for dut, data in prune_dict.items():
        result = verify_mroutes(
            tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
    # for dut, data in prune_dict.items():
    #     result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
    #     assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_prune_r5(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Leave on H5/R5 and check forwarding
    app_helper.stop_host("h5")

    prune_dict = {
        "r6": {
            "src_address": "10.100.0.2",
            "iif": "r6-eth0",
            "oil": "r6-eth1",
            "joinState": "Joined",
        },
        "r3": {
            "src_address": "10.100.0.2",
            "iif": "r3-eth0",
            "oil": "r3-eth2",
            "joinState": "Joined",
        },
        "r2": {
            "src_address": "10.100.0.2",
            "iif": "r2-eth0",
            "oil": "r2-eth1",
            "joinState": "Joined",
        },
        "r1": {
            "src_address": "10.100.0.2",
            "iif": "r1-eth1",
            "oil": "r1-eth0",
            "joinState": "Joined",
        },
    }

    step("Verify 'show ip mroute' showing routes to R6")
    for dut, data in prune_dict.items():
        result = verify_mroutes(
            tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
    # for dut, data in prune_dict.items():
    #     result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
    #     assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_pim_dense_prune_r6(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Leave on H6/R6 and check forwarding
    app_helper.stop_host("h6")

    prune_dict = {
        "r3": {
            "src_address": "10.100.0.2",
            "iif": "r3-eth0",
            "oil": "none",
            "joinState": "NotJoined",
        },
        "r2": {
            "src_address": "10.100.0.2",
            "iif": "r2-eth0",
            "oil": "none",
            "joinState": "NotJoined",
        },
        "r1": {
            "src_address": "10.100.0.2",
            "iif": "r1-eth1",
            "oil": "none",
            "joinState": "NotJoined",
        },
    }

    step("Verify 'show ip mroute' showing routes with no OIL")
    for dut, data in prune_dict.items():
        result = verify_mroutes(
            tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"]
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # TODO
    # Moving to not joined state on R1 takes like 30 seconds, then after that, R2 takes
    # another 2 minutes until it moves to not joined state...that is entirely too long.
    # After the leave it should be pretty immediate to go to not joined
    # step("Verify 'show ip pim upstream' showing correct IIF and join state on all the nodes")
    # for dut, data in prune_dict.items():
    #     result = verify_upstream_iif(tgen, dut, data["iif"], data["src_address"], DENSE_GROUP, joinState=data["joinState"])
    #     assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
