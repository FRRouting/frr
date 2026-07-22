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
              +--+--+                       +--+--+  r1-eth2 (d)   r3-eth3 (sd)
              | H4  |                       | R1  |-------------------------------| R3 |
              +--+--+                       +--+--+  .1    10.1.3.1/24         .2
        h4-eth0  | .2                          | .1 r1-eth0 (d)
                 |                             |
 10.101.0.0/24   |                             |   10.0.0.0/24
                 |                             |
    r4-eth1 (p)  | .1                          | .2 r2-eth0 (d)
              +--+--+   10.0.2.0/24 (shared) +--+--+
              | R4  |-------+--------+-------| R2  |
              +--+--+ .2    |             .1 +--+--+
              r4-eth0 (d)   |    r2-eth2 (sd)  | .1 r2-eth1 (sd)
              r7-eth0 (d)   |                  |
                        +--+--+                |
                        | R7  |                |
                        +--+--+                |
               r7-eth1 (p) | .3                |
        10.104.0.0/24      |                   |
                           |                   |
               h7-eth0     | .2                |
                        +--+--+                |
                        | H7  |                |
                        +--+--+                |
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
SPARSE_GROUP = "238.1.1.1"
OUT_OF_PREFIX_GROUP = "240.1.1.1"
RP_ADDR = "10.0.2.1"
SRC = "10.100.0.2"

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
    tgen.add_router("r7")
    tgen.add_host("h1", "10.100.0.2/24", "via 10.100.0.1")
    tgen.add_host("h4", "10.101.0.2/24", "via 10.101.0.1")
    tgen.add_host("h5", "10.102.0.2/24", "via 10.102.0.1")
    tgen.add_host("h6", "10.103.0.2/24", "via 10.103.0.1")
    tgen.add_host("h7", "10.104.0.2/24", "via 10.104.0.1")

    # Create topology links
    tgen.add_link(tgen.gears["h1"], tgen.gears["r1"], "h1-eth0", "r1-eth1")
    tgen.add_link(tgen.gears["h4"], tgen.gears["r4"], "h4-eth0", "r4-eth1")
    tgen.add_link(tgen.gears["h5"], tgen.gears["r5"], "h5-eth0", "r5-eth1")
    tgen.add_link(tgen.gears["h6"], tgen.gears["r6"], "h6-eth0", "r6-eth1")
    tgen.add_link(tgen.gears["h7"], tgen.gears["r7"], "h7-eth0", "r7-eth1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "r1-eth0", "r2-eth0")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "r1-eth2", "r3-eth3")
    tgen.add_link(tgen.gears["r2"], tgen.gears["r3"], "r2-eth1", "r3-eth0")
    switch = tgen.add_switch("s02")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth2")
    switch.add_link(tgen.gears["r4"], nodeif="r4-eth0")
    switch.add_link(tgen.gears["r7"], nodeif="r7-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r5"], "r3-eth1", "r5-eth0")
    tgen.add_link(tgen.gears["r3"], tgen.gears["r6"], "r3-eth2", "r6-eth0")


def setup_module(mod):
    logger.info("PIM Dense mode basic functionality:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    app_helper.init(tgen)

    logger.info("Testing PIM Dense Mode support")
    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config()

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
                "10.0.2.3": {
                    "interface": "r2-eth2",
                    "neighbor": "10.0.2.3",
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
                "10.0.2.3": {
                    "interface": "r4-eth0",
                    "neighbor": "10.0.2.3",
                    "drPriority": 1,
                },
            },
        },
        "r7": {
            "r7-eth0": {
                "10.0.2.1": {
                    "interface": "r7-eth0",
                    "neighbor": "10.0.2.1",
                    "drPriority": 1,
                },
                "10.0.2.2": {
                    "interface": "r7-eth0",
                    "neighbor": "10.0.2.2",
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


def stop_all_hosts():
    """Stop multicast traffic and IGMP joins on all hosts."""
    for host in ("h1", "h4", "h5", "h6", "h7"):
        app_helper.stop_host(host)


def mroute_entry(tgen, router, src, group):
    """Return the JSON mroute object for a specific (S,G) entry."""
    output = tgen.gears[router].vtysh_cmd(
        "show ip mroute {} json".format(group), isjson=True
    )
    return output.get(group, {}).get(src, {})


def mroute_oil_names(mroute):
    """Return sorted OIF names for an mroute JSON object, excluding pimreg."""
    return sorted([oif for oif in mroute.get("oil", {}).keys() if oif != "pimreg"])


def check_mroute_oil(tgen, router, src, group, iif, oil):
    """
    Lightweight mroute check for run_and_expect polling.

    Unlike verify_mroutes(), this does not use @retry and returns immediately.
    """
    entry = mroute_entry(tgen, router, src, group)
    if not entry:
        return "No mroute for ({},{}) on {}".format(src, group, router)
    if entry.get("installed", 0) == 0:
        return "mroute ({},{}) not installed on {}".format(src, group, router)

    if isinstance(iif, str):
        iif = [iif]
    if entry.get("iif") not in iif:
        return "Unexpected iif on {}: {} (expected {})".format(
            router, entry.get("iif"), iif
        )

    oil_names = mroute_oil_names(entry)
    if oil == "none":
        if oil_names:
            return "Expected no OIL on {}, got {}".format(router, oil_names)
        return None

    if isinstance(oil, str):
        oil = [oil]
    for oif in oil:
        if oif not in oil_names:
            return "Expected OIF {} on {}, got {}".format(oif, router, oil_names)
    return None


def check_mroute_iif(tgen, router, src, group, iif):
    """Return None once (S,G) is installed on router with the expected iif.

    Unlike check_mroute_oil(), this does not constrain the OIL; it only confirms
    the entry exists and resolves RPF to the given incoming interface.
    """
    entry = mroute_entry(tgen, router, src, group)
    if not entry:
        return "No mroute for ({},{}) on {}".format(src, group, router)
    if entry.get("installed", 0) == 0:
        return "mroute ({},{}) not installed on {}".format(src, group, router)
    if isinstance(iif, str):
        iif = [iif]
    if entry.get("iif") not in iif:
        return "Unexpected iif on {}: {} (expected {})".format(
            router, entry.get("iif"), iif
        )
    return None


def check_mroute_oif_present(tgen, router, src, group, oif):
    """Return None if (S,G) OIL on router includes oif, else an error string."""
    entry = mroute_entry(tgen, router, src, group)
    if not entry or entry.get("installed", 0) == 0:
        return "No installed mroute for ({},{}) on {}".format(src, group, router)
    oil_names = mroute_oil_names(entry)
    if oif not in oil_names:
        return "Expected OIF {} on {}, got {}".format(oif, router, oil_names)
    return None


def check_mroute_oif_absent(tgen, router, src, group, oif):
    """Return None if (S,G) OIL on router does not include oif."""
    entry = mroute_entry(tgen, router, src, group)
    if not entry or entry.get("installed", 0) == 0:
        return None
    oil_names = mroute_oil_names(entry)
    if oif in oil_names:
        return "Unexpected OIF {} still on {}, OIL {}".format(oif, router, oil_names)
    return None


def check_igmp_group_absent(tgen, router, interface, group):
    """Return None when interface has no IGMP membership for group."""
    output = tgen.gears[router].vtysh_cmd("show ip igmp groups json", isjson=True)
    iface = output.get(interface)
    if not iface:
        return None
    for entry in iface.get("groups", []):
        if entry.get("group") == group:
            return "IGMP group {} still present on {} {}".format(
                group, router, interface
            )
    return None


def _join_entries_for_group(iface_data, group):
    """Return join entry dict for group, tolerating /32 suffix in JSON keys."""
    if group in iface_data:
        return iface_data[group]
    for key, val in iface_data.items():
        if key.split("/")[0] == group:
            return val
    return None


def check_pim_join_present(tgen, router, iface, group):
    """Return None if iface has an active PIM JOIN for group."""
    output = tgen.gears[router].vtysh_cmd("show ip pim join json", isjson=True)
    if iface not in output:
        return "No PIM join data on {} {}".format(router, iface)
    grp_data = _join_entries_for_group(output[iface], group)
    if grp_data is None:
        return "No PIM join for {} on {} {}".format(group, router, iface)
    for entry in grp_data.values():
        if entry.get("channelJoinName") == "JOIN":
            return None
    return "No JOIN entry for {} on {} {}".format(group, router, iface)


def check_r3_sparse_join(tgen, group):
    """Return None if r3 has sparse join/upstream state for an RP-covered group."""
    join_out = tgen.gears["r3"].vtysh_cmd("show ip pim join json", isjson=True)
    for iface_data in join_out.values():
        if not isinstance(iface_data, dict):
            continue
        grp_data = _join_entries_for_group(iface_data, group)
        if grp_data is None:
            continue
        for entry in grp_data.values():
            if entry.get("channelJoinName") == "JOIN":
                return None

    up_out = tgen.gears["r3"].vtysh_cmd("show ip pim upstream json", isjson=True)
    group_up = up_out.get(group, {})
    for up in group_up.values():
        if up.get("joinState") == "Joined":
            return None

    return "No sparse join/upstream state for {} on r3".format(group)


def verify_mroute_flags(tgen, router, src, group, must_have=None, must_not_have=None):
    """Return None if mroute flags match, else an error string."""
    entry = mroute_entry(tgen, router, src, group)
    if not entry:
        return "No mroute for ({},{}) on {}".format(src, group, router)

    flags = entry.get("flags", "")
    if must_have:
        if not flags:
            return "No flags in mroute for ({},{}) on {}".format(src, group, router)
        if must_have not in flags:
            return "Expected {!r} in flags {!r} on {}".format(must_have, flags, router)
    if must_not_have and must_not_have in flags:
        return "Unexpected {!r} in flags {!r} on {}".format(
            must_not_have, flags, router
        )
    return None


def verify_mroute_not_installed(tgen, router, src, group):
    """Return None if (S,G) is absent or not installed."""
    output = tgen.gears[router].vtysh_cmd(
        "show ip mroute {} json".format(group), isjson=True
    )
    if group not in output or src not in output[group]:
        return None
    if output[group][src].get("installed", 0) == 0:
        return None
    return "Unexpected installed mroute ({},{}) on {}".format(src, group, router)


def verify_pruned_mroute_persists(tgen, router, src, group):
    """Return None if an installed mroute exists with an empty OIL."""
    entry = mroute_entry(tgen, router, src, group)
    if not entry:
        return "No mroute for ({},{}) on {}".format(src, group, router)
    if entry.get("installed", 0) == 0:
        return "mroute ({},{}) not installed on {}".format(src, group, router)
    if mroute_oil_names(entry):
        return "Expected empty OIL on pruned {}, got {}".format(
            router, mroute_oil_names(entry)
        )
    return None


def test_pim_dense_flood_prune(request):
    "Test PIM Dense mode basic functionality"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_all_hosts()

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

        def _check_pruned(dut=dut, data=data):
            return check_mroute_oil(
                tgen, dut, data["src_address"], DENSE_GROUP, data["iif"], data["oil"]
            )

        _, result = topotest.run_and_expect(_check_pruned, None, count=30, wait=2)
        assert result is None, "Testcase {} : Failed Error: {}".format(tc_name, result)

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


def verify_mroute_pimreg_absent(tgen, router, group, group_type):
    """
    Verify that pimreg is NOT in the OIL for the given group.
    Returns None if pimreg is absent (test passes), error string if present (test fails).
    """
    output = tgen.gears[router].vtysh_cmd(
        "show ip mroute {} json".format(group), isjson=True
    )

    if group not in output:
        return "No mroute found for {} group {}".format(group_type, group)

    for source in output[group]:
        mroute_data = output[group][source]

        if "oil" in mroute_data:
            oil = mroute_data["oil"]
            if "pimreg" in oil:
                return (
                    "pimreg incorrectly present in OIL for {} group {}, OIL: {}".format(
                        group_type, group, list(oil.keys())
                    )
                )

    return None


def test_pim_verify_pimreg_not_in_ssm_dense(request):
    """
    Verify that pimreg interface is NOT added to Dense mode groups.

    Bug: In pim_upstream_switch(), when upstream transitions to NOT_JOINED on FHR,
    pimreg was incorrectly added to Dense mode groups. pimreg should ONLY be
    added for ASM (Any Source Multicast) groups, not for SSM or Dense mode.

    Test flow:
    1. Previous prune tests removed all receivers (upstream may still be JOINED
    due to KATimer from ongoing traffic)
    2. This test restarts traffic to trigger fresh upstream state
    3. With no receivers, upstream transitions from JOINED to NOT_JOINED
    4. Bug triggers during this transition - pimreg incorrectly added to OIL
    5. Test detects pimreg in OIL and fails

    Before fix (bug present):
    Source      Group      Flags  Proto  Input    Output  TTL  Uptime
    10.100.0.2  239.1.1.1  FDP    PIM    r1-eth1  pimreg  1    00:01:00

    After fix:
    Source      Group      Flags  Proto  Input    Output  TTL  Uptime
    10.100.0.2  239.1.1.1  FDP    none   r1-eth1  none    0    --:--:--
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # ===== Restart traffic to trigger fresh state transition =====
    # The bug triggers when upstream transitions to NOT_JOINED on FHR.
    # Previous tests may have left traffic running with KATimer keeping upstream in JOINED.
    # Restart traffic to ensure clean state transition.
    step("Restart multicast traffic to trigger fresh state transition")
    app_helper.stop_host("h1")
    result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
    assert result is True, "Failed to restart multicast traffic"

    # ===== Wait for upstream to transition to NOT_JOINED =====
    # After traffic restarts with no receivers, upstream should transition to NOT_JOINED.
    # The bug triggers during this transition - pimreg incorrectly added to OIL.
    step("Wait for upstream to transition to NOT_JOINED state")

    def check_upstream_not_joined():
        output = tgen.gears["r1"].vtysh_cmd("show ip pim upstream json", isjson=True)
        # JSON format: {group: {source: {joinState: "..."}}}
        if DENSE_GROUP in output:
            for source, data in output[DENSE_GROUP].items():
                state = data.get("joinState", "")
                if state == "NotJoined":
                    return None  # Success - upstream is NOT_JOINED
                else:
                    return "Upstream {} -> {} state is '{}', waiting for 'NotJoined'".format(
                        source, DENSE_GROUP, state
                    )
        return "Dense group {} not found in upstream".format(DENSE_GROUP)

    _, result = topotest.run_and_expect(
        check_upstream_not_joined, None, count=60, wait=1
    )
    assert (
        result is None
    ), "Upstream failed to transition to NOT_JOINED state: {}".format(result)

    # Check OIL for Dense mode group - this is where bug would show pimreg
    step("Check if pimreg was incorrectly added to Dense mode group OIL")

    # Show upstream state
    output = tgen.gears["r1"].vtysh_cmd("show ip pim upstream")
    logger.info("R1 upstream state:\n{}".format(output))

    # Check OIL and show proof
    output_json = tgen.gears["r1"].vtysh_cmd(
        "show ip mroute {} json".format(DENSE_GROUP), isjson=True
    )
    if DENSE_GROUP in output_json:
        for src in output_json[DENSE_GROUP]:
            oil = output_json[DENSE_GROUP][src].get("oil", {})
            logger.info("Dense group {} OIL: {}".format(DENSE_GROUP, list(oil.keys())))

            # Show mroute proof output
            output_cli = tgen.gears["r1"].vtysh_cmd(
                "show ip mroute {}".format(DENSE_GROUP)
            )
            if "pimreg" in oil:
                logger.info("*** BUG DETECTED: pimreg in OIL for Dense mode group! ***")
                logger.info("PROOF (BUG - pimreg in Output):\n{}".format(output_cli))
            else:
                logger.info("*** OK: pimreg correctly excluded ***")
                logger.info("PROOF (FIXED - no pimreg):\n{}".format(output_cli))
    else:
        logger.info("No mroute found for Dense group {}".format(DENSE_GROUP))

    step("Verify pimreg is NOT in OIL for Dense mode group {}".format(DENSE_GROUP))
    test_func = functools.partial(
        verify_mroute_pimreg_absent, tgen, "r1", DENSE_GROUP, "Dense"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Dense mode test failed: {}".format(result)


def test_pim_sm_dense_mode_groups(request):
    """Verify sparse-dense picks sparse for RP groups and dense otherwise."""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_all_hosts()

    step(
        "Sparse-dense sends sparse joins for RP-covered group {} on sm-dm ifaces".format(
            SPARSE_GROUP
        )
    )
    result = app_helper.run_join("h5", SPARSE_GROUP, join_intf="h5-eth0")
    assert result is True, "Failed to join sparse group on h5: {}".format(result)

    def _sparse_join_on_smd_interface():
        return check_r3_sparse_join(tgen, SPARSE_GROUP)

    _, result = topotest.run_and_expect(
        _sparse_join_on_smd_interface, None, count=30, wait=2
    )
    assert result is None, "Sparse mode check failed: {}".format(result)

    stop_all_hosts()

    step("Sparse-dense uses dense mode for non-RP group {}".format(DENSE_GROUP))
    result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
    assert result is True, "Failed to start dense group traffic: {}".format(result)
    result = app_helper.run_join("h6", DENSE_GROUP, join_intf="h6-eth0")
    assert result is True, "Failed to join dense group on h6: {}".format(result)

    def _dense_path_ready():
        result = check_mroute_oil(tgen, "r6", SRC, DENSE_GROUP, "r6-eth0", "r6-eth1")
        if result is not None:
            return result
        # Transit routers may lack 'D'; that flag is set on FHR dense flood.
        return verify_mroute_flags(tgen, "r3", SRC, DENSE_GROUP, must_not_have="S")

    _, result = topotest.run_and_expect(_dense_path_ready, None, count=30, wait=2)
    assert result is None, "Dense mode check failed: {}".format(result)

    stop_all_hosts()


def test_pim_ssm_excluded_from_dense(request):
    """Verify SSM groups are not handled as PIM dense mode."""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_all_hosts()

    step("Send SSM traffic and join for ({},{})".format(SRC, SSM_GROUP))
    result = app_helper.run_traffic("h1", SSM_GROUP, bind_intf="h1-eth0")
    assert result is True, "Failed to start SSM traffic: {}".format(result)
    result = app_helper.run_join("h4", SSM_GROUP, join_intf="h4-eth0", source=SRC)
    assert result is True, "Failed SSM join on h4: {}".format(result)

    def _ssm_not_dense():
        result = verify_mroute_flags(tgen, "r1", SRC, SSM_GROUP, must_not_have="D")
        if result is not None:
            return result
        entry = mroute_entry(tgen, "r2", SRC, SSM_GROUP)
        if entry and entry.get("installed", 0):
            flags = entry.get("flags", "")
            if "D" in flags:
                return "SSM mroute incorrectly dense on r2: {!r}".format(flags)
        return None

    _, result = topotest.run_and_expect(_ssm_not_dense, None, count=60, wait=2)
    assert result is None, "SSM dense exclusion failed: {}".format(result)

    stop_all_hosts()


def test_pim_dm_prefix_list_filter(request):
    """Verify dm prefix-list limits dense mode to configured ranges."""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_all_hosts()

    step("Group outside prefix-list must not install dense mroute on r5")
    result = app_helper.run_traffic("h1", OUT_OF_PREFIX_GROUP, bind_intf="h1-eth0")
    assert result is True, "Failed to start out-of-prefix traffic: {}".format(result)
    result = app_helper.run_join("h5", OUT_OF_PREFIX_GROUP, join_intf="h5-eth0")
    assert result is True, "Failed join on h5 for out-of-prefix group: {}".format(
        result
    )

    _, result = topotest.run_and_expect(
        functools.partial(
            verify_mroute_not_installed, tgen, "r5", SRC, OUT_OF_PREFIX_GROUP
        ),
        None,
        count=30,
        wait=2,
    )
    assert result is None, "Out-of-prefix dense mroute check failed: {}".format(result)

    stop_all_hosts()

    step("Group inside prefix-list must install dense mroute on r5")
    result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
    assert result is True, "Failed to start dense traffic: {}".format(result)
    result = app_helper.run_join("h5", DENSE_GROUP, join_intf="h5-eth0")
    assert result is True, "Failed join on h5 for dense group: {}".format(result)

    def _prefix_list_allows_dense():
        result = check_mroute_oil(tgen, "r5", SRC, DENSE_GROUP, "r5-eth0", "r5-eth1")
        if result is not None:
            return result
        # r5 is a downstream LHR; dense transit sets 'D' on core routers only.
        return verify_mroute_flags(tgen, "r5", SRC, DENSE_GROUP, must_not_have="S")

    _, result = topotest.run_and_expect(
        _prefix_list_allows_dense, None, count=30, wait=2
    )
    assert result is None, "In-prefix dense mroute check failed: {}".format(result)

    stop_all_hosts()


def test_pim_dense_pruned_state_persists(request):
    """Verify pruned (S,G) state persists on middle hops while source sends traffic."""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_all_hosts()

    step("Join downstream receiver on long dense-mode path")
    result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
    assert result is True, "Failed to restart dense traffic: {}".format(result)
    result = app_helper.run_join("h6", DENSE_GROUP, join_intf="h6-eth0")
    assert result is True, "Failed to join on h6: {}".format(result)

    _, result = topotest.run_and_expect(
        functools.partial(
            check_mroute_oil,
            tgen,
            "r6",
            SRC,
            DENSE_GROUP,
            "r6-eth0",
            "r6-eth1",
        ),
        None,
        count=30,
        wait=2,
    )
    assert result is None, "Forwarding to h6 not ready: {}".format(result)

    step("Remove receiver and wait for upstream prune")
    app_helper.stop_host("h6")

    def _middle_hops_pruned():
        for dut in ("r2", "r3"):
            result = check_mroute_oil(
                tgen, dut, SRC, DENSE_GROUP, dut + "-eth0", "none"
            )
            if result is not None:
                return "{} not pruned yet: {}".format(dut, result)
        return None

    _, result = topotest.run_and_expect(_middle_hops_pruned, None, count=30, wait=2)
    assert result is None, "Prune did not propagate: {}".format(result)

    step("Keep source traffic and verify pruned state persists")
    for dut in ("r2", "r3"):
        test_func = functools.partial(
            verify_pruned_mroute_persists, tgen, dut, SRC, DENSE_GROUP
        )
        _, result = topotest.run_and_expect(test_func, None, count=45, wait=2)
        assert result is None, "Pruned state lost on {}: {}".format(dut, result)


def verify_state_refresh_received(tgen, router, src, group):
    """Return None once the router has logged a received State Refresh for (S,G).

    R5/R6 only neighbor R3, so any State Refresh they receive must have been
    relayed downstream through R2 -> R3. This is exactly the forwarding path that
    pim_staterefresh_recv() implements, so it confirms the relay works end to end.
    """
    logfile = os.path.join(tgen.logdir, router, "pimd.log")
    try:
        with open(logfile) as f:
            log = f.read()
    except IOError:
        return "could not open {}".format(logfile)

    for line in log.splitlines():
        if "pim_staterefresh_recv" not in line:
            continue
        # The detailed trace logs "pim_staterefresh_recv: from ... (S,G)=(<src>,<group>)"
        if src in line and group in line:
            return None
    return "no State Refresh for ({},{}) received on {}".format(src, group, router)


def test_pim_dense_state_refresh_relay(request):
    """Verify State Refresh is relayed downstream to multi-hop dense routers.

    R5 and R6 are two/three hops below the FHR (H1 -> R1 -> R2 -> R3 -> R5/R6)
    and only neighbor R3. They can therefore only see a State Refresh if R2 and
    R3 each forward it on their downstream interfaces. This exercises the
    pim_staterefresh_recv() relay path.
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_all_hosts()

    step("Enable State Refresh tracing on the relay-dependent downstream routers")
    for dut in ("r5", "r6"):
        tgen.gears[dut].vtysh_cmd("debug pim trace")

    try:
        step("Send dense traffic so the FHR (r1) originates State Refresh")
        result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        step("Verify State Refresh propagated through r2 -> r3 to r5 and r6")
        for dut in ("r5", "r6"):
            test_func = functools.partial(
                verify_state_refresh_received, tgen, dut, SRC, DENSE_GROUP
            )
            _, result = topotest.run_and_expect(test_func, None, count=45, wait=2)
            assert result is None, "Testcase {} : Failed Error: {}".format(
                tc_name, result
            )
    finally:
        for dut in ("r5", "r6"):
            tgen.gears[dut].vtysh_cmd("no debug pim trace")

    stop_all_hosts()


def verify_pim_assert_entry(
    tgen, router, iface, src, group, states=("WINNER", "LOSER")
):
    """Return None once (S,G) has active Assert state on iface.

    Dense-mode wrong-interface handling on multi-access links should enter
    the Assert FSM instead of sending an immediate prune.
    """
    output = tgen.gears[router].vtysh_cmd("show ip pim assert")
    for line in output.splitlines():
        if iface not in line or src not in line or group not in line:
            continue
        for state in states:
            if state in line:
                return None
    return "no Assert state for ({},{}) on {} {}".format(src, group, router, iface)


def verify_pim_assert_winner(tgen, router, iface, src, group, winner):
    """Return None once (S,G) on iface has elected a specific Assert winner.

    Confirms the LAN ran the Assert election (rather than an immediate prune)
    and that the expected forwarder won the duplicate-traffic arbitration.
    """
    output = tgen.gears[router].vtysh_cmd("show ip pim assert")
    for line in output.splitlines():
        if iface not in line or src not in line or group not in line:
            continue
        if winner in line.split():
            return None
    return "no Assert winner {} for ({},{}) on {} {}".format(
        winner, src, group, router, iface
    )


def test_pim_dense_wrongif_assert(request):
    """Verify dense-mode WRONGVIF on a multi-access LAN runs Assert, not a prune.

    r3 reaches the source via r3-eth0 (toward r2), but r1 also floods (S,G)
    directly onto the shared r1<->r3 link (r1-eth2 -> r3-eth3). That duplicate
    arrives on r3-eth3, which is not r3's RPF interface, so the kernel raises a
    WRONGVIF/WRVIFWHOLE upcall for r3-eth3. Because the link is multi-access,
    pim_dm_wrongif() must run the Assert FSM rather than an immediate prune, and
    r3 must lose the election to the directly connected first-hop router r1
    (10.1.3.1). A receiver behind r3 keeps the (S,G) tree (and thus r1's Assert)
    active so the loser state is stable.
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_all_hosts()

    step("Start dense traffic and a receiver behind r3 to keep the tree active")
    result = app_helper.run_traffic("h1", DENSE_GROUP, bind_intf="h1-eth0")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = app_helper.run_join("h6", DENSE_GROUP, join_intf="h6-eth0")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify r3 has (S,G) state with RPF on r3-eth0 (not the r1<->r3 link)")
    _, result = topotest.run_and_expect(
        functools.partial(check_mroute_iif, tgen, "r3", SRC, DENSE_GROUP, "r3-eth0"),
        None,
        count=30,
        wait=2,
    )
    assert result is None, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify WRONGVIF on r3-eth3 entered the Assert FSM (not an immediate prune)")
    test_func = functools.partial(
        verify_pim_assert_entry, tgen, "r3", "r3-eth3", SRC, DENSE_GROUP
    )
    _, result = topotest.run_and_expect(test_func, None, count=45, wait=2)
    assert result is None, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify r3 lost the LAN Assert to the first-hop router r1 (10.1.3.1)")
    test_func = functools.partial(
        verify_pim_assert_winner, tgen, "r3", "r3-eth3", SRC, DENSE_GROUP, "10.1.3.1"
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=2)
    assert result is None, "Testcase {} : Failed Error: {}".format(tc_name, result)

    stop_all_hosts()


def test_pim_sparse_non_rp_upstream_cleanup(request):
    """Verify non-RP sparse upstream cleans up after the last receiver leaves."""
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    stop_all_hosts()

    step("Create sparse join state on non-RP sm-dm router r3")
    result = app_helper.run_join("h5", SPARSE_GROUP, join_intf="h5-eth0")
    assert result is True, "Failed to join sparse group on h5: {}".format(result)

    _, result = topotest.run_and_expect(
        functools.partial(check_r3_sparse_join, tgen, SPARSE_GROUP),
        None,
        count=30,
        wait=2,
    )
    assert result is None, "Sparse join not present on r3: {}".format(result)

    step("Remove last receiver and verify r3 upstream is not stuck joined")
    app_helper.stop_host("h5")

    def _r3_star_g_not_joined():
        output = tgen.gears["r3"].vtysh_cmd("show ip pim upstream json", isjson=True)
        star = output.get(SPARSE_GROUP, {}).get("*", {})
        if not star:
            return None
        state = star.get("joinState", "")
        if state == "NotJoined":
            return None
        return "r3 *,G upstream still {!r} for {}".format(state, SPARSE_GROUP)

    _, result = topotest.run_and_expect(_r3_star_g_not_joined, None, count=60, wait=2)
    assert result is None, "Non-RP sparse upstream cleanup failed: {}".format(result)

    stop_all_hosts()


def test_pim_dense_to_sparse_on_rp_add(request):
    "Verify existing dense (S,G) transitions when RP is added"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    routers = ["r1", "r2", "r3", "r4", "r5", "r6"]

    # Use a dedicated dense group that no other test touches so r1 builds a
    # brand-new dense (S,G) for this test. Reusing the shared DENSE_GROUP makes
    # this test depend on whatever pruned/grafted (S,G) state earlier tests left
    # behind (kept alive by the keepalive timer), which is not a stable starting
    # point for exercising the DM->SM transition.
    group = "239.7.7.7"

    step("Reset dynamic RP mapping for dense test group")
    for rname in routers:
        tgen.gears[rname].vtysh_cmd(
            """
            conf t
              router pim
                no rp 10.0.2.1 239.0.0.0/8
            """
        )

    step("Bring up the downstream receiver before the source")
    stop_all_hosts()
    result = app_helper.run_join("h4", group, join_intf="h4-eth0")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # Make sure r4 has registered the local membership before the source starts,
    # so the very first dense flood is never pruned on the r1->r2->r4 branch.
    def _r4_has_membership():
        out = tgen.gears["r4"].vtysh_cmd("show ip pim upstream json", isjson=True)
        if group in out:
            return None
        return "r4 has no upstream state for {} yet".format(group)

    _, result = topotest.run_and_expect(_r4_has_membership, None, count=15, wait=2)
    assert result is None, "Receiver not ready on r4: {}".format(result)

    step("Start the dense source traffic")
    result = app_helper.run_traffic("h1", group, bind_intf="h1-eth0")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify dense (S,G) is flooding toward r2 before RP add")

    def _r1_dense_before_rp():
        entry = mroute_entry(tgen, "r1", SRC, group)
        if not entry:
            return "No mroute for ({},{}) on r1".format(SRC, group)
        if entry.get("installed", 0) == 0:
            return "mroute ({},{}) not installed on r1".format(SRC, group)
        if entry.get("iif") != "r1-eth1":
            return "Unexpected iif on r1 before RP add: {}".format(entry.get("iif"))
        flags = entry.get("flags", "")
        if "S" in flags:
            return "Unexpected sparse (S) flag on r1 before RP add, got {!r}".format(
                flags
            )
        if "D" not in flags:
            return "Expected dense (D) flag on r1 before RP add, got {!r}".format(flags)
        if "r1-eth0" not in mroute_oil_names(entry):
            return "Expected dense flood OIF r1-eth0 on r1, got {}".format(
                mroute_oil_names(entry)
            )
        return None

    _, result = topotest.run_and_expect(_r1_dense_before_rp, None, count=30, wait=2)
    assert result is None, "Dense upstream not present before RP add: {}".format(result)

    step("Add RP mapping for dense group range")
    for rname in routers:
        tgen.gears[rname].vtysh_cmd(
            """
            conf t
              router pim
                rp 10.0.2.1 239.0.0.0/8
            """
        )

    step("Verify existing upstream transitions to sparse mode state")

    def _r1_upstream_sparse():
        output = tgen.gears["r1"].vtysh_cmd(
            "show ip pim upstream {} {} json".format(SRC, group), isjson=True
        )
        upstream = output.get(group, {}).get(SRC, {})
        if not upstream:
            return "No upstream for {},{}".format(SRC, group)
        if not upstream.get("firstHopRouter"):
            return "Expected FHR upstream on r1 after RP add"
        if upstream.get("rpfAddress") != "10.0.2.1":
            return "Expected sparse RP RPF on r1 after RP add, got {}".format(
                upstream.get("rpfAddress")
            )

        mroute = mroute_entry(tgen, "r1", SRC, group)
        if not mroute:
            return "No mroute for ({},{}) on r1 after RP add".format(SRC, group)
        if mroute.get("iif") != "r1-eth1":
            return "Unexpected IIF on r1 after RP add: {}".format(mroute.get("iif"))

        if "flags" in mroute:
            flags = mroute["flags"]
            if "D" in flags:
                return "Dense (D) mroute flag still set on r1, got {!r}".format(flags)
            if "S" not in flags:
                return "Expected sparse (S) mroute flag on r1, got {!r}".format(flags)
        else:
            oil = mroute_oil_names(mroute)
            if oil == ["r1-eth0"]:
                return "Still using dense-style OIL on r1 after RP add: {}".format(oil)
            if "r1-eth0" in oil:
                return (
                    "Unexpected dense flood OIF r1-eth0 on r1 after RP add: {}".format(
                        oil
                    )
                )

        return None

    _, result = topotest.run_and_expect(_r1_upstream_sparse, None, count=60, wait=1)
    assert result is None, "DM to SM transition check failed: {}".format(result)

    step("Verify r1 no longer uses dense-mode OIL toward r2")

    def _r1_not_dense_oil():
        mroute = mroute_entry(tgen, "r1", SRC, group)
        if not mroute:
            return "No mroute on r1 after RP add"
        oil = mroute_oil_names(mroute)
        if oil == ["r1-eth0"]:
            return "Dense-style OIL still present on r1: {}".format(oil)
        return None

    _, result = topotest.run_and_expect(_r1_not_dense_oil, None, count=30, wait=1)
    assert result is None, "Dense OIL check failed on r1: {}".format(result)

    step("Remove transient RP mapping added for this test")
    for rname in routers:
        tgen.gears[rname].vtysh_cmd(
            """
            conf t
              router pim
                no rp 10.0.2.1 239.0.0.0/8
            """
        )

    stop_all_hosts()


def test_pim_dense_lan_prune_with_active_branch(request):
    """Verify LAN prune/override on the shared 10.0.2.0/24 segment (r2, r4, r7).

    RFC 3973 items 4 and 5 with three PIM routers on one multi-access LAN:

    - Item 5 (join override): when h4 leaves, r4 Prunes on the LAN but r7 still
      has h7 joined. r7 must override so r2 keeps flooding on r2-eth2 and h7
      keeps receiving.

    - Item 4 (delayed prune): when h7 also leaves, no sibling on the LAN has
      downstream receivers. r2 must wait for the LAN override window before
      dropping r2-eth2 from its OIL.

    - Graft: re-joining h4 after the LAN branch pruned must restore the r4 path.

    Topology (r7 added on shared 10.0.2.0/24 with r2 and r4):
      h1 -> r1 -> r2 === 10.0.2 LAN (r2-eth2, r4-eth0, r7-eth0) === r4 -> h4
                                   |
                                   +-> r7 -> h7

    Uses a dedicated group so earlier tests cannot leave stale (S,G) state.
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    group = "239.8.8.8"

    stop_all_hosts()

    step("Join receivers on h4 and h7, then start dense traffic from h1")
    for host, intf in (
        ("h4", "h4-eth0"),
        ("h7", "h7-eth0"),
    ):
        result = app_helper.run_join(host, group, join_intf=intf)
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    result = app_helper.run_traffic("h1", group, bind_intf="h1-eth0")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify r2 floods on the shared LAN and both receivers get traffic")
    lan_setup = {
        "r2": ("r2-eth0", "r2-eth2"),
        "r4": ("r4-eth0", "r4-eth1"),
        "r7": ("r7-eth0", "r7-eth1"),
    }
    for router, (iif, oil) in lan_setup.items():
        _, result = topotest.run_and_expect(
            functools.partial(check_mroute_oil, tgen, router, SRC, group, iif, oil),
            None,
            count=30,
            wait=2,
        )
        assert result is None, "LAN setup failed on {}: {}".format(router, result)

    step("Stop h4 so r4 Prunes on the shared LAN while r7 still has h7")
    app_helper.stop_host("h4")

    step("Wait until r4 has no IGMP membership for the group")
    _, result = topotest.run_and_expect(
        functools.partial(check_igmp_group_absent, tgen, "r4", "r4-eth1", group),
        None,
        count=30,
        wait=2,
    )
    assert result is None, "r4 still has IGMP membership after h4 leave: {}".format(
        result
    )

    step("Verify the h7 branch stays up after r4 Prunes (item 5)")
    _, result = topotest.run_and_expect(
        functools.partial(
            check_mroute_oil, tgen, "r7", SRC, group, "r7-eth0", "r7-eth1"
        ),
        None,
        count=30,
        wait=2,
    )
    assert result is None, "h7 branch lost after h4 left: {}".format(result)

    step("Verify r2 keeps r2-eth2 in its OIL while r7 Join overrides r4 Prune (item 5)")
    _, result = topotest.run_and_expect(
        functools.partial(check_mroute_oif_present, tgen, "r2", SRC, group, "r2-eth2"),
        None,
        count=15,
        wait=1,
    )
    assert result is None, "LAN join override missing on r2-eth2: {}".format(result)

    step("Stop h7 so no sibling on the LAN has downstream receivers")
    app_helper.stop_host("h7")

    step("Wait until r7 has no IGMP membership for the group")
    _, result = topotest.run_and_expect(
        functools.partial(check_igmp_group_absent, tgen, "r7", "r7-eth1", group),
        None,
        count=30,
        wait=2,
    )
    assert result is None, "r7 still has IGMP membership after h7 leave: {}".format(
        result
    )

    step("Verify r2 keeps r2-eth2 in its OIL during the LAN override window (item 4)")
    _, result = topotest.run_and_expect(
        functools.partial(check_mroute_oif_present, tgen, "r2", SRC, group, "r2-eth2"),
        None,
        count=2,
        wait=1,
    )
    assert result is None, "LAN delayed prune missing on r2-eth2: {}".format(result)

    step("Stop the source so continuous flood cannot re-add pruned LAN OIFs")
    app_helper.stop_host("h1")

    step("Verify r2 eventually stops flooding on the shared LAN")
    _, result = topotest.run_and_expect(
        functools.partial(check_mroute_oif_absent, tgen, "r2", SRC, group, "r2-eth2"),
        None,
        count=30,
        wait=1,
    )
    assert result is None, "r2 still flooding pruned LAN branch: {}".format(result)

    step("Re-join h4, restart traffic, and verify the r4 branch grafts back")
    result = app_helper.run_join("h4", group, join_intf="h4-eth0")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    result = app_helper.run_traffic("h1", group, bind_intf="h1-eth0")
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    _, result = topotest.run_and_expect(
        functools.partial(
            check_mroute_oil, tgen, "r4", SRC, group, "r4-eth0", "r4-eth1"
        ),
        None,
        count=30,
        wait=2,
    )
    assert result is None, "Graft back to h4 failed: {}".format(result)

    stop_all_hosts()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
