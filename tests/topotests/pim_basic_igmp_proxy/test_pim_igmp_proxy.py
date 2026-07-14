#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_igmp_proxy.py
#
# Copyright (c) 2024 ATCorp
# Barry A. Trent
#

"""
Following tests are covered to test pim igmp proxy:

1. TC:1 Verify correct joins were read from the config and proxied
2. TC:2 Verify joins from another interface are proxied
3. TC:3 Verify correct proxy disable on 'no ip igmp proxy'
4. TC:4 Verify that proper proxy joins are set up on run-time enable
5. TC:5 Verify igmp drops/timeouts from another interface cause
        proxy join removal
6. TC:6 Verify that 'ip igmp proxy route-map' filters proxied groups
7. TC:7 Verify 'match multicast-source-interface' filters by source iface
8. TC:8 Verify leave on one downstream interface does not prune proxy
        while another downstream interface still has receivers for the
        same group
9. TC:9 Verify filtered downstream interest does not block proxy prune
10. TC:10 Verify (S,G) static-group covered by (*,G) is pruned when that
        (*,G) later leaves
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
from lib.pim import verify_local_igmp_proxy_groups


def build_topo(tgen):
    "Build function"

    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    tgen.add_router("rp")

    #   rp ------ r1 -------- r2 -------
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

    # 10.0.40.0/24
    sw = tgen.add_switch("sw3")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r3"])

    # Dummy interface for static joins
    tgen.gears["r2"].run("ip link add r2-eth1 type dummy")


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


def test_pim_igmp_proxy_config():
    "Ensure correct joins were read from the config and proxied"
    logger.info("Verify initial igmp proxy setup from config file")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    expected = {
        "vrf": "default",
        "r1-eth1": {
            "name": "r1-eth1",
            "groups": [
                {
                    "source": "*",
                    "group": "225.4.4.4",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.3.3.3",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.2.2.2",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.1.1.1",
                    "primaryAddr": "10.0.30.1",
                },
            ],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_pim_igmp_proxy_learn():
    "Ensure joins learned from a neighbor are propagated"
    logger.info("Verify joins can be learned")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        "conf\nint r2-eth0\nip igmp join 225.5.5.5\nip igmp join 225.6.6.6\nexit\nexit"
    )
    r2.vtysh_cmd(
        "conf\nint r2-eth1\nip igmp join 225.7.7.7\nip igmp join 225.8.8.8\nexit\nexit"
    )
    expected = {
        "vrf": "default",
        "r1-eth1": {
            "name": "r1-eth1",
            "groups": [
                {
                    "source": "*",
                    "group": "225.5.5.5",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.6.6.6",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.7.7.7",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.8.8.8",
                    "primaryAddr": "10.0.30.1",
                },
            ],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_pim_no_igmp_proxy():
    "Check for correct proxy disable"
    logger.info("Verify no ip igmp proxy")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf\nint r1-eth1\nno ip igmp proxy\nexit\nexit")
    expected = {"vrf": "default"}

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_pim_igmp_proxy_restart():
    "Check that all proxy joins are captured at run-time enable"
    logger.info("Verify runtime ip igmp proxy")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf\nint r1-eth1\nip igmp proxy\nexit\nexit")
    expected = {
        "vrf": "default",
        "r1-eth1": {
            "name": "r1-eth1",
            "groups": [
                {
                    "source": "*",
                    "group": "225.8.8.8",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.7.7.7",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.6.6.6",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.5.5.5",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.4.4.4",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.3.3.3",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.2.2.2",
                    "primaryAddr": "10.0.30.1",
                },
                {
                    "source": "*",
                    "group": "225.1.1.1",
                    "primaryAddr": "10.0.30.1",
                },
            ],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_pim_igmp_proxy_leave():
    "Ensure drops/timeouts learned from a neighbor are propagated"
    logger.info("Verify joins can be dropped")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.vtysh_cmd("conf\nint r1-eth0\nno ip igmp join 225.1.1.1\nexit\nexit")
    r2.vtysh_cmd("conf\nint r2-eth0\nno ip igmp join 225.6.6.6\nexit\nexit")
    r2.vtysh_cmd("conf\nint r2-eth1\nno ip igmp join 225.8.8.8\nexit\nexit")

    joined_addresses = ["225.2.2.2", "225.3.3.3", "225.4.4.4", "225.5.5.5", "225.7.7.7"]
    deleted_addresses = ["225.1.1.1", "225.6.6.6", "225.8.8.8"]

    result = verify_local_igmp_proxy_groups(
        tgen, "r1", joined_addresses, deleted_addresses
    )

    assert result is True, "Error: {}".format(result)
    # tgen.mininet_cli()


def test_pim_igmp_proxy_route_map():
    """
    TC:6 - Verify that 'ip igmp proxy route-map' filters proxied groups.

    State at entry (from test_pim_igmp_proxy_leave):
      proxied on r1-eth1: 225.2.2.2, 225.3.3.3, 225.4.4.4, 225.5.5.5, 225.7.7.7

    Steps:
      1. Configure a route-map on r1 that permits only 225.2.2.2 and 225.3.3.3.
      2. Apply 'ip igmp proxy route-map PROXY_FILTER' on r1-eth1.
      3. Verify the line appears in 'show running-config' (config persistence
         regression test for the AF-agnostic pim_config_write path).
      4. Cycle proxy (no/re-enable) so pim_if_gm_proxy_init re-runs with the filter.
      5. Verify only 225.2.2.2 and 225.3.3.3 appear in the proxy list.
      6. Add a new join that the route-map denies; verify it is NOT proxied.
      7. Remove the route-map; cycle proxy again; verify all groups return and
         the line is no longer in running-config.
    """
    logger.info("Verify ip igmp proxy route-map filtering")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Step 1+2: configure prefix-list, route-map, and apply to proxy interface
    r1.vtysh_cmd(
        """
conf
ip prefix-list PROXY_GROUPS seq 5 permit 225.2.2.2/32
ip prefix-list PROXY_GROUPS seq 10 permit 225.3.3.3/32
!
route-map PROXY_FILTER permit 10
 match ip multicast-group prefix-list PROXY_GROUPS
!
int r1-eth1
 ip igmp proxy route-map PROXY_FILTER
"""
    )

    # Verify the proxy route-map is emitted in running-config (regression
    # test for the AF-agnostic config-write path: the line must persist
    # across restarts for both pimd and pim6d).
    running = r1.vtysh_cmd("show running-config")
    assert "ip igmp proxy route-map PROXY_FILTER" in running, (
        "running-config missing 'ip igmp proxy route-map' line; "
        "config would not persist across restart:\n" + running
    )

    # Step 3: cycle proxy so pim_if_gm_proxy_init is called with the filter active
    r1.vtysh_cmd(
        """
conf
int r1-eth1
 no ip igmp proxy
 ip igmp proxy
"""
    )

    # Step 4: only the two permitted groups should be proxied
    expected_filtered = {
        "vrf": "default",
        "r1-eth1": {
            "name": "r1-eth1",
            "groups": [
                {"source": "*", "group": "225.2.2.2", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.3.3.3", "primaryAddr": "10.0.30.1"},
            ],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected_filtered
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r1" proxy groups mismatch after route-map filter applied'
    assert result is None, assertmsg

    # Step 5: add a new join that the route-map denies (225.9.9.9) — must NOT appear
    r2.vtysh_cmd(
        """
conf
int r2-eth0
 ip igmp join 225.9.9.9
"""
    )

    denied_groups = ["225.4.4.4", "225.5.5.5", "225.7.7.7", "225.9.9.9"]

    def step5_join_seen_proxy_omits_denied():
        igmp = r2.vtysh_cmd("show ip igmp groups json", isjson=True)
        try:
            r2_groups = [g["group"] for g in igmp["r2-eth0"]["groups"]]
        except (KeyError, TypeError):
            return False
        if "225.9.9.9" not in r2_groups:
            return False
        v = verify_local_igmp_proxy_groups(tgen, "r1", [], denied_groups)
        if v is True:
            return True
        assert False, v

    _, result = topotest.run_and_expect(
        step5_join_seen_proxy_omits_denied, True, count=30, wait=1
    )
    assert (
        result is True
    ), "Timed out waiting for r2 IGMP join while r1 proxy omits denied groups"

    # Step 6: remove the route-map and cycle proxy — all groups should return
    r2.vtysh_cmd(
        """
conf
int r2-eth0
 no ip igmp join 225.9.9.9
"""
    )
    r1.vtysh_cmd(
        """
conf
int r1-eth1
 no ip igmp proxy route-map
 no ip igmp proxy
 ip igmp proxy
"""
    )

    expected_unfiltered = {
        "vrf": "default",
        "r1-eth1": {
            "name": "r1-eth1",
            "groups": [
                {"source": "*", "group": "225.2.2.2", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.3.3.3", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.4.4.4", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.5.5.5", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.7.7.7", "primaryAddr": "10.0.30.1"},
            ],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected_unfiltered
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r1" proxy groups mismatch after route-map removed'
    assert result is None, assertmsg

    # Verify the proxy route-map is no longer emitted in running-config.
    running = r1.vtysh_cmd("show running-config")
    assert "ip igmp proxy route-map" not in running, (
        "running-config still has 'ip igmp proxy route-map' after removal:\n" + running
    )

    # cleanup route-map config
    r1.vtysh_cmd(
        """
conf
no route-map PROXY_FILTER
no ip prefix-list PROXY_GROUPS
"""
    )


def test_pim_igmp_proxy_source_interface_filter():
    """
    TC:7 - Verify 'match multicast-source-interface' filters proxied groups
           based on the interface where the IGMP report was received.

    Topology relevant to this test:
      r1-eth0 (10.0.20.1) <-> r2-eth0  (sw1)  -- groups from r2 arrive here
      r1-eth1 (10.0.30.1) <-> rp        (sw2)  -- proxy output interface
      r1-eth2 (10.0.40.1) <-> r3        (sw3)  -- static joins 225.3.3.3/225.4.4.4

    State at entry (from test_pim_igmp_proxy_route_map):
      Source iface r1-eth0: 225.2.2.2, 225.5.5.5, 225.7.7.7
      Source iface r1-eth2: 225.3.3.3, 225.4.4.4
      All five proxied on r1-eth1.

    Steps:
      1. Configure a route-map matching only source interface r1-eth2.
      2. Apply it and cycle proxy.
      3. Verify only 225.3.3.3 and 225.4.4.4 (from r1-eth2) are proxied.
      4. Verify groups from r1-eth0 are absent.
      5. Remove the route-map; cycle proxy; verify all five groups return.
    """
    logger.info("Verify match multicast-source-interface filtering")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]

    # Step 1+2: route-map matching source interface r1-eth2 only
    r1.vtysh_cmd(
        """
conf
route-map PROXY_SRC_IFC permit 10
 match multicast-source-interface r1-eth2
!
int r1-eth1
 ip igmp proxy route-map PROXY_SRC_IFC
 no ip igmp proxy
 ip igmp proxy
"""
    )

    # Step 3: only groups reported on r1-eth2 should be proxied
    expected_eth2_only = {
        "vrf": "default",
        "r1-eth1": {
            "name": "r1-eth1",
            "groups": [
                {"source": "*", "group": "225.3.3.3", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.4.4.4", "primaryAddr": "10.0.30.1"},
            ],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected_eth2_only
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r1" proxy groups mismatch: expected only r1-eth2 groups'
    assert result is None, assertmsg

    # Step 4: groups from r1-eth0 must not appear
    denied_groups = ["225.2.2.2", "225.5.5.5", "225.7.7.7"]
    result = verify_local_igmp_proxy_groups(tgen, "r1", [], denied_groups)
    assert result is True, "Error: r1-eth0 group leaked into proxy: {}".format(result)

    # Step 5: remove the route-map; all groups should return
    r1.vtysh_cmd(
        """
conf
int r1-eth1
 no ip igmp proxy route-map
 no ip igmp proxy
 ip igmp proxy
"""
    )

    expected_all = {
        "vrf": "default",
        "r1-eth1": {
            "name": "r1-eth1",
            "groups": [
                {"source": "*", "group": "225.2.2.2", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.3.3.3", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.4.4.4", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.5.5.5", "primaryAddr": "10.0.30.1"},
                {"source": "*", "group": "225.7.7.7", "primaryAddr": "10.0.30.1"},
            ],
        },
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected_all
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"r1" proxy groups mismatch after source-interface route-map removed'
    assert result is None, assertmsg

    # cleanup
    r1.vtysh_cmd(
        """
conf
no route-map PROXY_SRC_IFC
"""
    )


def test_pim_igmp_proxy_multi_downstream_leave():
    """
    TC:8 - Leave on one downstream must not proxy-prune while another still wants G.

    Topology reminder:
      r1-eth0 <-> r2   (downstream)
      r1-eth1 <-> rp   (upstream / igmp proxy)
      r1-eth2 <-> r3   (downstream)

    Join the same group on both downstream interfaces, leave on eth0 only, and
    confirm the upstream proxy join remains until the last downstream receiver
    leaves.
    """
    logger.info("Verify multi-downstream leave does not prune remaining proxy join")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    group = "239.0.0.1"

    r1.vtysh_cmd(
        f"""
conf
 interface r1-eth0
  ip igmp join {group}
 interface r1-eth2
  ip igmp join {group}
"""
    )

    result = verify_local_igmp_proxy_groups(tgen, "r1", [group], [])
    assert result is True, "Error: {}".format(result)

    r1.vtysh_cmd(
        f"""
conf
 interface r1-eth0
  no ip igmp join {group}
"""
    )

    result = verify_local_igmp_proxy_groups(tgen, "r1", [group], [])
    assert result is True, "Error: proxy pruned while r1-eth2 still joined: {}".format(
        result
    )

    r1.vtysh_cmd(
        f"""
conf
 interface r1-eth2
  no ip igmp join {group}
"""
    )

    result = verify_local_igmp_proxy_groups(tgen, "r1", [], [group])
    assert (
        result is True
    ), "Error: proxy join remained after last downstream leave: {}".format(result)


def test_pim_igmp_proxy_filtered_downstream_leave():
    """
    TC:9 - Filtered downstream interest must not keep the upstream proxy join.

    Join the same group on eth0 (permitted) and eth2 (denied by source-interface
    route-map).  Leaving eth0 must proxy-prune even though eth2 still has a join.
    """
    logger.info("Verify filtered downstream does not block proxy prune on leave")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    group = "239.0.0.2"

    r1.vtysh_cmd(
        f"""
conf
route-map PROXY_LEAVE_FILTER permit 10
 match multicast-source-interface r1-eth0
!
interface r1-eth0
 ip igmp join {group}
interface r1-eth2
 ip igmp join {group}
interface r1-eth1
 ip igmp proxy route-map PROXY_LEAVE_FILTER
 no ip igmp proxy
 ip igmp proxy
"""
    )

    result = verify_local_igmp_proxy_groups(tgen, "r1", [group], [])
    assert result is True, "Error: {}".format(result)

    # Leave the only unfiltered downstream; eth2 still joined but denied by rmap.
    r1.vtysh_cmd(
        f"""
conf
 interface r1-eth0
  no ip igmp join {group}
"""
    )

    result = verify_local_igmp_proxy_groups(tgen, "r1", [], [group])
    assert result is True, (
        "Error: proxy join remained after last unfiltered downstream leave "
        "(filtered eth2 still joined): {}".format(result)
    )

    # cleanup
    r1.vtysh_cmd(
        f"""
conf
interface r1-eth2
 no ip igmp join {group}
interface r1-eth1
 no ip igmp proxy route-map
no route-map PROXY_LEAVE_FILTER
"""
    )


def test_pim_igmp_proxy_starg_covers_sg_leave():
    """
    TC:10 - (S,G) kept by covering (*,G) must prune when that (*,G) later leaves.

    This is an ASM static-group edge case: join-group cannot install proxied
    (S,G) in ASM (igmp_source_forward_start refuses ASM+source), and SSM
    cannot hold covering (*,G).  static-group is the way to create (S,G) on
    an ASM group that also has (*,G) interest.

    Sequence:
      1. eth0 static-group (S,G) -> proxy adds (S,G)
      2. eth2 static-group (*,G) -> proxy adds (*,G)
      3. eth0 removes (S,G) -> skip (S,G) prune because eth2 (*,G) covers it
      4. eth2 removes (*,G) -> prune (*,G) and also the uncovered (S,G)
    """
    logger.info("Verify (S,G) proxy covered by (*,G) is not stranded on (*,G) leave")
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    group = "239.0.0.3"
    source = "10.1.1.10"

    r1.vtysh_cmd(
        f"""
conf
 interface r1-eth0
  ip igmp static-group {group} {source}
 interface r1-eth2
  ip igmp static-group {group}
"""
    )

    expected_both = {
        "r1-eth1": {
            "groups": [
                {
                    "source": source,
                    "group": group,
                },
                {
                    "source": "*",
                    "group": group,
                },
            ],
        },
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip igmp proxy json", expected_both
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "expected both (S,G) and (*,G) proxy joins: {}".format(
        r1.vtysh_cmd("show ip igmp proxy json")
    )

    # Remove (S,G); (*,G) on eth2 must keep coverage (and may keep (S,G) proxy).
    r1.vtysh_cmd(
        f"""
conf
 interface r1-eth0
  no ip igmp static-group {group} {source}
"""
    )

    result = verify_local_igmp_proxy_groups(tgen, "r1", [group], [])
    assert result is True, "Error: proxy pruned while eth2 still has (*,G): {}".format(
        result
    )

    # Remove covering (*,G); uncovered (S,G) proxy must go with it.
    r1.vtysh_cmd(
        f"""
conf
 interface r1-eth2
  no ip igmp static-group {group}
"""
    )

    result = verify_local_igmp_proxy_groups(tgen, "r1", [], [group])
    assert (
        result is True
    ), "Error: (S,G) proxy join stranded after covering (*,G) leave: {}".format(result)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
