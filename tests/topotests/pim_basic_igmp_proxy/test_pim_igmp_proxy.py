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
"""

import os
import sys
import pytest
import json
import time
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
    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

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


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
