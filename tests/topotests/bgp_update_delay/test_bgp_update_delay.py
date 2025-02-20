#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_update_delay.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Don Slice <dslice@nvidia.com>
#

"""
Test the ability to define update-delay to delay bestpath, rib install
and advertisement to peers when frr is started, restarted or "clear ip
bgp *" is performed. Test both the vrf-specific and global configuration
and operation.

r1
|
r2----r3
| \
|  \
r5  r4


r2 is UUT and peers with r1, r3, and r4 in default bgp instance.
r2 peers with r5 in vrf vrf1.

Check r2 initial convergence in default table
Define update-delay with max-delay in the default bgp instance on r2
Shutdown peering on r1 toward r2 so that delay timers can be exercised
Clear bgp neighbors on r2 and then check for the 'in progress' indicator
Check that r2 only installs route learned from r4 after the max-delay timer expires
Define update-delay with max-delay and estabish-wait and check json output showing set
Clear neighbors on r2 and check that r3 installs route from r4 after establish-wait time
Remove update-delay timer on r2 to verify that it goes back to normal behavior
Clear neighbors on r2 and check that route install time on r2 does not delay
Define global bgp update-delay with max-delay and establish-wait on r2
Check that r2 default instance and vrf1 have the max-delay and establish set
Clear neighbors on r2 and check route-install time is after the establish-wait timer

Note that the keepalive/hold times were changed to 3/9 and the connect retry timer
to 10 to improve the odds the convergence timing in this test case is useful in the
event of packet loss.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


CWD = os.path.dirname(os.path.realpath(__file__))


def build_topo(tgen):
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r5"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_update_delay():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # initial convergence without update-delay defined
    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_update_delay(router):
        output = json.loads(router.vtysh_cmd("show ip bgp sum json"))
        expected = {"ipv4Unicast": {"updateDelayLimit": 20}}

        return topotest.json_cmp(output, expected)

    def _bgp_check_update_delay_in_progress(router):
        output = json.loads(router.vtysh_cmd("show ip bgp sum json"))
        expected = {"ipv4Unicast": {"updateDelayInProgress": True}}

        return topotest.json_cmp(output, expected)

    def _bgp_check_route_install(router):
        output = json.loads(router.vtysh_cmd("show ip route 172.16.253.254/32 json"))
        expected = {"172.16.253.254/32": [{"protocol": "bgp"}]}

        return topotest.json_cmp(output, expected)

    def _bgp_check_update_delay_and_wait(router):
        output = json.loads(router.vtysh_cmd("show ip bgp sum json"))
        expected = {
            "ipv4Unicast": {"updateDelayLimit": 20, "updateDelayEstablishWait": 10}
        }

        return topotest.json_cmp(output, expected)

    def _bgp_check_update_delay(router):
        output = json.loads(router.vtysh_cmd("show ip bgp sum json"))
        expected = {"ipv4Unicast": {"updateDelayLimit": 20}}

        return topotest.json_cmp(output, expected)

    def _bgp_check_vrf_update_delay_and_wait(router):
        output = json.loads(router.vtysh_cmd("show ip bgp vrf vrf1 sum json"))
        expected = {
            "ipv4Unicast": {"updateDelayLimit": 20, "updateDelayEstablishWait": 10}
        }

        return topotest.json_cmp(output, expected)

    # Check r2 initial convergence in default table
    test_func = functools.partial(_bgp_converge, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed bgp convergence in "{}"'.format(router2)

    # Define update-delay with max-delay in the default bgp instance on r2
    router2.vtysh_cmd(
        """
          configure terminal
            router bgp 65002
              update-delay 20
        """
    )

    # Shutdown peering on r1 toward r2 so that delay timers can be exercised
    router1.vtysh_cmd(
        """
          configure terminal
            router bgp 65001
              neighbor 192.168.255.1 shut
        """
    )

    # Clear bgp neighbors on r2 and then check for the 'in progress' indicator
    router2.vtysh_cmd("""clear ip bgp *""")

    test_func = functools.partial(_bgp_check_update_delay_in_progress, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed to set update-delay max-delay timer "{}"'.format(
        router2
    )

    # Check that r2 only installs route learned from r4 after the max-delay timer expires
    test_func = functools.partial(_bgp_check_route_install, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed to install route after update-delay "{}"'.format(
        router2
    )

    # Define update-delay with max-delay and estabish-wait and check json output showing set
    router2.vtysh_cmd(
        """
          configure terminal
            router bgp 65002
              update-delay 20 10
        """
    )

    test_func = functools.partial(_bgp_check_update_delay_and_wait, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), 'Failed to set max-delay and establish-weight timers in "{}"'.format(router2)

    # Define update-delay with max-delay and estabish-wait and check json output showing set
    router2.vtysh_cmd("""clear ip bgp *""")

    test_func = functools.partial(_bgp_check_route_install, router3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), 'Failed to installed advertised route after establish-wait timer espired "{}"'.format(
        router2
    )

    # Remove update-delay timer on r2 to verify that it goes back to normal behavior
    router2.vtysh_cmd(
        """
          configure terminal
            router bgp 65002
              no update-delay
        """
    )

    # Clear neighbors on r2 and check that route install time on r2 does not delay
    router2.vtysh_cmd("""clear ip bgp *""")

    test_func = functools.partial(_bgp_check_route_install, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed to remove update-delay delay timing "{}"'.format(
        router2
    )

    # Define global bgp update-delay with max-delay and establish-wait on r2
    router2.vtysh_cmd(
        """
          configure terminal
            bgp update-delay 20 10
        """
    )

    # Check that r2 default instance and vrf1 have the max-delay and establish set
    test_func = functools.partial(_bgp_check_update_delay_and_wait, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed to set update-delay in default instance "{}"'.format(
        router2
    )

    test_func = functools.partial(_bgp_check_vrf_update_delay_and_wait, router2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed to set update-delay in vrf1 "{}"'.format(router2)

    # Clear neighbors on r2 and check route-install time is after the establish-wait timer
    router2.vtysh_cmd("""clear ip bgp *""")

    test_func = functools.partial(_bgp_check_route_install, router3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), 'Failed to installed advertised route after establish-wait timer espired "{}"'.format(
        router2
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
