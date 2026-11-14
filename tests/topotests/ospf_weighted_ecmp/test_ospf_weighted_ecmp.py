#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_weighted_ecmp.py
#
# Brian Miller
#

import os
import sys
import json
from operator import itemgetter
from functools import partial
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

from lib.common_config import (
    step,
)


"""
test_ospf_weighted_ecmp.py: Test OSPF weighted ECMP on multipath routes
"""

TOPOLOGY = """


            +-----+             +-----+ 
       eth4 |     |   eth0      |     | eth4
      ------+     +-------------+     +------
10.1.7.0/24 |     | 10.1.1.0/24 |     | 10.1.5.0/24
            |     |             |     |
            |     |   eth1      |     |
            |     +-------------+     |
            | R1  | 10.1.2.0/24 |  R2 |
            |     |             |     |
            |     |   eth2      |     |
            |     +-------------+     |
            |     | 10.1.3.0/24 |     |
            |     |             |     |
            |     |   eth3      |     |
            |     +-------------+     |
            |     | 10.1.4.0/24 |     |
         .1 +-----+.1         .2+-----+.2

"""

#This assumes zebra was started without the '--nexthop-weight-16-bit' flag
RIB_MAX_WEIGHT = 255

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    # Create 3 routers
    tgen.add_router("r1")
    tgen.add_router("r2")

    # Interconect router 1, 2 (0)
    switch = tgen.add_switch("s1-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 2 (1)
    switch = tgen.add_switch("s2-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 2 (2)
    switch = tgen.add_switch("s3-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 2 (3)
    switch = tgen.add_switch("s4-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Add standalone network to router 1
    switch = tgen.add_switch("s7-1")
    switch.add_link(tgen.gears["r1"])

    # Add standalone network to router 2
    switch = tgen.add_switch("s5-1")
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    logger.info("OSPF Prefix Suppression:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def get_nexthops_with_weights(nexthops):
    m = max(nexthops, key=itemgetter(2))[2]
    _nh = []
    for i,(iface,ip,weight) in enumerate(nexthops):
        weight = int(RIB_MAX_WEIGHT * weight / m)
        weight = 1 if weight == 0 else weight
        _nh.append({"interfaceName":iface,"ip":ip,"weight":weight})
    return _nh


def test_ospf_weighted_ecmp_startup():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    # Verify OSPF route is installed with appropriate next-hops and weights
    step("Check next-hop weights on R1 for route 10.1.5.0/24")
    r1 = tgen.gears["r1"]
    nh_list = [("r1-eth0","10.1.1.2",10),
               ("r1-eth1","10.1.2.2",100),
               ("r1-eth2","10.1.3.2",200),
               ("r1-eth3","10.1.4.2",400)]
    nexthops = get_nexthops_with_weights(nh_list)
    input_dict = {
        "10.1.5.0/24": [
            {
                "prefix": "10.1.5.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": nexthops
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 10.1.5.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.5.0/24 either not installed on router r1 or next-hop weights are invalid"
    assert result is None, assertmsg


def test_ospf_weight_config_removal():
    tgen = get_topogen()
    #Test removal of weight from an interface
    step("Configure R1 interface r1-eth3 without ospf weight")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("""
        conf term
            interface r1-eth3
                no ip ospf weight
    """)

    step("Verify the R1 configuration of 'no ip ospf weight'")
    def check_no_ospf_weight_config():
        rc, _, _ = tgen.net["r1"].cmd_status(
            "show running ospfd | sed -n '/interface r1-eth3/,/exit/p' | grep -q 'ip ospf weight'", warn=False
        )
        return rc

    _, rc = topotest.run_and_expect(
        check_no_ospf_weight_config, 1, count=30, wait=1
    )
    assertmsg = (
        "'ip ospf weight' not applied, but present in R1 configuration"
    )
    assert rc, assertmsg

    step("Check next-hop weights on R1 for route 10.1.5.0/24 after removing ospf weight config from r1-eth3")
    nh_list = [("r1-eth0","10.1.1.2",10),
               ("r1-eth1","10.1.2.2",100),
               ("r1-eth2","10.1.3.2",200),
               ("r1-eth3","10.1.4.2",1)]
    nexthops = get_nexthops_with_weights(nh_list)
    input_dict = {
        "10.1.5.0/24": [
            {
                "prefix": "10.1.5.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": nexthops
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 10.1.5.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "RIB for 10.1.5.0/24 not correct after removing weight from r1-eth3"
    assert result is None, assertmsg

def test_ospf_weight_config():
    tgen = get_topogen()
    #Test insertion of weight on an interface
    step("Configure R1 interface r1-eth3 with ospf weight 65536")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("""
        conf term
            interface r1-eth3
                ip ospf weight 65536
    """)

    step("Verify the R1 configuration of 'ip ospf weight 65536'")

    def check_ospf_weight_config():
        return (
            tgen.net["r1"]
            .cmd('vtysh -c "show running ospfd" | sed -n \'/interface r1-eth3/,/exit/p\' | grep "^ ip ospf weight"')
            .rstrip()
        )

    _, ospf_weight_cfg = topotest.run_and_expect(
        check_ospf_weight_config,
        " ip ospf weight 65536",
        count=30,
        wait=1,
    )
    assertmsg = "'ip ospf weight 65536' applied, but not present in configuration"
    assert ospf_weight_cfg == " ip ospf weight 65536", assertmsg

    step("Check next-hop weights on R1 for route 10.1.5.0/24 after setting ospf weight config to r1-eth3")
    nh_list = [("r1-eth0","10.1.1.2",10),
               ("r1-eth1","10.1.2.2",100),
               ("r1-eth2","10.1.3.2",200),
               ("r1-eth3","10.1.4.2",65536)]
    nexthops = get_nexthops_with_weights(nh_list)
    input_dict = {
        "10.1.5.0/24": [
            {
                "prefix": "10.1.5.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": nexthops
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 10.1.5.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "RIB for 10.1.5.0/24 not correct after setting weight on r1-eth3"
    assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
