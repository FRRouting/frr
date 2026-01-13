#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim.py
#
# Copyright (c) 2018 Cumulus Networks, Inc.
#                    Donald Sharp
#

"""
test_pim.py: Test pim
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

    # 10.0.40.0/24
    sw = tgen.add_switch("sw3")
    sw.add_link(tgen.gears["r1"])
    sw.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the integrated configuration file
    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_PIM, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

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
    json_file = "{}/{}/rp-info.json".format(CWD, r1.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim rp-info json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(r1.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_pim_send_mcast_stream():
    "Establish a Multicast stream from r2 -> r1 and then ensure S,G is created as appropriate"
    logger.info("Establish a Mcast stream from r2->r1 and then ensure S,G created")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rp = tgen.gears["rp"]
    r3 = tgen.gears["r3"]
    r2 = tgen.gears["r2"]
    r1 = tgen.gears["r1"]

    # Let's establish a S,G stream from r2 -> r1
    CWD = os.path.dirname(os.path.realpath(__file__))
    r2.run(
        "{}/mcast-tx.py --ttl 5 --count 40 --interval 2 229.1.1.1 r2-eth0 > {}/r2/mcast_tx_output".format(
            CWD, tgen.logdir
        )
    )
    # And from r3 -> r1
    r3.run(
        "{}/mcast-tx.py --ttl 5 --count 40 --interval 2 229.1.1.1 r3-eth0 > {}/r3/mcast_tx_output".format(
            CWD, tgen.logdir
        )
    )

    # Let's see that it shows up and we have established some basic state
    out = r1.vtysh_cmd("show ip pim upstream json", isjson=True)
    expected = {
        "229.1.1.1": {
            "10.0.20.2": {
                "firstHopRouter": 1,
                "joinState": "NotJoined",
                "regState": "RegPrune",
                "inboundInterface": "r1-eth0",
            }
        }
    }

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim upstream json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=1)
    assert result is None, "failed to converge pim"
    # tgen.mininet_cli()


def test_pim_rp_sees_stream():
    "Ensure that the RP sees the stream and has acted accordingly"
    tgen = get_topogen()

    rp = tgen.gears["rp"]
    json_file = "{}/{}/upstream.json".format(CWD, rp.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, rp, "show ip pim upstream json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(rp.name)
    assert result is None, assertmsg


def test_pim_igmp_report():
    "Send a igmp report from r2->r1 and ensure that the *,G state is created on r1"
    logger.info("Send a igmp report from r2-r1 and ensure *,G created")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r1 = tgen.gears["r1"]

    # Let's send a igmp report from r2->r1
    cmd = [os.path.join(CWD, "mcast-rx.py"), "229.1.1.2", "r2-eth0"]
    p = r2.popen(cmd)
    try:
        expected = {
            "229.1.1.2": {
                "*": {
                    "sourceIgmp": 1,
                    "joinState": "Joined",
                    "regState": "RegNoInfo",
                    "sptBit": 0,
                }
            }
        }
        test_func = partial(
            topotest.router_json_cmp, r1, "show ip pim upstream json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(r1.name)
        assert result is None, assertmsg
    finally:
        if p:
            p.terminate()
            p.wait()


def test_pim_ssm_ping():
    "Test SSM ping functionality between r1 and r2"
    logger.info("Testing SSM ping from r1 to r2")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("conf\nip ssmpingd 10.0.20.2")

    # Run ssmping from r1 to r2
    output = r1.run("ssmping -I r1-eth0 10.0.20.2 -c 5")

    # Check if we got successful responses
    assert "5 packets received" in output, "SSM ping failed"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


def test_pim_static_mroute():
    "Test Static routes add/remove cycle"
    logger.info("Testing static routes")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    ip_mroute_json = r1.vtysh_cmd("show ip mroute json", isjson=True)
    assert "239.1.1.1" not in ip_mroute_json.keys()

    # Add ip mroute with iif=r1-eth0 oil=r1-eth1
    r1.vtysh_cmd("conf t\ninterface r1-eth0\nip mroute r1-eth1 239.1.1.1 10.0.0.1")

    # Expect to find oil=[r1-eth1] in ip mroute command
    ip_mroute_json = r1.vtysh_cmd("show ip mroute json", isjson=True)
    assert list(ip_mroute_json["239.1.1.1"]["10.0.0.1"]["oil"].keys()) == ["r1-eth1"]

    # Add ip mroute with iif=r1-eth0 oil=r1-eth2
    r1.vtysh_cmd("conf t\ninterface r1-eth0\nip mroute r1-eth2 239.1.1.1 10.0.0.1")

    # Expect to find oil=[r1-eth1,r1-eth2] in ip mroute command
    ip_mroute_json = r1.vtysh_cmd("show ip mroute json", isjson=True)
    assert list(ip_mroute_json["239.1.1.1"]["10.0.0.1"]["oil"].keys()) == [
        "r1-eth1",
        "r1-eth2",
    ]

    # Remove ip mroute with oil=r1-eth1
    r1.vtysh_cmd("conf t\ninterface r1-eth0\nno ip mroute r1-eth1 239.1.1.1 10.0.0.1")
    ip_mroute_json = r1.vtysh_cmd("show ip mroute json", isjson=True)
    # This assert right here would break back in the day because only one oif was handled by the datamodel
    assert list(ip_mroute_json["239.1.1.1"]["10.0.0.1"]["oil"].keys()) == ["r1-eth2"]

    r1.vtysh_cmd("conf t\ninterface r1-eth0\nno ip mroute r1-eth2 239.1.1.1 10.0.0.1")
    # Expect a clean state
    ip_mroute_json = r1.vtysh_cmd("show ip mroute json", isjson=True)
    assert "239.1.1.1" not in ip_mroute_json.keys()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
