#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_pim_rp_as_lhr.py
#
# Copyright (c) 2025 by Vijayalaxmi Basavaraj, Nvidia Inc.
#

"""
test_pim_rp_as_lhr.py: RP acting as the last hop router for a receiver on the
segment it shares with the first hop router.

dut is the DR on vlan100, so it is the FHR for the source and it also owns h3's
membership on that same segment.  The RP wins the DR election on vlan200
(22.0.0.20 > 22.0.0.2), so the RP is the LHR that has to serve h2 and dut must
not forward there on its own.

dut therefore sends Join(*,G) together with Prune(S,G,rpt) towards the RP.  The
RP used to drop rp-eth0 from the (S,G) OIL on that prune even though its own
receiver sits on that segment, which left JoinDesired(S,G) false: it never joined
the SPT towards the source, sent a register-stop instead, and nothing was left to
forward the stream.  dut ended up holding an (S,G) with no OIF:

    11.0.0.1  225.1.1.1  SFT  none  vlan100  none  0  --:--:--
"""

import os
import sys
import time
from functools import partial

import pytest

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step, write_test_footer, write_test_header
from lib.pim import (
    McastTesterHelper,
    clear_mroute,
    verify_igmp_groups,
    verify_join_state_and_timer,
    verify_mroutes,
    verify_pim_neighbors,
    verify_sg_traffic,
    verify_upstream_iif,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

TOPOLOGY = """
            vlan100                                  vlan200

  h1 11.0.0.1 --+                                    +-- rp 22.0.0.20
     (source)   |                                    |      lo 200.200.200.200
                +-- sw100 -- dut 11.0.0.2 (eth0) -- sw200    (RP, DR, LHR)
  h3 11.0.0.3 --+            (FHR, DR)  22.0.0.2 (eth1)  |
     (receiver)              lo 100.100.100.100           +-- h2 22.0.0.10
                                                                (receiver)
"""

MCAST_GROUP = "225.1.1.1"
SOURCE = "11.0.0.1"
SOURCE_PREFIX = "11.0.0.0/24"
RP_ADDRESS = "200.200.200.200"

# vlan100 carries the source and a receiver, vlan200 the RP and the receiver the
# RP has to serve.  dut has one interface on each.
DUT_VLAN100 = "dut-eth0"
DUT_VLAN200 = "dut-eth1"
DUT_VLAN200_ADDR = "22.0.0.2"
RP_VLAN200 = "rp-eth0"
RP_VLAN200_ADDR = "22.0.0.20"

# Only the vlan200 segment has a PIM adjacency; dut is the sole router on vlan100.
PIM_TOPO = {
    "routers": {
        "dut": {
            "links": {
                "rp": {
                    "interface": DUT_VLAN200,
                    "ipv4": "{}/24".format(DUT_VLAN200_ADDR),
                    "pim": "enable",
                },
            }
        },
        "rp": {
            "links": {
                "dut": {
                    "interface": RP_VLAN200,
                    "ipv4": "{}/24".format(RP_VLAN200_ADDR),
                    "pim": "enable",
                },
            }
        },
    }
}

app_helper = McastTesterHelper()


def build_topo(tgen):
    """Build function"""

    tgen.add_router("dut")
    tgen.add_router("rp")

    # ixia1: source, in vlan100
    tgen.add_host("h1", ip="11.0.0.1/24", defaultRoute="via 11.0.0.2")
    # ixia3: receiver sharing vlan100 with the source
    tgen.add_host("h3", ip="11.0.0.3/24", defaultRoute="via 11.0.0.2")
    # ixia2: receiver in vlan200, served by the RP as DR of that segment
    tgen.add_host("h2", ip="22.0.0.10/24", defaultRoute="via 22.0.0.20")

    # vlan100 (11.0.0.0/24): source and a receiver on the same segment as dut
    sw100 = tgen.add_switch("sw100")
    sw100.add_link(tgen.gears["h1"])
    sw100.add_link(tgen.gears["h3"])
    sw100.add_link(tgen.gears["dut"])

    # vlan200 (22.0.0.0/24): dut, the RP and the second receiver
    sw200 = tgen.add_switch("sw200")
    sw200.add_link(tgen.gears["dut"])
    sw200.add_link(tgen.gears["rp"])
    sw200.add_link(tgen.gears["h2"])


def setup_module(mod):
    """Sets up the pytest environment"""
    logger.info("Testsuite start time: %s", time.asctime(time.localtime(time.time())))
    logger.info("Topology:\n%s", TOPOLOGY)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # The bridges come up with IGMP snooping enabled, which would let L2 decide
    # what this L3 test measures.  The reported failure happens with snooping
    # off, so keep both segments flooding.
    for swname in ("sw100", "sw200"):
        tgen.gears[swname].cmd(
            "ip link set dev {} type bridge mcast_snooping 0".format(swname)
        )

    app_helper.init(tgen)

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_PIM, None),
                (TopoRouter.RD_OSPF, None),
            ],
        )

    tgen.start_router()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_pim_neighbors(tgen, PIM_TOPO)
    assert result is True, "PIM neighbors failed to establish: {}".format(result)

    # Both unicast directions have to be in place before PIM can be blamed for
    # anything: the RP needs a route back to the source segment to RPF towards
    # the source, and dut needs a route to the RP address to register at all.
    for rname, prefix in (
        ("rp", SOURCE_PREFIX),
        ("dut", "{}/32".format(RP_ADDRESS)),
    ):
        expected = {prefix: [{"protocol": "ospf"}]}
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rname],
            "show ip route json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "{} has no unicast route to {}: {}".format(
            rname, prefix, result
        )


def teardown_module():
    """Teardown the pytest environment"""
    tgen = get_topogen()

    app_helper.cleanup()
    tgen.stop_topology()


def start_receivers_and_traffic(tgen):
    """Join the group from both receivers and start the source.

    Both memberships matter to the scenario: h3 is what makes dut a LHR while it
    is also the FHR, and h2 is the receiver only the RP can serve.
    """
    app_helper.stop_all_hosts()
    clear_mroute(tgen)

    assert app_helper.run_join("h3", MCAST_GROUP, join_intf="h3-eth0") is True
    assert app_helper.run_join("h2", MCAST_GROUP, join_intf="h2-eth0") is True

    # dut is DR on vlan100 so it owns h3's membership, and it has IGMP enabled on
    # vlan200 as well, matching the reported state where it sees h2 without being
    # the DR there.
    assert verify_igmp_groups(tgen, "dut", DUT_VLAN100, MCAST_GROUP) is True
    assert verify_igmp_groups(tgen, "rp", RP_VLAN200, MCAST_GROUP) is True

    assert app_helper.run_traffic("h1", MCAST_GROUP, bind_intf="h1-eth0") is True


def test_dr_roles_and_fhr_state(request):
    """Verify the DR outcomes the scenario rests on, and that dut is the FHR.

    dut has to win vlan100 and lose vlan200 for the RP to be the only router that
    can serve h2.  With the source directly connected on the interface dut is
    already a LHR for, the (S,G) also has to come up through the FHR path, inbound
    on the source interface rather than on pimreg.
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify dut is the DR on vlan100 and the RP is the DR on vlan200")
    for rname, ifname, dr_addr in (
        ("dut", DUT_VLAN100, "11.0.0.2"),
        ("dut", DUT_VLAN200, RP_VLAN200_ADDR),
        ("rp", RP_VLAN200, RP_VLAN200_ADDR),
    ):
        expected = {ifname: {"pimDesignatedRouter": dr_addr}}
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[rname],
            "show ip pim interface json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "{}: {} DR on {} is not {}: {}".format(
            tc_name, rname, ifname, dr_addr, result
        )

    step("Join the group from both receivers and start the source")
    start_receivers_and_traffic(tgen)

    step("Verify dut has an (S,G) inbound on the source interface")
    result = verify_upstream_iif(tgen, "dut", DUT_VLAN100, SOURCE, MCAST_GROUP)
    assert result is True, "{}: dut did not take the FHR role: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)


def test_rp_as_lhr_forwards_to_local_receiver(request):
    """Verify the RP joins the SPT despite the (S,G,rpt) prune, so dut forwards.

    The prune dut sends removes the joins(*,G) contribution on vlan200 but not the
    RP's own receiver, so the RP still has to inherit rp-eth0 into the (S,G) OIL,
    keep JoinDesired(S,G) true and join the SPT.  That join is what puts vlan200
    into dut's OIL and gets the stream onto the segment.
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Join the group from both receivers and start the source")
    start_receivers_and_traffic(tgen)

    step("Verify the RP learned the source, i.e. registration got through")
    result = verify_upstream_iif(tgen, "rp", RP_VLAN200, SOURCE, MCAST_GROUP)
    assert result is True, "{}: RP never learned the source: {}".format(tc_name, result)

    step("Verify the RP joined the SPT and keeps its join timer running")
    result = verify_join_state_and_timer(tgen, "rp", RP_VLAN200, SOURCE, MCAST_GROUP)
    assert result is True, (
        "{}: the RP is not joining the SPT, so dut is never asked to forward "
        "and the (S,G,rpt) prune has cancelled the RP's own receiver: {}".format(
            tc_name, result
        )
    )

    step("Verify dut forwards the (S,G) natively onto vlan200")
    result = verify_mroutes(tgen, "dut", SOURCE, MCAST_GROUP, DUT_VLAN100, DUT_VLAN200)
    assert result is True, "{}: dut has no OIF towards vlan200: {}".format(
        tc_name, result
    )

    step("Verify traffic is counted through dut's (S,G)")
    result = verify_sg_traffic(tgen, "dut", [MCAST_GROUP], SOURCE)
    assert result is True, "{}: no traffic through dut's (S,G): {}".format(
        tc_name, result
    )

    step("Verify h2 receives the stream on vlan200")
    report = app_helper.collect_receiver_sources(
        "h2", MCAST_GROUP, "h2-eth0", duration=5, source=SOURCE
    )
    received = report.get("sources", {}).get(SOURCE, 0)
    assert received > 0, "{}: h2 received nothing from {}: {}".format(
        tc_name, SOURCE, report
    )
    logger.info("h2 received %d packets from %s", received, SOURCE)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
