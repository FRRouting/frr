#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_rip_vrf_filter_lifecycle.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_rip_vrf_filter_lifecycle.py: Test RIP filter reference lifecycle in a
non-default (netns-backed) VRF.

ripd updates its cached per-interface filter pointers from the
access-list/prefix-list/route-map add and delete hooks. Those hooks used to
walk only VRF_DEFAULT, so on a non-default VRF:

- an interface distribute-list / route-map referencing a not-yet-existing
  object was never attached once the object got created, and
- deleting a referenced object left a dangling pointer that the next
  received or sent RIP packet dereferenced (use-after-free).

r1 runs its RIP instance in netns-backed VRF "r1-red"; r2 stays in the
default VRF as the control.
"""

import os
import re
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ripd]

VRF = "r1-red"
# prefixes advertised by r1 (red VRF) / r2 (default VRF)
P_R1 = "198.51.100.0/24"
P_R1B = "203.0.113.0/24"
P_R2 = "192.0.2.0/24"
P_R2B = "192.168.0.0/24"


def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth1")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"], nodeif="r1-eth2")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r2"], nodeif="r2-eth2")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # check for zebra capability
    for router in router_list.values():
        if router.check_capability(TopoRouter.RD_ZEBRA, "--vrfwnetns") == False:
            return pytest.skip(
                "Skipping RIP VRF NETNS feature. VRF NETNS backend not available on FRR"
            )

    if os.system("ip netns list") != 0:
        return pytest.skip("Skipping RIP VRF NETNS Test. NETNS not available on System")

    logger.info("Testing with VRF Namespace support")

    for rname, router in router_list.items():
        if rname == "r1":
            # create VRF r1-red and link r1-eth{0,1,2} to it
            router.net.add_netns(VRF)
            for i in range(3):
                router.net.set_intf_netns("r1-eth{}".format(i), VRF, up=True)

            router.use_netns_vrf()
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_RIP, os.path.join(CWD, "{}/ripd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()

    # remove the RIP instances so ripd frees its per-instance state before
    # the shutdown memory-leak report
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nno router rip vrf {}\nend".format(VRF)
    )
    tgen.gears["r2"].vtysh_cmd("configure terminal\nno router rip\nend")

    # Move interfaces out of vrf namespace and delete the namespace
    for i in range(3):
        tgen.net["r1"].reset_intf_netns("r1-eth{}".format(i))
    tgen.net["r1"].delete_netns(VRF)
    tgen.stop_topology()


def conf(router, *commands):
    "Apply configuration commands"
    router.vtysh_cmd("configure terminal\n" + "\n".join(commands) + "\nend")


def rip_rib(router, vrf=None):
    cmd = "show ip rip vrf {}".format(vrf) if vrf else "show ip rip"
    return router.vtysh_cmd(cmd)


def rip_has(router, prefix, vrf=None):
    return prefix in rip_rib(router, vrf)


def clear_rip(router, vrf=None):
    router.vtysh_cmd("clear ip rip vrf {}".format(vrf) if vrf else "clear ip rip")


def test_rip_convergence():
    "Test RIP convergence between the red VRF instance and the default VRF"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    result, _ = topotest.run_and_expect(
        lambda: rip_has(r1, P_R2, VRF), True, count=40, wait=1
    )
    assert result, "r1 did not learn {} via RIP in VRF {}".format(P_R2, VRF)
    result, _ = topotest.run_and_expect(
        lambda: rip_has(r2, P_R1), True, count=40, wait=1
    )
    assert result, "r2 did not learn {} via RIP".format(P_R1)


def test_acl_create_after_reference():
    "distribute-list referencing a missing ACL must attach once it is created"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    try:
        conf(r1, "router rip vrf {}".format(VRF), "distribute-list ACL_A in r1-eth0")
        conf(r2, "router rip", "distribute-list ACL_A in r2-eth0")
        result, _ = topotest.run_and_expect(
            lambda: rip_has(r1, P_R2, VRF), True, count=20, wait=2
        )
        assert result, "precondition: route still learned on r1"
        result, _ = topotest.run_and_expect(
            lambda: rip_has(r2, P_R1), True, count=20, wait=2
        )
        assert result, "precondition: route still learned on r2"

        conf(r1, "access-list ACL_A seq 5 deny 192.0.2.0/24",
                 "access-list ACL_A seq 10 permit any")
        conf(r2, "access-list ACL_A seq 5 deny 198.51.100.0/24",
                 "access-list ACL_A seq 10 permit any")
        clear_rip(r1, VRF)
        clear_rip(r2)
        time.sleep(15)

        rib1 = rip_rib(r1, VRF)
        assert P_R2 not in rib1, (
            "ACL created after reference is not applied on the non-default VRF:\n"
            + rib1
        )
        rib2 = rip_rib(r2)
        assert P_R1 not in rib2, (
            "ACL created after reference is not applied on the default VRF:\n" + rib2
        )
    finally:
        conf(r1, "router rip vrf {}".format(VRF), "no distribute-list ACL_A in r1-eth0",
             "no access-list ACL_A")
        conf(r2, "router rip", "no distribute-list ACL_A in r2-eth0",
             "no access-list ACL_A")


def test_prefix_list_create_after_reference():
    "distribute-list referencing a missing prefix-list must attach once created"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    try:
        conf(r1, "router rip vrf {}".format(VRF),
             "distribute-list prefix PL_A in r1-eth0")
        conf(r2, "router rip", "distribute-list prefix PL_A in r2-eth0")
        result, _ = topotest.run_and_expect(
            lambda: rip_has(r1, P_R2, VRF), True, count=20, wait=2
        )
        assert result, "precondition: route still learned on r1"
        result, _ = topotest.run_and_expect(
            lambda: rip_has(r2, P_R1), True, count=20, wait=2
        )
        assert result, "precondition: route still learned on r2"

        conf(r1, "ip prefix-list PL_A seq 5 deny 192.0.2.0/24",
                 "ip prefix-list PL_A seq 10 permit 0.0.0.0/0 le 32")
        conf(r2, "ip prefix-list PL_A seq 5 deny 198.51.100.0/24",
                 "ip prefix-list PL_A seq 10 permit 0.0.0.0/0 le 32")
        clear_rip(r1, VRF)
        clear_rip(r2)
        time.sleep(15)

        rib1 = rip_rib(r1, VRF)
        assert P_R2 not in rib1, (
            "prefix-list created after reference is not applied on the non-default VRF:\n"
            + rib1
        )
        rib2 = rip_rib(r2)
        assert P_R1 not in rib2, (
            "prefix-list created after reference is not applied on the default VRF:\n"
            + rib2
        )
    finally:
        conf(r1, "router rip vrf {}".format(VRF),
             "no distribute-list prefix PL_A in r1-eth0", "no ip prefix-list PL_A")
        conf(r2, "router rip", "no distribute-list prefix PL_A in r2-eth0",
             "no ip prefix-list PL_A")


def test_route_map_create_after_reference():
    "interface route-map referencing a missing route-map must attach once created"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    try:
        conf(r1, "router rip vrf {}".format(VRF), "route-map RM_A in r1-eth0")
        conf(r2, "router rip", "route-map RM_A in r2-eth0")
        result, _ = topotest.run_and_expect(
            lambda: rip_has(r1, P_R2, VRF), True, count=20, wait=2
        )
        assert result, "precondition: route still learned on r1"
        result, _ = topotest.run_and_expect(
            lambda: rip_has(r2, P_R1), True, count=20, wait=2
        )
        assert result, "precondition: route still learned on r2"

        # the ACL used by the match clause exists up-front; only the
        # route-map is created after the reference
        conf(r1, "access-list ACL_RM seq 5 permit 10.0.0.0/8",
                 "access-list ACL_RM seq 10 deny any",
                 "route-map RM_A permit 10", "match ip address ACL_RM")
        conf(r2, "access-list ACL_RM seq 5 permit 10.0.0.0/8",
                 "access-list ACL_RM seq 10 deny any",
                 "route-map RM_A permit 10", "match ip address ACL_RM")
        clear_rip(r1, VRF)
        clear_rip(r2)
        time.sleep(15)

        rib1 = rip_rib(r1, VRF)
        assert P_R2 not in rib1, (
            "route-map created after reference is not applied on the non-default VRF:\n"
            + rib1
        )
        rib2 = rip_rib(r2)
        assert P_R1 not in rib2, (
            "route-map created after reference is not applied on the default VRF:\n"
            + rib2
        )
    finally:
        conf(r1, "router rip vrf {}".format(VRF), "no route-map RM_A in r1-eth0",
             "no route-map RM_A", "no access-list ACL_RM")
        conf(r2, "router rip", "no route-map RM_A in r2-eth0",
             "no route-map RM_A", "no access-list ACL_RM")


def test_redistribute_route_map_create_after_reference():
    "redistribute route-map referencing a missing route-map must attach once created"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    try:
        # reference before create on r1 (red VRF). While the cached map
        # pointer is NULL, route_map_apply(NULL) denies every redistributed
        # route.
        conf(r1, "router rip vrf {}".format(VRF),
             "redistribute connected route-map RM_R")
        clear_rip(r2)
        time.sleep(8)  # at least one RIP update cycle
        assert not rip_has(r2, P_R1B), "precondition: NULL map denies all on r1"

        conf(r1, "ip prefix-list PL_R seq 5 deny 198.51.100.0/24",
                 "ip prefix-list PL_R seq 10 permit 0.0.0.0/0 le 32",
                 "route-map RM_R permit 10", "match ip address prefix-list PL_R")
        time.sleep(15)

        rib2 = rip_rib(r2)
        assert P_R1 not in rib2, "denied prefix still advertised:\n" + rib2
        assert P_R1B in rib2, (
            "permitted prefix not re-advertised after the route-map was created "
            "on the non-default VRF:\n" + rib2
        )

        # control on r2 default VRF instance
        conf(r2, "router rip", "redistribute connected route-map RM_R2")
        conf(r2, "ip prefix-list PL_R2 seq 5 deny 192.0.2.0/24",
                 "ip prefix-list PL_R2 seq 10 permit 0.0.0.0/0 le 32",
                 "route-map RM_R2 permit 10", "match ip address prefix-list PL_R2")
        clear_rip(r1, VRF)
        time.sleep(15)

        rib1 = rip_rib(r1, VRF)
        assert P_R2 not in rib1, "denied prefix still advertised (control):\n" + rib1
        assert P_R2B in rib1, "permitted prefix not advertised (control):\n" + rib1
    finally:
        conf(r1, "router rip vrf {}".format(VRF), "no redistribute connected",
             "redistribute connected", "no route-map RM_R", "no ip prefix-list PL_R")
        conf(r2, "router rip", "no redistribute connected",
             "redistribute connected", "no route-map RM_R2", "no ip prefix-list PL_R2")


def test_route_map_set_metric():
    "legitimate route-map set on the non-default VRF keeps working"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    try:
        conf(r1, "route-map RM_S permit 10", "set metric 4")
        conf(r1, "router rip vrf {}".format(VRF), "route-map RM_S out r1-eth0")

        # RIP adds the receiving interface metric (1) to the advertised 4
        def check_metric():
            return bool(re.search(r"198\.51\.100\.0/24\s+\S+\s+5\s", rip_rib(r2)))

        result, _ = topotest.run_and_expect(
            lambda: check_metric(), True, count=30, wait=1
        )
        assert result, (
            "route-map set metric not applied on the non-default VRF:\n"
            + rip_rib(r2)
        )
    finally:
        conf(r1, "router rip vrf {}".format(VRF), "no route-map RM_S out r1-eth0",
             "no route-map RM_S")


def _delete_reference_check(r1, r2, create_cmds_r1, create_cmds_r2, ref_cmd,
                            delete_cmd, obj):
    "shared body of the delete-after-reference tests"

    # r2 (default VRF control) first: the hook must clear the reference
    # there even on unpatched daemons
    conf(r2, *create_cmds_r2)
    conf(r2, "router rip", ref_cmd.format(intf="r2-eth0"))
    time.sleep(2)
    clear_rip(r2)
    time.sleep(15)
    rib2 = rip_rib(r2)
    assert P_R1 not in rib2, (
        "{} not filtering on the default VRF before delete:\n{}".format(obj, rib2)
    )
    conf(r2, delete_cmd)
    time.sleep(15)
    assert "" == r2.check_router_running(), "ripd died on the default VRF control"
    rib2 = rip_rib(r2)
    assert P_R1 in rib2, (
        "route did not return after {} delete on the default VRF:\n{}".format(obj, rib2)
    )

    # r1 (non-default VRF): deleting the referenced object must not leave a
    # dangling pointer behind
    conf(r1, *create_cmds_r1)
    conf(r1, "router rip vrf {}".format(VRF), ref_cmd.format(intf="r1-eth0"))
    time.sleep(2)
    clear_rip(r1, VRF)
    time.sleep(15)
    rib1 = rip_rib(r1, VRF)
    assert P_R2 not in rib1, (
        "{} not filtering on the non-default VRF before delete:\n{}".format(obj, rib1)
    )
    conf(r1, delete_cmd)
    time.sleep(15)
    assert "" == r1.check_router_running(), (
        "ripd died after {} delete on the non-default VRF".format(obj)
    )
    rib1 = rip_rib(r1, VRF)
    assert P_R2 in rib1, (
        "route did not return after {} delete on the non-default VRF:\n{}".format(
            obj, rib1
        )
    )


def test_acl_delete_after_reference():
    "deleting a referenced ACL must not leave a dangling pointer"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    _delete_reference_check(
        tgen.gears["r1"], tgen.gears["r2"],
        ["access-list ACL_D seq 5 deny 192.0.2.0/24",
         "access-list ACL_D seq 10 permit any"],
        ["access-list ACL_D seq 5 deny 198.51.100.0/24",
         "access-list ACL_D seq 10 permit any"],
        "distribute-list ACL_D in {intf}",
        "no access-list ACL_D",
        "ACL",
    )


def test_prefix_list_delete_after_reference():
    "deleting a referenced prefix-list must not leave a dangling pointer"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    _delete_reference_check(
        tgen.gears["r1"], tgen.gears["r2"],
        ["ip prefix-list PL_D seq 5 deny 192.0.2.0/24",
         "ip prefix-list PL_D seq 10 permit 0.0.0.0/0 le 32"],
        ["ip prefix-list PL_D seq 5 deny 198.51.100.0/24",
         "ip prefix-list PL_D seq 10 permit 0.0.0.0/0 le 32"],
        "distribute-list prefix PL_D in {intf}",
        "no ip prefix-list PL_D",
        "prefix-list",
    )


def test_route_map_delete_after_reference():
    "deleting a referenced route-map must not leave a dangling pointer"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    create_cmds = [
        "access-list ACL_RMD seq 5 permit 10.0.0.0/8",
        "access-list ACL_RMD seq 10 deny any",
        "route-map RM_D permit 10",
        "match ip address ACL_RMD",
    ]
    _delete_reference_check(
        tgen.gears["r1"], tgen.gears["r2"],
        create_cmds,
        create_cmds,
        "route-map RM_D in {intf}",
        "no route-map RM_D",
        "route-map",
    )
    # remove the match ACL as well
    conf(tgen.gears["r1"], "no access-list ACL_RMD")
    conf(tgen.gears["r2"], "no access-list ACL_RMD")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
