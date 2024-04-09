#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by Louis Scalbert <louis.scalbert@6wind.com>
# Copyright 2023 6WIND S.A.
#

"""

"""

import os
import re
import sys
import json
import pytest
import functools

from copy import deepcopy

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import kill_router_daemons, start_router_daemons, step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for rtr in [1, 2]:
        tgen.add_router("r{}".format(rtr))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rtr in [1, 2]:
        tgen.gears["r{}".format(rtr)].cmd("ip link add vrf1 type vrf table 10")
        tgen.gears["r{}".format(rtr)].cmd("ip link set vrf1 up")
        tgen.gears["r{}".format(rtr)].cmd(
            "ip address add dev vrf1 192.0.3.{}/32".format(rtr)
        )
        tgen.gears["r{}".format(rtr)].run(
            "sysctl -w net.mpls.conf.r{}-eth0.input=1".format(rtr)
        )
        tgen.gears["r{}".format(rtr)].run("sysctl -w net.mpls.conf.vrf1.input=1")

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_LDP, os.path.join(CWD, "{}/ldpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_bgp_vpn_prefix(label, rname="r1", rd=None):
    tgen = get_topogen()

    if rd:
        output = json.loads(
            tgen.gears[rname].vtysh_cmd(
                "show bgp ipv4 vpn rd {} 192.0.3.2/32 json".format(rd)
            )
        )
    else:
        output = json.loads(
            tgen.gears[rname].vtysh_cmd(
                "show bgp vrf vrf1 ipv4 unicast 192.0.3.2/32 json"
            )
        )

    if label == "auto":
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "nexthops": [{"ip": "192.0.2.2"}],
                },
            ]
        }
    elif label and not rd:
        expected = {
            "paths": [
                {
                    "valid": True,
                    "remoteLabel": label,
                    "aspath": {"string": "65002"},
                    "nexthops": [{"ip": "192.0.2.2"}],
                },
            ]
        }
    elif label and rd:
        expected = {
            "102:1": {
                "prefix": "192.0.3.2/32",
                "paths": [
                    {
                        "valid": True,
                        "remoteLabel": label,
                        "nexthops": [{"ip": "0.0.0.0"}],
                    }
                ],
            }
        }
    else:
        expected = {}

    return topotest.json_cmp(output, expected, exact=(label is None))


def check_mpls_table(label, protocol):
    tgen = get_topogen()

    if label == "auto":
        cmd = "show mpls table json"
    else:
        cmd = "show mpls table {} json".format(label)

    output = json.loads(tgen.gears["r2"].vtysh_cmd(cmd))

    if label == "auto" and protocol:
        output_copy = deepcopy(output)
        for key, data in output_copy.items():
            for nexthop in data.get("nexthops", []):
                if nexthop.get("type", None) != protocol:
                    continue
                output = data
                break

    if protocol:
        expected = {
            "nexthops": [
                {
                    "type": protocol,
                },
            ]
        }
    else:
        expected = {}

    return topotest.json_cmp(output, expected, exact=(protocol is None))


def check_mpls_ldp_binding():
    tgen = get_topogen()

    output = json.loads(
        tgen.gears["r1"].vtysh_cmd("show mpls ldp binding 192.0.2.2/32 json")
    )
    expected = {
        "bindings": [
            {
                "prefix": "192.0.2.2/32",
                "localLabel": "16",  # first available label
                "inUse": 1,
            },
        ]
    }

    return topotest.json_cmp(output, expected)


def test_convergence():
    "Test protocol convergence"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check BGP and LDP convergence")
    test_func = functools.partial(check_bgp_vpn_prefix, 2222)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefix on R1"

    test_func = functools.partial(check_mpls_ldp_binding)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP binding on R2"

    test_func = functools.partial(check_mpls_table, 16, "LDP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP label on R2"

    test_func = functools.partial(check_mpls_table, 2222, "BGP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP label on R2"

    output = tgen.net["r2"].cmd("vtysh -c 'show debugging label-table' | grep Proto")
    assert re.match(
        r"Proto ldp: \[16/(1[7-9]|[2-9]\d+|\d{3,})\]", output
    ), "Failed to see LDP label chunk"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: [2222/2222]" in output, "Failed to see BGP label chunk"


def test_vpn_label_export_16():
    "Test that assigning the label value of 16 is not possible because it used by LDP"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "label vpn export 16"
    )

    step("Check that label vpn export 16 fails")
    test_func = functools.partial(check_bgp_vpn_prefix, None)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected BGP prefix on R1"

    test_func = functools.partial(check_mpls_ldp_binding)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP binding on R2"

    test_func = functools.partial(check_mpls_table, 16, "LDP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP label on R2"

    test_func = functools.partial(check_mpls_table, 2222, None)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected BGP label on R2"

    output = tgen.net["r2"].cmd("vtysh -c 'show debugging label-table' | grep Proto")
    assert re.match(
        r"Proto ldp: \[16/(1[7-9]|[2-9]\d+|\d{3,})\]", output
    ), "Failed to see LDP label chunk"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp" not in output, "Unexpected BGP label chunk"


def test_vpn_label_export_2222():
    "Test that setting back the label value of 2222 works"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "label vpn export 2222"
    )

    step("Check that label vpn export 2222 is OK")
    test_func = functools.partial(check_bgp_vpn_prefix, 2222)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefix on R1"

    test_func = functools.partial(check_mpls_ldp_binding)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP binding on R2"

    test_func = functools.partial(check_mpls_table, 16, "LDP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP label on R2"

    test_func = functools.partial(check_mpls_table, "auto", "BGP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected BGP label on R2"

    output = tgen.net["r2"].cmd("vtysh -c 'show debugging label-table' | grep Proto")
    assert re.match(
        r"Proto ldp: \[16/(1[7-9]|[2-9]\d+|\d{3,})\]", output
    ), "Failed to see LDP label chunk"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: [2222/2222]" in output, "Failed to see BGP label chunk"


def test_vpn_label_export_auto():
    "Test that setting label vpn export auto works"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "label vpn export auto"
    )

    step("Check that label vpn export auto is OK")
    test_func = functools.partial(check_bgp_vpn_prefix, "auto")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefix on R1"

    test_func = functools.partial(check_mpls_ldp_binding)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP binding on R2"

    test_func = functools.partial(check_mpls_table, 16, "LDP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP label on R2"

    test_func = functools.partial(check_mpls_table, "auto", "BGP")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, "Failed to see BGP label on R2"

    output = tgen.net["r2"].cmd("vtysh -c 'show debugging label-table' | grep Proto")
    assert re.match(
        r"Proto ldp: \[16/(1[7-9]|[2-9]\d+|\d{3,})\]", output
    ), "Failed to see LDP label chunk"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: " in output, "Failed to see BGP label chunk"


def test_vpn_label_export_no_auto():
    "Test that UNsetting label vpn export auto removes the prefix from R1 table and R2 LDP table"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = json.loads(
        tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf1 ipv4 unicast 192.0.3.2/32 json")
    )

    auto_label = output.get("paths")[0].get("remoteLabel", None)
    assert auto_label is not None, "Failed to fetch prefix label on R1"

    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "no label vpn export auto"
    )

    step("Check that no label vpn export auto is OK")
    test_func = functools.partial(check_bgp_vpn_prefix, 3, rname="r2", rd="102:1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected BGP prefix on R2"

    test_func = functools.partial(check_mpls_ldp_binding)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP binding on R2"

    test_func = functools.partial(check_mpls_table, 16, "LDP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP label on R2"

    test_func = functools.partial(check_mpls_table, auto_label, None)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, "Unexpected BGP label on R2"

    output = tgen.net["r2"].cmd("vtysh -c 'show debugging label-table' | grep Proto")
    assert re.match(
        r"Proto ldp: \[16/(1[7-9]|[2-9]\d+|\d{3,})\]", output
    ), "Failed to see LDP label chunk"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: " not in output, "Unexpected BGP label chunk"


def test_vpn_label_export_auto_back():
    "Test that setting back label vpn export auto works"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = json.loads(
        tgen.gears["r2"].vtysh_cmd("show bgp vrf vrf1 ipv4 unicast 192.0.3.2/32 json")
    )

    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "label vpn export auto"
    )

    step("Check that label vpn export auto is OK")
    test_func = functools.partial(check_bgp_vpn_prefix, "auto")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefix on R1"

    test_func = functools.partial(check_mpls_ldp_binding)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP binding on R2"

    test_func = functools.partial(check_mpls_table, 16, "LDP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP label on R2"

    test_func = functools.partial(check_mpls_table, "auto", "BGP")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, "Failed to see BGP label on R2"

    output = tgen.net["r2"].cmd("vtysh -c 'show debugging label-table' | grep Proto")
    assert re.match(
        r"Proto ldp: \[16/(1[7-9]|[2-9]\d+|\d{3,})\]", output
    ), "Failed to see LDP label chunk"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: " in output, "Failed to see BGP label chunk"


def test_vpn_label_export_manual_from_auto():
    "Test that setting a manual label value from the BGP chunk range works"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = json.loads(
        tgen.gears["r1"].vtysh_cmd("show bgp vrf vrf1 ipv4 unicast 192.0.3.2/32 json")
    )

    auto_label = output.get("paths")[0].get("remoteLabel", None)
    assert auto_label is not None, "Failed to fetch prefix label on R1"

    auto_label = auto_label + 1

    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "label vpn export {}".format(auto_label)
    )

    step("Check that label vpn export {} is OK".format(auto_label))
    test_func = functools.partial(
        check_bgp_vpn_prefix, auto_label, rname="r2", rd="102:1"
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefix on R2"

    test_func = functools.partial(check_mpls_ldp_binding)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP binding on R2"

    test_func = functools.partial(check_mpls_table, 16, "LDP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP label on R2"

    test_func = functools.partial(check_mpls_table, auto_label, "BGP")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, "Failed to see BGP label on R2"

    output = tgen.net["r2"].cmd("vtysh -c 'show debugging label-table' | grep Proto")
    assert re.match(
        r"Proto ldp: \[16/(1[7-9]|[2-9]\d+|\d{3,})\]", output
    ), "Failed to see LDP label chunk"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: " in output, "Failed to see BGP label chunk"


def test_vpn_label_configure_dynamic_range():
    "Test that if a dynamic range is configured, then the next dynamic allocations will be done in that block"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    tgen.gears["r2"].vtysh_cmd("conf\n" "mpls label dynamic-block 500 1000\n")
    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "label vpn export auto"
    )
    step("Check that label vpn export auto starting at 500 is OK")
    test_func = functools.partial(check_bgp_vpn_prefix, 500, rname="r2", rd="102:1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected BGP prefix on R2"

    test_func = functools.partial(check_mpls_table, 500, "BGP")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, "Unexpected BGP label on R2"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: " in output, "Failed to see BGP label chunk"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


def test_vpn_label_restart_ldp():
    "Test that if a dynamic range is configured, then when LDP restarts, it follows the new dynamic range"

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router_list = tgen.routers()

    step("Kill LDP on R2")
    kill_router_daemons(tgen, "r2", ["ldpd"])

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto ldp: " not in output, "Unexpected LDP label chunk"

    step("Bring up LDP on R2")

    start_router_daemons(tgen, "r2", ["ldpd"])

    test_func = functools.partial(check_mpls_table, 628, "LDP")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see LDP label on R2"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto ldp: [628/691]" in output, "Failed to see LDP label chunk [628/691]"
    assert "Proto ldp: [692/755]" in output, "Failed to see LDP label chunk [692/755]"


def test_vpn_label_unconfigure_dynamic_range():
    "Test that if the dynamic range is unconfigured, then the next dynamic allocations will be done at the first free place."

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    tgen.gears["r2"].vtysh_cmd("conf\n" "no mpls label dynamic-block 500 1000\n")
    step("Check that unconfiguring label vpn export auto will remove BGP label chunk")
    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "no label vpn export auto"
    )

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: " not in output, "Unexpected BGP label chunk"

    tgen.gears["r2"].vtysh_cmd(
        "conf\n"
        "router bgp 65002 vrf vrf1\n"
        "address-family ipv4 unicast\n"
        "label vpn export auto"
    )
    step("Check that label vpn export auto starting at 16 is OK")
    test_func = functools.partial(check_bgp_vpn_prefix, 16, rname="r2", rd="102:1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected BGP prefix on R2"

    test_func = functools.partial(check_mpls_table, 16, "BGP")
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=0.5)
    assert result is None, "Unexpected BGP label on R2"

    output = tgen.gears["r2"].vtysh_cmd("show debugging label-table")
    assert "Proto bgp: " in output, "Failed to see BGP label chunk"
