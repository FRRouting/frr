#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_mpls_static.py
#
# Copyright (c) 2026 by Nvidia Inc.
#                       Donald Sharp
#

"""
test_zebra_mpls_static.py: Static MPLS push, swap, and pop.

r1 pushes label 100 toward 3.3.3.3/32. r2 swaps 100 to 200. r3 pops 200
with implicit-null toward h1, a connected host that owns 3.3.3.3/32.
Zebra does not install an LSP whose gateway is only a local address.
The return path is unlabeled IP.

Later steps replace the swap label, switch it to explicit-null, delete
the transit LSP, and add an LSP whose gateway is not connected.
"""

import os
import sys
import re
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.checkping import check_ping
from lib.topogen import Topogen, get_topogen
from lib.common_config import step


pytestmark = [pytest.mark.staticd]

DEST = "3.3.3.3"
POP_NH = "10.1.3.2"


def build_topo(tgen):
    "r1 -- r2 -- r3 -- h1"
    for name in ("r1", "r2", "r3"):
        tgen.add_router(name)
    h1 = tgen.add_host("h1", "10.1.3.2/24", "via 10.1.3.1")

    sw1 = tgen.add_switch("s1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])

    sw2 = tgen.add_switch("s2")
    sw2.add_link(tgen.gears["r2"])
    sw2.add_link(tgen.gears["r3"])

    sw3 = tgen.add_switch("s3")
    sw3.add_link(tgen.gears["r3"])
    sw3.add_link(h1)


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    if not tgen.hasmpls:
        pytest.skip("MPLS is not available, skipping test")

    tgen.start_topology()

    # 3.3.3.3 is the FEC. It lives on the host so the popped packet is
    # delivered there; r3's own loopback is not a resolvable LSP gateway.
    h1 = tgen.gears["h1"]
    h1.cmd("ip link set lo up")
    h1.cmd("ip addr add 3.3.3.3/32 dev lo")

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


def _expect_json(router, cmd, expected):
    test_func = functools.partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    return result


def _mpls_lines(router):
    return router.run("ip -M route show").splitlines()


def _route_line(lines, label):
    prefix = "{} ".format(label)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(prefix) or stripped == str(label):
            return stripped
    return None


def test_mpls_status():
    "MPLS support is enabled"
    tgen = _skip_on_failure()
    step("Verify show mpls status on r1, r2, and r3")

    for name in ("r1", "r2", "r3"):
        output = tgen.gears[name].vtysh_cmd("show mpls status")
        assert "MPLS support enabled: yes" in output, "{}: {}".format(name, output)


def test_static_lsp_installed():
    "Push, swap, and pop are installed in zebra and the kernel"
    tgen = _skip_on_failure()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Verify r1 pushes label 100 for 3.3.3.3/32")
    push = {
        "3.3.3.3/32": [
            {
                "protocol": "static",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "fib": True,
                        "ip": "10.1.1.2",
                        "interfaceName": "r1-eth0",
                        "active": True,
                        "labels": [100],
                    }
                ],
            }
        ]
    }
    result = _expect_json(r1, "show ip route 3.3.3.3/32 json", push)
    assert result is None, "r1 push route missing: {}".format(result)

    step("Verify r2 swaps 100 to 200")
    swap = {
        "100": {
            "inLabel": 100,
            "installed": True,
            "nexthops": [
                {
                    "type": "Static",
                    "outLabel": 200,
                    "nexthop": "10.1.2.3",
                    "interface": "r2-eth1",
                    "installed": True,
                }
            ],
        }
    }
    result = _expect_json(r2, "show mpls table json", swap)
    assert result is None, "r2 swap LSP missing: {}".format(result)

    step("Verify r3 pops 200 with implicit-null")
    pop = {
        "200": {
            "inLabel": 200,
            "installed": True,
            "nexthops": [
                {
                    "type": "Static",
                    "outLabel": 3,
                    "nexthop": POP_NH,
                    "interface": "r3-eth1",
                    "installed": True,
                }
            ],
        }
    }
    result = _expect_json(r3, "show mpls table json", pop)
    assert result is None, "r3 pop LSP missing: {}".format(result)

    pop_text = r3.vtysh_cmd("show mpls table")
    assert "implicit-null" in pop_text, pop_text

    step("Verify kernel push, swap, and pop routes")

    def _kernel_installed():
        ip_route = r1.run("ip route show 3.3.3.3")
        if not re.search(r"encap mpls\s+100\b", ip_route):
            return "r1 kernel route missing encap mpls 100: {}".format(ip_route)

        swap_line = _route_line(_mpls_lines(r2), 100)
        if (
            swap_line is None
            or "10.1.2.3" not in swap_line
            or not re.search(r"\bas to 200\b", swap_line)
        ):
            return "r2 kernel swap route missing: {}".format(swap_line)

        pop_line = _route_line(_mpls_lines(r3), 200)
        if pop_line is None or POP_NH not in pop_line or " as " in pop_line:
            return "r3 kernel pop route missing: {}".format(pop_line)
        return None

    _, result = topotest.run_and_expect(_kernel_installed, None, count=20, wait=1)
    assert result is None, result

    step("Verify running-config still has the static LSPs")
    r2_run = r2.vtysh_cmd("show running-config")
    r3_run = r3.vtysh_cmd("show running-config")
    assert "mpls lsp 100 10.1.2.3 200" in r2_run, r2_run
    assert "mpls lsp 200 {} implicit-null".format(POP_NH) in r3_run, r3_run


def test_mpls_forwarding():
    "Ping from r1 to 3.3.3.3 crosses the LSP"
    tgen = _skip_on_failure()
    step("Ping 3.3.3.3 from r1")
    check_ping("r1", DEST, True, 20, 1, source_addr="1.1.1.1")


def test_swap_label_replace():
    "Replacing the swap label updates zebra, the kernel, and forwarding"
    tgen = _skip_on_failure()
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # r3 must pop the new label or the ping cannot succeed.
    step("Replace r2 swap 200 with 201 and r3 pop 200 with 201")
    r2.vtysh_cmd(
        """
        configure terminal
        mpls lsp 100 10.1.2.3 201
        """
    )
    r3.vtysh_cmd(
        """
        configure terminal
        no mpls lsp 200
        mpls lsp 201 10.1.3.2 implicit-null
        """
    )

    swap = {
        "100": {
            "installed": True,
            "nexthops": [
                {
                    "type": "Static",
                    "outLabel": 201,
                    "nexthop": "10.1.2.3",
                    "installed": True,
                }
            ],
        }
    }
    result = _expect_json(r2, "show mpls table json", swap)
    assert result is None, "r2 did not swap to 201: {}".format(result)

    pop = {
        "200": None,
        "201": {
            "installed": True,
            "nexthops": [
                {
                    "type": "Static",
                    "outLabel": 3,
                    "nexthop": POP_NH,
                    "interface": "r3-eth1",
                    "installed": True,
                }
            ],
        },
    }
    result = _expect_json(r3, "show mpls table json", pop)
    assert result is None, "r3 did not pop 201: {}".format(result)

    def _kernel_swapped():
        swap_line = _route_line(_mpls_lines(r2), 100)
        if swap_line is None or not re.search(r"\bas to 201\b", swap_line):
            return "r2 kernel route is not as to 201: {}".format(swap_line)
        if re.search(r"\bas to 200\b", swap_line):
            return "r2 kernel route still swaps to 200: {}".format(swap_line)
        pop_line = _route_line(_mpls_lines(r3), 201)
        if pop_line is None or " as " in pop_line:
            return "r3 kernel pop for 201 missing: {}".format(pop_line)
        if _route_line(_mpls_lines(r3), 200) is not None:
            return "r3 kernel still has label 200"
        return None

    _, result = topotest.run_and_expect(_kernel_swapped, None, count=20, wait=1)
    assert result is None, result

    check_ping("r1", DEST, True, 20, 1, source_addr="1.1.1.1")


def test_explicit_null():
    "Explicit-null is installed and the kernel pops label 0"
    tgen = _skip_on_failure()
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Change r2 outgoing label to explicit-null")
    r2.vtysh_cmd(
        """
        configure terminal
        mpls lsp 100 10.1.2.3 explicit-null
        """
    )

    expected = {
        "100": {
            "installed": True,
            "nexthops": [
                {
                    "type": "Static",
                    "outLabel": 0,
                    "nexthop": "10.1.2.3",
                    "installed": True,
                }
            ],
        }
    }
    result = _expect_json(r2, "show mpls table json", expected)
    assert result is None, "explicit-null LSP missing: {}".format(result)

    table = r2.vtysh_cmd("show mpls table")
    assert "IPv4 Explicit Null" in table, table

    # r3's pop LSP is no longer on the path.
    still_there = {
        "201": {
            "installed": True,
            "nexthops": [{"outLabel": 3, "nexthop": POP_NH}],
        }
    }
    result = _expect_json(r3, "show mpls table json", still_there)
    assert result is None, "r3 pop LSP was removed: {}".format(result)

    def _kernel_explicit_null():
        line = _route_line(_mpls_lines(r2), 100)
        if line is None or "10.1.2.3" not in line:
            return "r2 kernel route missing: {}".format(line)
        if not re.search(r"\bas to 0\b", line):
            return "r2 kernel route is not explicit-null (as to 0): {}".format(line)
        if re.search(r"\bas to 201\b", line):
            return "r2 kernel route still swaps to 201: {}".format(line)
        return None

    _, result = topotest.run_and_expect(_kernel_explicit_null, None, count=20, wait=1)
    assert result is None, result

    check_ping("r1", DEST, True, 20, 1, source_addr="1.1.1.1")


def test_lsp_delete():
    "Deleting the transit LSP withdraws forwarding"
    tgen = _skip_on_failure()
    r2 = tgen.gears["r2"]

    step("Delete r2 LSP 100")
    r2.vtysh_cmd(
        """
        configure terminal
        no mpls lsp 100
        """
    )

    result = _expect_json(r2, "show mpls table json", {"100": None})
    assert result is None, "LSP 100 still present: {}".format(result)

    def _kernel_gone():
        line = _route_line(_mpls_lines(r2), 100)
        if line is not None:
            return "kernel still has label 100: {}".format(line)
        return None

    _, result = topotest.run_and_expect(_kernel_gone, None, count=20, wait=1)
    assert result is None, result

    check_ping("r1", DEST, False, 20, 1, source_addr="1.1.1.1")


def test_unresolved_nexthop():
    "An LSP toward a non-connected gateway is not installed"
    tgen = _skip_on_failure()
    r2 = tgen.gears["r2"]

    step("Add LSP 300 via 10.9.9.9, which is not connected")
    r2.vtysh_cmd(
        """
        configure terminal
        mpls lsp 300 10.9.9.9 400
        """
    )

    expected = {
        "300": {
            "inLabel": 300,
            "installed": None,
            "nexthops": [
                {
                    "type": "Static",
                    "outLabel": 400,
                    "nexthop": "10.9.9.9",
                    "installed": None,
                }
            ],
        }
    }
    result = _expect_json(r2, "show mpls table json", expected)
    assert result is None, "unresolved LSP was installed or missing: {}".format(result)

    def _kernel_absent():
        line = _route_line(_mpls_lines(r2), 300)
        if line is not None:
            return "kernel installed unresolved label 300: {}".format(line)
        return None

    _, result = topotest.run_and_expect(_kernel_absent, None, count=20, wait=1)
    assert result is None, result

    running = r2.vtysh_cmd("show running-config")
    assert "mpls lsp 300 10.9.9.9 400" in running, running
