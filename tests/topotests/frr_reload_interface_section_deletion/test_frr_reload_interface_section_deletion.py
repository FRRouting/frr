#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025 by
# Kyrylo Yatsenko <hedrok@gmail.com>
#

"""
test_frr_reload_interface_section_deletion.py

test frr-reload.py on 'interface' section deletion.

1. Save clean configuration to 'frr-clean.conf'
2. Add virtual interface pair.
3. Configure IP address with peer.
4. Save configuration to 'frr-with-interface.conf'
5. Use frr-reload.py to load 'frr-clean.conf' - check there is no IP.
6. Use frr-reload.py to load 'frr-with-interface.conf' - check there is IP.
7. Delete virtual interface pair.
8. Use frr-reload.py to load 'frr-clean.conf'. No errors should be issued.
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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")

def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_frr_reload_interface_section_deletion():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def test_have_ip_converge():
        output = json.loads(r1.vtysh_cmd(f"show interface veth0 json"))
        expected = {
            "veth0": {
                "ipAddresses": [
                    {
                        "address":"10.0.0.5/32",
                        "peer":"10.0.0.6/32",
                    },
                ],
            },
        }
        return topotest.json_cmp(output, expected)

    def test_have_no_ip_converge():
        output = json.loads(r1.vtysh_cmd(f"show interface veth0 json"))
        expected = {
            "veth0": {
                "ipAddresses": [
                ],
            },
        }
        res = topotest.json_cmp(output, expected)
        if res:
            return res
        # Check if array is empty
        if len(output["veth0"]["ipAddresses"]):
            return "IP addresses not empty!"
        return None

    frrreload = '/usr/lib/frr/frr-reload.py --reload'
    r1.cmd_raises("vtysh -c 'write terminal no-header' > frr-clean.conf")
    r1.cmd_raises("sudo ip link add veth0 type veth peer name veth1")
    r1.vtysh_cmd("configure terminal\ninterface veth0\nip address 10.0.0.5 peer 10.0.0.6/32\n")
    r1.run("vtysh -c 'write terminal no-header' > frr-with-interface.conf")

    _, result = topotest.run_and_expect(test_have_ip_converge, None, count=30, wait=1)
    assert (
        result is None
    ), "No IP after initial configuration"

    r1.cmd_raises(f"{frrreload} frr-clean.conf")
    _, result = topotest.run_and_expect(test_have_no_ip_converge, None, count=30, wait=1)
    assert (
        result is None
    ), "Has IP address after reload to clean"

    r1.cmd_raises(f"{frrreload} frr-with-interface.conf")
    _, result = topotest.run_and_expect(test_have_ip_converge, None, count=30, wait=1)
    assert (
        result is None
    ), "No IP address after reload to configuration with interface"

    # Now delete the interface pair
    r1.cmd_raises("sudo ip link delete veth0")
    r1.cmd_raises(f"{frrreload} frr-clean.conf")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
