#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Andreas Karis <ak.karis@gmail.com>
#

"""
test_frr_reload_segment_routing.py

test frr-reload.py on 'segment-routing' section deletion.

1. Save clean configuration to 'frr-clean.conf'
2. For each test case:
  a. Create and load first configuration, 'frr-from.conf'
  b. Create and load second configuration, 'frr-to.conf'
  c. Load clean configuration from 'frr-clean.conf'
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_frr_reload_segment_routing():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def sanitize_config(config: str):
        sanitize_list = (
            "!",
            "frr version",
            "frr defaults",
            "hostname",
            "domainname",
            "log",
            "service",
            "end",
        )

        sanitized_config = []
        for line in config.splitlines():
            stripped = line.strip()
            if len(stripped) == 0:
                continue

            drop_line = False
            for sanitize_item in sanitize_list:
                if stripped.startswith(sanitize_item):
                    drop_line = True
                    break
            if drop_line:
                continue
            sanitized_config.append(stripped)

        return sanitized_config

    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    frrreload = frrdir + "/frr-reload.py --reload"

    r1.cmd_raises("vtysh -c 'write terminal no-header' > frr-clean.conf")

    test_cases = [
        {
            "from": """
segment-routing
 srv6
  locators
   locator MAIN
    prefix fd00:0:33::/48 block-len 32 node-len 16
   exit
  exit
 exit
exit
    """,
            "to": "",
            "expected_to": "",
        },
        {
            "from": """
segment-routing
 srv6
  locators
   locator MAIN
    prefix fd00:0:33::/48 block-len 32 node-len 16
   exit
  exit
 exit
exit
    """,
            "to": """
segment-routing
 srv6
  locators
   locator MAIN
   exit
  exit
 exit
exit
    """,
            "expected_to": """
segment-routing
 srv6
  locators
   locator MAIN
   exit
  exit
 exit
exit
    """,
        },
        {
            "from": """
segment-routing
 srv6
  locators
   locator MAIN
    prefix fd00:0:33::/48 block-len 32 node-len 16
   exit
  exit
 exit
exit
    """,
            "to": """
segment-routing
 srv6
  locators
   exit
  exit
 exit
exit
    """,
            "expected_to": "",
        },
    ]

    for tc in test_cases:
        clean_config = r1.cmd_raises("cat frr-clean.conf | head -n-1")

        r1.cmd_raises(f"echo '{clean_config}{tc['from']}' > frr-from.conf")
        r1.cmd_raises(f"{frrreload} frr-from.conf")
        running_config = r1.cmd_raises("vtysh -c 'write terminal no-header'")
        assert sanitize_config(tc["from"]) == sanitize_config(running_config), (
            "running configuration does not contain expected"
        )

        r1.cmd_raises(f"echo '{clean_config}{tc['to']}' > frr-to.conf")
        r1.cmd_raises(f"{frrreload} frr-to.conf")
        running_config = r1.cmd_raises("vtysh -c 'write terminal no-header'")
        assert sanitize_config(tc["expected_to"]) == sanitize_config(running_config), (
            "running configuration does not equal expected"
        )

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
