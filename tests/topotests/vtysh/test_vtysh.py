#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_vtysh.py
#

"""
test_vtysh.py: Test some basic vtysh commands
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Import topogen and topotest helpers
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    "Build function"

    # Create routers
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, "-s 90000000"), (TopoRouter.RD_MGMTD, None)],
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ping_command():
    "Test the vtysh ping command with all the available options"

    tgen = get_topogen()
    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _cmp_ping_output(router, cmd):
        output = router.vtysh_cmd(cmd)
        if "192.168.0.1 ping statistics" in output:
            return None
        else:
            return output

    test_func = partial(
        _cmp_ping_output, r1, "ping 192.168.0.1 source r1-eth0 count 3 dontfragment"
    )
    result, diff = topotest.run_and_expect(test_func, None, count=20, wait=3)

    assert result, "'ping' output mismatch: \n{}".format(diff)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
