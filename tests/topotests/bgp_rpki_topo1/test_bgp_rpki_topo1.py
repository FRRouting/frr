#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.

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
from lib.common_config import step
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        if rname == "r1":
            # use rtrd.py for the RPKI server
            continue
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            " -M bgpd_rpki",
        )

    tgen.start_router()

    r1_path = os.path.join(CWD, "r1")
    log_dir = os.path.join(tgen.logdir, "r1")
    pid_file = os.path.join(log_dir, "rtrd.pid")

    tgen.gears["r1"].cmd("chmod u+x {}/rtrd.py".format(r1_path))
    tgen.gears["r1"].popen("{}/rtrd.py & echo $! >{}".format(r1_path, pid_file))


def teardown_module(mod):
    tgen = get_topogen()

    log_dir = os.path.join(tgen.logdir, "r1")
    pid_file = os.path.join(log_dir, "rtrd.pid")

    logger.info("r1: sending SIGTERM to rtrd RPKI server")
    tgen.gears["r1"].cmd("kill $(cat {})".format(pid_file))
    tgen.stop_topology()


def test_show_bgp_rpki_prefixes():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _show_rpki_prefixes(rname, expected):
        output = json.loads(tgen.gears[rname].vtysh_cmd("show rpki prefix-table json"))

        return topotest.json_cmp(output, expected)

    rname = "r2"
    tgen.gears[rname].vtysh_cmd(
        """
configure
rpki
 rpki cache 192.0.2.1 15432 preference 1
exit
"""
    )

    step("Check RPKI prefix table")

    expected = open(os.path.join(CWD, "{}/rpki_prefix_table.json".format(rname))).read()
    expected_json = json.loads(expected)
    test_func = functools.partial(_show_rpki_prefixes, rname, expected_json)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see RPKI prefixes on {}".format(rname)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
