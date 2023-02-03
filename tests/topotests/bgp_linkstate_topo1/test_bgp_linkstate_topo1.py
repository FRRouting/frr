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
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


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
            # use bgp_injector.py to inject BGP prefixes
            continue
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    r1_path = os.path.join(CWD, "r1")
    log_dir =  os.path.join(tgen.logdir, "r1")
    tgen.gears["r1"].cmd("chmod u+x {}/bgp_injector.py".format(r1_path))
    tgen.gears["r1"].run("{}/bgp_injector.py {}".format(r1_path, log_dir))


def teardown_module(mod):
    tgen = get_topogen()

    log_dir =  os.path.join(tgen.logdir, "r1")
    pid_file = os.path.join(log_dir, "bgp_injector.pid")

    logger.info("r1: sending SIGTERM to bgp_injector")
    tgen.gears["r1"].cmd("kill $(cat {})".format(pid_file))
    tgen.stop_topology()


def test_show_bgp_link_state():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _remove_prefixlen(tmp_json):
        new_json = {
            prefix.split("}/")[0] + "}/XX": data
            for prefix, data in tmp_json["routes"].items()
        }

        return new_json

    def _show_bgp_link_state_json(rname, tmp_expected):
        tmp_output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp link-state link-state json")
        )
        # prefix length is the size of prefix in memory
        # which differs on 32 and 64 bits.
        # do not compare the prefix length
        output = _remove_prefixlen(tmp_output)
        expected = _remove_prefixlen(tmp_expected)

        return topotest.json_cmp(output, expected)

    step("Check BGP Link-State tables")
    for rname in ["r2", "r3"]:
        expected = open(os.path.join(CWD, "{}/linkstate.json".format(rname))).read()
        expected_json = json.loads(expected)
        test_func = functools.partial(_show_bgp_link_state_json, rname, expected_json)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "Failed to see BGP prefixes on {}".format(rname)


def test_show_bgp_link_state_detail():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _show_bgp_link_state_json(rname, expected):
        output = json.loads(
            tgen.gears[rname].vtysh_cmd("show bgp link-state link-state detail-routes json")
        )
        json_output = {
            prefix.split("/")[0] + "/XX": item["linkStateAttributes"]
            for prefix, data in output["routes"].items()
            for item in data
            if "linkStateAttributes" in item
        }

        return topotest.json_cmp(json_output, expected)

    step("Check BGP Link-State Attributes tables")
    for rname in ["r2", "r3"]:
        expected = open(
            os.path.join(CWD, "{}/linkstate_detail.json".format(rname))
        ).read()
        expected_json = json.loads(expected)
        test_func = functools.partial(_show_bgp_link_state_json, rname, expected_json)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assert result is None, "Failed to display BGP-LS Attributes on {}".format(rname)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
