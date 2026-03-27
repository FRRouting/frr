#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Nvidia Inc.
#
"""
Generic FE periodic sampling tests.
"""

import json
import os
import re

import pytest
from lib.topogen import Topogen
from munet.testing.util import waitline
from oper import check_kernel_32

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

CWD = os.path.dirname(os.path.realpath(__file__))
FE_CLIENT = CWD + "/../lib/fe_client.py"


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests."
    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config("frr-ds.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def _get_op_and_json(output):
    values = []
    op = ""
    path = ""
    data = ""
    for line in output.split("\n"):
        if not line:
            break
        match = re.match(r"#OP=([A-Z]*): (.*)", line)
        if op and match:
            values.append((op, path, data))
            data = ""
            path = ""
            op = ""
        if not op and match:
            op = match.group(1)
            path = match.group(2)
            continue
        data += line + "\n"

    if op:
        values.append((op, path, data))

    return values


@pytest.mark.parametrize(
    "xpath,topkey",
    [
        ("/frr-interface:lib/interface", "frr-interface:lib"),
        ("/frr-zebra:lib/vrf/ipv4-route-count/total", "frr-zebra:lib"),
    ],
)
def test_frontend_periodic_sampling_generic(tgen, xpath, topkey):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net
    check_kernel_32(r1, "11.11.11.11", 1, "")

    proc = r1.popen(
        [
            FE_CLIENT,
            "--server",
            "/var/run/frr/mgmtd_fe.sock",
            "--listen",
            xpath,
            "--notify-mode",
            "periodic",
            "--notify-mode-data",
            "1000",
            "--notify-count",
            "3",
            "--datastore",
        ]
    )
    assert waitline(proc.stderr, "Connected", timeout=30)

    try:
        output, _ = proc.communicate(timeout=30)
        notifications = _get_op_and_json(output)
        assert len(notifications) >= 3, output

        for op, path, data in notifications[:3]:
            assert op == "SYNC", output
            assert path == xpath, output
            jsout = json.loads(data)
            assert topkey in jsout, output

            if xpath == "/frr-zebra:lib/vrf/ipv4-route-count/total":
                total = jsout["frr-zebra:lib"]["vrf"][0]["ipv4-route-count"]["total"]
                assert isinstance(total, int), output
    finally:
        proc.kill()


if __name__ == "__main__":
    import sys

    ret = pytest.main(["-s"])
    sys.exit(ret)
