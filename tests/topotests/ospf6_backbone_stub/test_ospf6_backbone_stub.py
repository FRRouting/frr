#!/usr/bin/env python
# SPDX-License-Identifier: ISC
"""Reject backbone Stub configuration without touching live or absent areas."""

import os
import time

import pytest

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = pytest.mark.ospf6d
CWD = os.path.dirname(os.path.realpath(__file__))
EXPECTED = {"r1": {"2.2.2.2"}, "r2": {"1.1.1.1", "3.3.3.3"}, "r3": {"2.2.2.2"}}


def build_topo(tgen):
    for name in ("r1", "r2", "r3", "r4"):
        tgen.add_router(name)
    for name, pair in [("s1", ("r1", "r2")), ("s2", ("r2", "r3"))]:
        switch = tgen.add_switch(name)
        for router in pair:
            switch.add_link(tgen.gears[router])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _neighbors_healthy():
    for name, expected in EXPECTED.items():
        output = (
            get_topogen()
            .gears[name]
            .vtysh_cmd("show ipv6 ospf6 neighbor json", isjson=True)
        )
        rows = output["neighbors"]
        if {n["neighborId"] for n in rows} != expected or any(
            n["state"] != "Full" for n in rows
        ):
            return "{} neighbors are not Full".format(name)
    return None


def _healthy():
    error = _neighbors_healthy()
    if error is not None:
        return error
    routes = (
        get_topogen()
        .gears["r1"]
        .vtysh_cmd("show ipv6 ospf6 route detail json", isjson=True)
    )
    if "2001:db8:333::3/128" not in routes["routes"]:
        return "Backbone control prefix is missing"
    return None


def _epochs():
    result = {}
    for name in EXPECTED:
        start = time.monotonic()
        rows = (
            get_topogen()
            .gears[name]
            .vtysh_cmd("show ipv6 ospf6 neighbor json", isjson=True)["neighbors"]
        )
        end = time.monotonic()
        assert end - start < 1, "Neighbor observation took too long"
        for n in rows:
            age = sum(
                int(value) * scale
                for value, scale in zip(n["duration"].split(":"), (3600, 60, 1))
            )
            result[(name, n["neighborId"], n["interfaceName"])] = (
                start - age - 1,
                end - age,
            )
    return result


def _config(router, command):
    return router.vtysh_cmd("configure terminal\nrouter ospf6\n" + command)


def test_backbone_stub_refusal():
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors
    _, error = topotest.run_and_expect(_healthy, None, count=60, wait=1)
    assert error is None, error
    time.sleep(2)
    before = _epochs()
    configs = {
        name: r.vtysh_cmd("show running-config") for name, r in tgen.routers().items()
    }
    pids = {
        name: r.cmd("cat /var/run/frr/ospf6d.pid").strip()
        for name, r in tgen.routers().items()
    }

    for area in ("0.0.0.0", "0"):
        for suffix in ("", " no-summary"):
            command = "area {} stub{}".format(area, suffix)
            for name in ("r2", "r4"):
                router = tgen.gears[name]
                reply = _config(router, command)
                assert "Backbone area cannot be configured as stub" in reply, reply
                assert router.vtysh_cmd("show running-config") == configs[name]
            # r4 has no interfaces in any area: refusal must not create Area 0.
            empty = tgen.gears["r4"].vtysh_cmd("show ipv6 ospf6 json", isjson=True)
            assert not empty.get("areas", {}), empty
            assert empty["numberOfAreaInRouter"] == 0, empty
            time.sleep(2)
            assert _healthy() is None
            area0 = tgen.gears["r2"].vtysh_cmd("show ipv6 ospf6 json", isjson=True)[
                "areas"
            ]["0.0.0.0"]
            assert not area0["areaIsStub"] and not area0["areaIsNSSA"]
            now = _epochs()
            assert now.keys() == before.keys()
            for key in before:
                assert (
                    max(before[key][0], now[key][0])
                    <= min(before[key][1], now[key][1]) + 1
                ), (key, before[key], now[key])
            assert all(
                tgen.gears[name].cmd("cat /var/run/frr/ospf6d.pid").strip() == pid
                for name, pid in pids.items()
            )

    # Both handlers must still accept a non-backbone Stub and undo it.
    for suffix in ("", " no-summary"):
        for name in ("r1", "r2"):
            reply = _config(tgen.gears[name], "area 0.0.0.1 stub" + suffix)
            assert "Backbone area" not in reply
            assert (
                " area 0.0.0.1 stub" + suffix
                in tgen.gears[name].vtysh_cmd("show running-config").splitlines()
            )

        def stub_healthy():
            error = _neighbors_healthy()
            if error is not None:
                return error
            for name in ("r1", "r2"):
                areas = tgen.gears[name].vtysh_cmd("show ipv6 ospf6 json", isjson=True)[
                    "areas"
                ]
                if not areas["0.0.0.1"]["areaIsStub"]:
                    return "{} Area 1 is not Stub".format(name)
                if name == "r2" and areas["0.0.0.0"]["areaIsStub"]:
                    return "Backbone changed during legal Stub configuration"
            return None

        _, error = topotest.run_and_expect(stub_healthy, None, count=60, wait=1)
        assert error is None, error
        for name in ("r1", "r2"):
            _config(tgen.gears[name], "no area 0.0.0.1 stub")
        _, error = topotest.run_and_expect(_healthy, None, count=60, wait=1)
        assert error is None, error
        assert all(
            tgen.gears[name].vtysh_cmd("show running-config") == configs[name]
            for name in ("r1", "r2")
        )
