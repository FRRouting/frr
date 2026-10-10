#!/usr/bin/env python
# SPDX-License-Identifier: ISC
"""Restore NSSA Router-LSA capabilities and balance translator ASBR contributions."""

import os
import json
import pytest
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospf6d, pytest.mark.staticd]
CWD = os.path.dirname(os.path.realpath(__file__))
RIDS = {"r1": "1.1.1.1", "r2": "2.2.2.2", "r3": "3.3.3.3", "r4": "4.4.4.4"}
AREAS = {
    "r1": ["0.0.0.1"],
    "r2": ["0.0.0.0", "0.0.0.1", "0.0.0.2"],
    "r3": ["0.0.0.0"],
    "r4": ["0.0.0.2"],
}
NEIGHBORS = {
    "r1": {"2.2.2.2"},
    "r2": {"1.1.1.1", "3.3.3.3", "4.4.4.4"},
    "r3": {"2.2.2.2"},
    "r4": {"2.2.2.2"},
}
EXTERNAL = "2001:db8:ee::/64"


def build_topo(tgen):
    for name in RIDS:
        tgen.add_router(name)
    for name, pair in [
        ("s1", ("r1", "r2")),
        ("s2", ("r2", "r3")),
        ("s3", ("r2", "r4")),
    ]:
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


def configure(name, command):
    reply = (
        get_topogen()
        .gears[name]
        .vtysh_cmd("configure terminal\nrouter ospf6\n" + command)
    )
    assert (
        "Unknown command" not in reply
        and "Command incomplete" not in reply
        and "% Warning" not in reply
    ), reply


def area_config(area, enable, suffix=""):
    for router in (["r1", "r2"] if area == 1 else ["r4", "r2"]):
        configure(
            router,
            ("" if enable else "no ")
            + "area 0.0.0.{} nssa{}".format(area, suffix if enable else ""),
        )


def state_error(nssa_areas, asbr):
    errors = []
    for name in RIDS:
        router = get_topogen().gears[name]
        neighbors = router.vtysh_cmd("show ipv6 ospf6 neighbor json", isjson=True)[
            "neighbors"
        ]
        if {n["neighborId"] for n in neighbors} != NEIGHBORS[name] or any(
            n["state"] != "Full" for n in neighbors
        ):
            errors.append(name + " neighbors not Full")
        areas = router.vtysh_cmd("show ipv6 ospf6 json", isjson=True)["areas"]
        db = router.vtysh_cmd("show ipv6 ospf6 database detail json", isjson=True)
        for area in AREAS[name]:
            active = area in nssa_areas
            if areas[area]["areaIsNSSA"] != active or areas[area]["areaIsStub"]:
                errors.append(name + " " + area + " area type")
            rows = [
                lsa
                for group in db["areaScopedLinkStateDb"]
                if group["areaId"] == area
                for lsa in group["lsa"]
                if lsa["type"] == "Router"
                and lsa["advertisingRouter"] == RIDS[name]
                and lsa["age"] < 3600
            ]
            if not rows:
                errors.append(name + " " + area + " missing Router-LSA")
            for lsa in rows:
                options = lsa["options"].split("|")
                if ("N" in options) != active or ("E" in options) == active:
                    errors.append(
                        name
                        + " "
                        + area
                        + " wrong Router-LSA Options "
                        + lsa["options"]
                    )
                if ("E" in lsa["bits"]) != (name == "r2" and asbr):
                    errors.append(name + " " + area + " wrong ASBR flag " + lsa["bits"])
    return "; ".join(errors) if errors else None


def wait_state(areas, asbr):
    _, error = topotest.run_and_expect(
        lambda: state_error(areas, asbr), None, count=40, wait=1
    )
    assert error is None, error


def test_nssa_remove_capabilities_and_asbr():
    tgen = get_topogen()
    assert not tgen.routers_have_failure(), tgen.errors
    wait_state(set(), False)
    original = {
        n: r.vtysh_cmd("show running-config") for n, r in tgen.routers().items()
    }
    pids = {
        n: r.cmd("cat /var/run/frr/ospf6d.pid").strip()
        for n, r in tgen.routers().items()
    }

    def restored():
        wait_state(set(), False)
        for name, router in tgen.routers().items():
            assert router.vtysh_cmd("show running-config") == original[name]
            assert router.cmd("cat /var/run/frr/ospf6d.pid").strip() == pids[name]

        def forwarding_restored():
            routes = tgen.gears["r1"].vtysh_cmd(
                "show ipv6 ospf6 route detail json", isjson=True
            )["routes"]
            if "2001:db8:333::3/128" not in routes:
                return "Backbone control prefix has not returned"
            ping = tgen.gears["r1"].cmd("ping -6 -c 1 -W 2 2001:db8:333::3")
            return None if ", 0% packet loss" in ping else ping

        _, error = topotest.run_and_expect(forwarding_restored, None, count=30, wait=1)
        assert error is None, error

    # Repeat both summary policies; an unrelated cost change must not be needed.
    for suffix in ("", " no-summary"):
        for cycle in range(2):
            area_config(1, True, suffix)
            wait_state({"0.0.0.1"}, True)
            area_config(1, False)
            restored()

    # Removing one translator contribution must preserve the other NSSA.
    area_config(1, True)
    area_config(2, True)
    wait_state({"0.0.0.1", "0.0.0.2"}, True)
    area_config(1, False)
    wait_state({"0.0.0.2"}, True)
    area_config(2, False)
    restored()

    # Real static redistribution must continue to hold ASBR status on NSSA exit.
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nipv6 route "
        + EXTERNAL
        + " Null0\nrouter ospf6\nredistribute static"
    )
    wait_state(set(), True)
    area_config(1, True)
    wait_state({"0.0.0.1"}, True)
    area_config(1, False)
    wait_state(set(), True)

    def external_present():
        text = tgen.gears["r3"].vtysh_cmd("show ipv6 route " + EXTERNAL + " json")
        assert "Unknown command" not in text, text
        routes = json.loads(text)
        rows = routes.get(EXTERNAL, [])
        return (
            None
            if any(r.get("installed") for r in rows)
            else "Redistributed control route is not installed: " + json.dumps(rows)
        )

    _, error = topotest.run_and_expect(external_present, None, count=30, wait=1)
    assert error is None, error
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\nno ipv6 route "
        + EXTERNAL
        + " Null0\nrouter ospf6\nno redistribute static"
    )
    restored()

    # A configured NSSA with no interfaces must also balance its exit.
    for cycle in range(2):
        configure("r2", "area 0.0.0.3 nssa")
        configure("r2", "no area 0.0.0.3 nssa")
        restored()
        areas = tgen.gears["r2"].vtysh_cmd("show ipv6 ospf6 json", isjson=True)["areas"]
        assert "0.0.0.3" not in areas
