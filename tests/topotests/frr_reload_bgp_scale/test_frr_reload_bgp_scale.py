#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_frr_reload_bgp_scale.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_frr_reload_bgp_scale.py: time frr-reload.py unloading a big BGP
configuration.

r1 starts with a "router bgp" holding NEIGHBORS neighbors, each with
LINES_PER_NEIGHBOR lines of configuration (half in the router context, half
in "address-family ipv4 unicast"). Reloading the base configuration (the same
"router bgp" without any neighbor) makes frr-reload.py delete every one of
those lines, since the "router bgp" context itself stays.

1. Unload: reload the base configuration and time it.
2. Load: reload the full configuration and time it.
3. Unload again: reload the base configuration and time it.

After each reload the neighbor count must match and frr-reload.py --test
must find nothing left to do. Each unload must finish within
UNLOAD_TIMEOUT seconds. The times are logged and saved to
<logdir>/r1/frr-reload-times.json.

Knobs (override via env):
  FRR_RELOAD_BGP_NEIGHBORS       number of BGP neighbors (500)
  FRR_RELOAD_BGP_UNLOAD_TIMEOUT  unload budget in seconds (30)
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

NEIGHBORS = int(os.environ.get("FRR_RELOAD_BGP_NEIGHBORS", "500"))
LINES_PER_NEIGHBOR = 10
UNLOAD_TIMEOUT = float(os.environ.get("FRR_RELOAD_BGP_UNLOAD_TIMEOUT", "30"))

# Lines frr-reload.py --test reports that do not come from the test
IGNORED_DELTA = ("log commands", "no log commands", "domainname ", "no domainname ")

TIMES = {}


def neighbor_address(i):
    "Neighbor addresses live in 10.0.0.0/16, on r1-eth0."
    return f"10.0.{i // 250 + 1}.{i % 250 + 1}"


def base_lines():
    "Configuration kept by every reload: everything but the neighbors."
    return [
        "hostname r1",
        "!",
        "interface r1-eth0",
        " ip address 10.0.0.1/16",
        "exit",
        "!",
        "ip prefix-list PL-IN seq 5 permit 0.0.0.0/0 le 32",
        "!",
        "route-map RM-IN permit 10",
        " match ip address prefix-list PL-IN",
        "exit",
        "!",
        "route-map RM-OUT permit 10",
        "exit",
        "!",
        "router bgp 65001",
        " bgp router-id 10.254.254.1",
        " no bgp ebgp-requires-policy",
    ]


def full_lines():
    "Base configuration plus NEIGHBORS fully configured neighbors."
    lines = base_lines()
    for i in range(NEIGHBORS):
        peer = neighbor_address(i)
        lines += [
            f" neighbor {peer} remote-as {65100 + i}",
            f" neighbor {peer} description peer number {i}",
            f" neighbor {peer} passive",
            f" neighbor {peer} timers 10 30",
            f" neighbor {peer} advertisement-interval 5",
        ]
    lines.append(" !")
    lines.append(" address-family ipv4 unicast")
    for i in range(NEIGHBORS):
        peer = neighbor_address(i)
        lines += [
            f"  neighbor {peer} soft-reconfiguration inbound",
            f"  neighbor {peer} allowas-in 1",
            f"  neighbor {peer} maximum-prefix 1000",
            f"  neighbor {peer} route-map RM-IN in",
            f"  neighbor {peer} route-map RM-OUT out",
        ]
    lines.append(" exit-address-family")
    lines.append("exit")
    return lines


def close_base(lines):
    return lines + ["exit"]


def conf_path(tgen, name):
    path = os.path.join(tgen.logdir, "r1")
    os.makedirs(path, exist_ok=True)
    return os.path.join(path, name)


def write_conf(path, lines):
    with open(path, "w", encoding="ascii") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    write_conf(conf_path(tgen, "frr-base.conf"), close_base(base_lines()))
    full = write_conf(conf_path(tgen, "frr-full.conf"), full_lines())

    for router in tgen.routers().values():
        router.load_frr_config(full)

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    path = conf_path(tgen, "frr-reload-times.json")
    with open(path, "w", encoding="ascii") as fh:
        json.dump({"neighbors": NEIGHBORS, "times": TIMES}, fh, indent=2)
    logger.info("frr-reload times saved to %s: %s", path, TIMES)
    tgen.stop_topology()


def frr_reload(router, conf, mode="--reload"):
    tgen = get_topogen()
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    start = time.monotonic()
    rc, out, err = router.net.cmd_status(
        f"{frrdir}/frr-reload.py {mode} --stdout {conf}", warn=False
    )
    elapsed = time.monotonic() - start
    assert rc == 0, f"frr-reload.py {mode} {conf} failed (rc={rc}):\n{out}\n{err}"
    return out, elapsed


def reload_delta(router, conf):
    """
    Return the commands frr-reload.py --test would add and delete.

    --test prints every command inside its contexts, closing each with
    "exit", so only the leaves (lines not followed by a deeper line) are
    commands. "log commands" and "domainname" are ignored: topotest daemons
    always run with the first, take the second from the host, and the config
    files have neither.
    """
    out, _ = frr_reload(router, conf, mode="--test")
    sections = {"add": [], "delete": []}
    section = None
    for line in out.splitlines():
        if line.startswith("Lines To Delete"):
            section = "delete"
        elif line.startswith("Lines To Add"):
            section = "add"
        elif section and line.strip() and not line.startswith("====="):
            sections[section].append(line)

    def depth(line):
        return len(line) - len(line.lstrip())

    delta = {}
    for section, lines in sections.items():
        delta[section] = [
            line.strip()
            for idx, line in enumerate(lines)
            if line.strip() not in ("exit", "exit-address-family")
            and (idx + 1 == len(lines) or depth(lines[idx + 1]) <= depth(line))
            and not line.strip().startswith(IGNORED_DELTA)
        ]
    return delta


def check_neighbor_count(router, expected):
    def _check():
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast summary json"))
        count = len(output.get("peers", {}))
        if count != expected:
            return f"{count} neighbors, expected {expected}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result


def timed_reload(name, conf, neighbors, timeout=None):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    delta = reload_delta(r1, conf)
    _, elapsed = frr_reload(r1, conf)
    TIMES[name] = {
        "seconds": round(elapsed, 2),
        "lines_to_add": len(delta["add"]),
        "lines_to_delete": len(delta["delete"]),
    }
    logger.info(
        "frr-reload.py %s: %.2fs (%d lines to add, %d lines to delete)",
        name,
        elapsed,
        len(delta["add"]),
        len(delta["delete"]),
    )

    check_neighbor_count(r1, neighbors)
    leftover = reload_delta(r1, conf)
    assert (
        not leftover["add"] and not leftover["delete"]
    ), f"unexpected delta after {name}: {leftover}"
    assert not tgen.routers_have_failure(), tgen.errors
    if timeout is not None:
        assert (
            elapsed <= timeout
        ), f"frr-reload.py {name} took {elapsed:.2f}s, more than {timeout:.0f}s"


def test_initial_config():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    check_neighbor_count(r1, NEIGHBORS)
    delta = reload_delta(r1, conf_path(tgen, "frr-full.conf"))
    assert not delta["add"] and not delta["delete"], f"unexpected delta: {delta}"


def test_unload():
    tgen = get_topogen()
    timed_reload("unload", conf_path(tgen, "frr-base.conf"), 0, UNLOAD_TIMEOUT)


def test_load():
    tgen = get_topogen()
    timed_reload("load", conf_path(tgen, "frr-full.conf"), NEIGHBORS)


def test_unload_again():
    tgen = get_topogen()
    timed_reload("unload_again", conf_path(tgen, "frr-base.conf"), 0, UNLOAD_TIMEOUT)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
