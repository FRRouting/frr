#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Exercise MaxAge external LSAs during restart and delayed flooding.

An ASBR r1 is connected through areas 1, 0 and 2 to r4:
    r1 -- area 1 -- r2 -- area 0 -- r3 -- area 2 -- r4
The ASBR redistributes two static routes so withdrawing one does not
change its ASBR status. Graceful restart is not enabled.
"""

import json
import os
import re
import struct
import sys
import time
from pathlib import Path

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib import topotest
from lib.common_config import get_frr_ipv6_linklocal
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.ospf6d]
PREFIX = "2001:db8:100::/64"
KEEP_PREFIX = "2001:db8:101::/64"
REMOTE_ROUTERS = ("r2", "r3", "r4")


def build_topo(tgen):
    for number in range(1, 5):
        tgen.add_router(f"r{number}")
    for left in range(1, 4):
        switch = tgen.add_switch(f"s{left}")
        switch.add_link(tgen.gears[f"r{left}"], nodeif=f"eth-r{left + 1}")
        switch.add_link(tgen.gears[f"r{left + 1}"], nodeif=f"eth-r{left}")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


@pytest.fixture(autouse=True)
def check_router_status():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def wait_for(check, description, count=30, wait=1):
    _, result = topotest.run_and_expect(check, True, count=count, wait=wait)
    assert result is True, description


def neighbors_full():
    tgen = get_topogen()
    for name, expected in (("r1", 1), ("r2", 2), ("r3", 2), ("r4", 1)):
        neighbors = (
            tgen.gears[name]
            .vtysh_cmd("show ipv6 ospf6 neighbor json", isjson=True)
            .get("neighbors", [])
        )
        if len(neighbors) != expected or any(n["state"] != "Full" for n in neighbors):
            return False
    return True


def routes_present(prefix=PREFIX, present=True):
    for name in REMOTE_ROUTERS:
        routes = (
            get_topogen()
            .gears[name]
            .vtysh_cmd("show ipv6 route ospf json", isjson=True)
        )
        if bool(routes.get(prefix)) != present:
            return False
    return True


def external_lsa(name, prefix=PREFIX, output=None):
    if output is None:
        output = (
            get_topogen()
            .gears[name]
            .vtysh_cmd("show ipv6 ospf6 database as-external detail")
        )
    for block in re.split(r"(?=Age:)", output):
        if not re.search(rf"Prefix: {re.escape(prefix)}\s", block):
            continue
        return {
            "age": int(re.search(r"Age:\s*(\d+)", block).group(1)),
            "id": re.search(r"Link State ID: (\S+)", block).group(1),
            "advertiser": re.search(r"Advertising Router: (\S+)", block).group(1),
            "sequence": int(
                re.search(r"LS Sequence Number: (0x[\da-fA-F]+)", block).group(1), 16
            ),
            "checksum": int(
                re.search(r"CheckSum: (0x[\da-fA-F]+)", block).group(1), 16
            ),
        }
    return None


def newer_than_maxage(lsa, old):
    # At equal sequence and checksum, a live instance cannot beat MaxAge.
    if lsa["sequence"] == old["sequence"]:
        return lsa["checksum"] > old["checksum"]
    return (
        struct.unpack("!i", struct.pack("!I", lsa["sequence"]))[0]
        > struct.unpack("!i", struct.pack("!I", old["sequence"]))[0]
    )


def snapshot(label, state=None):
    if state is None:
        state = {}
        for name in ("r1",) + REMOTE_ROUTERS:
            router = get_topogen().gears[name]
            database = router.vtysh_cmd("show ipv6 ospf6 database as-external detail")
            state[name] = {
                "lsa": external_lsa(name, output=database),
                "keep_lsa": external_lsa(name, KEEP_PREFIX, output=database),
                "routes": router.vtysh_cmd("show ipv6 route ospf json", isjson=True),
                "database": database,
            }
    Path(get_topogen().logdir, f"{label}.json").write_text(json.dumps(state, indent=2))


def converge():
    wait_for(neighbors_full, "OSPFv3 adjacencies did not become Full", count=120)
    wait_for(routes_present, "External prefix did not reach every area")
    wait_for(lambda: routes_present(KEEP_PREFIX), "Second external prefix is missing")


def wait_maxage_removers_idle():
    def removers_idle():
        for name in REMOTE_ROUTERS:
            timers = (
                get_topogen()
                .gears[name]
                .vtysh_cmd("show event timers", daemon="ospf6d", raises=True)
            )
            assert "Showing timers for" in timers, timers
            if "ospf6_maxage_remover" in timers:
                return False
        return True

    # An older, process-wide timer can collect a new withdrawal before 60s.
    # Drain it before the stop instead of assuming a fresh removal interval.
    wait_for(
        removers_idle, "An earlier MaxAge-removal timer is still pending", count=120
    )


def test_initial_convergence():
    converge()


@pytest.mark.parametrize("restart_delay", [0, 2])
def test_normal_restart_with_retained_maxage(restart_delay):
    """A normal FRR stop/start must recover with newer LSA instances."""
    converge()
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    # Keep the shutdown flush outside MinLSArrival after a preceding restart.
    time.sleep(1.2)
    snapshot(f"restart-{restart_delay}-before-stop")

    wait_maxage_removers_idle()
    receive_log = Path(tgen.logdir, "r2", "ospf6d.log")
    receive_offset = receive_log.stat().st_size
    stopped_state = {}

    def withdrawn():
        stopped_state.clear()
        for name in REMOTE_ROUTERS:
            router = tgen.gears[name]
            database = router.vtysh_cmd("show ipv6 ospf6 database as-external detail")
            lsa = external_lsa(name, output=database)
            keep_lsa = external_lsa(name, KEEP_PREFIX, output=database)
            routes = router.vtysh_cmd("show ipv6 route ospf json", isjson=True)
            stopped_state[name] = {
                "lsa": lsa,
                "keep_lsa": keep_lsa,
                "routes": routes,
                "database": database,
            }
            if (
                lsa is None
                or keep_lsa is None
                or lsa["age"] != 3600
                or keep_lsa["age"] != 3600
                or routes.get(PREFIX)
                or routes.get(KEEP_PREFIX)
            ):
                return False
        return True

    stopped = time.monotonic()
    assert r1.stop() == ""
    try:
        wait_for(withdrawn, "Peers did not retain the withdrawn MaxAge external LSAs")
        # A cold restart can assign the two prefixes different LSA IDs.
        # Compare instances by LSA identity, independently of prefix order.
        retained = {
            lsa["id"]: lsa
            for lsa in (stopped_state["r2"]["lsa"], stopped_state["r2"]["keep_lsa"])
        }
        # Reuse the successful poll; live diagnostic commands delay restart.
        snapshot(f"restart-{restart_delay}-stopped", state=stopped_state)
        # Exercise immediate and delayed restart while peers retain MaxAge.
        time.sleep(restart_delay)
    finally:
        assert r1.start() == ""

    identifiers = "|".join(re.escape(lsa_id) for lsa_id in retained)
    advertiser = re.escape(next(iter(retained.values()))["advertiser"])
    collected = re.compile(
        rf"Remove MaxAge \[AS-External Id:(?:{identifiers}) Adv:{advertiser}\]$",
        re.MULTILINE,
    )

    def assert_retained():
        # A skipped removal logs a retrans_count suffix; match real removals only.
        assert (
            collected.search(receive_log.read_text()[receive_offset:]) is None
        ), "Retained MaxAge copies were garbage-collected during restart"

    def recovered():
        assert_retained()
        if not neighbors_full():
            return False
        for name in ("r1",) + REMOTE_ROUTERS:
            router = tgen.gears[name]
            database = router.vtysh_cmd("show ipv6 ospf6 database as-external detail")
            for prefix in (PREFIX, KEEP_PREFIX):
                lsa = external_lsa(name, prefix, output=database)
                if (
                    lsa is None
                    or lsa["age"] == 3600
                    or lsa["id"] not in retained
                    or not newer_than_maxage(lsa, retained[lsa["id"]])
                ):
                    return False
            if name in REMOTE_ROUTERS:
                routes = router.vtysh_cmd("show ipv6 route ospf json", isjson=True)
                if not routes.get(PREFIX) or not routes.get(KEEP_PREFIX):
                    return False
        return True

    wait_for(
        recovered, "Normal restart did not recover above retained MaxAge", count=120
    )
    assert_retained()
    elapsed = time.monotonic() - stopped
    logger.info(
        "Normal restart recovered in %.3fs above retained instances %s",
        elapsed,
        {
            key: (hex(value["sequence"]), hex(value["checksum"]))
            for key, value in retained.items()
        },
    )
    snapshot(f"restart-{restart_delay}-recovered")


def test_stale_external_lsa_after_withdrawal():
    """Replaying a valid pre-withdrawal LSA must not restore its route."""
    converge()
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    original = external_lsa("r1")
    router_id = original["advertiser"]
    area_id = r1.vtysh_cmd("show ipv6 ospf6 interface eth-r2 json", isjson=True)[
        "eth-r2"
    ]["areaId"]
    dump = r1.vtysh_cmd("show ipv6 ospf6 database as-external dump")
    match = re.search(
        rf"\[[^\]\n]*Id:{re.escape(original['id'])} Adv:{re.escape(router_id)}\]:\s*"
        r"((?:[0-9a-fA-F]{8}[ \n]*)+)",
        dump,
    )
    assert match, dump
    raw_lsa = "".join(match.group(1).split())
    linklocal = get_frr_ipv6_linklocal(tgen, "r1", intf="eth-r2")
    wait_maxage_removers_idle()
    time.sleep(1.2)  # Let MinLSArrival elapse before the legitimate withdrawal.
    r1.vtysh_cmd(f"configure terminal\nno ipv6 route {PREFIX} Null0")
    wait_for(lambda: routes_present(present=False), "Prefix was not withdrawn")
    wait_for(
        lambda: all(
            (lsa := external_lsa(name)) is not None
            and lsa["age"] == 3600
            and lsa["sequence"] == original["sequence"]
            and lsa["checksum"] == original["checksum"]
            for name in REMOTE_ROUTERS
        ),
        "Withdrawal did not retain the original LSA at MaxAge",
    )
    snapshot("stale-before-replay")
    # Delay the originator's repairs while replaying through its established
    # adjacency. The 40s dead interval keeps this short filter from tearing
    # down the neighbor relationship; sendp bypasses the OUTPUT filter.
    receive_log = Path(tgen.logdir, "r2", "ospf6d.log")
    receive_offset = receive_log.stat().st_size
    replay_age = struct.unpack("!H", bytes.fromhex(raw_lsa)[:2])[0]
    r1.cmd_raises("ip6tables -I OUTPUT -p 89 -j DROP")
    try:
        # Keep the replay outside MinLSArrival after the MaxAge withdrawal.
        time.sleep(1.2)
        r1.cmd_raises(
            [
                "python3",
                os.path.join(CWD, "replay_lsa.py"),
                "eth-r2",
                linklocal,
                router_id,
                area_id,
                raw_lsa,
                os.path.join(tgen.logdir, "replayed-lsa.pcap"),
            ]
        )
        wait_for(
            lambda: re.search(
                rf"\[AS-External Id:{re.escape(original['id'])} Adv:{re.escape(router_id)}\]\n"
                rf"[^\n]*Age:\s*{replay_age} SeqNum: 0x{original['sequence']:08x}",
                receive_log.read_text()[receive_offset:],
            )
            is not None,
            "Receiver did not process the replayed external LSA",
            count=15,
            wait=1,
        )
        state = {}
        for _ in range(5):
            for name in REMOTE_ROUTERS:
                routes = tgen.gears[name].vtysh_cmd(
                    "show ipv6 route ospf json", isjson=True
                )
                assert not routes.get(PREFIX), "Stale LSA restored a withdrawn route"
                state[name] = {"routes": routes}
            database = tgen.gears["r2"].vtysh_cmd(
                "show ipv6 ospf6 database as-external detail"
            )
            lsa = external_lsa("r2", output=database)
            assert lsa is not None and lsa["age"] == 3600, "Stale LSA replaced MaxAge"
            state["r2"].update(
                {
                    "lsa": lsa,
                    "keep_lsa": external_lsa("r2", KEEP_PREFIX, output=database),
                    "database": database,
                }
            )
            # Sample for one second to catch delayed stale-route installation.
            time.sleep(0.2)
        # The blocked peer cannot regain Full while the OUTPUT filter is held.
        assert neighbors_full(), "Replay lost an established adjacency"
        snapshot("stale-after-replay", state=state)
    finally:
        r1.cmd_raises("ip6tables -D OUTPUT -p 89 -j DROP")
        r1.vtysh_cmd(f"configure terminal\nipv6 route {PREFIX} Null0")
    wait_for(routes_present, "A fresh origination failed to restore the route")
    snapshot("stale-fresh-origination")


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak reporting is disabled")
    tgen.report_memory_leaks()
