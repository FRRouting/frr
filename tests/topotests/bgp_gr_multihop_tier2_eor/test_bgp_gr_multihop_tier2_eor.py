#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Johan Linder

"""A mixed direct/multihop GR cycle must end tier 2 on its final EOR.

r1 peers directly with r2 and over loopbacks with r3/r4 through r2. Static
transport routes isolate selection from underlay bootstrap; tenant routes
reach r1 only over their respective multihop BGP sessions. Administrative
re-enable opens each independent startup-selection window.
"""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest  # noqa: E402
from lib.common_config import step  # noqa: E402
from lib.topogen import Topogen  # noqa: E402

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]
MULTIHOP = {"r3": "3.3.3.3", "r4": "4.4.4.4"}
PREFIXES = {"r3": "198.51.100.3/32", "r4": "198.51.100.4/32"}
TIER2_START = "Started tier-2 path-select deferral timer for IPv4 Unicast"
TIER2_END = "No multihop EORs pending for IPv4 Unicast"
TIER2_TIMEOUT = "Starting 2nd deferred path selection for IPv4 Unicast"


@pytest.fixture
def select_defer_time():
    return 60


@pytest.fixture
def startup_time():
    return 120


@pytest.fixture
def hold_direct_eor():
    return False


@pytest.fixture(params=[False, True], ids=["without-k", "with-k"])
def routers(request, select_defer_time, startup_time, hold_direct_eor):
    """Each case owns fresh daemons and an independent deferral cycle."""
    tgen = Topogen(build_topo, request.node.name)
    tgen.start_topology()
    try:
        for name, router in tgen.routers().items():
            path = os.path.join(CWD, name, "frr.conf")
            daemons = [
                "zebra",
                "staticd",
                ("bgpd", "-K" if request.param and name == "r1" else ""),
            ]
            router.load_frr_config(path, daemons=daemons)
        tgen.start_router()
        assert not tgen.routers_have_failure(), tgen.errors
        dut = tgen.gears["r1"]
        pid = dut.run("cat /var/run/frr/bgpd.pid").strip()
        assert pid.isdigit(), pid
        argv = dut.run("cat /proc/" + pid + "/cmdline").split("\x00")
        assert ("-K" in argv) == request.param, argv
        with open(os.path.join(tgen.logdir, "dut-argv.json"), "w") as output:
            json.dump(argv, output)
        configure(
            dut,
            f"bgp graceful-restart select-defer-time {select_defer_time}\n"
            f"bgp graceful-restart restart-time {startup_time}",
        )
        if hold_direct_eor:
            configure(tgen.gears["r2"], "bgp graceful-restart disable-eor")
        for name in ("r2", "r3", "r4"):
            configure(tgen.gears[name], "no bgp shutdown")
        # Administrative re-enable uses the configured restart-time even on
        # a baseline without the independent constructor/startup-timer fix.
        time.sleep(2)
        log = daemon_log(tgen)
        enabled = time.monotonic()
        configure(tgen.gears["r1"], "no bgp shutdown")
        yield tgen, request.param, enabled, log
    finally:
        # Let an outstanding deferral finish before daemon teardown, including
        # on negative controls, so its timer cannot obscure the assertion.
        if "log" in locals() and TIER2_START in log():
            deadline = time.monotonic() + select_defer_time + 5
            while TIER2_END not in log() and TIER2_TIMEOUT not in log():
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.2)
        tgen.stop_topology()


def test_tier2_ends_on_last_multihop_eor(routers, select_defer_time):
    tgen, _, enabled, log = routers
    cycle_enabled = expect_tier2(tgen, log, enabled)
    release_eor(tgen, "r3")
    assert_pending(tgen, log, 2)
    released = time.monotonic()
    release_eor(tgen, "r4")
    expect_complete(tgen, log)
    assert time.monotonic() - released < 15
    assert time.monotonic() - cycle_enabled < select_defer_time - 10
    assert TIER2_TIMEOUT not in log()
    for name in MULTIHOP:
        expect(
            lambda name=name: " 0% packet loss"
            in tgen.gears["r1"].run(
                "ping -c 2 -W 1 -I 1.1.1.1 " + PREFIXES[name].split("/")[0]
            ),
            True,
            count=15,
            wait=1,
        )
    check_withdrawal(tgen)


@pytest.mark.parametrize("select_defer_time", [25])
def test_missing_multihop_eor_uses_timeout(routers, select_defer_time):
    tgen, _, enabled, log = routers
    cycle_enabled = expect_tier2(tgen, log, enabled)
    release_eor(tgen, "r3")
    assert_pending(tgen, log, 2)
    withheld_opens = neighbor(tgen.gears["r1"], "4.4.4.4")["messageStats"]["opensRecv"]
    expect(lambda: TIER2_TIMEOUT in log(), True, count=150, wait=0.2)
    elapsed = time.monotonic() - cycle_enabled
    assert elapsed >= select_defer_time - 2, elapsed
    assert TIER2_END not in log()
    withheld = neighbor(tgen.gears["r1"], "4.4.4.4")
    assert withheld["bgpState"] == "Established", withheld
    assert withheld["messageStats"]["opensRecv"] == withheld_opens, withheld
    assert not eor_received(tgen.gears["r1"], "4.4.4.4")
    for name in MULTIHOP:
        expect_route(tgen.gears["r1"], PREFIXES[name], selected=True)
        expect_kernel(tgen.gears["r1"], PREFIXES[name], present=True)


@pytest.mark.parametrize("routers", [False], indirect=True, ids=["without-k"])
@pytest.mark.parametrize("startup_time", [20])
def test_multihop_eor_after_startup_window(routers, startup_time):
    tgen, _, enabled, log = routers
    cycle_enabled = expect_tier2(tgen, log, enabled)
    expect(
        lambda: "Startup timer expired" in log(),
        True,
        count=(startup_time + 5) * 5,
        wait=0.2,
    )
    assert time.monotonic() - enabled >= startup_time - 1
    assert_pending(tgen, log, 1)
    release_eor(tgen, "r3")
    assert_pending(tgen, log, 1)
    release_eor(tgen, "r4")
    expect_complete(tgen, log)
    assert time.monotonic() - cycle_enabled < 50
    assert TIER2_TIMEOUT not in log()


@pytest.mark.parametrize("routers", [False], indirect=True, ids=["without-k"])
@pytest.mark.parametrize("hold_direct_eor", [True])
def test_direct_eor_precedes_tier2(routers, hold_direct_eor):
    tgen, _, _, log = routers
    expect_peers(tgen)
    receiver = tgen.gears["r1"]
    assert not eor_received(receiver, "10.0.12.2")
    introduce_routes(tgen)
    for name in MULTIHOP:
        expect_route(receiver, PREFIXES[name], selected=False)
    release_eor(tgen, "r3")
    assert_pending(tgen, log, 2)
    assert TIER2_START not in log()
    release_eor(tgen, "r2")
    expect(lambda: TIER2_START in log(), True)
    assert not eor_received(receiver, "4.4.4.4")
    # Tier 1 may select routes already received from a multihop peer.
    # Tier 2 and GR completion must still wait for the remaining EOR.
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        assert TIER2_END not in log()
        assert TIER2_TIMEOUT not in log()
        time.sleep(0.2)
    release_eor(tgen, "r4")
    expect_complete(tgen, log)
    assert TIER2_TIMEOUT not in log()


def build_topo(tgen):
    for name in ("r1", "r2", "r3", "r4"):
        tgen.add_router(name)
    for index, name in enumerate(("r1", "r3", "r4"), start=1):
        switch = tgen.add_switch("s" + str(index))
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears[name])


def configure(router, commands):
    router.vtysh_cmd(
        f"configure terminal\nrouter bgp {65000 + int(router.name[1:])}\n{commands}\n"
    )


def neighbor(router, address):
    return json.loads(router.vtysh_cmd(f"show bgp neighbors {address} json")).get(
        address, {}
    )


def eor_received(router, address):
    return (
        neighbor(router, address)
        .get("gracefulRestartInfo", {})
        .get("endOfRibRecv", {})
        .get("ipv4Unicast", False)
    )


def expect(func, value, count=75, wait=0.2):
    success, result = topotest.run_and_expect(func, value, count=count, wait=wait)
    assert success, str(result)


def daemon_log(tgen):
    path = os.path.join(tgen.logdir, "r1", "bgpd.log")
    start = os.path.getsize(path)

    def read():
        with open(path, encoding="utf-8", errors="replace") as source:
            source.seek(start)
            return source.read()

    return read


def expect_peers(tgen):
    for address in ("10.0.12.2", "3.3.3.3", "4.4.4.4"):

        def check(address=address):
            output = neighbor(tgen.gears["r1"], address)
            return topotest.json_cmp(
                output,
                {
                    "bgpState": "Established",
                    "neighborCapabilities": {
                        "gracefulRestart": "advertisedAndReceived"
                    },
                    "gracefulRestartInfo": {"rBit": False},
                },
            )

        expect(check, None)
        output = neighbor(tgen.gears["r1"], address)
        assert "ipv4Unicast" in output.get("addressFamilyInfo", {}), output


def expect_tier2(tgen, log, enabled):
    step("Receive the direct EOR, then wait with two established multihop EORs missing")
    expect(lambda: TIER2_START in log(), True)
    expect_peers(tgen)
    expect(lambda: TIER2_START in log(), True)
    assert eor_received(tgen.gears["r1"], "10.0.12.2")
    assert log().index("rcvd End-of-RIB for IPv4 Unicast from 10.0.12.2") < log().index(
        TIER2_START
    )
    # Inject only after tier 1: routes already received before the direct
    # EOR may legitimately be selected during the first tier.
    introduce_routes(tgen)
    for name, address in MULTIHOP.items():
        assert not eor_received(tgen.gears["r1"], address)
        expect_route(tgen.gears["r1"], PREFIXES[name], selected=False)
        expect_kernel(tgen.gears["r1"], address + "/32", present=True)
    assert TIER2_END not in log()
    assert TIER2_TIMEOUT not in log()
    snapshot = {
        address: neighbor(tgen.gears["r1"], address)
        for address in ("10.0.12.2", "3.3.3.3", "4.4.4.4")
    }
    with open(os.path.join(tgen.logdir, "pending-peers.json"), "w") as output:
        json.dump(snapshot, output, indent=2)
    # Re-enable precedes tier-2 start: this is a conservative timing bound,
    # not an inferred timestamp of the timer's internal origin.
    return enabled


def introduce_routes(tgen):
    for name, prefix in PREFIXES.items():
        configure(tgen.gears[name], "address-family ipv4 unicast\nnetwork " + prefix)


def release_eor(tgen, name):
    router = tgen.gears[name]
    receiver = tgen.gears["r1"]
    address = "10.0.12.2" if name == "r2" else MULTIHOP[name]
    remote = "10.0.12.1" if name == "r2" else "1.1.1.1"
    previous = neighbor(receiver, address)["messageStats"]["opensRecv"]
    configure(router, "no bgp graceful-restart disable-eor")
    router.vtysh_cmd(f"clear bgp {remote} soft out")
    expect(lambda: eor_received(receiver, address), True)
    assert neighbor(receiver, address)["messageStats"]["opensRecv"] == previous


def expect_route(router, prefix, selected):
    def check():
        paths = json.loads(
            router.vtysh_cmd(f"show bgp ipv4 unicast {prefix} json")
        ).get("paths", [])
        if not paths:
            return "No received path for " + prefix
        expected_peer = next(
            MULTIHOP[name] for name in MULTIHOP if PREFIXES[name] == prefix
        )
        if len(paths) != 1 or paths[0].get("peer", {}).get("peerId") != expected_peer:
            return paths
        if not any(
            hop.get("ip") == expected_peer for hop in paths[0].get("nexthops", [])
        ):
            return paths
        if not any(path.get("valid") for path in paths):
            return "No valid path for " + prefix
        best = any(
            path.get("valid") and path.get("bestpath", {}).get("overall")
            for path in paths
        )
        return None if bool(best) == selected else paths

    expect(check, None)


def expect_kernel(router, prefix, present):
    expect(
        lambda: bool(json.loads(router.run("ip -j route show exact " + prefix))),
        present,
    )


def assert_pending(tgen, log, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        assert TIER2_END not in log()
        assert TIER2_TIMEOUT not in log()
        for name in MULTIHOP:
            paths = json.loads(
                tgen.gears["r1"].vtysh_cmd(
                    "show bgp ipv4 unicast " + PREFIXES[name] + " json"
                )
            ).get("paths", [])
            assert paths and any(path.get("valid") for path in paths), paths
            assert not any(
                path.get("bestpath", {}).get("overall") for path in paths
            ), paths
        time.sleep(0.2)


def expect_complete(tgen, log):
    try:
        for name in MULTIHOP:
            expect_route(tgen.gears["r1"], PREFIXES[name], selected=True)
            expect_kernel(tgen.gears["r1"], PREFIXES[name], present=True)
        expect(lambda: TIER2_END in log(), True)
    except AssertionError:
        receiver = tgen.gears["r1"]
        snapshot = {"log": log(), "peers": {}, "routes": {}, "kernel": {}}
        for name, address in MULTIHOP.items():
            prefix = PREFIXES[name]
            snapshot["peers"][address] = neighbor(receiver, address)
            snapshot["routes"][prefix] = json.loads(
                receiver.vtysh_cmd("show bgp ipv4 unicast " + prefix + " json")
            )
            snapshot["kernel"][prefix] = json.loads(
                receiver.run("ip -j route show exact " + prefix)
            )
        with open(os.path.join(tgen.logdir, "completion-failure.json"), "w") as output:
            json.dump(snapshot, output, indent=2)
        raise


def check_withdrawal(tgen):
    step("A real withdrawal removes only its own selected and installed route")
    configure(
        tgen.gears["r3"], "address-family ipv4 unicast\nno network " + PREFIXES["r3"]
    )
    receiver = tgen.gears["r1"]

    def absent():
        return not json.loads(
            receiver.vtysh_cmd("show bgp ipv4 unicast " + PREFIXES["r3"] + " json")
        ).get("paths")

    expect(absent, True)
    expect_kernel(receiver, PREFIXES["r3"], present=False)
    expect_route(receiver, PREFIXES["r4"], selected=True)
    expect_kernel(receiver, PREFIXES["r4"], present=True)
