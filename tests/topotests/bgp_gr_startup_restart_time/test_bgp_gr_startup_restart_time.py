#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Johan Linder

"""Observe the configured startup Restart State window in received BGP OPENs."""

import json
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest  # noqa: E402
from lib.topogen import Topogen  # noqa: E402
from lib.common_config import step  # noqa: E402

pytestmark = [pytest.mark.bgpd]
PEER = "192.0.2.1"
RESTART_TIME = 10


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in ("r1", "r2"):
        switch.add_link(tgen.add_router(name))


@pytest.fixture
def restart_time():
    return RESTART_TIME


@pytest.fixture(params=["global", "instance"])
def routers(request, restart_time):
    """Each case gets a fresh instance and an independent startup window."""
    tgen = Topogen(build_topo, request.node.name)
    tgen.start_topology()
    try:
        for index, router in enumerate(tgen.routers().values(), start=1):
            config = ""
            if index == 1 and request.param == "global":
                config += f"bgp graceful-restart restart-time {restart_time}\n"
            config += (
                f"interface r{index}-eth0\n"
                f" ip address 192.0.2.{index}/24\n"
                "exit\n"
                f"router bgp {65000 + index}\n"
                " no bgp ebgp-requires-policy\n"
                " bgp graceful-restart\n"
            )
            if index == 1 and request.param == "instance":
                config += f" bgp graceful-restart restart-time {restart_time}\n"
            peer = "192.0.2.2" if index == 1 else PEER
            config += (
                f" neighbor {peer} remote-as external\n"
                f" neighbor {peer} timers 1 3\n"
                f" neighbor {peer} timers connect 1\n"
            )
            path = os.path.join(tgen.logdir, f"r{index}.conf")
            with open(path, "w", encoding="ascii") as output:
                output.write(config)
            router.load_frr_config(path)
        before = time.monotonic()
        tgen.start_router()
        after = time.monotonic()
        if tgen.routers_have_failure():
            pytest.skip(tgen.errors)
        yield tgen, request.param, before, after
    finally:
        tgen.stop_topology()


def neighbor(receiver):
    return json.loads(receiver.vtysh_cmd(f"show bgp neighbors {PEER} json")).get(
        PEER, {}
    )


def expect_open(receiver, rbit, restart_time, previous_opens=0):
    def check():
        output = neighbor(receiver)
        expected = {
            "bgpState": "Established",
            "gracefulRestartInfo": {
                "rBit": rbit,
                "timers": {"receivedRestartTimer": restart_time},
            },
        }
        result = topotest.json_cmp(output, expected)
        if result is not None:
            return result
        if output["messageStats"]["opensRecv"] <= previous_opens:
            return f"No new OPEN received: {output['messageStats']}"
        return None

    _, result = topotest.run_and_expect(check, None, count=75, wait=0.2)
    assert result is None, (
        f"r2 expected a new OPEN with R-bit={rbit}, restart-time={restart_time}: "
        f"{result}"
    )


def reconnect(receiver, rbit, restart_time):
    opens = neighbor(receiver)["messageStats"]["opensRecv"]
    receiver.vtysh_cmd("clear bgp *")
    expect_open(receiver, rbit, restart_time, opens)


def configure_restart(dut, scope, value):
    command = (
        "no bgp graceful-restart restart-time"
        if value is None
        else f"bgp graceful-restart restart-time {value}"
    )
    context = "router bgp 65001\n" if scope == "instance" else ""
    dut.vtysh_cmd(f"configure terminal\n{context}{command}")


def shutdown(dut, receiver):
    dut.vtysh_cmd("configure terminal\nrouter bgp 65001\nbgp shutdown")

    def check():
        if neighbor(receiver).get("bgpState") != "Established":
            return None
        return "r2 still sees the old session Established"

    _, result = topotest.run_and_expect(check, None, count=75, wait=0.2)
    assert result is None, result


def wait_until(deadline):
    time.sleep(max(0, deadline - time.monotonic()))


def test_configured_startup_window(routers):
    tgen, _, before, after = routers
    receiver = tgen.gears["r2"]
    step("The first received OPEN carries Restart State and the configured time")
    expect_open(receiver, True, RESTART_TIME)

    step("A new OPEN after the configured window no longer carries Restart State")
    wait_until(after + RESTART_TIME + 2)
    reconnect(receiver, False, RESTART_TIME)
    assert time.monotonic() < before + 120, "Default window already elapsed"


def test_restart_time_changes_and_administrative_reenable(routers):
    tgen, scope, _, after = routers
    dut, receiver = tgen.gears["r1"], tgen.gears["r2"]
    expect_open(receiver, True, RESTART_TIME)

    step("The no form restores the default and extends the active window")
    configure_restart(dut, scope, None)
    wait_until(after + RESTART_TIME + 2)
    reconnect(receiver, True, 120)

    step("Shortening below elapsed time ends the window immediately")
    configure_restart(dut, scope, 5)
    reconnect(receiver, False, 5)

    step("Changes after expiry do not create another Restart State window")
    configure_restart(dut, scope, 20)
    reconnect(receiver, False, 20)
    configure_restart(dut, scope, None)
    reconnect(receiver, False, 120)

    step("Administrative re-enable starts a new configured window")
    configure_restart(dut, scope, 30)
    shutdown(dut, receiver)
    opens = neighbor(receiver)["messageStats"]["opensRecv"]
    before_enable = time.monotonic()
    dut.vtysh_cmd("configure terminal\nrouter bgp 65001\nno bgp shutdown")
    after_enable = time.monotonic()
    expect_open(receiver, True, 30, opens)

    step("Runtime shortening and lengthening retain the original time origin")
    wait_until(after_enable + 6)
    configure_restart(dut, scope, 12)
    configure_restart(dut, scope, 22)
    reconnect(receiver, True, 22)
    wait_until(after_enable + 24)
    reconnect(receiver, False, 22)
    assert (
        time.monotonic() < before_enable + 28
    ), "Observation too late to distinguish an anchored from a sliding window"

    step("A zero restart-time ends a new window and the no form cannot reopen it")
    shutdown(dut, receiver)
    dut.vtysh_cmd("configure terminal\nrouter bgp 65001\nno bgp shutdown")
    configure_restart(dut, scope, 0)
    reconnect(receiver, False, 0)
    configure_restart(dut, scope, None)
    reconnect(receiver, False, 120)


@pytest.mark.parametrize("restart_time", [0])
def test_zero_startup_window(routers, restart_time):
    tgen, scope, _, _ = routers
    dut, receiver = tgen.gears["r1"], tgen.gears["r2"]
    expect_open(receiver, False, restart_time)
    configure_restart(dut, scope, None)
    reconnect(receiver, False, 120)


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
