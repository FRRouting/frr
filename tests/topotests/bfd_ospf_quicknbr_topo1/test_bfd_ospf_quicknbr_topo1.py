#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Exercise OSPF quick-neighbor behavior with BFD.

This test validates two key properties:
- With `ip ospf bfd quick`, the BFD session remains present even when the
  neighbor is down, so that BFD can detect it again quickly.
- If quick mode is disabled while the neighbor is down, any orphan/down BFD
  sessions kept alive by quick mode are pruned.

This test traffic-blackholes the L2 switch with ``tc netem`` (kernel ``sch_netem``).
``setup_module`` attempts to ``modprobe sch_netem``; if the qdisc still isn't
available (e.g. a kernel image without the module), the whole module is skipped.
"""

import json
import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bfdd, pytest.mark.ospfd]

SWITCH_NAME = "s1"

LONG_HELLO = 60
LONG_DEAD = 180


def tc_netem_supported(sw_gear):
    """
    Ensure `sch_netem` is available, loading the module if necessary.

    Kernel modules are global, so loading it from the switch namespace makes it
    available to all the topology namespaces. If it is already loaded (or built
    in) the modprobe is a no-op.
    """
    sw_net = sw_gear.net
    check_cmd = "lsmod 2>/dev/null | grep -q sch_netem"

    status, out, err = sw_net.cmd_status(check_cmd, warn=False)
    if status == 0:
        return True

    # Not loaded yet; try to load it. modprobe is idempotent and succeeds if the
    # module is already present, so we don't need to special-case that here.
    sw_net.cmd_status("modprobe sch_netem", warn=False)

    status, out, err = sw_net.cmd_status(check_cmd, warn=False)
    return status == 0


def set_switch_blackhole(enable):
    """
    Enable/disable traffic blackholing on the middle switch without bringing
    router links down. This avoids link-up/down events and simulates a silent
    L2 forwarding failure (no traffic passes). Requires tc qdisc ``netem``;
    callers run only after ``setup_module`` has called ``tc_netem_supported``.
    """
    tgen = get_topogen()
    sw = tgen.gears[SWITCH_NAME]
    sw_net = sw.net
    switch_ports = sorted(sw.links.keys())

    if enable:
        for ifname in switch_ports:
            sw.cmd_raises("tc qdisc replace dev {} root netem loss 100%".format(ifname))
    else:
        for ifname in switch_ports:
            sw.cmd_raises("tc qdisc del dev {} root".format(ifname))


def get_bfd_peers(router):
    out = router.vtysh_cmd("show bfd peers json", isjson=False)
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON from 'show bfd peers json':\n%s", out)
        raise


def summarize_bfd_peer_status_by_interface(peers, ifname):
    """
    Return (present, all_statuses) for a given interface name.
    Multiple entries may exist depending on address-family/etc.
    """
    statuses = [p.get("status") for p in peers if p.get("interface") == ifname]
    return (len(statuses) > 0, statuses)


def assert_bfd_interface_session_state(
    rname, ifname, want_present, want_status=None, count=30, wait=1
):
    tgen = get_topogen()
    router = tgen.gears[rname]

    def check():
        peers = get_bfd_peers(router)
        present, statuses = summarize_bfd_peer_status_by_interface(peers, ifname)
        if present != want_present:
            return {"present": present, "statuses": statuses, "peers": peers}
        if want_present and want_status is not None and want_status not in statuses:
            return {"present": present, "statuses": statuses, "peers": peers}
        return None

    test_func = partial(check)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert diff is None, f"{rname}: BFD peers on {ifname} did not reach expected state"


def assert_ospf_neighbor_full(rname, neighbor_rid, count=40, wait=1):
    tgen = get_topogen()
    router = tgen.gears[rname]

    def check():
        output = router.vtysh_cmd("show ip ospf neighbor json", isjson=True)
        neighbors = output.get("neighbors", {})
        nbr_list = neighbors.get(neighbor_rid)
        if not nbr_list:
            return {"missing": neighbor_rid, "neighbors": neighbors}

        # The JSON schema varies a bit across versions/tests; accept either.
        nbr = nbr_list[0] if isinstance(nbr_list, list) and nbr_list else {}
        if nbr.get("converged") == "Full":
            return None

        nbr_state = nbr.get("nbrState", "")
        if isinstance(nbr_state, str) and nbr_state.split("/")[0] == "Full":
            return None

        return {"routerId": neighbor_rid, "nbr": nbr}

    test_func = partial(check)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert diff is None, f"{rname}: OSPF neighbor {neighbor_rid} did not reach Full"


def assert_ospf_neighbor_below_twoway(rname, neighbor_rid, count=90, wait=1):
    """
    Wait until the neighbor is either absent or below TwoWay.
    This aligns with non-quick behavior which only keeps BFD sessions for
    neighbors that are TwoWay+.
    """
    tgen = get_topogen()
    router = tgen.gears[rname]

    def check():
        output = router.vtysh_cmd("show ip ospf neighbor json", isjson=True)
        neighbors = output.get("neighbors", {})
        nbr_list = neighbors.get(neighbor_rid)
        if not nbr_list:
            return None

        nbr = nbr_list[0] if isinstance(nbr_list, list) and nbr_list else {}
        # Prefer nbrState when available (e.g. "Full/DR", "2-Way/DROther", "Down", etc.)
        nbr_state = nbr.get("nbrState", "")
        if isinstance(nbr_state, str) and nbr_state:
            base = nbr_state.split("/")[0]
            if base not in ("Full", "2-Way"):
                return None
            return {"routerId": neighbor_rid, "nbrState": nbr_state, "nbr": nbr}

        # Fallback: if only "converged" exists, treat non-Full as "below TwoWay enough" for this wait.
        if nbr.get("converged") != "Full":
            return None

        return {"routerId": neighbor_rid, "nbr": nbr}

    test_func = partial(check)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert (
        diff is None
    ), f"{rname}: OSPF neighbor {neighbor_rid} did not drop below TwoWay"


def set_ospf_bfd_quick_mode(rname, ifname, enable):
    tgen = get_topogen()
    router = tgen.gears[rname]
    if enable:
        cmd = f"configure terminal\ninterface {ifname}\nip ospf bfd quick\nend\n"
    else:
        # Keep BFD enabled, but disable quick mode.
        cmd = f"configure terminal\ninterface {ifname}\nip ospf bfd\nend\n"
    router.vtysh_cmd(cmd, isjson=False)


def assert_ospf_bfd_quick_config(rname, ifname, enabled, count=20, wait=1):
    tgen = get_topogen()
    router = tgen.gears[rname]

    def check():
        out = router.vtysh_cmd("show running-config", isjson=False)
        # Extract the interface stanza in a simple, robust way.
        # This avoids relying on 'show running-config interface ...' which isn't always available.
        stanza = ""
        marker = f"interface {ifname}\n"
        idx = out.find(marker)
        if idx >= 0:
            rest = out[idx:]
            # Stanza ends at next 'interface ' line or end of config.
            next_idx = rest.find("\ninterface ", 1)
            stanza = rest if next_idx < 0 else rest[: next_idx + 1]

        has_quick = "ip ospf bfd quick" in stanza
        has_bfd = "ip ospf bfd" in stanza
        if enabled:
            if has_quick:
                return None
            return {
                "want": "quick",
                "has_quick": has_quick,
                "has_bfd": has_bfd,
                "stanza": stanza,
            }
        # disabled: accept "ip ospf bfd" without "quick"
        if has_bfd and not has_quick:
            return None
        return {
            "want": "non-quick",
            "has_quick": has_quick,
            "has_bfd": has_bfd,
            "stanza": stanza,
        }

    test_func = partial(check)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert (
        diff is None
    ), f"{rname}: interface {ifname} did not reach expected quick config state"


def set_ospf_timers(rname, ifname, hello, dead):
    tgen = get_topogen()
    router = tgen.gears[rname]
    cmd = (
        "configure terminal\n"
        f"interface {ifname}\n"
        f"ip ospf hello-interval {hello}\n"
        f"ip ospf dead-interval {dead}\n"
        "end\n"
    )
    router.vtysh_cmd(cmd, isjson=False)


def assert_ospf_timers_config(rname, ifname, hello, dead, count=20, wait=1):
    tgen = get_topogen()
    router = tgen.gears[rname]

    def check():
        out = router.vtysh_cmd("show running-config", isjson=False)
        marker = f"interface {ifname}\n"
        idx = out.find(marker)
        if idx < 0:
            return {"missing": ifname}
        rest = out[idx:]
        next_idx = rest.find("\ninterface ", 1)
        stanza = rest if next_idx < 0 else rest[: next_idx + 1]

        want_hello = f"ip ospf hello-interval {hello}" in stanza
        want_dead = f"ip ospf dead-interval {dead}" in stanza
        if want_hello and want_dead:
            return None
        return {"stanza": stanza, "want_hello": want_hello, "want_dead": want_dead}

    test_func = partial(check)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assert (
        diff is None
    ), f"{rname}: interface {ifname} did not reach expected OSPF timer config"


def setup_module(mod):
    topodef = {"s1": ("rt1:eth-rt2", "rt2:eth-rt1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    if not tc_netem_supported(tgen.gears[SWITCH_NAME]):
        pytest.skip(
            "tc qdisc netem (Linux sch_netem) is required for this topotest; "
            "load the module / use a fuller kernel image"
        )

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_quicknbr_bfd_session_established_on_startup():
    """
    Step 1: Verify OSPF adjacency and BFD session are established.

    This is the baseline expectation: quick-neighbor mode must not prevent
    normal OSPF+BFD bringup.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Startup uses short hello/dead timers for fast convergence.
    assert_ospf_neighbor_full("rt1", "2.2.2.2", count=60, wait=1)
    assert_ospf_neighbor_full("rt2", "1.1.1.1", count=60, wait=1)

    assert_bfd_interface_session_state(
        "rt1", "eth-rt2", want_present=True, want_status="up"
    )
    assert_bfd_interface_session_state(
        "rt2", "eth-rt1", want_present=True, want_status="up"
    )

    # Switch to long hello/dead timers before exercising quick-neighbor behavior.
    set_ospf_timers("rt1", "eth-rt2", LONG_HELLO, LONG_DEAD)
    set_ospf_timers("rt2", "eth-rt1", LONG_HELLO, LONG_DEAD)

    assert_ospf_timers_config("rt1", "eth-rt2", LONG_HELLO, LONG_DEAD)
    assert_ospf_timers_config("rt2", "eth-rt1", LONG_HELLO, LONG_DEAD)


def test_quicknbr_bfd_session_stays_active_when_neighbor_goes_away():
    """
    Step 2: Bring the peer link down (rt2 side) and confirm rt1 keeps the BFD
    session present (now down) due to quick mode.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Blackhole traffic on the middle switch. Interfaces remain up, but traffic stops.
    set_switch_blackhole(True)
    topotest.sleep(4, "Wait for BFD down notification (traffic blackholed)")

    # With quick enabled on rt1, the BFD peer should still be present and down on rt1.
    assert_bfd_interface_session_state(
        "rt1", "eth-rt2", want_present=True, want_status="down"
    )

    # Ensure OSPF has reacted (neighbor below TwoWay) before toggling quick off.
    assert_ospf_neighbor_below_twoway("rt1", "2.2.2.2")


def test_quicknbr_comes_back_while_bfd_session_still_present():
    """
    Step 3: Restore the link while quick mode is still enabled and the BFD
    session is still present. This validates the "down/up" cycle without
    pruning in between.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Restore traffic. With long OSPF hello, recovery should still happen promptly via BFD+quick.
    set_switch_blackhole(False)

    # First ensure BFD comes back (this is what triggers the quick-neighbor add path).
    assert_bfd_interface_session_state(
        "rt1", "eth-rt2", want_present=True, want_status="up", count=30, wait=1
    )

    # Then ensure OSPF returns to Full. This window should still be far less than
    # the configured hello interval (60s), demonstrating we didn't just wait for a periodic hello.
    assert_ospf_neighbor_full("rt1", "2.2.2.2", count=40, wait=1)
    assert_ospf_neighbor_full("rt2", "1.1.1.1", count=40, wait=1)

    assert_bfd_interface_session_state(
        "rt1", "eth-rt2", want_present=True, want_status="up"
    )
    assert_bfd_interface_session_state(
        "rt2", "eth-rt1", want_present=True, want_status="up"
    )


def test_quicknbr_bfd_session_pruned_when_quick_disabled_while_down():
    """
    Step 4: Bring the peer link down again, then disable quick mode while
    down and confirm the orphan/down BFD session is pruned (removed) on rt1.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Blackhole traffic again.
    set_switch_blackhole(True)
    topotest.sleep(4, "Wait for BFD down notification (traffic blackholed)")

    # Confirm session is present and down before pruning.
    assert_bfd_interface_session_state(
        "rt1", "eth-rt2", want_present=True, want_status="down"
    )
    assert_ospf_neighbor_below_twoway("rt1", "2.2.2.2")

    # Disable quick mode while the neighbor is down, this should prune orphan sessions.
    set_ospf_bfd_quick_mode("rt1", "eth-rt2", enable=False)

    assert_ospf_bfd_quick_config("rt1", "eth-rt2", enabled=False)

    assert_bfd_interface_session_state(
        "rt1", "eth-rt2", want_present=False, count=60, wait=1
    )


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
