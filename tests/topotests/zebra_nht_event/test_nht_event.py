#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_nht_event.py: Verify DPLANE_OP_NHT_EVENT_UPDATE emission from zebra.

Coverage:
1. prev != 0, curr == 0 (nexthop became unreachable via BGP withdraw)
2. prev == 0, curr != 0 (nexthop came back up via BGP re-announce)
3. Idle sanity: no NHT event lines when nothing changes

"""

import os
import re
import sys
import time
import pytest

from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(CWD)

# Log line grammar produced by dplane_nht_event_update() in zebra_dplane.c.
NHT_LOG_RE = re.compile(
    r"NHT_EVENT_UPDATE: "
    r"rnh=(?P<rnh>\S+) "
    r"prev_prefix=(?P<prev_prefix>\S+) "
    r"prev_nhg=(?P<prev_nhg>\d+) "
    r"curr_prefix=(?P<curr_prefix>\S+) "
    r"curr_nhg=(?P<curr_nhg>\d+)"
)


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def _read_zebra_log(router):
    """Return the current contents of r1's zebra.log."""
    log_path = os.path.join(router.logdir, router.name, "zebra.log")
    try:
        with open(log_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _parse_nht_events(log_text):
    """Return list of dicts parsed from all NHT_EVENT_UPDATE log lines."""
    events = []
    for line in log_text.splitlines():
        m = NHT_LOG_RE.search(line)
        if not m:
            continue
        events.append(
            {
                "rnh": m.group("rnh"),
                "prev_prefix": m.group("prev_prefix"),
                "prev_nhg": int(m.group("prev_nhg")),
                "curr_prefix": m.group("curr_prefix"),
                "curr_nhg": int(m.group("curr_nhg")),
            }
        )
    return events


def _wait_for_new_event(router, baseline_count, timeout=15.0):
    """Poll r1's zebra.log until a new NHT event beyond baseline arrives."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        events = _parse_nht_events(_read_zebra_log(router))
        if len(events) > baseline_count:
            return events[-1]
        time.sleep(0.2)
    return None


def test_nht_event_prev_only():
    """Withdrawing the route for the nexthop should trigger an NHT event with curr_nhg=0."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Wait for BGP to converge on r1")
    time.sleep(5)

    baseline = len(_parse_nht_events(_read_zebra_log(r1)))

    step("Withdraw 192.168.100.0/24 on r2")
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        " address-family ipv4 unicast\n"
        "  no network 192.168.100.0/24\n"
        " exit-address-family\n"
        "end"
    )

    ev = _wait_for_new_event(r1, baseline, timeout=15.0)
    assert ev is not None, "expected NHT_EVENT_UPDATE log line after withdraw"
    assert ev["curr_nhg"] == 0, "curr_nhg should be 0 when nexthop unreachable, got {}".format(ev)


def test_nht_event_curr_only():
    """Re-announcing the route should trigger an NHT event with prev_nhg=0, curr_nhg!=0."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Ensure prefix is currently withdrawn -- force a clean state
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        " address-family ipv4 unicast\n"
        "  no network 192.168.100.0/24\n"
        " exit-address-family\n"
        "end"
    )
    time.sleep(2)

    baseline = len(_parse_nht_events(_read_zebra_log(r1)))

    step("Re-announce 192.168.100.0/24 on r2")
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        " address-family ipv4 unicast\n"
        "  network 192.168.100.0/24\n"
        " exit-address-family\n"
        "end"
    )

    ev = _wait_for_new_event(r1, baseline, timeout=15.0)
    assert ev is not None, "expected NHT_EVENT_UPDATE log line after re-announce"
    assert ev["prev_nhg"] == 0, "prev_nhg should be 0 when previously unreachable, got {}".format(ev)
    assert ev["curr_nhg"] != 0, "curr_nhg should be non-zero after re-announce, got {}".format(ev)


@pytest.mark.skip(
    reason="Requires 3-router topology to change resolution NHG (prev!=0, curr!=0); "
    "deferred to future phase."
)
def test_nht_event_prev_and_curr():
    """IGP reconvergence switches the NHG -> prev != 0, curr != 0."""
    pass


def test_no_nht_event_when_idle():
    """No new NHT event should occur while idle (sanity check)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    baseline = len(_parse_nht_events(_read_zebra_log(r1)))
    time.sleep(3)
    after = len(_parse_nht_events(_read_zebra_log(r1)))
    assert after == baseline, (
        "unexpected NHT events during idle period: baseline={}, after={}"
        .format(baseline, after)
    )


if __name__ == "__main__":
    args = ["-s", "-v"] + sys.argv[1:]
    sys.exit(pytest.main(args))
