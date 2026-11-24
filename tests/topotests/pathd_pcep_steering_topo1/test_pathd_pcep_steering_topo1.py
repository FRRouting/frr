#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pathd_pcep_steering_topo1.py
#

"""
test_pathd_pcep_steering_topo1.py:

Verify that pathd installs a per-destination steering route for a
PCE-initiated SR policy, withdraws it when the policy goes down, and
reinstalls it when the policy comes back up.

         +-------------+                       +-------------+
         |             |eth-rt2         eth-rt1|             |
         |     RT1     +-----------------------+     RT2     |
         | 192.0.2.1   |   203.0.113.0/24      | 192.0.2.2   |
         | 2001:db8::1 |  2001:db8:10:1::/64   | 2001:db8::2 |
         +-------------+                       +-------------+
                |
         mock PCE (127.0.0.1:4189, inside RT1's namespace)

RT1 is the SR-TE headend running pathd with the PCEP module.  A
scripted PCE (mock_pce.py) runs inside RT1's network namespace and
initiates two SR policies towards RT2's loopbacks, one per address
family, each with a single prefix-SID label (IPv4: 16020, IPv6:
16021).  Once IS-IS SR has installed the labels, the policies come up
and pathd is expected to install the steering routes:

    192.0.2.2/32     proto srte distance 10, resolving via SR-TE color
    2001:db8::2/128  proto srte distance 10, resolving via SR-TE color
"""

import os
import re
import sys
import json
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd, pytest.mark.pathd]

ENDPOINT = "192.0.2.2"
PREFIX = "192.0.2.2/32"
LABEL = 16020

ENDPOINT6 = "2001:db8::2"
PREFIX6 = "2001:db8::2/128"
LABEL6 = 16021

# Churn scale: policies created per address family beyond the two
# initial ones, colors well away from the initiated-policy default (1)
# and disjoint between the families.
CHURN_COUNT = 100
CHURN_COLOR_BASE = 1000
CHURN_COLOR_BASE6 = 2000
# Colors for the multipath cap and failed replace tests, clear of churn
CAP_COLOR_BASE = 5000
SIBLING_COLOR = 4000
# In the SRGB but no prefix-SID uses it, so a policy on it cannot resolve
UNUSED_LABEL = 16999


def build_topo(tgen):
    "Build function"

    for router in ["rt1", "rt2"]:
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-rt2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt1")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)

    # The test depends on IS-IS SR labels and MPLS steering routes.
    if not tgen.hasmpls:
        logger.info("MPLS is not available, skipping test")
        pytest.skip("MPLS is not available, skipping")

    tgen.start_topology()

    # pathd is not inferred from frr.conf (there are no candidate paths,
    # the policies are PCE-initiated) and needs the PCEP module, so it
    # is named explicitly on rt1.
    for rname, router in tgen.routers().items():
        if rname == "rt1":
            router.load_frr_config(extra_daemons=[("pathd", " -M pathd_pcep")])
        else:
            router.load_frr_config()

    tgen.start_router()

    # Start the scripted PCE inside rt1's network namespace.  pathd
    # retries the PCEP connection, so starting it after the routers
    # is fine.  The command file drives the churn tests: the PCE polls
    # it for 'add'/'remove' lines.
    start_pce()


def teardown_module():
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()


def print_pce_log():
    "Dump the mock PCE's session log to the test log for debugging"

    tgen = get_topogen()
    pce_log = os.path.join(tgen.logdir, "rt1", "mock_pce.log")
    try:
        with open(pce_log) as log:
            logger.info("mock PCE log:\n%s", log.read())
    except IOError:
        logger.info("mock PCE log %s not found", pce_log)


def check_label_installed():
    "Check that RT2's prefix-SID labels are in RT1's LFIB"

    tgen = get_topogen()
    output = json.loads(tgen.gears["rt1"].vtysh_cmd("show mpls table json"))
    for label in [LABEL, LABEL6]:
        if str(label) not in output:
            return "label {} not in LFIB".format(label)
    return None


def check_steering_route_af(present, prefix, show_cmd):
    "Check one address family's steering route on RT1"

    tgen = get_topogen()
    output = json.loads(
        tgen.gears["rt1"].vtysh_cmd("{} {} json".format(show_cmd, prefix))
    )
    routes = [
        route for route in output.get(prefix, []) if route.get("protocol") == "srte"
    ]

    if not present:
        if routes:
            return "steering route for {} still present".format(prefix)
        return None

    if not routes:
        return "no srte route for {}".format(prefix)

    route = routes[0]
    if route.get("distance") != 10:
        return "wrong distance for {}: {}".format(prefix, route.get("distance"))
    if not route.get("installed"):
        return "steering route for {} not installed".format(prefix)
    if not any(nh.get("active") for nh in route.get("nexthops", [])):
        return "no active nexthop for {}".format(prefix)

    return None


def check_steering_route(present):
    "Check the presence/absence of both steering routes on RT1"

    result = check_steering_route_af(present, PREFIX, "show ip route")
    if result is not None:
        return result

    return check_steering_route_af(present, PREFIX6, "show ipv6 route")


def test_isis_sr_convergence():
    "Wait for IS-IS SR to install RT2's prefix-SID label on RT1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for labels %u and %u in rt1's LFIB", LABEL, LABEL6)
    _, result = topotest.run_and_expect(check_label_installed, None, count=60, wait=1)
    assert result is None, "IS-IS SR did not install labels: {}".format(result)


def test_steering_route_installed():
    "PCE initiates the policy; pathd must install the steering route"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for the PCEP session, PCInitiate and steering route")
    check = lambda: check_steering_route(True)
    _, result = topotest.run_and_expect(check, None, count=120, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "steering route missing: {}".format(result)

    # Each route carries its policy's SR-TE color
    for v6 in (False, True):
        result = check_steering_colors([base_color(v6)], v6)
        assert result is None, result


def test_steering_route_withdrawn_on_policy_down():
    "Take the policy down; pathd must withdraw the steering route"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("shutting down rt2's eth-rt1")
    tgen.gears["rt2"].vtysh_cmd(
        """
        configure terminal
         interface eth-rt1
          shutdown
        """
    )

    check = lambda: check_steering_route(False)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "steering route not withdrawn: {}".format(result)


def test_steering_route_reinstalled_on_policy_up():
    "Bring the policy back up; pathd must reinstall the steering route"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("bringing rt2's eth-rt1 back up")
    tgen.gears["rt2"].vtysh_cmd(
        """
        configure terminal
         interface eth-rt1
          no shutdown
        """
    )

    check = lambda: check_steering_route(True)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "steering route not reinstalled: {}".format(result)


# Bumped on every PCE restart so each PCE instance polls a fresh
# command file instead of replaying the previous instance's history.
PCE_GEN = [0]


def pce_command_file():
    "The current PCE instance's command file"

    tgen = get_topogen()
    suffix = "" if PCE_GEN[0] == 0 else "_{}".format(PCE_GEN[0])
    return os.path.join(tgen.logdir, "rt1", "pce_commands" + suffix)


def start_pce():
    "Start the scripted PCE inside rt1's network namespace"

    tgen = get_topogen()
    pce_log = os.path.join(tgen.logdir, "rt1", "mock_pce.log")
    tgen.gears["rt1"].run(
        "nohup python3 {}/mock_pce.py "
        "--policy {},{},test-steer "
        "--policy {},{},test-steer-v6 "
        "--pcc-address 192.0.2.1 --pcc-address6 2001:db8::1 "
        "--command-file {} "
        "--log {} > /dev/null 2>&1 &".format(
            CWD, ENDPOINT, LABEL, ENDPOINT6, LABEL6, pce_command_file(), pce_log
        )
    )


def kill_pce():
    "Kill the scripted PCE"

    tgen = get_topogen()
    tgen.gears["rt1"].run("pkill -f mock_pce.py; true")


def pce_command(line):
    "Append one command line for the mock PCE to act on"

    with open(pce_command_file(), "a") as cmds:
        cmds.write(line + "\n")


def churn_name(i, v6=False):
    return "churn6-{}".format(i) if v6 else "churn-{}".format(i)


def churn_add(i, v6=False):
    "Ask the PCE to initiate one churn policy for the family's endpoint"

    endpoint = ENDPOINT6 if v6 else ENDPOINT
    label = LABEL6 if v6 else LABEL
    color = (CHURN_COLOR_BASE6 if v6 else CHURN_COLOR_BASE) + i
    pce_command("add {},{},{},{}".format(endpoint, label, churn_name(i, v6), color))


def _diag_section(title, lines, empty="(no output)"):
    """One labelled block for failure_diagnostics(): a title line followed
    by its output indented four spaces, so the sections stay visually
    distinct in the CI console."""

    body = "\n".join("    " + line for line in lines) if lines else "    " + empty
    return "{}\n{}".format(title, body)


def failure_diagnostics():
    """A readable dump of the head-end's PCEP and policy state plus the
    mock PCE log, appended to the assertion message so that a CI failure
    explains itself without needing the archived logs."""

    tgen = get_topogen()
    rt1 = tgen.gears["rt1"]

    sections = [
        _diag_section("routers", [tgen.routers_have_failure() or "all running"])
    ]

    for cmd in [
        "show sr-te pcep session",
        "show sr-te policy",
        "show zebra client summary",
    ]:
        lines = rt1.vtysh_cmd(cmd).splitlines()
        if len(lines) > 30:
            lines = lines[:30] + ["... ({} more lines)".format(len(lines) - 30)]
        sections.append(_diag_section("vtysh -c '{}'".format(cmd), lines))

    sections.append(
        _diag_section(
            "mock PCE log (last 40 lines)",
            mock_pce_log_text().splitlines()[-40:],
            empty="(empty)",
        )
    )

    rule = "=" * 64
    return "\n\n{0}\nDIAGNOSTICS\n{0}\n\n{1}\n{0}".format(rule, "\n\n".join(sections))


def check_policy_count(expected):
    "Check the number of Active SR-TE policies on RT1"

    tgen = get_topogen()
    active = tgen.gears["rt1"].vtysh_cmd("show sr-te policy").count("Active")
    if active != expected:
        return "expected {} Active policies, have {}".format(expected, active)
    return None


def policy_colors():
    "Each SR-TE policy on RT1 by name: (color, is Active)"

    output = get_topogen().gears["rt1"].vtysh_cmd("show sr-te policy")
    policies = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 5 and fields[4] in ("Active", "Inactive"):
            if fields[1].isdigit():
                policies[fields[2]] = (int(fields[1]), fields[4] == "Active")
    return policies


def base_color(v6=False):
    "The color of the family's initial policy"

    return policy_colors()["test-steer-v6" if v6 else "test-steer"][0]


def steering_colors(v6=False):
    """The SR-TE colors of RT1's steering route for the family (None if
    absent).  The route's nexthops are recursive (endpoint via endpoint,
    resolved through the policy); zebra's JSON flattens each recursive
    parent and its resolved nexthop into the same array, so read only
    the parents."""

    prefix = PREFIX6 if v6 else PREFIX
    show_cmd = "show ipv6 route" if v6 else "show ip route"
    tgen = get_topogen()
    output = json.loads(
        tgen.gears["rt1"].vtysh_cmd("{} {} json".format(show_cmd, prefix))
    )
    routes = [
        route for route in output.get(prefix, []) if route.get("protocol") == "srte"
    ]
    if not routes:
        return None
    nexthops = routes[0].get("nexthops", [])
    return sorted(nh.get("srteColor") for nh in nexthops if nh.get("recursive"))


def ecmp_max():
    "zebra's runtime multipath limit, which caps the route's nexthops"

    tgen = get_topogen()
    output = tgen.gears["rt1"].vtysh_cmd("show zebra")
    match = re.search(r"ECMP Maximum\s*\|?\s*(\d+)", output)
    assert match is not None, "cannot read ECMP Maximum from 'show zebra'"
    return int(match.group(1))


def check_steering_colors(colors, v6=False):
    "Check the family's steering route carries the lowest colors, up to the cap"

    prefix = PREFIX6 if v6 else PREFIX
    expected = sorted(colors)[: ecmp_max()]
    have = steering_colors(v6)
    if have != expected:
        return "expected colors {} on {}, have {}".format(
            short_colors(expected), prefix, short_colors(have)
        )
    return None


def short_colors(colors):
    "A short form of a color list for failure messages"

    if colors is None or len(colors) <= 6:
        return colors
    return "{} colors {}..{}".format(len(colors), colors[:3], colors[-3:])


def churn_colors(count, v6=False):
    "The colors of the family's initial policy and its first count churn ones"

    churn_base = CHURN_COLOR_BASE6 if v6 else CHURN_COLOR_BASE
    return [base_color(v6)] + [churn_base + i for i in range(count)]


def check_churn_colors_both(count):
    "Check both families' steering routes after count churn policies each"

    result = check_steering_colors(churn_colors(count, v6=False), v6=False)
    if result is not None:
        return result

    return check_steering_colors(churn_colors(count, v6=True), v6=True)


def test_policy_churn_scale():
    "Initiate CHURN_COUNT extra policies per family for the endpoints"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "initiating %u churn policies each for %s and %s",
        CHURN_COUNT,
        ENDPOINT,
        ENDPOINT6,
    )
    for i in range(CHURN_COUNT):
        churn_add(i, v6=False)
        churn_add(i, v6=True)

    # 2 initial policies + CHURN_COUNT churn ones per family
    check = lambda: check_policy_count(2 + 2 * CHURN_COUNT)
    _, result = topotest.run_and_expect(check, None, count=180, wait=1)
    if result is not None:
        print_pce_log()
        result += failure_diagnostics()
    assert result is None, "churn policies never came up: {}".format(result)

    # Each endpoint now has 1 + CHURN_COUNT policies; its steering route
    # aggregates one colored nexthop per policy, capped at the multipath
    # limit (colors beyond it are logged and unrepresented).
    check = lambda: check_churn_colors_both(CHURN_COUNT)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "steering route wrong after churn add: {}".format(result)


def test_policy_churn_remove_readd():
    "Remove a subset, re-add some of it, then remove all churn policies"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Remove the first 40 churn policies of each family.
    logger.info("removing 40 churn policies per family")
    for i in range(40):
        pce_command("remove {}".format(churn_name(i, v6=False)))
        pce_command("remove {}".format(churn_name(i, v6=True)))

    check = lambda: check_policy_count(2 + 2 * (CHURN_COUNT - 40))
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "churn remove failed: {}".format(result)

    # Re-add 20 of them per family (same names, same colors): pathd
    # hands back the PLSP-IDs it retained for these keys.
    logger.info("re-adding 20 churn policies per family")
    for i in range(20):
        churn_add(i, v6=False)
        churn_add(i, v6=True)

    check = lambda: check_policy_count(2 + 2 * (CHURN_COUNT - 40 + 20))
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "churn re-add failed: {}".format(result)

    # Remove every churn policy; only the two initial ones remain, and
    # both steering routes must collapse back to a single nexthop.
    logger.info("removing all churn policies")
    for v6 in (False, True):
        for i in range(20):
            pce_command("remove {}".format(churn_name(i, v6)))
        for i in range(40, CHURN_COUNT):
            pce_command("remove {}".format(churn_name(i, v6)))

    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=120, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "churn teardown failed: {}".format(result)

    check = lambda: check_churn_colors_both(0)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "steering route wrong after churn teardown: {}".format(
        result
    )


def pathd_log_text():
    "RT1's pathd log so far"

    tgen = get_topogen()
    with open(os.path.join(tgen.logdir, "rt1", "pathd.log")) as log:
        return log.read()


def test_steering_route_multipath_cap():
    "One policy more than the multipath limit: the highest color waits"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    cap = ecmp_max()
    names = ["cap-{}".format(i) for i in range(cap)]
    colors = [base_color()] + [CAP_COLOR_BASE + i for i in range(cap)]

    logger.info(
        "initiating %u policies for %s (multipath limit %u)", cap, ENDPOINT, cap
    )
    for i, name in enumerate(names):
        pce_command("add {},{},{},{}".format(ENDPOINT, LABEL, name, CAP_COLOR_BASE + i))

    check = lambda: check_policy_count(2 + cap)
    _, result = topotest.run_and_expect(check, None, count=300, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "cap policies never came up: {}".format(result)

    # The route carries the lowest cap colors; pathd logs the one left out
    check = lambda: check_steering_colors(colors)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "steering route wrong at the cap: {}".format(result)
    assert "not represented" in pathd_log_text(), "pathd did not log the cap"

    # An included color goes: the color left out takes its place
    logger.info("removing an included color")
    pce_command("remove {}".format(names[0]))
    colors.remove(CAP_COLOR_BASE)
    check = lambda: check_steering_colors(colors)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "left out color not promoted: {}".format(result)

    logger.info("removing the cap policies")
    for name in names[1:]:
        pce_command("remove {}".format(name))
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=300, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "cap teardown failed: {}".format(result)

    check = lambda: check_steering_colors([base_color()])
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "steering route wrong after cap teardown: {}".format(result)


def test_steering_route_failed_replace():
    "A policy zebra cannot replace leaves the route; its sibling color stays"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    base = base_color()
    logger.info("initiating a sibling policy for %s", ENDPOINT)
    pce_command("add {},{},sibling,{}".format(ENDPOINT, LABEL, SIBLING_COLOR))
    check = lambda: check_steering_colors([base, SIBLING_COLOR])
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "sibling not in the steering route: {}".format(result)

    # zebra cannot resolve the new first label, so it reports the policy
    # down while pathd has it GOING_UP
    logger.info("replacing test-steer with unresolvable label %u", UNUSED_LABEL)
    pce_command("update test-steer,{}".format(UNUSED_LABEL))

    def check_replace_failed():
        if policy_colors()["test-steer"][1]:
            return "test-steer still Active"
        return check_steering_colors([SIBLING_COLOR])

    _, result = topotest.run_and_expect(check_replace_failed, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "failed replace not withdrawn: {}".format(result)

    logger.info("replacing test-steer with label %u again", LABEL)
    pce_command("update test-steer,{}".format(LABEL))

    def check_replace_ok():
        if not policy_colors()["test-steer"][1]:
            return "test-steer not Active"
        return check_steering_colors([base, SIBLING_COLOR])

    _, result = topotest.run_and_expect(check_replace_ok, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "valid replace not reinstalled: {}".format(result)

    pce_command("remove sibling")
    check = lambda: check_steering_colors([base])
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "sibling not removed: {}".format(result)


def mock_pce_log_text():
    "The mock PCE's log so far (empty when not yet written)"

    tgen = get_topogen()
    try:
        with open(os.path.join(tgen.logdir, "rt1", "mock_pce.log")) as log:
            return log.read()
    except IOError:
        return ""


def count_pce_errors(error_type, error_value):
    "Number of PCErr messages of the given type/value the PCE received"

    return mock_pce_log_text().count(
        "RECV-ERROR type=%d value=%d" % (error_type, error_value)
    )


def get_plsp_id(name):
    "The last PLSP-ID the PCC reported for the named policy"

    matches = re.findall(
        r"MAPPED name=%s plsp-id=(\d+)" % re.escape(name), mock_pce_log_text()
    )
    if not matches:
        return None
    return int(matches[-1])


def configure_segment_list(name, no=False):
    "Configure (or unconfigure) an empty segment list on RT1"

    tgen = get_topogen()
    return tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          traffic-eng
           {}segment-list {}
        """.format(
            "no " if no else "", name
        )
    )


def test_duplicate_symbolic_name_rejected():
    "A PCInitiate reusing a live symbolic name must get PCErr 23/1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    errors_before = count_pce_errors(23, 1)

    # test-steer has been alive since setup; a different color makes
    # this a create of a NEW LSP with an in-use name, not a
    # re-initiate of the existing one.
    logger.info("initiating a duplicate of test-steer (different color)")
    pce_command("add {},{},test-steer,4242".format(ENDPOINT, LABEL))

    check = lambda: (
        None if count_pce_errors(23, 1) > errors_before else "no PCErr 23/1 yet"
    )
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "duplicate name was not rejected: {}".format(result)

    # Nothing new may have come up, and the session must still work.
    result = check_policy_count(2)
    assert result is None, result

    logger.info("verifying the session still accepts a unique name")
    pce_command("add {},{},post-dup-check,4243".format(ENDPOINT, LABEL))
    check = lambda: check_policy_count(3)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, "session unusable after rejection: {}".format(result)

    pce_command("remove post-dup-check")
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "cleanup remove failed: {}".format(result)


def test_cli_rejected_on_pcep_name():
    "Configuring a segment list named like a PCEP one must be refused"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # A segment list created by a PCInitiate is named "<name>-0": the
    # PCInitiate carries PLSP-ID 0, and the real PLSP-ID (assigned
    # when the PCC reports) only renames the list if a PCUpd arrives.
    # test-steer has never been updated, so its list is test-steer-0.
    name = "test-steer-0"

    logger.info("trying to configure segment list %s", name)
    output = configure_segment_list(name)
    assert "already exists" in output, "config of {} was not refused: {}".format(
        name, output
    )

    running = tgen.gears["rt1"].vtysh_cmd("show running-config")
    assert (
        "segment-list %s" % name not in running
    ), "refused segment list {} still appeared in the config".format(name)


def test_reserved_prefix_rejected():
    "Names starting with the reserved pcep-hash- prefix are refused"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = configure_segment_list("pcep-hash-cli")
    assert "reserved for PCEP" in output, "reserved name was configured: {}".format(
        output
    )

    errors_before = count_pce_errors(24, 1)
    pce_command("add {},{},pcep-hash-pce,4350".format(ENDPOINT, LABEL))
    check = lambda: (
        None if count_pce_errors(24, 1) > errors_before else "no PCErr 24/1 yet"
    )
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "reserved name was initiated: {}".format(result)
    result = check_policy_count(2)
    assert result is None, result


def test_pcep_rejected_on_cli_name():
    "A PCEP path whose segment list name is taken by config gets 24/1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # A PCInitiate-created segment list is named "<name>-0" (see the
    # previous test), so taking that name in the configuration first
    # makes the collision deterministic.
    name = "cli-clash-0"
    logger.info("configuring segment list %s to squat the name", name)
    output = configure_segment_list(name)
    assert (
        "already exists" not in output
    ), "config of {} was unexpectedly refused: {}".format(name, output)

    errors_before = count_pce_errors(24, 1)
    logger.info("initiating cli-clash against the squatted name")
    pce_command("add {},{},cli-clash,4300".format(ENDPOINT, LABEL))
    check = lambda: (
        None if count_pce_errors(24, 1) > errors_before else "no PCErr 24/1 yet"
    )
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "colliding path was not rejected: {}".format(result)
    result = check_policy_count(2)
    assert result is None, result

    # Free the name: the same add must now succeed, and a remove
    # returns the topology to its baseline.
    logger.info("releasing %s and re-initiating", name)
    configure_segment_list(name, no=True)
    pce_command("add {},{},cli-clash,4300".format(ENDPOINT, LABEL))
    check = lambda: check_policy_count(3)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "path did not recover after name was freed: {}".format(
        result
    )

    pce_command("remove cli-clash")
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "final cleanup failed: {}".format(result)


def test_long_symbolic_names():
    "Names up to the supported length work; longer ones get PCErr 24/1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # pathd's policy, candidate and segment list names are limited to 64
    # characters by its YANG model, and a PCEP path's segment list is
    # named "<name>-<plsp_id>" with a PLSP-ID of up to 7 digits, so 56 is
    # the longest symbolic name pathd accepts.  Both lengths below are
    # multiples of 4, so the SYMBOLIC-PATH-NAME TLV needs no padding.
    name_max = "L" * 56
    name_long = "L" * 60

    logger.info("initiating a policy with a %d-byte name", len(name_max))
    pce_command("add {},{},{},4501".format(ENDPOINT, LABEL, name_max))
    check = lambda: check_policy_count(3)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "longest supported name did not come up: {}".format(result)

    # A name over the YANG limit used to abort every northbound walk of
    # pathd's tree; the stored name must be readable back in full.
    output = tgen.gears["rt1"].vtysh_cmd(
        "show yang operational-data /frr-pathd:pathd with-config pathd"
    )
    assert name_max + "-0" in output, "pathd northbound data is not readable"

    errors_before = count_pce_errors(24, 1)
    logger.info("initiating a policy with a %d-byte name", len(name_long))
    pce_command("add {},{},{},4502".format(ENDPOINT, LABEL, name_long))
    check = lambda: (
        None if count_pce_errors(24, 1) > errors_before else "no PCErr 24/1 yet"
    )
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "over-long name was not rejected: {}".format(result)
    result = check_policy_count(3)
    assert result is None, result

    pce_command("remove {}".format(name_max))
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "long-name cleanup failed: {}".format(result)


def test_pcupd_rejected_in_report():
    "A refused PCUpd is reported in a PCRpt LSP-ERROR-CODE, not a PCErr"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    name = "upd-clash"
    pce_command("add {},{},{},4600".format(ENDPOINT, LABEL, name))
    check = lambda: None if get_plsp_id(name) else "no PLSP-ID for {} yet".format(name)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, result
    result = check_policy_count(3)
    assert result is None, result

    # The PCUpd renames "<name>-0" to "<name>-<plsp_id>": take that name first
    plsp_id = get_plsp_id(name)
    squat = "{}-{}".format(name, plsp_id)
    output = configure_segment_list(squat)
    assert "already exists" not in output, output

    errors_before = mock_pce_log_text().count("RECV-ERROR type=24")
    pce_command("update {},{}".format(name, LABEL))

    def check_report():
        sent = re.findall(
            r"UPDATE-SENT name=%s plsp-id=\d+ srp=(\d+)" % re.escape(name),
            mock_pce_log_text(),
        )
        if not sent:
            return "PCUpd not sent yet"
        expected = "REPORT plsp-id={} ".format(plsp_id)
        for line in mock_pce_log_text().splitlines():
            if expected in line and "srp={} lsp-error=4".format(sent[-1]) in line:
                return None
        return "no PCRpt with LSP-ERROR-CODE 4 for SRP {}".format(sent[-1])

    _, result = topotest.run_and_expect(check_report, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, result
    assert (
        mock_pce_log_text().count("RECV-ERROR type=24") == errors_before
    ), "a refused PCUpd must not be answered with PCErr type 24"
    result = check_policy_count(3)
    assert result is None, result

    configure_segment_list(squat, no=True)
    pce_command("remove {}".format(name))
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "cleanup remove failed: {}".format(result)


def test_pce_restart():
    "Kill and restart the PCE; policies must re-establish"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for round_num in range(2):
        logger.info("killing the PCE (round %d)", round_num)
        kill_pce()

        # Flap the link while the session is down: the policy status
        # reports this fires have no session to be sent on, which is
        # exactly the path that used to leak the formatted messages.
        tgen.gears["rt2"].vtysh_cmd(
            """
            configure terminal
             interface eth-rt1
              shutdown
            """
        )
        time.sleep(2)
        tgen.gears["rt2"].vtysh_cmd(
            """
            configure terminal
             interface eth-rt1
              no shutdown
            """
        )
        time.sleep(2)

        logger.info("restarting the PCE (round %d)", round_num)
        initiated = mock_pce_log_text().count("INITIATE-SENT")
        PCE_GEN[0] += 1
        start_pce()

        # The new instance only initiates its two base policies once
        # pathd has connected to it and completed state sync, so this
        # proves a fresh session rather than policies kept from the old.
        def check_new_session():
            sent = mock_pce_log_text().count("INITIATE-SENT") - initiated
            if sent < 2:
                return "new PCE sent {} of 2 base policies".format(sent)
            return None

        _, result = topotest.run_and_expect(check_new_session, None, count=120, wait=1)
        if result is not None:
            print_pce_log()
        assert result is None, "PCE session did not re-establish: {}".format(result)

        # Whether pathd kept or timed out the old policies, it must
        # converge back to exactly the two of them Active.
        check = lambda: check_policy_count(2)
        _, result = topotest.run_and_expect(check, None, count=90, wait=1)
        if result is not None:
            print_pce_log()
        assert result is None, "policies did not re-establish: {}".format(result)

    # The steering routes must have survived the whole exercise.
    check = lambda: check_steering_route(True)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "steering route missing after restarts: {}".format(result)


def restart_pce():
    "Start a new PCE instance and wait for it to initiate the base policies"

    initiated = mock_pce_log_text().count("INITIATE-SENT")
    PCE_GEN[0] += 1
    start_pce()

    def check_new_session():
        sent = mock_pce_log_text().count("INITIATE-SENT") - initiated
        return None if sent >= 2 else "new PCE sent {} of 2 base policies".format(sent)

    _, result = topotest.run_and_expect(check_new_session, None, count=120, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "PCE session did not re-establish: {}".format(result)


def sr_te_policies():
    return get_topogen().gears["rt1"].vtysh_cmd("show sr-te policy")


def test_orphans_removed_at_timeout():
    "PCE-initiated paths are removed at the session timeout, freeing names"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pce_command("add {},{},orphan-b,4800".format(ENDPOINT, LABEL))
    check = lambda: check_policy_count(3)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, result

    kill_pce()

    # session-timeout-interval defaults to 30 seconds
    check = lambda: (
        None if "orphan-b" not in sr_te_policies() else "orphan-b still present"
    )
    _, result = topotest.run_and_expect(check, None, count=90, wait=1)
    assert result is None, result

    restart_pce()
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "base policies did not come back: {}".format(result)

    # The name is free again: a different color is a new LSP, not a 23/1
    errors_before = count_pce_errors(23, 1)
    pce_command("add {},{},orphan-b,4801".format(ENDPOINT, LABEL))
    check = lambda: check_policy_count(3)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "freed name was not reusable: {}".format(result)
    assert count_pce_errors(23, 1) == errors_before, "got PCErr 23/1"

    pce_command("remove orphan-b")
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "cleanup remove failed: {}".format(result)


def configure_pce2(no=False):
    "Add or remove a second PCE, PCE2, on port 4190"

    pce = "pce PCE2\n address ip 127.0.0.1 port 4190\n pce-initiated\n exit"
    peer = "pcc\n peer PCE2\n exit"
    # The PCE must exist before the PCC peers with it
    steps = ["pcc\n no peer PCE2\n exit", "no pce PCE2"] if no else [pce, peer]
    for step in steps:
        get_topogen().gears["rt1"].vtysh_cmd(
            "configure terminal\nsegment-routing\ntraffic-eng\npcep\n" + step
        )


def test_session_timeout_per_pce():
    "A PCE's session timeout removes its own paths, unless another PCE adopted them"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rt1 = tgen.gears["rt1"]
    pce2_log = os.path.join(tgen.logdir, "rt1", "mock_pce2.log")
    pce2_commands = os.path.join(tgen.logdir, "rt1", "pce2_commands")

    def pce2_command(line):
        with open(pce2_commands, "a") as cmds:
            cmds.write(line + "\n")

    def pce2_log_text():
        try:
            with open(pce2_log) as log:
                return log.read()
        except IOError:
            return ""

    def present(name, expected=True):
        if (name in sr_te_policies()) == expected:
            return None
        return "{} {}".format(name, "missing" if expected else "still present")

    def last_srp(kind, name):
        sent = re.findall(
            r"{}-SENT name={} plsp-id=\d+ srp=(\d+)".format(kind, name),
            pce2_log_text(),
        )
        return sent[-1] if sent else None

    def answered(srp):
        "'ok' for a PCRpt echoing srp, 'error' for a PCErr, else None"
        if "srp={} lsp-error=None".format(srp) in pce2_log_text():
            return "ok"
        if re.search(
            r"RECV-ERROR type=\d+ value=\d+ srp={} ".format(srp), pce2_log_text()
        ):
            return "error"
        return None

    # PCE1 initiates two paths: PCE2 adopts one and only updates the other
    pce_command("add {},{},taken-path,4901".format(ENDPOINT, LABEL))
    pce_command("add {},{},lost-path,4902".format(ENDPOINT, LABEL))
    for name in ["taken-path", "lost-path"]:
        _, result = topotest.run_and_expect(
            lambda: present(name), None, count=30, wait=1
        )
        assert result is None, result

    configure_pce2()
    rt1.run(
        "nohup python3 {}/mock_pce.py --port 4190 "
        "--policy {},{},pce2-path,4900 "
        "--command-file {} --log {} > /dev/null 2>&1 &".format(
            CWD, ENDPOINT, LABEL, pce2_commands, pce2_log
        )
    )
    _, result = topotest.run_and_expect(
        lambda: present("pce2-path"), None, count=60, wait=1
    )
    assert result is None, result

    # PCE1 is up, so its paths are not orphans and cannot be adopted
    pce2_command("adopt test-steer")
    _, result = topotest.run_and_expect(
        lambda: (
            None
            if "RECV-ERROR type=19 value=8" in pce2_log_text()
            else "no PCErr 19/8 for adopting a path of a connected PCE"
        ),
        None,
        count=30,
        wait=1,
    )
    assert result is None, result

    # Only PCE1 goes away; its timeout must fire while PCE2 is connected
    rt1.run("pkill -f 'mock_pce.py --policy'; true")

    def until_accepted(kind, name, command):
        "Resend command until pathd accepts it, as PCE1 may not be seen down yet"

        def check():
            srp = last_srp(kind, name)
            state = answered(srp) if srp else "error"
            if state == "ok":
                return None
            if state == "error":
                pce2_command(command)
            return "{} of {} not accepted yet".format(kind, name)

        _, result = topotest.run_and_expect(check, None, count=30, wait=1)
        assert result is None, result

    until_accepted("ADOPT", "taken-path", "adopt taken-path")
    until_accepted("UPDATE", "lost-path", "update lost-path,{}".format(LABEL))

    _, result = topotest.run_and_expect(
        lambda: present("test-steer", False), None, count=90, wait=1
    )
    assert result is None, result
    assert present("pce2-path") is None, "PCE1's session timeout removed pce2-path"
    assert present("taken-path") is None, "PCE1's session timeout removed taken-path"
    assert present("lost-path", False) is None, "lost-path survived without adoption"

    # Removing PCE2 from the configuration removes its paths right away,
    # well before a session timeout could
    configure_pce2(no=True)
    for name in ["pce2-path", "taken-path"]:
        _, result = topotest.run_and_expect(
            lambda: present(name, False), None, count=10, wait=1
        )
        assert result is None, result

    rt1.run("pkill -f 'mock_pce.py --port 4190'; true")
    restart_pce()
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "base policies did not come back: {}".format(result)


def test_steering_route_withdrawn_on_policy_delete():
    "The PCE deletes the last policy per endpoint; the steering route goes"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # The churn teardown left only the initial policies, still steering
    check = lambda: check_steering_route(True)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    assert result is None, "steering route missing before delete: {}".format(result)

    logger.info("removing test-steer and test-steer-v6")
    pce_command("remove test-steer")
    pce_command("remove test-steer-v6")

    check = lambda: check_policy_count(0)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "policies not deleted: {}".format(result)

    check = lambda: check_steering_route(False)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "steering route not withdrawn: {}".format(result)


def test_inflight_shutdown():
    "Leave PCInitiates in flight for the module teardown to race"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Deliberately no waiting: the module teardown races these
    # in-flight creations, and the teardown memory check is the
    # detector for anything they leak.
    logger.info("firing in-flight PCInitiates and ending immediately")
    for i in range(5):
        pce_command("add {},{},inflight-{},475{}".format(ENDPOINT, LABEL, i, i))

    # Wait only until the mock has put them on the wire, not until pathd
    # installs them, so the teardown still races their processing.
    def check_sent():
        sent = len(re.findall(r"ADD-SENT .*name=inflight-", mock_pce_log_text()))
        if sent < 5:
            return "mock PCE sent {} of 5 in-flight PCInitiates".format(sent)
        return None

    _, result = topotest.run_and_expect(check_sent, None, count=40, wait=0.25)
    assert result is None, result


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
