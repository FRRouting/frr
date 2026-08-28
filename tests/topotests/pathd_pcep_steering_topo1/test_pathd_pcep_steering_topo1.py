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
         | 1.1.1.1     |     10.0.1.0/24       | 2.2.2.2     |
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

    2.2.2.2/32       proto srte distance 10, resolving via SR-TE color
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.isisd, pytest.mark.pathd]

ENDPOINT = "2.2.2.2"
PREFIX = "2.2.2.2/32"
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

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    tgen.gears["rt1"].load_config(
        TopoRouter.RD_PATH, os.path.join(CWD, "rt1/pathd.conf"), " -M pathd_pcep"
    )

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


def test_steering_route_withdrawn_on_policy_down():
    "Take the policy down; pathd must withdraw the steering route"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("shutting down rt2's eth-rt1")
    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
         interface eth-rt1
          shutdown
        """)

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
    tgen.gears["rt2"].vtysh_cmd("""
        configure terminal
         interface eth-rt1
          no shutdown
        """)

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
        "--pcc-address 1.1.1.1 --pcc-address6 2001:db8::1 "
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


def check_policy_count(expected):
    "Check the number of Active SR-TE policies on RT1"

    tgen = get_topogen()
    active = tgen.gears["rt1"].vtysh_cmd("show sr-te policy").count("Active")
    if active != expected:
        return "expected {} Active policies, have {}".format(expected, active)
    return None


def steering_nexthop_count(v6=False):
    """The number of colored nexthops on RT1's steering route for the
    family (-1 if absent).  The route's nexthops are recursive (endpoint
    via endpoint, resolved through the policy); zebra's JSON flattens
    each recursive parent and its resolved nexthop into the same array,
    so count only the parents."""

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
        return -1
    return len([nh for nh in routes[0].get("nexthops", []) if nh.get("recursive")])


def ecmp_max():
    "zebra's runtime multipath limit, which caps the route's nexthops"

    tgen = get_topogen()
    output = tgen.gears["rt1"].vtysh_cmd("show zebra")
    match = re.search(r"ECMP Maximum\s*\|?\s*(\d+)", output)
    assert match is not None, "cannot read ECMP Maximum from 'show zebra'"
    return int(match.group(1))


def check_steering_nexthops(policies, v6=False):
    "Check the family's steering route carries min(policies, ECMP max) nexthops"

    prefix = PREFIX6 if v6 else PREFIX
    expected = min(policies, ecmp_max())
    have = steering_nexthop_count(v6)
    if have != expected:
        return "expected {} nexthops on {} ({} policies, ecmp {}), have {}".format(
            expected, prefix, policies, ecmp_max(), have
        )
    return None


def check_steering_nexthops_both(policies):
    "Check both families' steering routes at the same expected count"

    result = check_steering_nexthops(policies, v6=False)
    if result is not None:
        return result

    return check_steering_nexthops(policies, v6=True)


def test_policy_churn_scale():
    "Initiate CHURN_COUNT extra policies per family for the endpoints"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "initiating %u churn policies each for %s and %s",
        CHURN_COUNT, ENDPOINT, ENDPOINT6,
    )
    for i in range(CHURN_COUNT):
        churn_add(i, v6=False)
        churn_add(i, v6=True)

    # 2 initial policies + CHURN_COUNT churn ones per family
    check = lambda: check_policy_count(2 + 2 * CHURN_COUNT)
    _, result = topotest.run_and_expect(check, None, count=180, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "churn policies never came up: {}".format(result)

    # Each endpoint now has 1 + CHURN_COUNT policies; its steering route
    # aggregates one colored nexthop per policy, capped at the multipath
    # limit (colors beyond it are logged and unrepresented).
    check = lambda: check_steering_nexthops_both(1 + CHURN_COUNT)
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

    check = lambda: check_steering_nexthops_both(1)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "steering route wrong after churn teardown: {}".format(
        result
    )


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
        """.format("no " if no else "", name)
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


def test_pcep_rejected_on_cli_name():
    "A PCEP path whose segment list name is taken by config gets 24/2"

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

    errors_before = count_pce_errors(24, 2)
    logger.info("initiating cli-clash against the squatted name")
    pce_command("add {},{},cli-clash,4300".format(ENDPOINT, LABEL))
    check = lambda: (
        None if count_pce_errors(24, 2) > errors_before else "no PCErr 24/2 yet"
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
    "Two long names sharing a prefix must stay distinct policies"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # 76 bytes each (a multiple of 4, so the SYMBOLIC-PATH-NAME TLV
    # needs no padding), longer than the 64 bytes the name fields
    # used to hold -- and only differing after the point where the
    # old fields would have truncated them.
    prefix = "L" * 70
    name_a = prefix + "-alpha"
    name_b = prefix + "-beta1"

    logger.info("initiating two long-named policies")
    pce_command("add {},{},{},4501".format(ENDPOINT, LABEL, name_a))
    pce_command("add {},{},{},4502".format(ENDPOINT, LABEL, name_b))
    check = lambda: check_policy_count(4)
    _, result = topotest.run_and_expect(check, None, count=30, wait=1)
    if result is not None:
        print_pce_log()
    assert result is None, "long-named policies did not come up: {}".format(result)

    pce_command("remove {}".format(name_a))
    pce_command("remove {}".format(name_b))
    check = lambda: check_policy_count(2)
    _, result = topotest.run_and_expect(check, None, count=60, wait=1)
    assert result is None, "long-name cleanup failed: {}".format(result)


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
        PCE_GEN[0] += 1
        start_pce()

        # The new instance re-initiates both base policies; whether
        # pathd kept or timed out the old ones, it must converge back
        # to exactly the two of them Active.
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
    assert result is None, "steering route missing after restarts: {}".format(
        result
    )


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


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
