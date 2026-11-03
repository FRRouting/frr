#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 NVIDIA Corporation
#               Rajasekar Raja
#

r"""
Check that update subgroups merge only when they have sent the same routes.

    a1 (65001) --\                 /-- c (65000)
                  b (65000) -- s3 -
    a2 (65002) --/                 \-- d (65000)

a1 and a2 both send 10.10.10.0/24 to b, and b prefers a1 (local-pref 200).
c and d are iBGP peers of b with the same outbound policy, so they start in
one update subgroup S.

The race: a1 changes its attributes, b stores them at once and queues the
route for best path. A soft outbound clear to c moves c into a new subgroup
W, and W's table walk sends the new attributes while the table version
has not moved yet. S has sent the old attributes at the same version.
If S merged into W before best path ran, d would inherit W's record and
best path would then treat the change as already sent, so d would never get
it.

- Test 1: W finishes first. W must not merge into S while they have sent
  different attributes. Once best path runs, d gets the change and c and d
  merge.
- Test 2: S finishes last, the order seen in the field. UPDATEs to d are
  held so S is still busy when W finishes. Releasing d must not merge S
  into W. Once best path runs, d gets the change and c and d merge.

  In tests 1 and 2, S and W are at the same version while they are apart,
  so the version check alone would let them merge.
- Test 3: the pending route is a2's path, which is not the best path, so W
  sends the same routes S has sent. c and d merge at once, without waiting
  for best path.

The hidden "bgp test" commands only control timing: "bgp test metaq
disable" stops best path from running, and "bgp test updates disable
neighbor X" stops UPDATEs to X. They exist only in --enable-dev-build
builds.
"""

import functools
import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

PFX = "10.10.10.0/24"
Q = "10.20.20.0/24"
A1 = "192.168.1.1"
A2 = "192.168.2.1"
C = "192.168.3.2"
D = "192.168.3.3"


def build_topo(tgen):
    for rname in ["a1", "a2", "b", "c", "d"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["a1"])
    switch.add_link(tgen.gears["b"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["a2"])
    switch.add_link(tgen.gears["b"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["b"])
    switch.add_link(tgen.gears["c"])
    switch.add_link(tgen.gears["d"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _paths(router, prefix):
    output = router.vtysh_cmd(
        "show bgp ipv4 unicast {} json".format(prefix), isjson=True
    )
    return output.get("paths", [])


def _summary(path):
    return {
        "peer": path.get("peer", {}).get("peerId"),
        "aspath": path.get("aspath", {}).get("string"),
        "community": path.get("community", {}).get("string"),
        "best": path.get("bestpath", {}).get("overall", False),
        "pending": path.get("processScheduled", False),
    }


def _check(router, prefix, expected):
    """None if some path on router matches every key in expected."""
    found = [_summary(path) for path in _paths(router, prefix)]
    for path in found:
        if all(path[key] == value for key, value in expected.items()):
            return None
    return "{} has {} for {}, want a path with {}".format(
        router.name, found, prefix, expected
    )


def _check_no_route(router, prefix):
    found = [_summary(path) for path in _paths(router, prefix)]
    return "{} has {} for {}".format(router.name, found, prefix) if found else None


def _subgroup(b, nbr):
    output = b.vtysh_cmd("show bgp neighbor {} json".format(nbr), isjson=True)
    return output[nbr]["addressFamilyInfo"]["ipv4Unicast"].get("subGroupId")


def _check_subgroups(b, same):
    c_id, d_id = _subgroup(b, C), _subgroup(b, D)
    if same and c_id != d_id:
        return "c is in subgroup {}, d in {}, want them together".format(c_id, d_id)
    if not same and c_id == d_id:
        return "c and d are both in subgroup {}, want them apart".format(c_id)
    return None


def _check_same_version(b):
    """None if the subgroups of c and d are at the same version."""
    c_id, d_id = _subgroup(b, C), _subgroup(b, D)
    output = b.vtysh_cmd("show bgp ipv4 unicast update-groups json", isjson=True)
    versions = {}
    for updgrp in output.get("default", {}).values():
        for subgrp in updgrp.get("subGroup", []):
            versions[subgrp["subGroupId"]] = subgrp["version"]
    if c_id in versions and versions.get(c_id) == versions.get(d_id):
        return None
    return "c's subgroup {} is at version {}, d's subgroup {} at {}".format(
        c_id, versions.get(c_id), d_id, versions.get(d_id)
    )


def _wait(func, *args):
    _, result = topotest.run_and_expect(
        functools.partial(func, *args), None, count=30, wait=1
    )
    assert result is None, result


def _holds(func, *args, seconds=3):
    for _ in range(seconds):
        time.sleep(1)
        result = func(*args)
        assert result is None, result


def _log_count(tgen, text):
    with open(os.path.join(tgen.logdir, "b", "bgpd.log")) as log:
        return sum(text in line for line in log)


def _check_logged(tgen, text, before):
    """None once b's log has more lines with text than before."""
    count = _log_count(tgen, text)
    if count > before:
        return None
    return "b logged '{}' {} times, want more than {}".format(text, count, before)


def _test_commands_built(router):
    """Release the meta queue hold. False if bgpd was built without the
    "bgp test" commands."""
    return "Unknown command" not in router.vtysh_cmd("no bgp test metaq disable")


def _log_state(tgen, label):
    b = tgen.gears["b"]
    for router in [b, tgen.gears["c"], tgen.gears["d"]]:
        logger.info(
            "STATE %s: %s %s",
            label,
            router.name,
            [_summary(path) for path in _paths(router, PFX)],
        )
    logger.info(
        "STATE %s: subgroup of c %s, of d %s\n%s",
        label,
        _subgroup(b, C),
        _subgroup(b, D),
        b.vtysh_cmd("show bgp ipv4 unicast update-groups"),
    )


def _a2_q(tgen, enable):
    tgen.gears["a2"].vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          address-family ipv4 unicast
           {}network {}
        """.format(
            "" if enable else "no ", Q
        )
    )


def _community(tgen, router, rmap, community):
    tgen.gears[router].vtysh_cmd(
        """
        configure terminal
         route-map {} permit 10
          {}
        """.format(
            rmap,
            "set community {}".format(community) if community else "no set community",
        )
    )


def _reset(tgen):
    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    b.vtysh_cmd("no bgp test metaq disable")
    b.vtysh_cmd("no bgp test updates disable neighbor {}".format(D))
    _a2_q(tgen, False)
    _community(tgen, "a1", "A1-OUT", None)
    _community(tgen, "a2", "A2-OUT", None)
    for router in [c, d]:
        _wait(_check, router, PFX, {"aspath": "65001", "community": None})
        _wait(_check_no_route, router, Q)
    _wait(_check, b, PFX, {"peer": A2, "community": None, "pending": False})
    _wait(_check_subgroups, b, True)


def test_bgp_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    for peer in [A1, A2, C, D]:
        expected = {peer: {"bgpState": "Established"}}
        test_func = functools.partial(
            topotest.router_json_cmp,
            b,
            "show bgp neighbor {} json".format(peer),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "b to {} not established".format(peer)

    for router in [c, d]:
        _wait(_check, router, PFX, {"aspath": "65001"})
    _wait(_check_subgroups, b, True)


def test_new_subgroup_finishes_first():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("a2 advertises Q, c and d both get it")
    _a2_q(tgen, True)
    _wait(_check, c, Q, {"aspath": "65002"})
    _wait(_check, d, Q, {"aspath": "65002"})

    step("Plug the meta queue on b, then a1 adds community 65001:1")
    b.vtysh_cmd("bgp test metaq disable")
    _community(tgen, "a1", "A1-OUT", "65001:1")
    _wait(_check, b, PFX, {"peer": A1, "community": "65001:1", "pending": True})

    step("Soft outbound clear to c: c gets the community, c and d stay apart")
    refused = _log_count(tgen, "adj-out differs")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check, c, PFX, {"community": "65001:1"})
    _wait(_check_subgroups, b, False)
    _holds(_check_subgroups, b, False)
    _wait(_check_logged, tgen, "adj-out differs", refused)
    assert _check_same_version(b) is None
    _log_state(tgen, "new subgroup first, best path pending")

    step("Unplug the meta queue: d gets the community, c and d merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, d, PFX, {"community": "65001:1"})
    _wait(_check_subgroups, b, True)
    _log_state(tgen, "new subgroup first, final")


def test_busy_subgroup_finishes_last():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("Plug UPDATEs to d, then a2 advertises Q: c gets it, d does not")
    b.vtysh_cmd("bgp test updates disable neighbor {}".format(D))
    _a2_q(tgen, True)
    _wait(_check, c, Q, {"aspath": "65002"})
    _holds(_check_no_route, d, Q)

    step("Plug the meta queue on b, then a1 adds community 65001:1")
    b.vtysh_cmd("bgp test metaq disable")
    _community(tgen, "a1", "A1-OUT", "65001:1")
    _wait(_check, b, PFX, {"peer": A1, "community": "65001:1", "pending": True})

    step("Soft outbound clear to c: c gets the community, c and d are apart")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check, c, PFX, {"community": "65001:1"})
    _wait(_check_subgroups, b, False)

    step("Unplug UPDATEs to d: d gets Q, c and d stay apart")
    refused = _log_count(tgen, "adj-out differs")
    b.vtysh_cmd("no bgp test updates disable neighbor {}".format(D))
    _wait(_check, d, Q, {"aspath": "65002"})
    _holds(_check_subgroups, b, False)
    _wait(_check_logged, tgen, "adj-out differs", refused)
    assert _check_same_version(b) is None
    assert _check(d, PFX, {"community": None}) is None
    _log_state(tgen, "busy subgroup last, best path pending")

    step("Unplug the meta queue: d gets the community, c and d merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, d, PFX, {"community": "65001:1"})
    _wait(_check_subgroups, b, True)
    _log_state(tgen, "busy subgroup last, final")


def test_merge_while_non_best_path_is_pending():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("Plug the meta queue on b, then a2 adds 65002:1 to its non-best path")
    b.vtysh_cmd("bgp test metaq disable")
    _community(tgen, "a2", "A2-OUT", "65002:1")
    pending = {"peer": A2, "community": "65002:1", "best": False, "pending": True}
    _wait(_check, b, PFX, pending)

    step("Soft outbound clear to c: c and d merge while best path is pending")
    merged = _log_count(tgen, "merged into")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check_logged, tgen, "merged into", merged)
    _wait(_check_subgroups, b, True)
    assert _check(b, PFX, pending) is None
    _log_state(tgen, "non-best path pending, merged")

    step("Unplug the meta queue: c and d stay together with the same route")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, b, PFX, {"peer": A2, "community": "65002:1", "pending": False})
    _wait(_check, b, PFX, {"peer": A1, "best": True})
    _holds(_check_subgroups, b, True)
    for router in [c, d]:
        assert _check(router, PFX, {"aspath": "65001", "community": None}) is None
    _log_state(tgen, "non-best path pending, final")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
