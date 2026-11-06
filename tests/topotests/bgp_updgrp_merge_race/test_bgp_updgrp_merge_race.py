#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 NVIDIA Corporation
#               Rajasekar Raja
#

r"""
Check that update subgroups do not merge while best path is pending for a
route they have sent.

    a1 (65001) --\                 /-- c (65000)
                  b (65000) -- s3 --- d (65000)
    a2 (65002) --/                 \-- e (65000)

a1 and a2 both send 10.10.10.0/24 to b, and b prefers a1 (local-pref 200).
c, d and e are iBGP peers of b with the same outbound policy, so they start
in one update subgroup S.

The race: a1 changes its attributes, b stores them at once and queues the
route for best path. A soft outbound clear to c moves c into a new subgroup
W, and W's table walk sends the new attributes while the table version
has not moved yet. S has sent the old attributes at the same version.
If S merged into W before best path ran, d would inherit W's record and
best path would then treat the change as already sent, so d would never get
it.

A merge counts as refused when two subgroups stay apart although they are
at the same version, hold the same number of adj-out entries, have nothing
queued to send and need no refresh: every other merge condition holds, so
only the best path check keeps them apart.

- Test 1: W finishes first. W must not merge into S while best path is
  pending. Once best path runs, d gets the change and c and d merge.
- Test 2: S finishes last, the order seen in the field. UPDATEs to d are
  held so S is still busy when W finishes. Releasing d must not merge S
  into W while best path is pending. Once best path runs, d gets the change
  and c and d merge.
- Test 3: the pending route is a2's path, which is not the best path. c and
  d stay apart while it waits for best path. Best path then finds nothing
  changed and sends nothing, so no packet triggers a merge check; the check
  run after best path must still merge them, and both keep a1's route.
- Test 4: an outbound route-map strips communities towards c, d and e, and
  a1 adds one. c and d stay apart while best path is pending. Best path
  then changes the route, but the result for c and d is a duplicate of what
  they have, so nothing is sent; the check run after best path must still
  merge them.
- Test 5: with nothing pending, a soft outbound clear to c splits c off and
  c merges back at once.
- Test 6: soft outbound clears to c and to e while a2's non-best path waits
  for best path leave c, d and e in three subgroups. A refused check stops
  at the first subgroup that could take it, so not every pair is checked.
  Best path sends nothing, yet the checks run after it must merge all three.
- Test 7: as in test 6, but the session to c goes down while its merge is
  refused, so its subgroup is deleted before best path runs. d and e must
  still merge, and c must join them when it comes back.
- Test 8: a2 advertises a new route R while best path is held. R has no
  best path yet, so no subgroup has sent it, and it must not stop c from
  merging back after a soft outbound clear.
- Test 9: a2 withdraws Q while best path is held. A soft outbound clear
  to c withdraws Q from c at once, because the table walk does not
  announce a withdrawn path, while d keeps Q until best path runs. Their
  adj-outs then hold different routes, so they stay apart without the
  best path check; once best path runs, d loses Q too and they merge.
- Test 10: the field case. Only a1 sends 10.10.10.0/24, with the
  graceful-shutdown community, so c and d have it with local-pref 0. With
  UPDATEs to d held, a1 removes the community, and c sends a ROUTE-REFRESH
  that splits it off. c gets the route without graceful-shutdown. Once d
  is released, its subgroup must not merge into c's while best path is
  pending, or d keeps graceful-shutdown and local-pref 0 for good.
- Test 11: the session to e comes up while a1's change waits for best
  path. e's new subgroup sends e the change, and must not merge with c and
  d until best path has run.
- Matrix: every route event in EVENTS, combined with each way a peer gets
  a new subgroup (a soft outbound clear to c, a ROUTE-REFRESH from c, or
  the session to e coming up) and with each order (the new subgroup
  finishes first, or UPDATEs to d are held so d's subgroup finishes last).
  While best path is held, the two subgroups must be refused a merge, stay
  apart because they hold different routes, or merge at once when nothing
  they have sent is pending. Once best path runs, c, d and e must all have
  the right route and share one subgroup.

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

pytestmark = [pytest.mark.bgpd]

PFX = "10.10.10.0/24"
Q = "10.20.20.0/24"
R = "10.30.30.0/24"
BUSY = "10.40.40.0/24"
ASN = {"a1": 65001, "a2": 65002}
A1 = "192.168.1.1"
A2 = "192.168.2.1"
C = "192.168.3.2"
D = "192.168.3.3"
E = "192.168.3.4"
GSHUT = {"aspath": "65001", "community": "graceful-shutdown", "locprf": 0}


def build_topo(tgen):
    for rname in ["a1", "a2", "b", "c", "d", "e"]:
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
    switch.add_link(tgen.gears["e"])


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
        "locprf": path.get("locPrf"),
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


def _check_pair(b, nbr1, nbr2, same):
    """None if nbr1 and nbr2 are in one subgroup (same) or in two."""
    id1, id2 = _subgroup(b, nbr1), _subgroup(b, nbr2)
    if (id1 == id2) == same:
        return None
    return "{} is in subgroup {}, {} in {}, want them {}".format(
        nbr1, id1, nbr2, id2, "together" if same else "apart"
    )


def _check_all(b, nbrs, same):
    """None if nbrs are all in one subgroup (same) or each in its own."""
    ids = {nbr: _subgroup(b, nbr) for nbr in nbrs}
    count = len(set(ids.values()))
    if (same and count == 1) or (not same and count == len(nbrs)):
        return None
    return "subgroups {}, want them {}".format(ids, "together" if same else "apart")


def _subgroups(b):
    """The subgroups of b by id, from "show bgp ipv4 unicast update-groups"."""
    output = b.vtysh_cmd("show bgp ipv4 unicast update-groups json", isjson=True)
    subgrps = {}
    for updgrp in output.get("default", {}).values():
        for subgrp in updgrp.get("subGroup", []):
            subgrps[subgrp["subGroupId"]] = subgrp
    return subgrps


def _check_refused(b, nbr1, nbr2):
    """None if nbr1 and nbr2 are in two subgroups that meet every merge
    condition other than the best path check: the same version, the same
    number of adj-out entries, nothing queued to send and no refresh due."""
    id1, id2 = _subgroup(b, nbr1), _subgroup(b, nbr2)
    if id1 == id2:
        return "{} and {} are both in subgroup {}, want them apart".format(
            nbr1, nbr2, id1
        )
    subgrps = _subgroups(b)
    if id1 not in subgrps or id2 not in subgrps:
        return "subgroup {} or {} is missing".format(id1, id2)
    sub1, sub2 = subgrps[id1], subgrps[id2]
    for key in ["version", "adjListCount"]:
        if sub1.get(key) != sub2.get(key):
            return "{} of {}'s subgroup is {}, of {}'s is {}".format(
                key, nbr1, sub1.get(key), nbr2, sub2.get(key)
            )
    for nbr, sub in [(nbr1, sub1), (nbr2, sub2)]:
        queued = sub.get("packetQueueInfo", {}).get("qeueueLen")
        if queued or sub.get("needsRefresh"):
            return "{}'s subgroup has {} packets queued, needs refresh: {}".format(
                nbr, queued, sub.get("needsRefresh")
            )
    return None


def _stat(b, name):
    """A counter from "show bgp update-groups statistics"."""
    for line in b.vtysh_cmd("show bgp update-groups statistics").splitlines():
        if line.strip().startswith(name + ":"):
            return int(line.split(":", 1)[1])
    return None


def _check_stat_above(b, name, before):
    count = _stat(b, name)
    if count is not None and count > before:
        return None
    return "{} is {}, want more than {}".format(name, count, before)


def _check_established(b, nbr, up):
    output = b.vtysh_cmd("show bgp neighbor {} json".format(nbr), isjson=True)
    state = output.get(nbr, {}).get("bgpState")
    if (state == "Established") == up:
        return None
    return "b to {} is {}, want {}".format(
        nbr, state, "Established" if up else "not Established"
    )


def _shutdown(tgen, nbr, enable):
    tgen.gears["b"].vtysh_cmd(
        """
        configure terminal
         router bgp 65000
          {}neighbor {} shutdown
        """.format(
            "" if enable else "no ", nbr
        )
    )


def _accepted(b, nbr):
    output = b.vtysh_cmd("show bgp neighbor {} json".format(nbr), isjson=True)
    return output[nbr]["addressFamilyInfo"]["ipv4Unicast"].get("acceptedPrefixCounter")


def _check_accepted(b, nbr, count):
    accepted = _accepted(b, nbr)
    if accepted == count:
        return None
    return "b accepted {} routes from {}, want {}".format(accepted, nbr, count)


def _wait(func, *args):
    _, result = topotest.run_and_expect(
        functools.partial(func, *args), None, count=30, wait=1
    )
    assert result is None, result


def _holds(func, *args, seconds=3):
    """Check that func stays None for a few seconds. This tests that
    something does not happen, such as a merge, so there is no state to
    poll for and it has to wait."""
    for _ in range(seconds):
        time.sleep(1)
        result = func(*args)
        assert result is None, result


def _wait_all(tgen, prefix, expected):
    """Wait until c, d and e have prefix as in expected, or no route if None."""
    for rname in ["c", "d", "e"]:
        router = tgen.gears[rname]
        if expected is None:
            _wait(_check_no_route, router, prefix)
        else:
            _wait(_check, router, prefix, expected)


def _test_commands_built(router):
    """Release the meta queue hold. False if bgpd was built without the
    "bgp test" commands."""
    return "Unknown command" not in router.vtysh_cmd("no bgp test metaq disable")


def _network(tgen, rname, prefix, enable):
    tgen.gears[rname].vtysh_cmd(
        """
        configure terminal
         router bgp {}
          address-family ipv4 unicast
           {}network {}
        """.format(
            ASN[rname], "" if enable else "no ", prefix
        )
    )


def _a2_network(tgen, prefix, enable):
    _network(tgen, "a2", prefix, enable)


def _a2_q(tgen, enable):
    _a2_network(tgen, Q, enable)


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


def _strip_community(tgen, enable):
    tgen.gears["b"].vtysh_cmd(
        """
        configure terminal
         route-map TO-CD permit 10
          set community none
         router bgp 65000
          address-family ipv4 unicast
           {0}neighbor {1} route-map TO-CD out
           {0}neighbor {2} route-map TO-CD out
           {0}neighbor {3} route-map TO-CD out
        """.format(
            "" if enable else "no ", C, D, E
        )
    )


def _reset(tgen):
    b = tgen.gears["b"]
    b.vtysh_cmd("no bgp test metaq disable")
    b.vtysh_cmd("no bgp test updates disable neighbor {}".format(D))
    for nbr in [C, E]:
        _shutdown(tgen, nbr, False)
    _strip_community(tgen, False)
    _network(tgen, "a1", PFX, True)
    _network(tgen, "a1", BUSY, False)
    _a2_network(tgen, PFX, True)
    _a2_network(tgen, Q, False)
    _a2_network(tgen, R, False)
    _community(tgen, "a1", "A1-OUT", None)
    _community(tgen, "a2", "A2-OUT", None)
    for nbr in [C, E]:
        _wait(_check_established, b, nbr, True)
    for rname in ["c", "d", "e"]:
        router = tgen.gears[rname]
        _wait(_check, router, PFX, {"aspath": "65001", "community": None})
        for prefix in [Q, R, BUSY]:
            _wait(_check_no_route, router, prefix)
    _wait(_check, b, PFX, {"peer": A2, "community": None, "pending": False})
    _wait(_check_all, b, [C, D, E], True)


def test_bgp_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    for peer in [A1, A2, C, D, E]:
        expected = {peer: {"bgpState": "Established"}}
        test_func = functools.partial(
            topotest.router_json_cmp,
            b,
            "show bgp neighbor {} json".format(peer),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "b to {} not established".format(peer)

    for router in [c, d, tgen.gears["e"]]:
        _wait(_check, router, PFX, {"aspath": "65001"})
    _wait(_check_all, b, [C, D, E], True)


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

    step("Soft outbound clear to c: c gets the community, the merge is refused")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check, c, PFX, {"community": "65001:1"})
    _wait(_check_refused, b, C, D)
    _holds(_check_refused, b, C, D)

    step("Unplug the meta queue: d gets the community, c and d merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, d, PFX, {"community": "65001:1"})
    _wait(_check_subgroups, b, True)


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

    step("Unplug UPDATEs to d: d gets Q, the merge is refused")
    b.vtysh_cmd("no bgp test updates disable neighbor {}".format(D))
    _wait(_check, d, Q, {"aspath": "65002"})
    _wait(_check_refused, b, C, D)
    _holds(_check_refused, b, C, D)
    assert _check(d, PFX, {"community": None}) is None

    step("Unplug the meta queue: d gets the community, c and d merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, d, PFX, {"community": "65001:1"})
    _wait(_check_subgroups, b, True)


def test_merge_after_non_best_path_best_path():
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

    step("Soft outbound clear to c: c keeps a1's route, the merge is refused")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check_refused, b, C, D)
    _holds(_check_refused, b, C, D)
    assert _check(c, PFX, {"aspath": "65001", "community": None}) is None

    step("Unplug the meta queue: best path sends nothing, yet c and d merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, b, PFX, {"peer": A2, "community": "65002:1", "pending": False})
    _wait(_check, b, PFX, {"peer": A1, "best": True})
    _wait(_check_subgroups, b, True)
    for router in [c, d]:
        assert _check(router, PFX, {"aspath": "65001", "community": None}) is None


def test_merge_after_suppressed_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("Strip communities towards c, d and e with an outbound route-map")
    _strip_community(tgen, True)
    _wait(_check_all, b, [C, D, E], True)

    step("Plug the meta queue on b, then a1 adds community 65001:1")
    b.vtysh_cmd("bgp test metaq disable")
    _community(tgen, "a1", "A1-OUT", "65001:1")
    _wait(_check, b, PFX, {"peer": A1, "community": "65001:1", "pending": True})

    step("Soft outbound clear to c: the merge is refused")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check_refused, b, C, D)
    _holds(_check_refused, b, C, D)

    step("Unplug the meta queue: best path changes, sends nothing, c and d merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, b, PFX, {"peer": A1, "community": "65001:1", "pending": False})
    _wait(_check_subgroups, b, True)
    for router in [c, d]:
        assert _check(router, PFX, {"aspath": "65001", "community": None}) is None

    _strip_community(tgen, False)


def test_merge_without_pending_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b = tgen.gears["b"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("Soft outbound clear to c with nothing pending: c merges back")
    split = _stat(b, "Split events")
    merged = _stat(b, "Merge events")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check_stat_above, b, "Split events", split)
    _wait(_check_stat_above, b, "Merge events", merged)
    _wait(_check_all, b, [C, D, E], True)


def _split_three_ways(tgen):
    """Hold best path for a2's non-best path, then split c and e off."""
    b = tgen.gears["b"]

    step("Plug the meta queue on b, then a2 adds 65002:1 to its non-best path")
    b.vtysh_cmd("bgp test metaq disable")
    _community(tgen, "a2", "A2-OUT", "65002:1")
    pending = {"peer": A2, "community": "65002:1", "best": False, "pending": True}
    _wait(_check, b, PFX, pending)

    step("Soft outbound clears to c and to e: three subgroups, merges refused")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check_refused, b, C, D)
    b.vtysh_cmd("clear bgp {} soft out".format(E))
    _wait(_check_refused, b, E, D)
    _wait(_check_all, b, [C, D, E], False)
    _holds(_check_all, b, [C, D, E], False)


def test_three_subgroups_merge_after_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b = tgen.gears["b"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    _split_three_ways(tgen)

    step("Unplug the meta queue: best path sends nothing, all three merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, b, PFX, {"peer": A2, "community": "65002:1", "pending": False})
    _wait(_check_all, b, [C, D, E], True)
    for rname in ["c", "d", "e"]:
        router = tgen.gears[rname]
        assert _check(router, PFX, {"aspath": "65001", "community": None}) is None


def test_waiting_subgroup_deleted_before_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b = tgen.gears["b"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    _split_three_ways(tgen)

    step("Shut down the session to c, deleting its waiting subgroup")
    _shutdown(tgen, C, True)
    _wait(_check_established, b, C, False)
    _holds(_check_refused, b, E, D)

    step("Unplug the meta queue: best path sends nothing, d and e merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, b, PFX, {"peer": A2, "community": "65002:1", "pending": False})
    _wait(_check_all, b, [D, E], True)
    for rname in ["d", "e"]:
        router = tgen.gears[rname]
        assert _check(router, PFX, {"aspath": "65001", "community": None}) is None
    assert not tgen.routers_have_failure(), tgen.errors

    step("Bring the session to c back: c joins d and e")
    _shutdown(tgen, C, False)
    _wait(_check_established, b, C, True)
    _wait(_check, tgen.gears["c"], PFX, {"aspath": "65001", "community": None})
    _wait(_check_all, b, [C, D, E], True)


def test_unsent_pending_route_does_not_block_merge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("Plug the meta queue on b, then a2 advertises R: R has no best path")
    b.vtysh_cmd("bgp test metaq disable")
    _a2_network(tgen, R, True)
    _wait(_check, b, R, {"peer": A2, "best": False, "pending": True})

    step("Soft outbound clear to c: c merges back while R still waits")
    merged = _stat(b, "Merge events")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check_stat_above, b, "Merge events", merged)
    _wait(_check_all, b, [C, D, E], True)
    for router in [c, d]:
        assert _check_no_route(router, R) is None

    step("Unplug the meta queue: c, d and e get R")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait_all(tgen, R, {"aspath": "65002"})
    _wait(_check_all, b, [C, D, E], True)


def test_pending_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("a2 advertises Q, c and d both get it")
    _a2_q(tgen, True)
    for router in [c, d]:
        _wait(_check, router, Q, {"aspath": "65002"})
    _wait(_check_accepted, b, A2, 2)

    step("Plug the meta queue on b, then a2 withdraws Q: c and d keep Q")
    b.vtysh_cmd("bgp test metaq disable")
    _a2_q(tgen, False)
    _wait(_check_accepted, b, A2, 1)
    for router in [c, d]:
        assert _check(router, Q, {"aspath": "65002"}) is None

    step("Soft outbound clear to c: c loses Q at once, d keeps it, apart")
    b.vtysh_cmd("clear bgp {} soft out".format(C))
    _wait(_check_no_route, c, Q)
    _wait(_check_subgroups, b, False)
    _holds(_check_subgroups, b, False)
    assert _check(d, Q, {"aspath": "65002"}) is None

    step("Unplug the meta queue: c, d and e lose Q, and c and d merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait_all(tgen, Q, None)
    _wait(_check_all, b, [C, D, E], True)


def test_graceful_shutdown_removal_reaches_held_peer():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("Only a1 sends PFX, with graceful-shutdown: c and d get local-pref 0")
    _a2_network(tgen, PFX, False)
    _community(tgen, "a1", "A1-OUT", "graceful-shutdown")
    for router in [c, d]:
        _wait(_check, router, PFX, GSHUT)
    _wait(_check_all, b, [C, D, E], True)

    step("Plug UPDATEs to d, then a2 advertises Q: c gets it, d does not")
    b.vtysh_cmd("bgp test updates disable neighbor {}".format(D))
    _a2_q(tgen, True)
    _wait(_check, c, Q, {"aspath": "65002"})
    _holds(_check_no_route, d, Q)

    step("Plug the meta queue on b, then a1 removes graceful-shutdown")
    b.vtysh_cmd("bgp test metaq disable")
    _community(tgen, "a1", "A1-OUT", None)
    _wait(_check, b, PFX, {"peer": A1, "community": None, "pending": True})

    step("c sends a ROUTE-REFRESH: c gets PFX without graceful-shutdown")
    c.vtysh_cmd("clear bgp ipv4 unicast 192.168.3.1 soft in")
    clean = {"aspath": "65001", "community": None, "locprf": 200}
    _wait(_check, c, PFX, clean)
    _wait(_check_subgroups, b, False)

    step("Unplug UPDATEs to d: d gets Q, the merge is refused")
    b.vtysh_cmd("no bgp test updates disable neighbor {}".format(D))
    _wait(_check, d, Q, {"aspath": "65002"})
    _wait(_check_refused, b, C, D)
    _holds(_check_refused, b, C, D)
    assert _check(d, PFX, GSHUT) is None

    step("Unplug the meta queue: d loses graceful-shutdown, c and d merge")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait(_check, d, PFX, clean)
    _wait(_check_subgroups, b, True)


def test_new_peer_waits_for_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d, e = (tgen.gears[rname] for rname in ["b", "c", "d", "e"])
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    step("Shut down the session to e")
    _shutdown(tgen, E, True)
    _wait(_check_established, b, E, False)

    step("Plug the meta queue on b, then a1 adds community 65001:1")
    b.vtysh_cmd("bgp test metaq disable")
    _community(tgen, "a1", "A1-OUT", "65001:1")
    _wait(_check, b, PFX, {"peer": A1, "community": "65001:1", "pending": True})

    step("Bring the session to e up: e gets the community, the merge is refused")
    _shutdown(tgen, E, False)
    _wait(_check_established, b, E, True)
    _wait(_check, e, PFX, {"community": "65001:1"})
    _wait(_check_refused, b, E, D)
    _holds(_check_refused, b, E, D)
    assert _check_subgroups(b, True) is None
    for router in [c, d]:
        assert _check(router, PFX, {"community": None}) is None

    step("Unplug the meta queue: c and d get the community, all three merge")
    b.vtysh_cmd("no bgp test metaq disable")
    for router in [c, d]:
        _wait(_check, router, PFX, {"community": "65001:1"})
    _wait(_check_all, b, [C, D, E], True)


def _withdraw(tgen, rname, prefix):
    """rname withdraws prefix; wait until b has received the withdraw."""
    b = tgen.gears["b"]
    nbr = A1 if rname == "a1" else A2
    before = _accepted(b, nbr)
    _network(tgen, rname, prefix, False)
    _wait(_check_accepted, b, nbr, before - 1)


def _only_a1(tgen, community):
    """Only a1 sends PFX, with community set on a1's side."""
    _a2_network(tgen, PFX, False)
    _community(tgen, "a1", "A1-OUT", community)
    _wait(_check_accepted, tgen.gears["b"], A2, 0)
    _wait_all(
        tgen,
        PFX,
        GSHUT if community else {"aspath": "65001", "community": None},
    )


def _setup_none(tgen):
    pass


def _setup_strip(tgen):
    _strip_community(tgen, True)
    _wait(_check_all, tgen.gears["b"], [C, D, E], True)


def _setup_q(tgen):
    _a2_q(tgen, True)
    _wait_all(tgen, Q, {"aspath": "65002"})


def _setup_only_a1(tgen):
    _only_a1(tgen, None)


def _setup_only_a1_gshut(tgen):
    _only_a1(tgen, "graceful-shutdown")


def _change_a1_community(tgen):
    _community(tgen, "a1", "A1-OUT", "65001:1")
    pending = {"peer": A1, "community": "65001:1", "pending": True}
    _wait(_check, tgen.gears["b"], PFX, pending)


def _change_a2_community(tgen):
    _community(tgen, "a2", "A2-OUT", "65002:1")
    pending = {"peer": A2, "community": "65002:1", "best": False, "pending": True}
    _wait(_check, tgen.gears["b"], PFX, pending)


def _change_add_r(tgen):
    _a2_network(tgen, R, True)
    _wait(_check, tgen.gears["b"], R, {"peer": A2, "best": False, "pending": True})


def _change_withdraw_q(tgen):
    _withdraw(tgen, "a2", Q)


def _change_withdraw_best(tgen):
    _withdraw(tgen, "a1", PFX)


def _change_gshut_on(tgen):
    _community(tgen, "a1", "A1-OUT", "graceful-shutdown")
    pending = {"peer": A1, "community": "graceful-shutdown", "pending": True}
    _wait(_check, tgen.gears["b"], PFX, pending)


def _change_gshut_off(tgen):
    _community(tgen, "a1", "A1-OUT", None)
    pending = {"peer": A1, "community": None, "pending": True}
    _wait(_check, tgen.gears["b"], PFX, pending)


def _change_flap_q(tgen):
    b = tgen.gears["b"]
    before = _accepted(b, A2)
    _withdraw(tgen, "a2", Q)
    _a2_q(tgen, True)
    _wait(_check_accepted, b, A2, before)
    _wait(_check, b, Q, {"peer": A2, "pending": True})


# Each event: set up, the change made while best path is held, what the two
# subgroups must do while it is held ("refused", "apart" because they hold
# different routes, or "merged" because nothing they sent is pending), and
# the route c, d and e must have once best path has run (None: no route).
EVENTS = {
    "best_path_change": (
        _setup_none,
        _change_a1_community,
        "refused",
        PFX,
        {"aspath": "65001", "community": "65001:1"},
    ),
    "non_best_path_change": (
        _setup_none,
        _change_a2_community,
        "refused",
        PFX,
        {"aspath": "65001", "community": None},
    ),
    "change_hidden_by_policy": (
        _setup_strip,
        _change_a1_community,
        "refused",
        PFX,
        {"aspath": "65001", "community": None},
    ),
    "new_route": (_setup_none, _change_add_r, "merged", R, {"aspath": "65002"}),
    "only_path_withdraw": (_setup_q, _change_withdraw_q, "apart", Q, None),
    "best_path_withdraw": (
        _setup_none,
        _change_withdraw_best,
        "apart",
        PFX,
        {"aspath": "65002"},
    ),
    "gshut_on": (_setup_only_a1, _change_gshut_on, "refused", PFX, GSHUT),
    "gshut_off": (
        _setup_only_a1_gshut,
        _change_gshut_off,
        "refused",
        PFX,
        {"aspath": "65001", "community": None, "locprf": 200},
    ),
    "flap": (_setup_q, _change_flap_q, "refused", Q, {"aspath": "65002"}),
}


@pytest.mark.parametrize("order", ["new_first", "old_last"])
@pytest.mark.parametrize("trigger", ["soft_out", "refresh", "new_peer"])
@pytest.mark.parametrize("event", list(EVENTS))
def test_matrix(event, trigger, order):
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    b, c, d = tgen.gears["b"], tgen.gears["c"], tgen.gears["d"]
    if not _test_commands_built(b):
        pytest.skip("the bgp test commands need --enable-dev-build")
    _reset(tgen)

    setup, change, held, prefix, expected = EVENTS[event]
    mover = E if trigger == "new_peer" else C

    step("Set up {}".format(event))
    setup(tgen)
    if trigger == "new_peer":
        _shutdown(tgen, E, True)
        _wait(_check_established, b, E, False)
    if order == "old_last":
        step("Plug UPDATEs to d, then a1 advertises BUSY: d's subgroup is busy")
        b.vtysh_cmd("bgp test updates disable neighbor {}".format(D))
        _network(tgen, "a1", BUSY, True)
        _wait(_check, c, BUSY, {"aspath": "65001"})
        assert _check_no_route(d, BUSY) is None

    step("Plug the meta queue on b, then {}".format(event))
    b.vtysh_cmd("bgp test metaq disable")
    change(tgen)

    step("{}: {} gets a new subgroup".format(trigger, mover))
    if trigger == "soft_out":
        b.vtysh_cmd("clear bgp {} soft out".format(C))
    elif trigger == "refresh":
        c.vtysh_cmd("clear bgp ipv4 unicast 192.168.3.1 soft in")
    else:
        _shutdown(tgen, E, False)
        _wait(_check_established, b, E, True)
    if order == "old_last":
        _wait(_check_pair, b, mover, D, False)
        b.vtysh_cmd("no bgp test updates disable neighbor {}".format(D))
        _wait(_check, d, BUSY, {"aspath": "65001"})

    step("While best path is held, the subgroups of {} and d: {}".format(mover, held))
    if held == "refused":
        _wait(_check_refused, b, mover, D)
        _holds(_check_refused, b, mover, D, seconds=2)
    elif held == "apart":
        _wait(_check_pair, b, mover, D, False)
        _holds(_check_pair, b, mover, D, False, seconds=2)
    else:
        _wait(_check_pair, b, mover, D, True)

    step("Unplug the meta queue: c, d and e converge and share one subgroup")
    b.vtysh_cmd("no bgp test metaq disable")
    _wait_all(tgen, prefix, expected)
    _wait(_check_all, b, [C, D, E], True)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
