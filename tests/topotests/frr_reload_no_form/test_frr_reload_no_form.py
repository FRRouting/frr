#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_frr_reload_no_form.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_frr_reload_no_form.py: test frr-reload.py removing configuration
whose "no" form does not take the configured arguments.

- interface "description LINE" (lib, northbound): only "no description"
  exists. frr-reload.py rewrites this delete itself.
- interface "ip ospf adjacency-pacing dynamic thresholds (1-1000) (1-1000)"
  (ospfd, no northbound): only "no ip ospf adjacency-pacing dynamic
  thresholds" exists.
- router ospf6 "aggregation timer (5-1800)" (ospf6d, no northbound): the
  "no" form is "no aggregation timer [5-1800]", where "5-1800" is a keyword,
  not a range, so "no aggregation timer 20" is rejected.

For the last two, frr-reload.py first tries the full "no" line, vtysh
rejects it, and the command is retried with trailing words dropped until it
is accepted.

1. Start with all of the above configured (frr.conf).
2. Reload frr-new.conf: remove and change descriptions, remove the
   adjacency pacing thresholds (keeping dynamic pacing), change the
   aggregation timer. frr-reload.py must succeed and the result must match.
3. Reload frr.conf: the original configuration comes back.
4. After each reload, frr-reload.py --test must find nothing left to do.
5. Add "affinity-map blue" used by r1-eth2 link-params and reload
   frr-new-affinity.conf: frr-new.conf, but r1-eth2 still uses the
   affinity-map it removes. The deletion file now has numbered errors (the
   two retried "no" forms above) and a rejected commit (the affinity-map is
   still referenced). The rejected commit rolls back the other deletes in
   its transaction, such as the descriptions, so frr-reload.py must retry
   those too and report the failure instead of leaving the old settings
   behind.
"""

import difflib
import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd, pytest.mark.ospf6d]

ORIGINAL_CONF = os.path.join(CWD, "r1/frr.conf")
NEW_CONF = os.path.join(CWD, "r1/frr-new.conf")
NEW_AFFINITY_CONF = os.path.join(CWD, "r1/frr-new-affinity.conf")

# Lines frr-reload.py --test reports that do not come from the test
IGNORED_DELTA = ("log commands", "no log commands", "domainname ", "no domainname ")

ORIGINAL_DESCRIPTIONS = {
    "r1-eth0": "link to s1 with several words",
    "r1-eth1": "old-description",
}
NEW_DESCRIPTIONS = {
    "r1-eth0": None,
    "r1-eth1": "new description for eth1",
}

ORIGINAL_STANZAS = {
    "interface r1-eth0": """
interface r1-eth0
 description link to s1 with several words
 ip address 192.168.1.1/24
 ip ospf adjacency-pacing dynamic
 ip ospf adjacency-pacing dynamic thresholds 100 50
exit
""",
    "router ospf6": """
router ospf6
 ospf6 router-id 10.254.254.1
 aggregation timer 20
exit
""",
}
NEW_STANZAS = {
    "interface r1-eth0": """
interface r1-eth0
 ip address 192.168.1.1/24
 ip ospf adjacency-pacing dynamic
exit
""",
    "router ospf6": """
router ospf6
 ospf6 router-id 10.254.254.1
 aggregation timer 30
exit
""",
}


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)

    switch = tgen.add_switch("s2")
    switch.add_link(r1)

    switch = tgen.add_switch("s3")
    switch.add_link(r1)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def frr_reload(router, conf, mode="--reload", expect_success=True):
    tgen = get_topogen()
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    rc, out, err = router.net.cmd_status(
        f"{frrdir}/frr-reload.py {mode} --stdout {conf}", warn=False
    )
    if expect_success:
        assert rc == 0, f"frr-reload.py {mode} {conf} failed (rc={rc}):\n{out}\n{err}"
    else:
        assert rc != 0, f"frr-reload.py {mode} {conf} did not fail:\n{out}\n{err}"
    return out


def check_descriptions(router, expected):
    "Check the interface descriptions, None meaning no description."

    def _check():
        for ifname, desc in expected.items():
            output = json.loads(router.vtysh_cmd(f"show interface {ifname} json"))
            if ifname not in output:
                return f"{ifname} not found"
            # Addresses must survive the description changes
            if not output[ifname].get("ipAddresses"):
                return f"{ifname} lost its IP address"
            current = output[ifname].get("description")
            if current != desc:
                return f"{ifname} description is {current!r}, expected {desc!r}"
        return None

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, result


def running_stanza(router, header):
    "Return the running configuration stanza that starts with header."
    stanza = []
    for line in router.vtysh_cmd("show running-config").splitlines():
        if line == header:
            stanza.append(line)
        elif stanza:
            stanza.append(line)
            if line == "exit":
                break
    return stanza


def check_stanzas(router, expected):
    "Check the running configuration stanzas match exactly."

    def _check():
        diff = []
        for header, text in expected.items():
            diff.extend(
                difflib.unified_diff(
                    running_stanza(router, header),
                    text.strip().splitlines(),
                    "running",
                    "expected",
                    lineterm="",
                )
            )
        return "\n".join(diff)

    _, result = topotest.run_and_expect(_check, "", count=30, wait=1)
    assert result == "", f"running configuration differs:\n{result}"


def check_nothing_to_reload(router, conf):
    """
    frr-reload.py --test must find nothing left to change after a reload.
    "log commands" and "domainname" are ignored: topotest daemons always run
    with the first, take the second from the host, and the config files have
    neither.
    """
    out = frr_reload(router, conf, mode="--test")
    delta = out.split("Lines To", 1)[1] if "Lines To" in out else ""
    leftover = [
        line
        for line in delta.splitlines()[1:]
        if line.strip()
        and not line.startswith(("Lines To", "====="))
        and not line.strip().startswith(IGNORED_DELTA)
    ]
    assert not leftover, f"unexpected delta after reload:\n{out}"


def test_initial_config():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    check_descriptions(r1, ORIGINAL_DESCRIPTIONS)
    check_stanzas(r1, ORIGINAL_STANZAS)
    check_nothing_to_reload(r1, ORIGINAL_CONF)


def test_reload_remove_and_change():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    frr_reload(r1, NEW_CONF)
    check_descriptions(r1, NEW_DESCRIPTIONS)
    check_stanzas(r1, NEW_STANZAS)
    check_nothing_to_reload(r1, NEW_CONF)


def test_reload_restore():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    frr_reload(r1, ORIGINAL_CONF)
    check_descriptions(r1, ORIGINAL_DESCRIPTIONS)
    check_stanzas(r1, ORIGINAL_STANZAS)
    check_nothing_to_reload(r1, ORIGINAL_CONF)


def test_reload_commit_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r1.vtysh_multicmd(
        """
configure
affinity-map blue bit-position 1
interface r1-eth2
 link-params
  affinity blue
 exit-link-params
exit
"""
    )
    assert "affinity-map blue" in r1.vtysh_cmd("show running-config")

    # "no affinity-map blue" is rejected, so the reload must fail, but every
    # other delete must still be applied.
    frr_reload(r1, NEW_AFFINITY_CONF, expect_success=False)
    check_descriptions(r1, NEW_DESCRIPTIONS)
    check_stanzas(r1, NEW_STANZAS)
    assert "affinity-map blue" in r1.vtysh_cmd("show running-config")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
