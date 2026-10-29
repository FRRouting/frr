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
6. Run a deletion file where vtysh rejects a context line. vtysh then leaves
   the file at that context's "exit", so the deletes after it must still be
   applied.

Additional tests for exec_delete_lines() and lines_to_del handling:

7. Test deletion of ip/ipv6 static routes via exec_delete_lines().
8. Test deletion of bgp community-list, large-community-list, extcommunity-list,
   and as-path access-list (all with seq numbers) via exec_delete_lines().
9. End-to-end frr-reload.py --reload test for static routes, prefix-lists,
   and access-lists to verify the full flow from compare_context_objects()
   through ignore_delete_re_add_lines() to exec_delete_lines().
10. Test that entries with seq numbers in running config correctly match
    entries without seq numbers in the target config (no spurious changes).
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

pytestmark = [
    pytest.mark.ospfd,
    pytest.mark.ospf6d,
    pytest.mark.bgpd,
    pytest.mark.staticd,
]

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


def test_delete_file_failed_context():
    """
    A rejected context line must not stop the rest of the deletion file.

    When vtysh rejects the line that enters a context, it stays at the
    config node, so the "exit" closing that context leaves the config file
    ("early exit from config file") and vtysh stops reading it. Only the
    entry with the rejected lines is retried, so every delete after it must
    still be applied.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    prefix_lists = (
        "ip prefix-list PL-BEFORE seq 5 permit 10.0.0.0/8",
        "ip prefix-list PL-AFTER seq 5 permit 172.16.0.0/12",
    )
    r1.vtysh_multicmd("configure\n" + "\n".join(prefix_lists) + "\n")
    running = r1.vtysh_cmd("show running-config")
    for prefix_list in prefix_lists:
        assert prefix_list in running

    # "router unknown" stands for any context line vtysh rejects.
    entries = [
        ((prefix_lists[0],), None),
        (("router unknown",), "foo bar"),
        ((prefix_lists[1],), None),
    ]
    rc, out, err = r1.net.cmd_status(
        f"""python3 - <<'EOF'
import importlib.util

spec = importlib.util.spec_from_file_location(
    "frr_reload", "{frrdir}/frr-reload.py"
)
reload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reload)
ok = reload.exec_delete_lines(reload.Vtysh(), "/var/run/frr", {entries!r})
print("exec_delete_lines returned", ok)
EOF""",
        warn=False,
    )
    assert rc == 0, f"running exec_delete_lines failed:\n{out}\n{err}"
    # The "router unknown" entry cannot be deleted.
    assert "exec_delete_lines returned False" in out, out

    running = r1.vtysh_cmd("show running-config")
    for prefix_list in prefix_lists:
        assert prefix_list not in running, f"{prefix_list!r} was not deleted"


def test_static_route_deletion():
    """
    Static route deletions must go through exec_delete_lines successfully.

    This tests the code path where ip/ipv6 route deletions are kept in
    lines_to_del (processed via exec_delete_lines with vtysh -f) rather
    than being moved to lines_to_add with a "no " prefix.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")

    static_routes = (
        "ip route 192.0.2.0/24 Null0",
        "ip route 198.51.100.0/24 Null0",
        "ipv6 route 2001:db8:1::/48 Null0",
        "ipv6 route 2001:db8:2::/48 Null0",
    )
    r1.vtysh_multicmd("configure\n" + "\n".join(static_routes) + "\n")
    running = r1.vtysh_cmd("show running-config")
    for route in static_routes:
        assert route in running, f"{route!r} not in running config"

    entries = [((route,), None) for route in static_routes]
    rc, out, err = r1.net.cmd_status(
        f"""python3 - <<'EOF'
import importlib.util

spec = importlib.util.spec_from_file_location(
    "frr_reload", "{frrdir}/frr-reload.py"
)
reload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reload)
ok = reload.exec_delete_lines(reload.Vtysh(), "/var/run/frr", {entries!r})
print("exec_delete_lines returned", ok)
EOF""",
        warn=False,
    )
    assert rc == 0, f"running exec_delete_lines failed:\n{out}\n{err}"
    assert "exec_delete_lines returned True" in out, out

    running = r1.vtysh_cmd("show running-config")
    for route in static_routes:
        assert route not in running, f"{route!r} was not deleted"


def test_bgp_community_list_deletion():
    """
    BGP community-list deletions with seq numbers must be handled correctly.

    The running config always includes seq numbers, but user config may omit
    them. When deleting (not re-adding), the delete must go through
    exec_delete_lines successfully.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")

    community_lists = (
        "bgp community-list standard CLIST1 seq 5 permit 65000:100",
        "bgp community-list standard CLIST1 seq 10 permit 65000:200",
        "bgp large-community-list standard LCLIST1 seq 5 permit 65000:1:1",
        "bgp large-community-list standard LCLIST1 seq 10 permit 65000:1:2",
        "bgp extcommunity-list standard ECLIST1 seq 5 permit rt 65000:100",
        "bgp extcommunity-list standard ECLIST1 seq 10 permit rt 65000:200",
    )
    r1.vtysh_multicmd("configure\n" + "\n".join(community_lists) + "\n")
    running = r1.vtysh_cmd("show running-config")
    for clist in community_lists:
        assert clist in running, f"{clist!r} not in running config"

    entries = [((clist,), None) for clist in community_lists]
    rc, out, err = r1.net.cmd_status(
        f"""python3 - <<'EOF'
import importlib.util

spec = importlib.util.spec_from_file_location(
    "frr_reload", "{frrdir}/frr-reload.py"
)
reload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reload)
ok = reload.exec_delete_lines(reload.Vtysh(), "/var/run/frr", {entries!r})
print("exec_delete_lines returned", ok)
EOF""",
        warn=False,
    )
    assert rc == 0, f"running exec_delete_lines failed:\n{out}\n{err}"
    assert "exec_delete_lines returned True" in out, out

    running = r1.vtysh_cmd("show running-config")
    for clist in community_lists:
        assert clist not in running, f"{clist!r} was not deleted"


def test_bgp_aspath_access_list_deletion():
    """
    BGP as-path access-list deletions with seq numbers must be handled correctly.

    The running config always includes seq numbers. When deleting (not re-adding),
    the delete must go through exec_delete_lines successfully.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")

    aspath_lists = (
        "bgp as-path access-list ASPATH1 seq 5 permit ^65000$",
        "bgp as-path access-list ASPATH1 seq 10 permit ^65001_",
        "bgp as-path access-list ASPATH2 seq 5 deny .*",
    )
    r1.vtysh_multicmd("configure\n" + "\n".join(aspath_lists) + "\n")
    running = r1.vtysh_cmd("show running-config")
    for aslist in aspath_lists:
        assert aslist in running, f"{aslist!r} not in running config"

    entries = [((aslist,), None) for aslist in aspath_lists]
    rc, out, err = r1.net.cmd_status(
        f"""python3 - <<'EOF'
import importlib.util

spec = importlib.util.spec_from_file_location(
    "frr_reload", "{frrdir}/frr-reload.py"
)
reload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reload)
ok = reload.exec_delete_lines(reload.Vtysh(), "/var/run/frr", {entries!r})
print("exec_delete_lines returned", ok)
EOF""",
        warn=False,
    )
    assert rc == 0, f"running exec_delete_lines failed:\n{out}\n{err}"
    assert "exec_delete_lines returned True" in out, out

    running = r1.vtysh_cmd("show running-config")
    for aslist in aspath_lists:
        assert aslist not in running, f"{aslist!r} was not deleted"


def test_frr_reload_static_route_prefix_and_access_list():
    """
    End-to-end test: frr-reload.py --reload removes static routes, prefix-lists,
    and access-lists.

    This tests the full flow from compare_context_objects() through
    ignore_delete_re_add_lines() to exec_delete_lines() for:
    - ip/ipv6 static routes (compare_context_objects change)
    - ip/ipv6 prefix-lists with seq numbers (ignore_delete_re_add_lines change)
    - ip/ipv6 access-lists with seq numbers (ignore_delete_re_add_lines change)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Add static routes, prefix-lists, and access-lists to running config
    extra_config = """
configure
ip route 203.0.113.0/24 Null0
ipv6 route 2001:db8:ffff::/48 Null0
ip prefix-list PL-TEST seq 5 permit 10.10.0.0/16
ip prefix-list PL-TEST seq 10 permit 10.20.0.0/16
ipv6 prefix-list PL6-TEST seq 5 permit 2001:db8:1000::/48
access-list ACL1 seq 5 permit 10.0.0.0/8
access-list ACL1 seq 10 deny any
ipv6 access-list ACL6 seq 5 permit 2001:db8::/32
"""
    r1.vtysh_multicmd(extra_config)

    running = r1.vtysh_cmd("show running-config")
    assert "ip route 203.0.113.0/24 Null0" in running
    assert "ipv6 route 2001:db8:ffff::/48 Null0" in running
    assert "ip prefix-list PL-TEST seq 5 permit 10.10.0.0/16" in running
    assert "ipv6 prefix-list PL6-TEST seq 5 permit 2001:db8:1000::/48" in running
    assert "access-list ACL1 seq 5 permit 10.0.0.0/8" in running
    assert "ipv6 access-list ACL6 seq 5 permit 2001:db8::/32" in running

    # Reload with original config (without these entries) - they should be deleted
    frr_reload(r1, ORIGINAL_CONF)

    running = r1.vtysh_cmd("show running-config")
    assert "ip route 203.0.113.0/24" not in running, "static route not deleted"
    assert "ipv6 route 2001:db8:ffff::" not in running, "ipv6 static route not deleted"
    assert "ip prefix-list PL-TEST" not in running, "ip prefix-list not deleted"
    assert "ipv6 prefix-list PL6-TEST" not in running, "ipv6 prefix-list not deleted"
    assert "access-list ACL1" not in running, "access-list not deleted"
    assert "ipv6 access-list ACL6" not in running, "ipv6 access-list not deleted"

    # Verify frr-reload --test shows no remaining changes
    delta = frr_reload(r1, ORIGINAL_CONF, mode="--test")
    for line in delta.splitlines():
        if line.startswith(("+", "-")) and not any(
            line.startswith(ign) for ign in IGNORED_DELTA
        ):
            assert False, f"Unexpected delta after reload: {line}"


def test_frr_reload_seq_number_matching():
    """
    Test that entries with seq numbers in running config match entries without
    seq numbers in the target config.

    The running config always includes seq numbers for prefix-lists, access-lists,
    and community-lists. When the target config has the same entries without seq
    numbers, frr-reload should recognize them as identical and make no changes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")

    # Add config entries (running config will include seq numbers)
    extra_config = """
configure
ip prefix-list PL-SEQ permit 10.10.0.0/16
ip prefix-list PL-SEQ permit 10.20.0.0/16
ipv6 prefix-list PL6-SEQ permit 2001:db8:1000::/48
access-list ACL-SEQ permit 172.16.0.0/12
ipv6 access-list ACL6-SEQ permit 2001:db8:2000::/48
bgp community-list standard CL-SEQ permit 65000:100
bgp large-community-list standard LCL-SEQ permit 65000:1:100
bgp extcommunity-list standard ECL-SEQ permit rt 65000:100
bgp as-path access-list ASPL-SEQ permit ^65000$
"""
    r1.vtysh_multicmd(extra_config)

    # Verify running config has seq numbers
    running = r1.vtysh_cmd("show running-config")
    assert "ip prefix-list PL-SEQ seq 5 permit 10.10.0.0/16" in running
    assert "ip prefix-list PL-SEQ seq 10 permit 10.20.0.0/16" in running
    assert "access-list ACL-SEQ seq 5 permit 172.16.0.0/12" in running
    assert "bgp community-list standard CL-SEQ seq 5 permit 65000:100" in running

    # Create target config file with same entries but WITHOUT seq numbers
    target_conf = os.path.join(tgen.logdir, "r1", "target-seq-match.conf")
    os.makedirs(os.path.dirname(target_conf), exist_ok=True)

    # Read original config and append entries without seq numbers
    with open(ORIGINAL_CONF) as f:
        base_config = f.read().rstrip()

    target_lines = (
        base_config
        + """
!
ip prefix-list PL-SEQ permit 10.10.0.0/16
ip prefix-list PL-SEQ permit 10.20.0.0/16
ipv6 prefix-list PL6-SEQ permit 2001:db8:1000::/48
access-list ACL-SEQ permit 172.16.0.0/12
ipv6 access-list ACL6-SEQ permit 2001:db8:2000::/48
bgp community-list standard CL-SEQ permit 65000:100
bgp large-community-list standard LCL-SEQ permit 65000:1:100
bgp extcommunity-list standard ECL-SEQ permit rt 65000:100
bgp as-path access-list ASPL-SEQ permit ^65000$
!
"""
    )
    with open(target_conf, "w") as f:
        f.write(target_lines)

    # frr-reload --test should show no changes for these entries
    # (seq numbers in running match no-seq in target)
    delta = frr_reload(r1, target_conf, mode="--test")

    # Should not see any prefix-list/access-list/community-list changes
    # in the "Lines To Delete" or "Lines To Add" output
    assert "PL-SEQ" not in delta, f"Unexpected delta for PL-SEQ:\n{delta}"
    assert "ACL-SEQ" not in delta, f"Unexpected delta for ACL-SEQ:\n{delta}"
    assert "CL-SEQ" not in delta, f"Unexpected delta for CL-SEQ:\n{delta}"
    assert "LCL-SEQ" not in delta, f"Unexpected delta for LCL-SEQ:\n{delta}"
    assert "ECL-SEQ" not in delta, f"Unexpected delta for ECL-SEQ:\n{delta}"
    assert "ASPL-SEQ" not in delta, f"Unexpected delta for ASPL-SEQ:\n{delta}"

    # Entries should still be present after reload
    frr_reload(r1, target_conf)
    running = r1.vtysh_cmd("show running-config")
    assert "ip prefix-list PL-SEQ seq 5 permit 10.10.0.0/16" in running
    assert "access-list ACL-SEQ seq 5 permit 172.16.0.0/12" in running
    assert "bgp community-list standard CL-SEQ seq 5 permit 65000:100" in running

    # Clean up: reload with original config to remove test entries
    frr_reload(r1, ORIGINAL_CONF)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
