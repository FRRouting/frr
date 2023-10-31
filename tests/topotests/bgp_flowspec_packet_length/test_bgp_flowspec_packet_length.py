#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright 2023 6WIND S.A.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

import os
import sys
import json
import re
import pytest
import functools
import subprocess

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step
from lib.topolog import logger


def build_topo(tgen):
    #
    # Define FRR Routers
    #
    for routern in range(2, 4):
        tgen.add_router("r{}".format(routern))

    ## Add eBGP ExaBGP neighbors
    r1 = tgen.add_exabgp_peer("r1", ip="192.168.1.1", defaultRoute="via 192.168.1.2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


#
# Check version of exabgp against known minimum level for
# syntax compatibility. Cache result.
#
def exabgp_version_ok():
    def _versiontuple(v):
        return tuple(map(int, (v.split("."))))

    logger.info("checking exabgp version")
    try:
        vstr = subprocess.check_output(["exabgp", "--version"], universal_newlines=True)
    except Exception as err:
        logger.warning(err)
        return False, "Cannot check Exabgp version"
    m = re.search(r"ExaBGP : ([\d\.]+)", vstr)
    if m:
        actual = _versiontuple(m.group(1))
        # We know 3.X is too old (syntax errors on our filter cmds).
        # Not sure what is the real minimum version.
        min_version = "4.1.2"
        minimum = _versiontuple(min_version)
        logger.info("Exabgp version is %s" % m.group(1))
        assert_msg = "Exabgp version %s is incompatible. Expecting >=  %s" % (
            m.group(1),
            min_version,
        )
        assert actual >= minimum, assert_msg

    return False, "Cannot check Exabgp version"


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
            "-M wrap_script",
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    exabgp_version_ok()

    peer_dir = os.path.join(CWD, "r1")
    env_file = os.path.join(CWD, "exabgp.env")
    tgen.gears["r1"].start(peer_dir, env_file)
    tgen.gears["r1"].run("ip address add dev lo 192.0.2.1/32")


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def bgp_prefixes(rname, count):
    tgen = get_topogen()

    if rname == "r2":
        expected = {
            "ipv4Flowspec": {
                "peers": {"192.0.2.1": {"pfxRcd": count, "state": "Established"}},
                "peers": {"192.0.2.3": {"pfxSnt": count, "state": "Established"}},
            },
        }
    elif rname == "r3":
        expected = {
            "ipv4Flowspec": {
                "peers": {"192.0.2.2": {"pfxRcd": count, "state": "Established"}},
            },
        }
    else:
        assert False, "Wrong router name"

    router = tgen.gears[rname]
    output = router.vtysh_cmd("show bgp summary json")
    json_output = json.loads(output)

    return topotest.json_cmp(json_output, expected)


def iptables(rname, expected):
    tgen = get_topogen()

    router = tgen.gears[rname]
    output = router.run("iptables -t mangle --list PREROUTING")
    length_values = re.findall(r"length (\d+(?::\d+)?)", output)

    return topotest.json_cmp(sorted(length_values), sorted(expected), exact=True)


def test_bgp_flowspec_prefix_list_convergence():
    """
    10 flowspec prefixes are sent on ipv4 adress family from r1 (ExaBGP).
    r2 and r3 must receive 10 prefixes.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    test_func = functools.partial(bgp_prefixes, "r2", 10)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge initial topology - error on r2"

    test_func = functools.partial(bgp_prefixes, "r3", 10)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge initial topology - error on r3"


def test_bgp_flowspec_prefix_list_test1():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
router bgp 65003
 address-family ipv4 flowspec
  neighbor 192.0.2.2 route-map RMAP_FLOWSPEC_4 in
 exit-address-family
exit
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.1/32
!
route-map RMAP_FLOWSPEC_4 permit 10
 match ip address prefix-list PLIST_FLOWSPEC_4
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", ["0:199"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test2():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.2/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", ["201:65535"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test3():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.3/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", ["0:200"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test4():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.4/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", ["200:65535"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test5():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.5/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", ["200"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test6():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.6/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", ["200", "300", "400"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test7():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.7/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", ["201:299"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test8():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.8/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", ["200:300"])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test9():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.9/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(
        iptables, "r3", ["101:199", "301:399", "501:599", "701:799", "1001:1099"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


def test_bgp_flowspec_prefix_list_test10():
    """
    Apply a prefix-list to select one prefix only and check the installed
    iptables rule(s).
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 deny any
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(iptables, "r3", [])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 198.51.100.10/32
"""
    )

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"

    test_func = functools.partial(
        iptables, "r3", ["100:200", "300:400", "500:600", "700:800", "1000:1100"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Unexpected iptables rules on r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
