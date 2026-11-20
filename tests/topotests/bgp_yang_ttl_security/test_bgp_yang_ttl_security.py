#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_ttl_security.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
ttl-security and ebgp-multihop are mutually exclusive.

A neighbor created in the same commit has no running peer yet, so the
check has to use the candidate. Replacing one knob with the other in
that same commit is allowed.
"""

import os
import sys
import subprocess
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _vtysh_text(err):
    output = getattr(err.value, "output", b"") or b""
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    stderr = getattr(err.value, "stderr", b"") or b""
    if isinstance(stderr, bytes):
        stderr = stderr.decode(errors="replace")
    return output + stderr


def _reject(router, commands):
    with pytest.raises(subprocess.CalledProcessError) as err:
        router.vtysh_multicmd(commands, pretty_output=False, raises=True)
    return _vtysh_text(err)


def _accept(router, commands):
    router.vtysh_multicmd(commands, pretty_output=False, raises=True)


def test_ttl_security_and_ebgp_multihop_are_exclusive():
    "both knobs in one candidate are rejected; replacing one is kept"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    text = _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.2 remote-as 65001
 neighbor 192.0.2.2 ttl-security hops 1
 neighbor 192.0.2.2 ebgp-multihop
""",
    )
    assert (
        "mutually exclusive" in text
        or "Cannot configure both ttl-security hops and ebgp-multihop" in text
    )

    text = _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.3 remote-as 65001
 neighbor 192.0.2.3 ebgp-multihop
 neighbor 192.0.2.3 ttl-security hops 1
""",
    )
    assert (
        "mutually exclusive" in text
        or "Cannot configure both ttl-security hops and ebgp-multihop" in text
    )

    text = _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.4 remote-as 65001
 neighbor 192.0.2.4 ebgp-multihop 5
 neighbor 192.0.2.4 ttl-security hops 1
""",
    )
    assert (
        "mutually exclusive" in text
        or "Cannot configure both ttl-security hops and ebgp-multihop" in text
    )

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.2" not in running
    assert "neighbor 192.0.2.3" not in running
    assert "neighbor 192.0.2.4" not in running

    _accept(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.2 remote-as 65001
 neighbor 192.0.2.2 ttl-security hops 1
""",
    )
    text = _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.2 ebgp-multihop
""",
    )
    assert "mutually exclusive" in text

    _accept(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.3 remote-as 65001
 neighbor 192.0.2.3 ebgp-multihop
""",
    )
    text = _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.3 ttl-security hops 1
""",
    )
    assert "Cannot configure both ttl-security hops and ebgp-multihop" in text

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.2 ttl-security hops 1" in running
    assert "neighbor 192.0.2.2 ebgp-multihop" not in running
    assert "neighbor 192.0.2.3 ebgp-multihop" in running
    assert "neighbor 192.0.2.3 ttl-security" not in running

    _accept(
        r1,
        """
router bgp 65000
 no neighbor 192.0.2.3 ebgp-multihop
 neighbor 192.0.2.3 ttl-security hops 1
""",
    )
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.3 ttl-security hops 1" in running
    assert "neighbor 192.0.2.3 ebgp-multihop" not in running

    text = _reject(
        r1,
        """
router bgp 65000
 neighbor PG peer-group
 neighbor PG remote-as 65001
 neighbor PG ttl-security hops 1
 neighbor 192.0.2.10 remote-as 65001
 neighbor 192.0.2.10 ebgp-multihop
 neighbor 192.0.2.10 peer-group PG
""",
    )
    assert (
        "mutually exclusive" in text
        or "Cannot configure both ttl-security hops and ebgp-multihop" in text
    )
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor PG peer-group" not in running
    assert "neighbor 192.0.2.10" not in running

    _accept(
        r1,
        """
router bgp 65000
 neighbor PG2 peer-group
 neighbor PG2 remote-as 65001
 neighbor PG2 ttl-security hops 1
 neighbor 192.0.2.11 remote-as 65001
 neighbor 192.0.2.11 peer-group PG2
""",
    )
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor PG2 peer-group" in running
    assert "neighbor PG2 ttl-security hops 1" in running
    assert "neighbor 192.0.2.11 peer-group PG2" in running

    _accept(
        r1,
        """
router bgp 65000
 neighbor PG_MIX peer-group
 neighbor PG_MIX remote-as 65001
 neighbor 192.0.2.36 remote-as 65001
 neighbor 192.0.2.36 peer-group PG_MIX
 neighbor 192.0.2.36 ttl-security hops 2
""",
    )
    text = _reject(
        r1,
        """
router bgp 65000
 neighbor PG_MIX ebgp-multihop
""",
    )
    assert "mutually exclusive" in text
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor PG_MIX ebgp-multihop" not in running
    assert "neighbor 192.0.2.36 ttl-security hops 2" in running

    _accept(
        r1,
        """
router bgp 65000
 neighbor PG_INH peer-group
 neighbor PG_INH remote-as 65001
 neighbor PG_INH ebgp-multihop 5
 neighbor 192.0.2.37 remote-as 65001
 neighbor 192.0.2.37 peer-group PG_INH
 no neighbor 192.0.2.37 ebgp-multihop
""",
    )
    text = _reject(
        r1,
        """
router bgp 65000
 neighbor 192.0.2.37 ttl-security hops 2
""",
    )
    assert "Cannot configure both ttl-security hops and ebgp-multihop" in text
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor 192.0.2.37 ttl-security" not in running
    assert "neighbor PG_INH ebgp-multihop 5" in running

    text = _reject(
        r1,
        """
router bgp 65000
 neighbor eth0 interface remote-as external
 neighbor eth0 ebgp-multihop
""",
    )
    assert "ebgp-multihop not valid for interface peer" in text

    text = _reject(
        r1,
        """
router bgp 65000
 neighbor eth0 interface remote-as external
 neighbor eth0 ttl-security hops 2
""",
    )
    assert "interface peer hops cannot exceed 1" in text

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor eth0" not in running

    _accept(
        r1,
        """
router bgp 65000
 neighbor eth0 interface remote-as external
 neighbor eth0 ttl-security hops 1
""",
    )
    running = r1.vtysh_cmd("show running-config")
    assert "neighbor eth0 interface" in running
    assert "neighbor eth0 ttl-security hops 1" in running
    assert "neighbor eth0 ebgp-multihop" not in running


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
