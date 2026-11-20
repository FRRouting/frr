#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_commit_failure.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
Test that a configuration rejected when a pending YANG transaction is
committed is reported to the caller.

The "neighbor X local-as ASN" command is queued as a pending northbound
change.  "exit" is a YANG command and does not flush that batch.  The
commit runs at XFRR_end_configuration.  When it is rejected, the failure
must make "vtysh -f" fail instead of being silently dropped.
"""

import os
import sys
import subprocess
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")

    switch = tgen.add_switch("s1")
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


def _running_config_has(router, text):
    output = router.vtysh_cmd("show running-config")
    return text in output


def test_valid_commit_succeeds():
    "A commit that is accepted must not make vtysh -f fail"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_multicmd(
        """
router bgp 65001
 neighbor 192.0.2.2 remote-as 65002
 neighbor 192.0.2.2 local-as 65003
exit
""",
        pretty_output=False,
        raises=True,
    )

    test_func = lambda: _running_config_has(r1, "neighbor 192.0.2.2 local-as 65003")
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "Accepted local-as is not in the running configuration"


def test_rejected_commit_is_reported():
    "A rejected pending commit must make vtysh -f fail"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # local-as equal to the BGP ASN is refused by the northbound validation.
    with pytest.raises(subprocess.CalledProcessError):
        r1.vtysh_multicmd(
            """
router bgp 65001
 neighbor 192.0.2.3 remote-as 65002
 neighbor 192.0.2.3 local-as 65001
exit
""",
            pretty_output=False,
            raises=True,
        )

    assert not _running_config_has(
        r1, "neighbor 192.0.2.3"
    ), "Rejected transaction was applied to the running configuration"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
