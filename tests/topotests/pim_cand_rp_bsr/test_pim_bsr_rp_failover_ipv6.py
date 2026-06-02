#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_bsr_rp_failover_ipv6.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, CWD)

from lib.topogen import get_topogen
from lib.common_config import write_test_header

from bsr_rp_failover_helper import (  # pylint: disable=import-error
    setup_module,
    teardown_module,
    verify_rp_failover_after_daemon_stop,
)

"""
Failover when the primary IPv6 RP daemon stops.

FRR advertises a minimum Candidate-RP holdtime of 151 seconds, so this
test waits up to 180 seconds for the backup RP to take over.
"""

pytestmark = [
    pytest.mark.pim6d,
    pytest.mark.ospfd,
    pytest.mark.ospf6d,
]


def test_pim_bsr_rp_failover_ipv6(request):
    "Failover to backup RP when primary pim6d stops (#17588)"
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    verify_rp_failover_after_daemon_stop(
        tgen,
        tc_name,
        "ipv6",
        "ffbb::0/64",
        "fd00:0:0:3::3",
        "fd00:0:0:3::4",
        "pim6d",
    )


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
