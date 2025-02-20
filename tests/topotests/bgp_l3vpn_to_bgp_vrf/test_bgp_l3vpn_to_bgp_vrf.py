#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
#

import os
import sys
import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../"))

from lib.ltemplate import *

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


def test_check_linux_vrf():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('4.1', iproute2='4.9')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_linux_vrf.py", False, CliOnFail, CheckFunc)


def test_adjacencies():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('4.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True)'
    ltemplateTest("scripts/adjacencies.py", False, CliOnFail, CheckFunc)


def test_notification_check():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('4.1', iproute2='4.9')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/notification_check.py", False, CliOnFail, CheckFunc)


def SKIP_test_add_routes():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('4.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True)'
    ltemplateTest("scripts/add_routes.py", False, CliOnFail, CheckFunc)


def test_check_routes():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('4.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True)'
    ltemplateTest("scripts/check_routes.py", False, CliOnFail, CheckFunc)


# manual data path setup test - remove once have bgp/zebra vrf path working
def test_check_linux_mpls():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('4.1', iproute2='4.9')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_linux_mpls.py", False, CliOnFail, CheckFunc)


def test_check_scale_up():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    # Skip test on 32bit platforms (limited memory)
    if sys.maxsize <= 2**32:
        pytest.skip("skipped because of limited memory on 32bit platforms")
    CheckFunc = "ltemplateVersionCheck('4.1', iproute2='4.9')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/scale_up.py", False, CliOnFail, CheckFunc)


def test_check_scale_down():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    # Skip test on 32bit platforms (limited memory)
    if sys.maxsize <= 2**32:
        pytest.skip("skipped because of limited memory on 32bit platforms")
    CheckFunc = "ltemplateVersionCheck('4.1', iproute2='4.9')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/scale_down.py", False, CliOnFail, CheckFunc)


def SKIP_test_cleanup_all():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('4.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True)'
    ltemplateTest("scripts/cleanup_all.py", False, CliOnFail, CheckFunc)


if __name__ == "__main__":
    retval = pytest.main(["-s"])
    sys.exit(retval)
