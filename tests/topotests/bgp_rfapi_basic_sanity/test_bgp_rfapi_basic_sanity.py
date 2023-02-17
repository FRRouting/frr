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

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

from lib.ltemplate import *

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


def test_add_routes():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/add_routes.py", False, CliOnFail, CheckFunc)


def test_adjacencies():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/adjacencies.py", False, CliOnFail, CheckFunc)


def test_check_routes():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/check_routes.py", False, CliOnFail, CheckFunc)


def test_check_close():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/check_close.py", False, CliOnFail, CheckFunc)


def test_check_timeout():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/check_timeout.py", False, CliOnFail, CheckFunc)


def test_cleanup_all():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = "ltemplateVersionCheck('3.1')"
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'3.1\', cli=True)'
    ltemplateTest("scripts/cleanup_all.py", False, CliOnFail, CheckFunc)


if __name__ == "__main__":
    retval = pytest.main(["-s"])
    sys.exit(retval)
