# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# June 13 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""
Test Logging Config
"""
import pytest
from basic import do_test_filter_file, do_test_log, do_test_syslog, setup_test

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

try:
    from munet.testing.fixtures import rundir_module
except ImportError:
    pytest.skip("munet.testing.fixtures not available", allow_module_level=True)

#
# OSPFd is unconverted daemon
# MGMTd is special daemon that is modern but not a mgmtd backend
# StaticD is a modern converted-to mgmtd backend
#
# Test all three
#


@pytest.fixture(scope="module", autouse=True)
def setup_watchlogs(unet):
    setup_test(unet)


# Running with munet currently is not placing support files under /tmp/topotest so it
# makes debugging remote results impossible. Need to fix this before re-enabling these
# tests.


def _test_log(unet):
    do_test_log(unet)


def _test_filter_file(unet):
    do_test_filter_file(unet)


def _test_syslog(unet):
    do_test_syslog(unet)
