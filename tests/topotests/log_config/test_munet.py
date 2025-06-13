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
from basic import do_test_log, do_test_syslog, setup_test

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

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


def test_log(unet):
    do_test_log(unet)


def test_syslog(unet):
    do_test_syslog(unet)
