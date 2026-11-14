# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Johan Linder
import frrtest
import pytest


@pytest.mark.skipif(
    'S["BFDD_TRUE"]=""\n' not in open("../config.status").readlines(),
    reason="BFDD not enabled",
)
class TestBfdSession(frrtest.TestMultiOut):
    program = "./test_bfd_session"


TestBfdSession.onesimple("IPv4 BFD key replacement and failure callbacks passed.")
TestBfdSession.onesimple("IPv6 BFD key replacement and failure callbacks passed.")
