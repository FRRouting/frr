# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 by Carmine Scarpitta
import frrtest


class TestLinkState(frrtest.TestMultiOut):
    program = "./test_link_state"


TestLinkState.onesimple("Link State database tests passed.")
