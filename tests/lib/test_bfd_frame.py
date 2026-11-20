# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Aviz Networks
import frrtest


class TestBfdFrame(frrtest.TestMultiOut):
    program = "./test_bfd_frame"


TestBfdFrame.onesimple("BFD frame builder checks passed.")
