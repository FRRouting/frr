# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBfdTimer(frrtest.TestMultiOut):
    program = "./test_bfd_timer"


TestBfdTimer.onesimple(
    "BFD detection-time arithmetic and normalized timer conversion passed."
)
