# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestRingbuf(frrtest.TestMultiOut):
    program = "./test_ringbuf"


TestRingbuf.exit_cleanly()
