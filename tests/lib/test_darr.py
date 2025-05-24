# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestDarr(frrtest.TestMultiOut):
    program = "./test_darr"


TestDarr.exit_cleanly()
