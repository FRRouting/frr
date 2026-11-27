# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestIsisFloodReduction(frrtest.TestMultiOut):
    program = "./test_isis_flood_reduction"


TestIsisFloodReduction.onesimple("All tests passed.")
TestIsisFloodReduction.exit_cleanly()
