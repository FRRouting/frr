# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestSrcdestTable(frrtest.TestMultiOut):
    program = "./test_srcdest_table"


TestSrcdestTable.onesimple("PRNG Test successful.")
