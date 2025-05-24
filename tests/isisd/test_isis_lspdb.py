# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestIsisLSPDB(frrtest.TestMultiOut):
    program = "./test_isis_lspdb"


TestIsisLSPDB.exit_cleanly()
