# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestVersionCmp(frrtest.TestMultiOut):
    program = "./test_versioncmp"


TestVersionCmp.exit_cleanly()
