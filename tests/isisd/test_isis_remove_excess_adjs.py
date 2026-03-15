# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestIsisRemoveExcessAdjs(frrtest.TestMultiOut):
    program = "./test_isis_remove_excess_adjs"


TestIsisRemoveExcessAdjs.exit_cleanly()