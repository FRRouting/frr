# SPDX-License-Identifier: ISC
import frrtest


class TestPtmLib(frrtest.TestMultiOut):
    program = "./test_ptm_lib"


TestPtmLib.exit_cleanly()
