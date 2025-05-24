# SPDX-License-Identifier: ISC
import frrtest

class TestXref(frrtest.TestMultiOut):
    program = './test_xref'

TestXref.exit_cleanly()
