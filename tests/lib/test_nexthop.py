# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestNexthopIter(frrtest.TestMultiOut):
    program = "./test_nexthop"


TestNexthopIter.onesimple("Simple test passed.")
