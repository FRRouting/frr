# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestNexthopIter(frrtest.TestMultiOut):
    program = "./test_nexthop_iter"


TestNexthopIter.onesimple("Simple test passed.")
TestNexthopIter.onesimple("PRNG test passed.")
