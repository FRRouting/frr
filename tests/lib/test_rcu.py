# SPDX-License-Identifier: ISC
import frrtest


class TestRcu(frrtest.TestMultiOut):
    program = "./test_rcu"


TestRcu.exit_cleanly()
