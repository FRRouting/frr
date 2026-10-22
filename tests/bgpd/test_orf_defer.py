# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestOrfDefer(frrtest.TestMultiOut):
    program = "./test_orf_defer"


TestOrfDefer.okfail("defer, malformed entry")
TestOrfDefer.okfail("defer, remove the last entries")
TestOrfDefer.okfail("defer, remove-all")
