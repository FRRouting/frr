# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestOrfInstance(frrtest.TestMultiOut):
    program = "./test_orf_instance"


TestOrfInstance.okfail("each peer has its own ORF prefix-list")
TestOrfInstance.okfail("peer A filters with its own entries only")
TestOrfInstance.okfail("Remove-All from peer B leaves peer A's ORF prefix-list")
TestOrfInstance.okfail("peer B going down leaves peer A's ORF prefix-list")
