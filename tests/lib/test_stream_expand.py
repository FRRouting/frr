# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestStreamExpand(frrtest.TestMultiOut):
    program = "./test_stream_expand"


TestStreamExpand.okfail("stream_put-expand-empty")
TestStreamExpand.okfail("stream_put-null-expand-empty")
TestStreamExpand.okfail("stream_put-expand-partial")
TestStreamExpand.okfail("stream_put-expand-full")
TestStreamExpand.okfail("stream_write-expand-empty")
TestStreamExpand.okfail("stream_write-expand-full")
