# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Qipeng Ding
import frrtest


class TestAttrDisposition(frrtest.TestMultiOut):
    program = "./test_attr_disposition"


TestAttrDisposition.okfail(
    "Deferred withdrawal, fatal dispositions and valid MP policy controls:"
)
