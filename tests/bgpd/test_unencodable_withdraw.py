# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Qipeng Ding
import frrtest


class TestUnencodableWithdraw(frrtest.TestMultiOut):
    program = "./test_unencodable_withdraw"


TestUnencodableWithdraw.okfail(
    "Unencodable replacement, new path, extended limit and recovery:"
)
