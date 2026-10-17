# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Qipeng Ding
import frrtest


class TestClassicNlriAttr(frrtest.TestMultiOut):
    program = "./test_classic_nlri_attr"


TestClassicNlriAttr.okfail(
    "Classic NLRI next-hop context and original MP attributes preserved."
)
