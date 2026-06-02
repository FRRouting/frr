# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestCommunity(frrtest.TestMultiOut):
    program = "./test_community"


TestCommunity.okfail("large-community-not-truncated")
