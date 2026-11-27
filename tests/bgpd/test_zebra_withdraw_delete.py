# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestZebraWithdrawDelete(frrtest.TestMultiOut):
    program = "./test_zebra_withdraw_delete"


TestZebraWithdrawDelete.okfail("normal 198.51.100.0/24")
TestZebraWithdrawDelete.okfail("normal 2001:db8::/64")
TestZebraWithdrawDelete.okfail("early 198.51.100.0/24")
TestZebraWithdrawDelete.okfail("early 2001:db8::/64")
TestZebraWithdrawDelete.okfail("normal retained 198.51.100.0/24")
