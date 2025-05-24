# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestEcommunity(frrtest.TestMultiOut):
    program = "./test_ecommunity"


TestEcommunity.okfail("ipaddr")
TestEcommunity.okfail("ipaddr-so")
TestEcommunity.okfail("asn")
TestEcommunity.okfail("asn4")
