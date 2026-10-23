# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestEcommunity(frrtest.TestMultiOut):
    program = "./test_ecommunity"


TestEcommunity.okfail("ipaddr")
TestEcommunity.okfail("ipaddr-so")
TestEcommunity.okfail("asn")
TestEcommunity.okfail("asn4")
TestEcommunity.okfail("lb-gbps")
TestEcommunity.okfail("lb-mbps")
TestEcommunity.okfail("lb-ipv6-gbps")
TestEcommunity.okfail("color-format")
TestEcommunity.okfail("color-format-co")
TestEcommunity.okfail("color-format-max")
