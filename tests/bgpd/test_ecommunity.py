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
TestEcommunity.okfail("str: rt 65001:100\n")
TestEcommunity.okfail("str: rt 192.168.1.1:100\n")
TestEcommunity.okfail("str: soo 192.168.1.1:100\n")
TestEcommunity.okfail("str: nt 192.168.1.1:0\n")
TestEcommunity.okfail("str: nt 192.168.1.1:0 nt 10.0.0.1:0\n")
TestEcommunity.okfail("str: nt 65001:100\n")
TestEcommunity.okfail("str: nt 65001:192.168.1.1\n")
TestEcommunity.okfail("str: nt 1.2:3\n")
TestEcommunity.okfail("str: nt 4200000000:1\n")
TestEcommunity.okfail("str: nt 192.168.1.1:5\n")
TestEcommunity.okfail("str: nt 192.168.1.1\n")
TestEcommunity.okfail("str: rt 192.168.1.1\n")
TestEcommunity.okfail("str: rt 100\n")
TestEcommunity.okfail("str: rt 100:\n")
