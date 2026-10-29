# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpLsAttr(frrtest.TestMultiOut):
    program = "./test_bgp_ls_attr"


TestBgpLsAttr.okfail("OSPFv2-1: OSPFv2 metric 1 is 2 octets")
TestBgpLsAttr.okfail("OSPFv2-100: OSPFv2 metric 100 is 2 octets")
TestBgpLsAttr.okfail("OSPFv2-1000: OSPFv2 metric 1000 is 2 octets")
TestBgpLsAttr.okfail("OSPFv2-65535: OSPFv2 metric 65535 is 2 octets")
TestBgpLsAttr.okfail("ISIS-L2-10: IS-IS L2 wide metric 10 is 3 octets")
TestBgpLsAttr.okfail("ISIS-L1-1000: IS-IS L1 wide metric 1000 is 3 octets")
TestBgpLsAttr.okfail("ISIS-L2-16777215: IS-IS L2 wide metric 16777215 is 3 octets")
