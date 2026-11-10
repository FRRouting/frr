# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestEcommunityLbFloat(frrtest.TestMultiOut):
    program = "./test_ecommunity_lb_float"


TestEcommunityLbFloat.okfail("1.5 Gbps (187500000.0)")
TestEcommunityLbFloat.okfail("2.5 Mbps (312500.0)")
TestEcommunityLbFloat.okfail("1.0 byte/s")
TestEcommunityLbFloat.okfail("-1.0 gives 0")
TestEcommunityLbFloat.okfail("-inf gives 0")
TestEcommunityLbFloat.okfail("quiet NaN gives 0")
TestEcommunityLbFloat.okfail("negative NaN gives 0")
TestEcommunityLbFloat.okfail("0.0")
TestEcommunityLbFloat.okfail("0.5 truncates to 0")
TestEcommunityLbFloat.okfail("2^63 is shown in full")
TestEcommunityLbFloat.okfail("largest float below 2^64")
TestEcommunityLbFloat.okfail("2^64 saturates")
TestEcommunityLbFloat.okfail("FLT_MAX saturates")
TestEcommunityLbFloat.okfail("+inf saturates")
TestEcommunityLbFloat.okfail("-0.0 gives 0")
TestEcommunityLbFloat.okfail("smallest denormal gives 0")
TestEcommunityLbFloat.okfail("extended LB at UINT64_MAX is shown in full")
