# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestIsisTlvRouterCap(frrtest.TestMultiOut):
    program = "./test_isis_tlv_router_cap"


TestIsisTlvRouterCap.okfail("one FAD with a one-word admin group")
TestIsisTlvRouterCap.okfail("SRv6 capabilities only")
TestIsisTlvRouterCap.okfail("six largest FADs, one per TLV")
TestIsisTlvRouterCap.okfail("no FAD and no SR: bare router capability")
TestIsisTlvRouterCap.okfail("FAD too large for any TLV is left out")
TestIsisTlvRouterCap.okfail("FADs filling the TLV to exactly 255 bytes")
TestIsisTlvRouterCap.okfail("one admin-group word more than fits starts a second TLV")
TestIsisTlvRouterCap.okfail("largest FAD alone fills one TLV")
TestIsisTlvRouterCap.okfail("SRv6 block after a full TLV goes into a second TLV")
TestIsisTlvRouterCap.okfail("64-word admin group (sub-sub-TLV length 256) is left out")
TestIsisTlvRouterCap.okfail("largest FAD that fits after the IPv6 TE Router ID")
TestIsisTlvRouterCap.okfail("one word more than fits after the IPv6 TE Router ID is left out")
TestIsisTlvRouterCap.okfail("FAD replaced by one too large for any TLV is not kept")
TestIsisTlvRouterCap.okfail("FAD grown too large after it was kept is not encoded")
