# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpUnaligned(frrtest.TestMultiOut):
    program = "./test_bgp_unaligned"


TestBgpUnaligned.okfail("route target is displayed")
TestBgpUnaligned.okfail("node target is displayed")
TestBgpUnaligned.okfail("node target matches the local ID")
TestBgpUnaligned.okfail("node target does not match another ID")
TestBgpUnaligned.okfail("route target is not a node target match")
TestBgpUnaligned.okfail("node target 255.255.255.255 is displayed")
TestBgpUnaligned.okfail("second node target matches the local ID")
TestBgpUnaligned.okfail("cluster list value 4-octet aligned")
TestBgpUnaligned.okfail("cluster list of 3 octets is malformed")
TestBgpUnaligned.okfail("cluster list value at offset 2 mod 4")
TestBgpUnaligned.okfail("cluster list value at an odd offset")
TestBgpUnaligned.okfail("two cluster IDs at an odd offset")
TestBgpUnaligned.okfail("63 cluster IDs, the most without extended length")
TestBgpUnaligned.okfail("64 cluster IDs with extended length")
TestBgpUnaligned.okfail("65 cluster IDs with extended length")
