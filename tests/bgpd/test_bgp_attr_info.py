# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpAttrInfo(frrtest.TestMultiOut):
    program = "./test_bgp_attr_info"


TestBgpAttrInfo.okfail("one attribute with origin, as-path and next-hop")
TestBgpAttrInfo.okfail("two attributes, one with local-pref")
TestBgpAttrInfo.okfail("three attributes with the same types")
TestBgpAttrInfo.okfail("optional types are counted")
TestBgpAttrInfo.okfail("attribute with no flags is not counted")
TestBgpAttrInfo.okfail("no attributes interned")
TestBgpAttrInfo.okfail("unnamed types 11-13 are not listed")
TestBgpAttrInfo.okfail("lowest type (ORIGIN, flag bit 1)")
TestBgpAttrInfo.okfail("highest named type with a flag bit (PREFIX_SID)")
TestBgpAttrInfo.okfail("type 41, above the highest named type, is not listed")
TestBgpAttrInfo.okfail("flag bit 64 (unnamed type 64) is not listed")
TestBgpAttrInfo.okfail("all 64 flag bits set")
TestBgpAttrInfo.okfail("flag bits 1 and 64 only")
TestBgpAttrInfo.okfail("all 64 flag bits set on three attributes")
