# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestAttrParse(frrtest.TestMultiOut):
    program = "./test_attr_parse"


TestAttrParse.okfail("baseline-ebgp: well-formed ORIGIN + AS_PATH + NEXT_HOP, eBGP")
TestAttrParse.okfail(
    "short-attr-header-ebgp: two trailing octets, too few for an attribute header, eBGP"
)
TestAttrParse.okfail(
    "short-attr-header-ibgp: two trailing octets, too few for an attribute header, iBGP"
)
TestAttrParse.okfail(
    "extlen-underflow-ebgp: three trailing octets with Extended Length set, eBGP"
)
TestAttrParse.okfail(
    "extlen-underflow-ibgp: three trailing octets with Extended Length set, iBGP"
)
TestAttrParse.okfail("repeated-attr-ebgp: MULTI_EXIT_DISC twice, eBGP")
TestAttrParse.okfail("repeated-attr-ibgp: MULTI_EXIT_DISC twice, iBGP")
TestAttrParse.okfail(
    "repeated-mp-reach-ibgp: MP_REACH_NLRI twice must still notify, iBGP"
)
TestAttrParse.okfail(
    "prefix-sid-bad-label-index-ebgp: PREFIX_SID with a malformed Label-Index TLV, eBGP"
)
TestAttrParse.okfail("aigp-bad-flags-ibgp: AIGP with the transitive bit set, iBGP")
