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
TestAttrParse.okfail("nexthop-flag-optional-ebgp: NEXT_HOP with the optional bit set, eBGP")
TestAttrParse.okfail("nexthop-len-3-ebgp: NEXT_HOP with length 3, eBGP")
TestAttrParse.okfail("nexthop-len-5-ebgp: NEXT_HOP with length 5, eBGP")
TestAttrParse.okfail("nexthop-len-0-ebgp: NEXT_HOP with length 0, eBGP")
TestAttrParse.okfail(
    "local-pref-len-3-ebgp: LOCAL_PREF length 3 from a plain eBGP peer is discarded"
)
TestAttrParse.okfail(
    "local-pref-len-3-ebgp-oad: LOCAL_PREF length 3 over an OAD session is treat-as-withdraw"
)
TestAttrParse.okfail(
    "local-pref-len-0-ebgp-oad: LOCAL_PREF length 0 over an OAD session is treat-as-withdraw"
)
