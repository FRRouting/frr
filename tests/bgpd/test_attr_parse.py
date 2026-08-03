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
