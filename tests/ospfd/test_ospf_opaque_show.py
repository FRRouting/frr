# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestOspfOpaqueShow(frrtest.TestMultiOut):
    program = "./test_ospf_opaque_show"


TestOspfOpaqueShow.okfail("opaque-show: opaque LSA TLVs are displayed within the LSA")
