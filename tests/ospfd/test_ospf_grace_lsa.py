# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestOspfGraceLsa(frrtest.TestMultiOut):
    program = "./test_ospf_grace_lsa"


TestOspfGraceLsa.okfail("grace-lsa: show a valid grace LSA")
TestOspfGraceLsa.okfail("grace-lsa: show steps over unknown TLVs")
