# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestOspfSrExtLsa(frrtest.TestMultiOut):
    program = "./test_ospf_sr_ext_lsa"


TestOspfSrExtLsa.okfail(
    "sr-ext-lsa: Extended Link and Prefix TLVs are read within the LSA"
)
