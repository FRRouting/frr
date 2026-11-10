# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestOspfLsaExamin(frrtest.TestMultiOut):
    program = "./test_ospf_lsa_examin"


TestOspfLsaExamin.okfail("router-lsa: accept 2 links:")
TestOspfLsaExamin.okfail("router-lsa: accept no links:")
TestOspfLsaExamin.okfail("router-lsa: accept 2 links, one with a TOS metric:")
TestOspfLsaExamin.okfail("router-lsa: reject 4 bytes after the links:")
TestOspfLsaExamin.okfail("router-lsa: reject 8 bytes after the links:")
TestOspfLsaExamin.okfail("router-lsa: reject 4 bytes and no links:")
TestOspfLsaExamin.okfail("router-lsa: reject 4 bytes after a link with a TOS metric:")
TestOspfLsaExamin.okfail("router-lsa: reject a truncated TOS metric:")
TestOspfLsaExamin.okfail("router-lsa: reject a missing link:")
TestOspfLsaExamin.okfail("router-lsa: reject a header only:")
