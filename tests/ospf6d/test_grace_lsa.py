# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestGraceLsa(frrtest.TestMultiOut):
    program = "./test_grace_lsa"


TestGraceLsa.okfail("grace-lsa: valid grace period and restart reason")
TestGraceLsa.okfail("grace-lsa: empty grace period TLV before another TLV")
TestGraceLsa.okfail("grace-lsa: empty restart reason TLV before another TLV")
TestGraceLsa.okfail("grace-lsa: empty grace period TLV at the end of the LSA")
TestGraceLsa.okfail("grace-lsa: show steps over an unknown TLV")
TestGraceLsa.okfail("grace-lsa: show an unknown restart reason")
