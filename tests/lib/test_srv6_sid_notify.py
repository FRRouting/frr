# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestSrv6SidNotify(frrtest.TestMultiOut):
    program = "./test_srv6_sid_notify"


TestSrv6SidNotify.onesimple("Local-only flag decoded after locator.")
TestSrv6SidNotify.onesimple("Legacy notification defaults to zero flags.")
TestSrv6SidNotify.onesimple("Unused locator and flags are consumed.")
TestSrv6SidNotify.onesimple("Flag decoded when locator output is ignored.")
TestSrv6SidNotify.onesimple("Locator decoded when flag output is ignored.")
TestSrv6SidNotify.onesimple("Alternating legacy and flagged notifications reset the output.")
