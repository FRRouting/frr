# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestSrv6SidNotify(frrtest.TestMultiOut):
    program = "./test_srv6_sid_notify"


TestSrv6SidNotify.onesimple("Names decode without stale suffixes.")
TestSrv6SidNotify.onesimple("Caller buffers retain independent names.")
TestSrv6SidNotify.onesimple("Buffer boundaries reserve space for the terminator.")
TestSrv6SidNotify.onesimple("Unused names are consumed.")
TestSrv6SidNotify.onesimple("Truncated notifications fail and do not poison later decodes.")
