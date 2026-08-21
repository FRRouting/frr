# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestZlog(frrtest.TestMultiOut):
    program = "./test_zlog"


TestZlog.onesimple("test hexdump passed")
TestZlog.onesimple("test from child")
TestZlog.onesimple("truncated in recirculation")
TestZlog.onesimple("test truncation")
TestZlog.onesimple("test recirculate passed")
