# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestRefreshTimers(frrtest.TestMultiOut):
    program = "./test_refresh_timers"


TestRefreshTimers.onesimple("family isolation OK")
TestRefreshTimers.onesimple("session cleanup OK")
TestRefreshTimers.onesimple("family deletion OK")
