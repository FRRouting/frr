# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpScript(frrtest.TestMultiOut):
    program = "./test_bgp_script"


TestBgpScript.okfail("Scripting")
