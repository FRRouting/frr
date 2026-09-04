# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestIPAssembly(frrtest.TestMultiOut):
    program = "./test_ip_assembly"


TestIPAssembly.onesimple("ALL PASS")
