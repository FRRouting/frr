# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestCli(frrtest.TestRefOut):
    program = "./test_cli"
    built_refout = True
