# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestIsisTlvExtReach(frrtest.TestMultiOut):
    program = "./test_isis_tlv_ext_reach"


TestIsisTlvExtReach.exit_cleanly()
