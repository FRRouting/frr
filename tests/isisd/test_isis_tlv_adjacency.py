# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestIsisTlvAdjacency(frrtest.TestMultiOut):
    program = "./test_isis_tlv_adjacency"


TestIsisTlvAdjacency.exit_cleanly()
