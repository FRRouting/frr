# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestOspfAdjPacing(frrtest.TestMultiOut):
    program = "./test_ospf_adj_pacing"


TestOspfAdjPacing.okfail("adj-pacing-free: a freed neighbor leaves the adjacency pacing queue")
