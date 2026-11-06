# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestNeighborLifecycle(frrtest.TestMultiOut):
    program = "./test_neighbor_lifecycle"


TestNeighborLifecycle.okfail("neighbor: pending events cancelled on delete")
TestNeighborLifecycle.okfail("neighbor: other neighbor's events survive")
TestNeighborLifecycle.okfail("neighbor: interface events survive")
