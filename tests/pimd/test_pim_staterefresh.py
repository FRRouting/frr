# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestPimStateRefresh(frrtest.TestMultiOut):
    program = "./test_pim_staterefresh"


TestPimStateRefresh.okfail("originate: pruned interface sets P")
TestPimStateRefresh.okfail("originate: forwarding interface clears P")
TestPimStateRefresh.okfail("originate: no (S,G) state clears P")
TestPimStateRefresh.okfail("originate: prune flag alone sets P")
TestPimStateRefresh.okfail("originate: every flag but prune clears P")
TestPimStateRefresh.okfail(
    "forward: pruned interface sets P and restarts the prune timer"
)
TestPimStateRefresh.okfail(
    "forward: forwarding interface clears P, prune timer untouched"
)
TestPimStateRefresh.okfail("forward: no (S,G) state clears P")
TestPimStateRefresh.okfail("forward: TTL 2 is forwarded with the prune state")
TestPimStateRefresh.okfail("forward: TTL 1 is not forwarded")
TestPimStateRefresh.okfail("forward: interface that lost the assert is skipped")
