# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpNbCandidate(frrtest.TestMultiOut):
    program = "./test_bgp_nb_candidate"


TestBgpNbCandidate.okfail("P0-01 instance_key")
TestBgpNbCandidate.okfail("P0-02/P0-03 each_instance & evpn_underlay")
TestBgpNbCandidate.okfail("P0-04/P0-05 group_members & peer_sort")
TestBgpNbCandidate.okfail("P0-06 enabled_afs")
TestBgpNbCandidate.okfail("P0-07 assert_applied")
TestBgpNbCandidate.okfail("P0 nb_transaction candidate_vs_running_and_swap")
