# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestEvpnL3mhNeigh(frrtest.TestMultiOut):
    program = "./test_evpn_l3mh_neigh"


TestEvpnL3mhNeigh.onesimple("L3MH neighbor lifecycle transitions passed.")
TestEvpnL3mhNeigh.onesimple("L3MH local binding generation checks passed.")
