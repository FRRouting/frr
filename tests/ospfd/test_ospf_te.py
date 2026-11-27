# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestOspfTe(frrtest.TestMultiOut):
    program = "./test_ospf_te"


TestOspfTe.okfail("area router LSA from 10.0.0.1 updates the TED")
TestOspfTe.okfail("area RI LSA from 10.0.0.1 updates the TED")
TestOspfTe.okfail("area Ext-Prefix LSA from 10.0.0.1 updates the TED")
TestOspfTe.okfail("ls_subnet_add() from 10.0.0.1 adds the subnet and its vertex")
TestOspfTe.okfail("AS-scope RI LSA with only a capabilities TLV is ignored")
TestOspfTe.okfail("AS-scope RI LSA with SR-Algorithm is ignored")
TestOspfTe.okfail("AS-scope Ext-Prefix LSA is handled")
TestOspfTe.okfail("AS-scope Ext-Link LSA is rejected")
TestOspfTe.okfail("router LSA from 0.0.0.0 is rejected")
TestOspfTe.okfail("area RI LSA from 0.0.0.0 is rejected")
TestOspfTe.okfail("area Ext-Prefix LSA from 0.0.0.0 is rejected")
TestOspfTe.okfail("ls_subnet_add() from 0.0.0.0 returns NULL")
TestOspfTe.okfail("AS-scope RI LSA with header only is rejected, no vertex")
TestOspfTe.okfail("area RI LSA with header only is rejected, no vertex")
TestOspfTe.okfail("AS-scope RI LSA from an area router leaves its vertex unchanged")
TestOspfTe.okfail("deleting an AS-scope RI LSA keeps area SR information")
TestOspfTe.okfail("deleting an installed AS-scope Ext-Prefix LSA clears its SID")
TestOspfTe.okfail("deleting an unknown AS-scope RI LSA is rejected")
TestOspfTe.okfail("deleting an unknown area RI LSA is rejected")
