import frrtest

class TestOspfSPF(frrtest.TestMultiOut):
    program = './test_ospf_spf'

TestOspfSPF.exit_cleanly()
