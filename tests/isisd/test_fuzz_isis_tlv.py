import frrtest

class TestFuzzIsisTLV(frrtest.TestMultiOut):
    program = './test_fuzz_isis_tlv'

TestFuzzIsisTLV.exit_cleanly()
