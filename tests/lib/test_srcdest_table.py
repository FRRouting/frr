import frrtest

class TestSrcdestTable(frrtest.TestMultiOut):
    program = './test_srcdest_table'

TestSrcdestTable.onesimple('PRNG Test successful.')
