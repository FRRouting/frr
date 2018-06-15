import frrtest

class TestTable(frrtest.TestMultiOut):
    program = './test_bgp_table'

for i in range(6):
    TestTable.onesimple('Checks successfull')
