import frrtest

class TestTable(frrtest.TestMultiOut):
    program = './test_bgp_table'

for i in range(9):
    TestTable.onesimple('Checks successfull')
