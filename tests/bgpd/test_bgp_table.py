import frrtest


class TestTable(frrtest.TestMultiOut):
    program = "./test_bgp_table"


for i in range(7):
    TestTable.onesimple("Checks successfull")
