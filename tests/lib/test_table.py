import frrtest

class TestTable(frrtest.TestMultiOut):
    program = './test_table'

for i in range(6):
    TestTable.onesimple('Verifying cmp')
for i in range(11):
    TestTable.onesimple('Verifying successor')
TestTable.onesimple('Verified pausing')
