import frrtest

class TestNexthopIter(frrtest.TestMultiOut):
    program = './test_nexthop_iter'

TestNexthopIter.onesimple('Simple test passed.')
TestNexthopIter.onesimple('PRNG test passed.')
