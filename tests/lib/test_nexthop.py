import frrtest


class TestNexthopIter(frrtest.TestMultiOut):
    program = "./test_nexthop"


TestNexthopIter.onesimple("Simple test passed.")
