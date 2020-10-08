import frrtest


class TestNtop(frrtest.TestMultiOut):
    program = "./test_ntop"


TestNtop.exit_cleanly()
