import frrtest


class TestDarr(frrtest.TestMultiOut):
    program = "./test_darr"


TestDarr.exit_cleanly()
