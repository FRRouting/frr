import frrtest


class TestFrrlua(frrtest.TestMultiOut):
    program = "./test_frrlua"


TestFrrlua.exit_cleanly()
