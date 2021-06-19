import frrtest


class TestFrrscript(frrtest.TestMultiOut):
    program = "./test_frrscript"


TestFrrscript.exit_cleanly()
