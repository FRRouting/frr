import frrtest


class TestPrintfrr(frrtest.TestMultiOut):
    program = "./test_printfrr"


TestPrintfrr.exit_cleanly()
