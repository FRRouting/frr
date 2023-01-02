import frrtest


class TestPrefix2str(frrtest.TestMultiOut):
    program = "./test_prefix2str"


TestPrefix2str.exit_cleanly()
