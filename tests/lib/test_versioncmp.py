import frrtest


class TestVersionCmp(frrtest.TestMultiOut):
    program = "./test_versioncmp"


TestVersionCmp.exit_cleanly()
