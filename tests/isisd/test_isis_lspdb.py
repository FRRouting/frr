import frrtest


class TestIsisLSPDB(frrtest.TestMultiOut):
    program = "./test_isis_lspdb"


TestIsisLSPDB.exit_cleanly()
