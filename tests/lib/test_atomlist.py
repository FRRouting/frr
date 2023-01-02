import frrtest


class TestAtomlist(frrtest.TestMultiOut):
    program = "./test_atomlist"


TestAtomlist.exit_cleanly()
