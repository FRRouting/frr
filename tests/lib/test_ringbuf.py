import frrtest

class TestRingbuf(frrtest.TestMultiOut):
    program = './test_ringbuf'

TestRingbuf.exit_cleanly()
