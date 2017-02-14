import frrtest

class TestTimerCorrectness(frrtest.TestMultiOut):
    program = './test_timer_correctness'

TestTimerCorrectness.onesimple('Expected output and actual output match.')
