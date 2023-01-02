import frrtest


class TestIDAlloc(frrtest.TestMultiOut):
    program = "./test_idalloc"


TestIDAlloc.onesimple("ID Allocator test successful.")
