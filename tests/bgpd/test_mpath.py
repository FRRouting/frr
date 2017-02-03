import frrtest

class TestMpath(frrtest.TestMultiOut):
    program = './test_mpath'

TestMpath.okfail("bgp maximum-paths config")
TestMpath.okfail("bgp_mp_list")
TestMpath.okfail("bgp_info_mpath_update")

