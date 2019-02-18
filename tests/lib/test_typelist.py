import frrtest

class TestTypelist(frrtest.TestMultiOut):
    program = './test_typelist'

TestTypelist.onesimple('SORTLIST_UNIQ end')
TestTypelist.onesimple('SORTLIST_NONUNIQ end')
TestTypelist.onesimple('HASH end')
TestTypelist.onesimple('SKIPLIST_UNIQ end')
TestTypelist.onesimple('SKIPLIST_NONUNIQ end')
TestTypelist.onesimple('RBTREE_UNIQ end')
TestTypelist.onesimple('RBTREE_NONUNIQ end')
TestTypelist.onesimple('ATOMSORT_UNIQ end')
TestTypelist.onesimple('ATOMSORT_NONUNIQ end')
