import frrtest


class TestTypelist(frrtest.TestMultiOut):
    program = "./test_typelist"


TestTypelist.onesimple("LIST end")
TestTypelist.onesimple("DLIST end")
TestTypelist.onesimple("ATOMLIST end")
TestTypelist.onesimple("HEAP end")
TestTypelist.onesimple("SORTLIST_UNIQ end")
TestTypelist.onesimple("SORTLIST_NONUNIQ end")
TestTypelist.onesimple("HASH end")
TestTypelist.onesimple("HASH_collisions end")
TestTypelist.onesimple("SKIPLIST_UNIQ end")
TestTypelist.onesimple("SKIPLIST_NONUNIQ end")
TestTypelist.onesimple("RBTREE_UNIQ end")
TestTypelist.onesimple("RBTREE_NONUNIQ end")
TestTypelist.onesimple("ATOMSORT_UNIQ end")
TestTypelist.onesimple("ATOMSORT_NONUNIQ end")
