# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestMldQuery(frrtest.TestMultiOut):
    program = "./test_mld_query"


TestMldQuery.onesimple("mldv1_general_query OK")
TestMldQuery.onesimple("mldv1_group_query OK")
TestMldQuery.onesimple("mldv2_general_query OK")
TestMldQuery.onesimple("mldv2_group_query OK")
TestMldQuery.onesimple("mldv2_group_source_query OK")
TestMldQuery.onesimple("mldv2_query_querier_source OK")
TestMldQuery.exit_cleanly()
