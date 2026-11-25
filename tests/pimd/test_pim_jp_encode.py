# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestPimJpEncode(frrtest.TestMultiOut):
    program = "./test_pim_jp_encode"


TestPimJpEncode.onesimple("sgrpt_prune_with_sg_join OK")
TestPimJpEncode.onesimple("sgrpt_prune_with_sg_join_and_prune OK")
TestPimJpEncode.onesimple("sgrpt_prune_split_records OK")
TestPimJpEncode.onesimple("sgrpt_prune_split_after_joins OK")
TestPimJpEncode.onesimple("sgrpt_prune_same_record_as_starg_join OK")
TestPimJpEncode.onesimple("sgrpt_prune_overflow OK")
TestPimJpEncode.exit_cleanly()
