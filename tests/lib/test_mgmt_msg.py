# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestMgmtMsg(frrtest.TestMultiOut):
    program = "./test_mgmt_msg"


TestMgmtMsg.onesimple("disconnect-in-handler: OK")
TestMgmtMsg.onesimple("disconnect-flushes-queues: OK")
