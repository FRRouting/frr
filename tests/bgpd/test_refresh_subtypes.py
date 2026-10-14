# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestRefreshSubtypes(frrtest.TestMultiOut):
    program = "./test_refresh_subtypes"


TestRefreshSubtypes.onesimple("refresh preflight read bounds OK")
TestRefreshSubtypes.onesimple("diagnostic buffer bounds OK")
