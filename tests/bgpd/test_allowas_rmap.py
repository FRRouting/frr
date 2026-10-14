# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestAllowasRmap(frrtest.TestMultiOut):
    program = "./test_allowas_rmap"


TestAllowasRmap.okfail(
    "allowas-in-rmap-uaf: UPDATE through allowas-in route-map does not free the parsed attr's extra"
)
