# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestIsisCryptoAuth(frrtest.TestMultiOut):
    program = "./test_isis_crypto_auth"


TestIsisCryptoAuth.exit_cleanly()
