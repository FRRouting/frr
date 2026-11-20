# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBgpLsTed(frrtest.TestMultiOut):
    program = "./test_bgp_ls_ted"


for scenario in (
    "captured_partial_full_wire",
    "partial_to_full",
    "full_to_partial",
    "ipv6_address_replacement",
    "add_replaces_existing",
    "sync_replaces_existing",
    "repeated_replacement",
    "delete_after_replacement",
    "metric_only_no_withdraw",
    "identical_refresh_no_withdraw",
    "mtid_and_remote_ipv6_identity",
    "missing_old_and_reverse_arrival",
    "primary_key_add_delete",
    "rejected_update_preserves_route",
    "unadvertisable_update_withdraws_old",
    "connected_unadvertisable_withdraws_old",
):
    TestBgpLsTed.okfail("BGPLS_CASE " + scenario)
