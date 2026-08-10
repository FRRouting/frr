// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/zebra_pbr.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* static function declarations */
DO_HOOK(zebra_pbr_ipset_entry_get_stat, (struct zebra_pbr_ipset_entry *, ipset),
	(uint64_t *, pkts), (uint64_t *, bytes));

DO_HOOK(zebra_pbr_iptable_get_stat, (struct zebra_pbr_iptable *, iptable), (uint64_t *, pkts),
	(uint64_t *, bytes));

DO_HOOK(zebra_pbr_iptable_update, (int, cmd), (struct zebra_pbr_iptable *, iptable));

DO_HOOK(zebra_pbr_ipset_entry_update, (int, cmd), (struct zebra_pbr_ipset_entry *, ipset));

DO_HOOK(zebra_pbr_ipset_update, (int, cmd), (struct zebra_pbr_ipset *, ipset));
