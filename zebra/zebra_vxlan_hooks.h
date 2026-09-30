// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/zebra_vxlan.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(zebra_rmac_update, (struct zebra_mac *, rmac), (struct zebra_l3vni *, zl3vni),
	(bool, delete), (const char *, reason));
