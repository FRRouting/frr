// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for ospfd/ospf_lsa.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/*
 * LSA Update and Delete Hook LSAs.
 */
DO_HOOK(ospf_lsa_update, (struct ospf_lsa *, lsa));
DO_HOOK(ospf_lsa_delete, (struct ospf_lsa *, lsa));
