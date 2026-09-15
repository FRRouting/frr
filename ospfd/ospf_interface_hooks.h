// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for ospfd/ospf_interface.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(ospf_vl_add, (struct ospf_vl_data *, vd));
DO_HOOK(ospf_vl_delete, (struct ospf_vl_data *, vd));

DO_HOOK(ospf_if_update, (struct interface *, ifp));
DO_HOOK(ospf_if_delete, (struct interface *, ifp));
