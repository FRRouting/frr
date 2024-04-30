// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra Mlag vty Code.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 */
#ifndef __ZEBRA_MLAG_VTY_CODE__
#define __ZEBRA_MLAG_VTY_CODE__

#ifdef __cplusplus
extern "C" {
#endif

extern int32_t zebra_mlag_test_mlag_internal(const char *none,
					     const char *primary,
					     const char *secondary);

extern void zebra_mlag_vty_init(void);

#ifdef __cplusplus
}
#endif

#endif
