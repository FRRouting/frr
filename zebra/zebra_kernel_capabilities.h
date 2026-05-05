// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Kernel capabilities
 * Copyright 2026 6WIND S.A.
 */
#ifndef _ZEBRA_KERNEL_CAPABILITIES_H
#define _ZEBRA_KERNEL_CAPABILITIES_H

#include <zebra.h>
#include <if.h>
#include <zebra/zebra_ns.h>

#ifdef __cplusplus
extern "C" {
#endif


bool zebra_kernel_capabilities_configure_interface(struct zebra_ns *zns, const char *ifname,
						   bool add_iface);
void zebra_kernel_capabilities_init(void);
void zebra_kernel_capabilities_interface_created_cb(struct interface *ifp);
bool zebra_kernel_capabilities_is_srv6_seg6local_dt6_vrftable_attr_supported(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_KERNEL_CAPABILITIES_H */
