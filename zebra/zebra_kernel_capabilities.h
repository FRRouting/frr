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

enum kernel_capabilities_interface_action_type {
	KERNEL_CAPABILITIES_INTERFACE_ADD,
	KERNEL_CAPABILITIES_INTERFACE_SHUTDOWN,
	KERNEL_CAPABILITIES_INTERFACE_DEL,
};

bool zebra_kernel_capabilities_configure_interface(
	struct zebra_ns *zns, const char *ifname,
	enum kernel_capabilities_interface_action_type action);
void zebra_kernel_capabilities_init(void);
void zebra_kernel_capabilities_interface_created_cb(struct interface *ifp);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_KERNEL_CAPABILITIES_H */
