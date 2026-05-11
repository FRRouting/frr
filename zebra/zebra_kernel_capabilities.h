// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Kernel capabilities
 * Copyright 2026 6WIND S.A.
 */
#ifndef _ZEBRA_KERNEL_CAPABILITIES_H
#define _ZEBRA_KERNEL_CAPABILITIES_H

#include <zebra.h>
#include <zebra/zebra_ns.h>

#ifdef __cplusplus
extern "C" {
#endif


bool zebra_kernel_capabilities_configure_interface(struct zebra_ns *zns, const char *ifname);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_KERNEL_CAPABILITIES_H */
