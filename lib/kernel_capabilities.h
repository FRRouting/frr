// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel capabilities
 * Copyright 2026 6WIND S.A.
 */
#ifndef _KERNEL_CAPABILITIES_H
#define _KERNEL_CAPABILITIES_H

#include <zebra.h>

#ifdef __cplusplus
extern "C" {
#endif

bool kernel_capabilities_is_srv6_seg6_source_encap_attr_supported(void);
void kernel_capabilities_set_srv6_seg6_source_encap_attr_supported(bool enabled);

#ifdef __cplusplus
}
#endif

#endif /* _KERNEL_CAPABILITIES_H */
