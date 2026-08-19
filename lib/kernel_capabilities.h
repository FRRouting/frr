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

bool kernel_capabilities_has_seg6_encap_source(void);
bool kernel_capabilities_has_seg6_encap_lookup(void);

void kernel_capabilities_set_seg6_encap_source(bool enabled);
void kernel_capabilities_set_seg6_encap_lookup(bool enabled);

#ifdef __cplusplus
}
#endif

#endif /* _KERNEL_CAPABILITIES_H */
