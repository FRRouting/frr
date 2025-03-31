// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP cli support
 * Copyright (C) 2024 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */
#ifndef __LIBAGENTX_H__
#define __LIBAGENTX_H__

extern void libagentx_init(void);
extern bool agentx_enabled;

DECLARE_HOOK(agentx_cli_enabled, (), ());
DECLARE_HOOK(agentx_cli_disabled, (), ());

#endif
