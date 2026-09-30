// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP cli support
 * Copyright (C) 2024 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */
#ifndef __LIBAGENTX_H__
#define __LIBAGENTX_H__

#include "lib/hook.h"

extern void libagentx_init(void);
extern bool agentx_enabled;

#define HOOKS_DECLARE
#include "lib/hooks_begin.h"
#include "lib/libagentx_hooks.h"
#include "lib/hooks_end.h"

#endif
