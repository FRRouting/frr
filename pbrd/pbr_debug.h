// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PBR - debugging
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Quentin Young
 */
#ifndef __PBR_DEBUG_H__
#define __PBR_DEBUG_H__

#include <zebra.h>

#include "debug.h"

/* PBR debugging records */
extern struct debug pbr_dbg_map;
extern struct debug pbr_dbg_zebra;
extern struct debug pbr_dbg_nht;
extern struct debug pbr_dbg_event;

/*
 * Initialize PBR debugging.
 *
 * Installs VTY commands and registers callbacks.
 */
void pbr_debug_init(void);

/*
 * Set or unset flags on all debugs for pbrd.
 *
 * flags
 *    The flags to set
 *
 * set
 *    Whether to set or unset the specified flags
 */
void pbr_debug_set_all(uint32_t flags, bool set);

#endif /* __PBR_DEBUG_H__ */
