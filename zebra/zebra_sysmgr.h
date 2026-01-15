// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra system manager interface module
 * Copyright (C) 2026 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */

#include <zebra.h>

#ifndef _ZEBRA_SYSMGR_H
#define _ZEBRA_SYSMGR_H 1

/*
 * Initialize the module at startup
 */
void zebra_sysmgr_init(void);

/*
 * Start the module pthread. This step is run later than the
 * 'init' step, in case zebra has fork-ed.
 */
void zebra_sysmgr_start(void);

/*
 * Module stop, called from the main pthread. This is synchronous:
 * once it returns, the pthread has stopped and exited.
 */
void zebra_sysmgr_stop(void);

/*
 * Module cleanup, called from the zebra main pthread. When it returns,
 * all module cleanup is complete.
 */
void zebra_sysmgr_finish(void);

#endif /* _ZEBRA_SYSMGR_H */
