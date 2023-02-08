// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VTY library for SHARP
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __SHARP_VTY_H__
#define __SHARP_VTY_H__

extern void sharp_vty_init(void);

struct vty;

extern void sharp_logpump_run(struct vty *vty, unsigned duration,
			      unsigned frequency, unsigned burst);

#endif
