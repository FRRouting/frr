// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Common definitions for watchfrr API socket.
 *
 * Copyright (C) 2016  David Lamparter for NetDEF, Inc.
 */

#ifndef FRR_WATCHFRR_H
#define FRR_WATCHFRR_H

#include "lib/memory.h"

DECLARE_MGROUP(WATCHFRR);

/*
 * This is the name of the pathspace we are in `-N XXX`
 * If the default then this is NULL
 */
extern const char *pathspace;

extern void watchfrr_vty_init(void);

extern pid_t integrated_write_pid;
extern void integrated_write_sigchld(int status);

struct vty;
extern void watchfrr_status(struct vty *vty);

/*
 * Check if all daemons we are monitoring are in the DAEMON_UP state.
 *
 * Returns:
 *    True if they are all DAEMON_UP, false otherwise.
 */
extern bool check_all_up(void);

extern void watchfrr_set_ignore_daemon(struct vty *vty, const char *dname,
				       bool ignore);
#endif /* FRR_WATCHFRR_H */
