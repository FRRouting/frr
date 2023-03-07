// SPDX-License-Identifier: GPL-2.0-or-later
/* lib/systemd Code
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 */

#ifdef __cplusplus
extern "C" {
#endif

/* fd 1/2 connected to journald? */
extern bool sd_stdout_is_journal;
extern bool sd_stderr_is_journal;

/*
 * Wrapper functions to systemd calls.
 *
 * Design point is that if systemd is not being used on this system
 * then these functions becomes a no-op.
 */
void systemd_send_stopping(void);

/*
 *  master - The struct event_loop * to use to schedule ourself
 *  the_process - Should we send watchdog if we are not the requested
 *                process?
 */
void systemd_send_started(struct event_loop *master);

/*
 * status - A status string to send to systemd
 */
void systemd_send_status(const char *status);

/*
 * grab startup state from env vars
 */
void systemd_init_env(void);

#ifdef __cplusplus
}
#endif
