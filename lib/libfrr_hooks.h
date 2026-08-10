// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for lib/libfrr.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* call order of these hooks is as ordered here */
DO_HOOK(frr_early_init, (struct event_loop *, tm));

DO_HOOK(frr_late_init, (struct event_loop *, tm));

/* fork() happens between late_init and config_pre */
DO_HOOK(frr_config_pre, (struct event_loop *, tm));

DO_HOOK(frr_config_post, (struct event_loop *, tm));

/* these two are before the protocol daemon does its own shutdown
 * it's named this way being the counterpart to frr_late_init */
DO_KOOH(frr_early_fini);

/* and these two are after the daemon did its own cleanup */
DO_KOOH(frr_fini);
