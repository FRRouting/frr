// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for lib/routing_nb_config.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/*
 * callbacks for routing to handle configuration events
 * based on the control plane protocol
 */
DO_HOOK(routing_conf_event, (struct nb_cb_create_args *, args));
DO_HOOK(routing_create, (struct nb_cb_create_args *, args));
DO_KOOH(routing_destroy, (struct nb_cb_destroy_args *, args));
