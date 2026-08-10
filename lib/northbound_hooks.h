// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for lib/northbound.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* Hooks. */
DO_HOOK(nb_notification_send, (const char *, xpath), (struct list *, arguments));

DO_HOOK(nb_notification_tree_send, (const char *, xpath), (const struct lyd_node *, tree));
