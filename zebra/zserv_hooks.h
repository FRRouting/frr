// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/zserv.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* Hooks for client connect / disconnect */
DO_HOOK(zserv_client_connect, (struct zserv *, client));
DO_KOOH(zserv_client_close, (struct zserv *, client));
