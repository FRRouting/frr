// SPDX-License-Identifier: ISC
/* hook definitions for ldpd/ldpd.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(ldp_register_mib, (struct event_loop *, tm));
