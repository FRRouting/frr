// SPDX-License-Identifier: ISC
/* hook definitions for lib/zlog.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(zlog_init, (const char *, progname), (const char *, protoname), (unsigned short, instance),
	(uid_t, uid), (gid_t, gid));
DO_KOOH(zlog_fini);

DO_HOOK(zlog_aux_init, (const char *, prefix), (int, prio_min));
