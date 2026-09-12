// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for lib/log_vty.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(zlog_rotate);
DO_HOOK(zlog_cli_show, (struct vty *, vty));
