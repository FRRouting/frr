// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/zebra_pw.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(pw_install, (struct zebra_pw *, pw));

DO_HOOK(pw_uninstall, (struct zebra_pw *, pw));
