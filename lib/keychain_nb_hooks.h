// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for lib/keychain_nb.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(keychain_updated, (const char *, keychain_name));
