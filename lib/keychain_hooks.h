// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for lib/keychain.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(keychain_removed, (const char *, keychain_name));
