// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/zebra_router.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(nos_initialize_data, (struct zebra_architectural_values *, zav));
