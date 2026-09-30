// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for isisd/isisd.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

#ifndef FABRICD
/* We also declare hook for every notification */
DO_HOOK(isis_hook_db_overload, (const struct isis_area *, area));
#endif
