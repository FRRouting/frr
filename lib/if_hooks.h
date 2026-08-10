// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for lib/if.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* called from the library code whenever interfaces are created/deleted
 * note: interfaces may not be fully realized at that point; also they
 * may not exist in the system (ifindex = IFINDEX_INTERNAL)
 *
 * priority values are important here, daemons should be at 0 while modules
 * can use 1000+ so they run after the daemon has initialised daemon-specific
 * interface data
 */
DO_HOOK(if_add, (struct interface *, ifp));

DO_KOOH(if_del, (struct interface *, ifp));

/* called (in daemons) when ZAPI tells us the interface actually exists
 * (ifindex != IFINDEX_INTERNAL)
 *
 * WARNING: these 2 hooks NEVER CALLED inside zebra!
 */
DO_HOOK(if_real, (struct interface *, ifp));

DO_KOOH(if_unreal, (struct interface *, ifp));

/* called (in daemons) on state changes on interfaces.  Whether this is admin
 * state (= pure config) or carrier state (= hardware link plugged) depends on
 * zebra's "link-detect" configuration.  By default, it's carrier state, so
 * this won't happen until the interface actually has a link.
 *
 * WARNING: these 2 hooks NEVER CALLED inside zebra!
 */
DO_HOOK(if_up, (struct interface *, ifp));

DO_KOOH(if_down, (struct interface *, ifp));
