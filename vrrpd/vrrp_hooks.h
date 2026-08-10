// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for vrrpd/vrrp.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* State machine ----------------------------------------------------------- */
/*
 * This hook called whenever the state of a Virtual Router changes, after the
 * specific internal state handlers have run.
 *
 * Use this if you need to react to state changes to perform non-critical
 * tasks. Critical tasks should go in the internal state change handlers.
 */
DO_HOOK(vrrp_change_state_hook, (struct vrrp_router *, r), (int, to));
