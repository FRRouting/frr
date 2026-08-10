// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/zebra_mlag.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(zebra_mlag_private_write_data, (uint8_t *, data), (uint32_t, len));

DO_HOOK(zebra_mlag_private_monitor_state);

DO_HOOK(zebra_mlag_private_open_channel);

DO_HOOK(zebra_mlag_private_close_channel);

DO_HOOK(zebra_mlag_private_cleanup_data);
