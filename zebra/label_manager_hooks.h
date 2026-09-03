// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/label_manager.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* declare hooks for the basic API, so that it can be specialized or served
 * externally. Also declare a hook when those functions have been registered,
 * so that any external module wanting to replace those can react
 */
DO_HOOK(lm_client_connect, (struct zserv *, client), (vrf_id_t, vrf_id));
DO_HOOK(lm_client_disconnect, (struct zserv *, client));

DO_HOOK(lm_get_chunk, (struct label_manager_chunk **, lmc), (struct zserv *, client),
	(uint8_t, keep), (uint32_t, size), (uint32_t, base), (vrf_id_t, vrf_id));
DO_HOOK(lm_release_chunk, (struct zserv *, client), (uint32_t, start), (uint32_t, end));

/* show running-config needs an API for dynamic-block */
DO_HOOK(lm_write_label_block_config, (struct vty *, vty), (struct zebra_vrf *, zvrf));

DO_HOOK(lm_cbs_inited);
