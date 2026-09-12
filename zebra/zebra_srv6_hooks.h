// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/zebra_srv6.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* declare hooks for the basic API, so that it can be specialized or served
 * externally. Also declare a hook when those functions have been registered,
 * so that any external module wanting to replace those can react
 */
DO_HOOK(srv6_manager_client_connect, (struct zserv *, client), (vrf_id_t, vrf_id));
DO_HOOK(srv6_manager_client_disconnect, (struct zserv *, client));

DO_HOOK(srv6_manager_get_chunk, (struct srv6_locator **, loc), (struct zserv *, client),
	(const char *, locator_name), (vrf_id_t, vrf_id));
DO_HOOK(srv6_manager_release_chunk, (struct zserv *, client), (const char *, locator_name),
	(vrf_id_t, vrf_id));

DO_HOOK(srv6_manager_get_sid, (struct zebra_srv6_sid **, sid), (struct zserv *, client),
	(struct srv6_sid_ctx *, ctx), (struct in6_addr *, sid_value), (const char *, locator_name),
	(bool, is_localonly));
DO_HOOK(srv6_manager_release_sid, (struct zserv *, client), (struct srv6_sid_ctx *, ctx),
	(const char *, locator_name), (bool, is_localonly));

DO_HOOK(srv6_manager_get_locator, (struct srv6_locator **, locator), (struct zserv *, client),
	(const char *, locator_name));
