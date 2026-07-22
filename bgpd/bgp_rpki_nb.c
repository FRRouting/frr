// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP RPKI northbound — module registration and NB data callbacks.
 * Copyright (C) 2026 FRRouting
 *
 * Loadable module pattern: bgpd_rpki.so assigns rpki_nb_cb at init.
 * Without the module, NB writes to bgp-rpki are silent no-ops.
 */

#include <zebra.h>

#include "northbound.h"
#include "yang.h"
#include "vrf.h"

#include "bgpd/bgp_rpki_nb.h"

struct rpki_nb_ops *rpki_nb_cb;

static const char *rpki_nb_vrf_name(const struct lyd_node *dnode)
{
	const struct lyd_node *vrf;

	/*
	 * VRF identity from candidate/running YANG — never from
	 * nb_running_get_entry operational objects at VALIDATE time.
	 */
	vrf = yang_dnode_get_parent(dnode, "vrf");
	if (vrf && yang_dnode_exists(vrf, "name"))
		return yang_dnode_get_string(vrf, "name");
	return VRF_DEFAULT_NAME;
}

static const char *rpki_nb_cli_indent(const struct lyd_node *dnode)
{
	const char *vrfname = rpki_nb_vrf_name(dnode);

	if (vrfname && !strmatch(vrfname, VRF_DEFAULT_NAME))
		return " ";
	return "";
}

static void bgp_rpki_container_cli_show(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, "%srpki\n", rpki_nb_cli_indent(dnode));
}

static void bgp_rpki_container_cli_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	/* Trailing `!` is added by RPKI_NODE / VRF config writers. */
	vty_out(vty, "%sexit\n", rpki_nb_cli_indent(dnode));
}

static int bgp_rpki_enable_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->enable_set)
		rpki_nb_cb->enable_set(rpki_nb_vrf_name(args->dnode),
				       yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

static int bgp_rpki_polling_time_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->polling_set)
		rpki_nb_cb->polling_set(rpki_nb_vrf_name(args->dnode),
					yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

static void bgp_rpki_polling_time_cli_show(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "%s rpki polling_period %u\n", rpki_nb_cli_indent(dnode),
		yang_dnode_get_uint32(dnode, NULL));
}

static int bgp_rpki_expire_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE: {
		uint32_t expire = yang_dnode_get_uint32(args->dnode, NULL);
		uint32_t polling = 3600;

		if (yang_dnode_exists(args->dnode, "../polling-time"))
			polling = yang_dnode_get_uint32(args->dnode, "../polling-time");
		if (expire < polling) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Expiry interval must be polling period or larger");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		if (rpki_nb_cb && rpki_nb_cb->expire_set)
			rpki_nb_cb->expire_set(rpki_nb_vrf_name(args->dnode),
					       yang_dnode_get_uint32(args->dnode, NULL));
		return NB_OK;
	}
	return NB_OK;
}

static int bgp_rpki_expire_time_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->expire_set)
		rpki_nb_cb->expire_set(rpki_nb_vrf_name(args->dnode), 0);
	return NB_OK;
}

static void bgp_rpki_expire_time_cli_show(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	uint32_t expire = yang_dnode_get_uint32(dnode, NULL);

	if (expire == 7200 && !show_defaults)
		return;
	vty_out(vty, "%s rpki expire_interval %u\n", rpki_nb_cli_indent(dnode), expire);
}

static int bgp_rpki_retry_time_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->retry_set)
		rpki_nb_cb->retry_set(rpki_nb_vrf_name(args->dnode),
				      yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

static void bgp_rpki_retry_time_cli_show(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "%s rpki retry_interval %u\n", rpki_nb_cli_indent(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

/*
 * cache-list is keyed only by preference. A later edit of address, port,
 * source, or transport does not destroy the list entry, so create does not
 * run again and the leaf callbacks are intentionally empty. create (on
 * APPLY) and apply_finish both install from the candidate entry. The add
 * ops leave an unchanged cache running and replace one whose parameters
 * differ, so the second call on create does not reconnect.
 */
static void bgp_rpki_cache_list_install(const struct lyd_node *dnode)
{
	const char *vrfname;
	uint8_t pref;
	const char *cache_type;
	const char *host = NULL;
	uint16_t port = 0;
	const char *source = NULL;

	vrfname = rpki_nb_vrf_name(dnode);
	pref = yang_dnode_get_uint8(dnode, "preference");
	cache_type = yang_dnode_get_string(dnode, "cache-type");

	if (yang_dnode_exists(dnode, "ip-address"))
		host = yang_dnode_get_string(dnode, "ip-address");
	else if (yang_dnode_exists(dnode, "ip-host-address"))
		host = yang_dnode_get_string(dnode, "ip-host-address");

	if (strmatch(cache_type, "TCP")) {
		const char *tcp_port = NULL;

		if (yang_dnode_exists(dnode, "transport/tcp/tcp-port"))
			tcp_port = yang_dnode_get_string(dnode, "transport/tcp/tcp-port");
		if (yang_dnode_exists(dnode, "transport/tcp/source-address"))
			source = yang_dnode_get_string(dnode, "transport/tcp/source-address");
		if (rpki_nb_cb && rpki_nb_cb->cache_add_tcp)
			rpki_nb_cb->cache_add_tcp(vrfname, pref, host, tcp_port, source);
		return;
	}

	if (strmatch(cache_type, "SSH")) {
		const char *user = NULL;
		const char *priv_key = NULL;
		const char *server_pub_key = NULL;

		if (yang_dnode_exists(dnode, "transport/ssh/ssh-port"))
			port = (uint16_t)yang_dnode_get_uint32(dnode, "transport/ssh/ssh-port");
		if (yang_dnode_exists(dnode, "transport/ssh/user-name"))
			user = yang_dnode_get_string(dnode, "transport/ssh/user-name");
		if (yang_dnode_exists(dnode, "transport/ssh/private-key"))
			priv_key = yang_dnode_get_string(dnode, "transport/ssh/private-key");
		if (yang_dnode_exists(dnode, "transport/ssh/server-public-key"))
			server_pub_key = yang_dnode_get_string(dnode,
							       "transport/ssh/server-public-key");
		if (yang_dnode_exists(dnode, "transport/ssh/source-address"))
			source = yang_dnode_get_string(dnode, "transport/ssh/source-address");
		if (rpki_nb_cb && rpki_nb_cb->cache_add_ssh)
			rpki_nb_cb->cache_add_ssh(vrfname, pref, host, port, user, priv_key,
						  server_pub_key, source);
	}
}

static int bgp_rpki_cache_list_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_rpki_cache_list_install(args->dnode);
	return NB_OK;
}

static void bgp_rpki_cache_list_apply_finish(struct nb_cb_apply_finish_args *args)
{
	bgp_rpki_cache_list_install(args->dnode);
}

static int bgp_rpki_cache_list_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (rpki_nb_cb && rpki_nb_cb->cache_remove)
		rpki_nb_cb->cache_remove(rpki_nb_vrf_name(args->dnode),
					 yang_dnode_get_uint8(args->dnode, "preference"));
	return NB_OK;
}

static void bgp_rpki_cache_list_cli_show(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	const char *indent = rpki_nb_cli_indent(dnode);
	uint8_t pref;
	const char *type;
	const char *host;
	uint16_t port = 0;
	const char *source = NULL;

	pref = yang_dnode_get_uint8(dnode, "preference");
	type = yang_dnode_get_string(dnode, "cache-type");

	if (yang_dnode_exists(dnode, "ip-address"))
		host = yang_dnode_get_string(dnode, "ip-address");
	else
		host = yang_dnode_get_string(dnode, "ip-host-address");

	if (strmatch(type, "TCP")) {
		const char *tcp_port = "";

		if (yang_dnode_exists(dnode, "transport/tcp/tcp-port"))
			tcp_port = yang_dnode_get_string(dnode, "transport/tcp/tcp-port");
		if (yang_dnode_exists(dnode, "transport/tcp/source-address"))
			source = yang_dnode_get_string(dnode, "transport/tcp/source-address");
		vty_out(vty, "%s rpki cache tcp %s %s", indent, host, tcp_port);
		if (source)
			vty_out(vty, " source %s", source);
		vty_out(vty, " preference %u\n", pref);
	} else {
		const char *user = "";
		const char *priv = "";
		const char *known = "";

		if (yang_dnode_exists(dnode, "transport/ssh/ssh-port"))
			port = (uint16_t)yang_dnode_get_uint32(dnode, "transport/ssh/ssh-port");
		if (yang_dnode_exists(dnode, "transport/ssh/user-name"))
			user = yang_dnode_get_string(dnode, "transport/ssh/user-name");
		if (yang_dnode_exists(dnode, "transport/ssh/private-key"))
			priv = yang_dnode_get_string(dnode, "transport/ssh/private-key");
		if (yang_dnode_exists(dnode, "transport/ssh/server-public-key"))
			known = yang_dnode_get_string(dnode, "transport/ssh/server-public-key");
		if (yang_dnode_exists(dnode, "transport/ssh/source-address"))
			source = yang_dnode_get_string(dnode, "transport/ssh/source-address");
		vty_out(vty, "%s rpki cache ssh %s %u %s %s %s", indent, host, port, user, priv,
			known);
		if (source)
			vty_out(vty, " source %s", source);
		vty_out(vty, " preference %u\n", pref);
	}
}

/*
 * Non-key cache-list leaves. The list entry stays in place, so these
 * callbacks do not touch the router. cache-list apply_finish rebuilds it.
 */
static int bgp_rpki_cache_leaf_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int bgp_rpki_cache_leaf_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_bgp_rpki_info = {
	.name = "frr-bgp-rpki",
	.nodes = {
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki",
			.cbs = {
				.cli_show = bgp_rpki_container_cli_show,
				.cli_show_end = bgp_rpki_container_cli_show_end,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/enable",
			.cbs = {
				.modify = bgp_rpki_enable_modify,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/polling-time",
			.cbs = {
				.modify = bgp_rpki_polling_time_modify,
				.cli_show = bgp_rpki_polling_time_cli_show,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/expire-time",
			.cbs = {
				.modify = bgp_rpki_expire_time_modify,
				.destroy = bgp_rpki_expire_time_destroy,
				.cli_show = bgp_rpki_expire_time_cli_show,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-timers/retry-time",
			.cbs = {
				.modify = bgp_rpki_retry_time_modify,
				.cli_show = bgp_rpki_retry_time_cli_show,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list",
			.cbs = {
				.create = bgp_rpki_cache_list_create,
				.destroy = bgp_rpki_cache_list_destroy,
				.apply_finish = bgp_rpki_cache_list_apply_finish,
				.cli_show = bgp_rpki_cache_list_cli_show,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/cache-type",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/ip-address",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/ip-host-address",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/tcp/tcp-port",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/tcp/source-address",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/ssh-port",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/user-name",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/private-key",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/public-key",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/server-public-key",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-bgp-rpki:bgp-rpki/rpki-cache-server/cache-list/transport/ssh/source-address",
			.cbs = {
				.modify = bgp_rpki_cache_leaf_modify,
				.destroy = bgp_rpki_cache_leaf_destroy,
			},
		},
		{
			.xpath = NULL,
		},
	},
};
/* clang-format on */
