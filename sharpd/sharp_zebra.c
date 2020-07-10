/*
 * Zebra connect code.
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "nexthop.h"
#include "nexthop_group.h"

#include "sharp_globals.h"
#include "sharp_nht.h"
#include "sharp_zebra.h"

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;

/* Privs info */
extern struct zebra_privs_t sharp_privs;

DEFINE_MTYPE_STATIC(SHARPD, ZC, "Test zclients");

/* Struct to hold list of test zclients */
struct sharp_zclient {
	struct sharp_zclient *prev;
	struct sharp_zclient *next;
	struct zclient *client;
};

/* Head of test zclient list */
static struct sharp_zclient *sharp_clients_head;

static int sharp_opaque_handler(ZAPI_CALLBACK_ARGS);

/* Utility to add a test zclient struct to the list */
static void add_zclient(struct zclient *client)
{
	struct sharp_zclient *node;

	node = XCALLOC(MTYPE_ZC, sizeof(struct sharp_zclient));

	node->client = client;

	node->next = sharp_clients_head;
	if (sharp_clients_head)
		sharp_clients_head->prev = node;
	sharp_clients_head = node;
}

/* Interface addition message from zebra. */
static int sharp_ifp_create(struct interface *ifp)
{
	return 0;
}

static int sharp_ifp_destroy(struct interface *ifp)
{
	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
}

static int sharp_ifp_up(struct interface *ifp)
{
	return 0;
}

static int sharp_ifp_down(struct interface *ifp)
{
	return 0;
}

int sharp_install_lsps_helper(bool install_p, const struct prefix *p,
			      uint8_t type, int instance, uint32_t in_label,
			      const struct nexthop_group *nhg,
			      const struct nexthop_group *backup_nhg)
{
	struct zapi_labels zl = {};
	struct zapi_nexthop *znh;
	const struct nexthop *nh;
	int i, ret;

	zl.type = ZEBRA_LSP_SHARP;
	zl.local_label = in_label;

	if (p) {
		SET_FLAG(zl.message, ZAPI_LABELS_FTN);
		prefix_copy(&zl.route.prefix, p);
		zl.route.type = type;
		zl.route.instance = instance;
	}

	/* List of nexthops is optional for delete */
	i = 0;
	if (nhg) {
		for (ALL_NEXTHOPS_PTR(nhg, nh)) {
			znh = &zl.nexthops[i];

			/* Must have labels to be useful */
			if (nh->nh_label == NULL ||
			    nh->nh_label->num_labels == 0)
				continue;

			if (nh->type == NEXTHOP_TYPE_IFINDEX ||
			    nh->type == NEXTHOP_TYPE_BLACKHOLE)
				/* Hmm - can't really deal with these types */
				continue;

			ret = zapi_nexthop_from_nexthop(znh, nh);
			if (ret < 0)
				return -1;

			i++;
		}
	}

	/* Whoops - no nexthops isn't very useful for install */
	if (i == 0 && install_p)
		return -1;

	zl.nexthop_num = i;

	/* Add optional backup nexthop info. Since these are used by index,
	 * we can't just skip over an invalid backup nexthop: we will
	 * invalidate the entire operation.
	 */
	if (backup_nhg != NULL) {
		i = 0;
		for (ALL_NEXTHOPS_PTR(backup_nhg, nh)) {
			znh = &zl.backup_nexthops[i];

			/* Must have labels to be useful */
			if (nh->nh_label == NULL ||
			    nh->nh_label->num_labels == 0)
				return -1;

			if (nh->type == NEXTHOP_TYPE_IFINDEX ||
			    nh->type == NEXTHOP_TYPE_BLACKHOLE)
				/* Hmm - can't really deal with these types */
				return -1;

			ret = zapi_nexthop_from_nexthop(znh, nh);
			if (ret < 0)
				return -1;

			i++;
		}

		if (i > 0)
			SET_FLAG(zl.message, ZAPI_LABELS_HAS_BACKUPS);

		zl.backup_nexthop_num = i;
	}

	if (install_p)
		ret = zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_ADD,
					     &zl);
	else
		ret = zebra_send_mpls_labels(zclient, ZEBRA_MPLS_LABELS_DELETE,
					     &zl);

	return ret;
}

void sharp_install_routes_helper(struct prefix *p, vrf_id_t vrf_id,
				 uint8_t instance,
				 const struct nexthop_group *nhg,
				 const struct nexthop_group *backup_nhg,
				 uint32_t routes)
{
	uint32_t temp, i;
	bool v4 = false;

	zlog_debug("Inserting %u routes", routes);

	if (p->family == AF_INET) {
		v4 = true;
		temp = ntohl(p->u.prefix4.s_addr);
	} else
		temp = ntohl(p->u.val32[3]);

	/* Only use backup route/nexthops if present */
	if (backup_nhg && (backup_nhg->nexthop == NULL))
		backup_nhg = NULL;

	monotime(&sg.r.t_start);
	for (i = 0; i < routes; i++) {
		route_add(p, vrf_id, (uint8_t)instance, nhg, backup_nhg);
		if (v4)
			p->u.prefix4.s_addr = htonl(++temp);
		else
			p->u.val32[3] = htonl(++temp);
	}
}

void sharp_remove_routes_helper(struct prefix *p, vrf_id_t vrf_id,
				uint8_t instance, uint32_t routes)
{
	uint32_t temp, i;
	bool v4 = false;

	zlog_debug("Removing %u routes", routes);

	if (p->family == AF_INET) {
		v4 = true;
		temp = ntohl(p->u.prefix4.s_addr);
	} else
		temp = ntohl(p->u.val32[3]);

	monotime(&sg.r.t_start);
	for (i = 0; i < routes; i++) {
		route_delete(p, vrf_id, (uint8_t)instance);
		if (v4)
			p->u.prefix4.s_addr = htonl(++temp);
		else
			p->u.val32[3] = htonl(++temp);
	}
}

static void handle_repeated(bool installed)
{
	struct prefix p = sg.r.orig_prefix;
	sg.r.repeat--;

	if (sg.r.repeat <= 0)
		return;

	if (installed) {
		sg.r.removed_routes = 0;
		sharp_remove_routes_helper(&p, sg.r.vrf_id,
					   sg.r.inst, sg.r.total_routes);
	}

	if (!installed) {
		sg.r.installed_routes = 0;
		sharp_install_routes_helper(&p, sg.r.vrf_id, sg.r.inst,
					    &sg.r.nhop_group,
					    &sg.r.backup_nhop_group,
					    sg.r.total_routes);
	}
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct timeval r;
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table, &note))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_INSTALLED:
		sg.r.installed_routes++;
		if (sg.r.total_routes == sg.r.installed_routes) {
			monotime(&sg.r.t_end);
			timersub(&sg.r.t_end, &sg.r.t_start, &r);
			zlog_debug("Installed All Items %jd.%ld",
				   (intmax_t)r.tv_sec, (long)r.tv_usec);
			handle_repeated(true);
		}
		break;
	case ZAPI_ROUTE_FAIL_INSTALL:
		zlog_debug("Failed install of route");
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		zlog_debug("Better Admin Distance won over us");
		break;
	case ZAPI_ROUTE_REMOVED:
		sg.r.removed_routes++;
		if (sg.r.total_routes == sg.r.removed_routes) {
			monotime(&sg.r.t_end);
			timersub(&sg.r.t_end, &sg.r.t_start, &r);
			zlog_debug("Removed all Items %jd.%ld",
				   (intmax_t)r.tv_sec, (long)r.tv_usec);
			handle_repeated(false);
		}
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		zlog_debug("Route removal Failure");
		break;
	}
	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);

	/*
	 * Do not actually turn this on yet
	 * This is just the start of the infrastructure needed here
	 * This can be fixed at a later time.
	 *
	 *	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP,
	 *			ZEBRA_ROUTE_ALL, 0, VRF_DEFAULT);
	 */
}

void vrf_label_add(vrf_id_t vrf_id, afi_t afi, mpls_label_t label)
{
	zclient_send_vrf_label(zclient, vrf_id, afi, label, ZEBRA_LSP_SHARP);
}

void route_add(const struct prefix *p, vrf_id_t vrf_id,
	       uint8_t instance, const struct nexthop_group *nhg,
	       const struct nexthop_group *backup_nhg)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct nexthop *nh;
	int i = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = vrf_id;
	api.type = ZEBRA_ROUTE_SHARP;
	api.instance = instance;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, p, sizeof(*p));

	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	for (ALL_NEXTHOPS_PTR(nhg, nh)) {
		api_nh = &api.nexthops[i];

		zapi_nexthop_from_nexthop(api_nh, nh);

		i++;
	}
	api.nexthop_num = i;

	/* Include backup nexthops, if present */
	if (backup_nhg && backup_nhg->nexthop) {
		SET_FLAG(api.message, ZAPI_MESSAGE_BACKUP_NEXTHOPS);

		i = 0;
		for (ALL_NEXTHOPS_PTR(backup_nhg, nh)) {
			api_nh = &api.backup_nexthops[i];

			zapi_backup_nexthop_from_nexthop(api_nh, nh);

			i++;
		}

		api.backup_nexthop_num = i;
	}

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

void route_delete(struct prefix *p, vrf_id_t vrf_id, uint8_t instance)
{
	struct zapi_route api;

	memset(&api, 0, sizeof(api));
	api.vrf_id = vrf_id;
	api.type = ZEBRA_ROUTE_SHARP;
	api.safi = SAFI_UNICAST;
	api.instance = instance;
	memcpy(&api.prefix, p, sizeof(*p));
	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

	return;
}

void sharp_zebra_nexthop_watch(struct prefix *p, vrf_id_t vrf_id, bool import,
			       bool watch, bool connected)
{
	int command;

	if (!import) {
		command = ZEBRA_NEXTHOP_REGISTER;

		if (!watch)
			command = ZEBRA_NEXTHOP_UNREGISTER;
	} else {
		command = ZEBRA_IMPORT_ROUTE_REGISTER;

		if (!watch)
			command = ZEBRA_IMPORT_ROUTE_UNREGISTER;
	}

	if (zclient_send_rnh(zclient, command, p, connected, vrf_id) < 0)
		zlog_warn("%s: Failure to send nexthop to zebra", __func__);
}

static int sharp_debug_nexthops(struct zapi_route *api)
{
	int i;
	char buf[PREFIX_STRLEN];

	if (api->nexthop_num == 0) {
		zlog_debug(
			"        Not installed");
		return 0;
	}

	for (i = 0; i < api->nexthop_num; i++) {
		struct zapi_nexthop *znh = &api->nexthops[i];

		switch (znh->type) {
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			zlog_debug(
				"        Nexthop %s, type: %d, ifindex: %d, vrf: %d, label_num: %d",
				inet_ntop(AF_INET, &znh->gate.ipv4.s_addr, buf,
					  sizeof(buf)),
				znh->type, znh->ifindex, znh->vrf_id,
				znh->label_num);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IPV6:
			zlog_debug(
				"        Nexthop %s, type: %d, ifindex: %d, vrf: %d, label_num: %d",
				inet_ntop(AF_INET6, &znh->gate.ipv6, buf,
					  sizeof(buf)),
				znh->type, znh->ifindex, znh->vrf_id,
				znh->label_num);
			break;
		case NEXTHOP_TYPE_IFINDEX:
			zlog_debug("        Nexthop IFINDEX: %d, ifindex: %d",
				   znh->type, znh->ifindex);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			zlog_debug("        Nexthop blackhole");
			break;
		}
	}

	return i;
}
static int sharp_nexthop_update(ZAPI_CALLBACK_ARGS)
{
	struct sharp_nh_tracker *nht;
	struct zapi_route nhr;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		zlog_warn("%s: Decode of update failed", __func__);

		return 0;
	}

	zlog_debug("Received update for %pFX", &nhr.prefix);

	nht = sharp_nh_tracker_get(&nhr.prefix);
	nht->nhop_num = nhr.nexthop_num;
	nht->updates++;

	sharp_debug_nexthops(&nhr);

	return 0;
}

static int sharp_redistribute_route(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route api;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		zlog_warn("%s: Decode of redistribute failed: %d", __func__,
			  ZEBRA_REDISTRIBUTE_ROUTE_ADD);

	zlog_debug("%s: %pFX (%s)", zserv_command_string(cmd),
		   &api.prefix, zebra_route_string(api.type));

	sharp_debug_nexthops(&api);

	return 0;
}

/* Add a zclient with a specified session id, for testing. */
int sharp_zclient_create(uint32_t session_id)
{
	struct zclient *client;
	struct sharp_zclient *node;

	/* Check for duplicates */
	for (node = sharp_clients_head; node != NULL; node = node->next) {
		if (node->client->session_id == session_id)
			return -1;
	}

	client = zclient_new(master, &zclient_options_default);
	client->sock = -1;
	client->session_id = session_id;

	zclient_init(client, ZEBRA_ROUTE_SHARP, 0, &sharp_privs);

	/* Register handlers for messages we expect this session to see */
	client->opaque_msg_handler = sharp_opaque_handler;

	/* Enqueue on the list of test clients */
	add_zclient(client);

	return 0;
}

/* Delete one of the extra test zclients */
int sharp_zclient_delete(uint32_t session_id)
{
	struct sharp_zclient *node;

	/* Search for session */
	for (node = sharp_clients_head; node != NULL; node = node->next) {
		if (node->client->session_id == session_id) {
			/* Dequeue from list */
			if (node->next)
				node->next->prev = node->prev;
			if (node->prev)
				node->prev->next = node->next;
			if (node == sharp_clients_head)
				sharp_clients_head = node->next;

			/* Clean up zclient */
			zclient_stop(node->client);
			zclient_free(node->client);

			/* Free memory */
			XFREE(MTYPE_ZC, node);
			break;
		}
	}

	return 0;
}

/* Handler for opaque messages */
static int sharp_opaque_handler(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct zapi_opaque_msg info;

	s = zclient->ibuf;

	if (zclient_opaque_decode(s, &info) != 0)
		return -1;

	zlog_debug("%s: [%u] received opaque type %u", __func__,
		   zclient->session_id, info.type);

	return 0;
}

/*
 * Send OPAQUE messages, using subtype 'type'.
 */
void sharp_opaque_send(uint32_t type, uint32_t proto, uint32_t instance,
		       uint32_t session_id, uint32_t count)
{
	uint8_t buf[32];
	int ret;
	uint32_t i;

	/* Prepare a small payload */
	for (i = 0; i < sizeof(buf); i++) {
		if (type < 255)
			buf[i] = type;
		else
			buf[i] = 255;
	}

	/* Send some messages - broadcast and unicast are supported */
	for (i = 0; i < count; i++) {
		if (proto == 0)
			ret = zclient_send_opaque(zclient, type, buf,
						  sizeof(buf));
		else
			ret = zclient_send_opaque_unicast(zclient, type, proto,
							  instance, session_id,
							  buf, sizeof(buf));
		if (ret < 0) {
			zlog_debug("%s: send_opaque() failed => %d",
				   __func__, ret);
			break;
		}
	}

}

/*
 * Send OPAQUE registration messages, using subtype 'type'.
 */
void sharp_opaque_reg_send(bool is_reg, uint32_t proto, uint32_t instance,
			   uint32_t session_id, uint32_t type)
{
	struct stream *s;

	s = zclient->obuf;
	stream_reset(s);

	if (is_reg)
		zclient_create_header(s, ZEBRA_OPAQUE_REGISTER, VRF_DEFAULT);
	else
		zclient_create_header(s, ZEBRA_OPAQUE_UNREGISTER, VRF_DEFAULT);

	/* Send sub-type */
	stream_putl(s, type);

	/* Add zclient info */
	stream_putc(s, proto);
	stream_putw(s, instance);
	stream_putl(s, session_id);

	/* Put length at the first point of the stream. */
	stream_putw_at(s, 0, stream_get_endp(s));

	(void)zclient_send_message(zclient);

}

void sharp_zebra_init(void)
{
	struct zclient_options opt = {.receive_notify = true};

	if_zapi_callbacks(sharp_ifp_create, sharp_ifp_up,
			  sharp_ifp_down, sharp_ifp_destroy);

	zclient = zclient_new(master, &opt);

	zclient_init(zclient, ZEBRA_ROUTE_SHARP, 0, &sharp_privs);
	zclient->zebra_connected = zebra_connected;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	zclient->route_notify_owner = route_notify_owner;
	zclient->nexthop_update = sharp_nexthop_update;
	zclient->import_check_update = sharp_nexthop_update;

	zclient->redistribute_route_add = sharp_redistribute_route;
	zclient->redistribute_route_del = sharp_redistribute_route;
	zclient->opaque_msg_handler = sharp_opaque_handler;
}
