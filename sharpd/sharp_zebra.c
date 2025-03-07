// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect code.
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include "frrevent.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "link_state.h"
#include "tc.h"

#include "sharp_globals.h"
#include "sharp_nht.h"
#include "sharp_zebra.h"

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct event_loop *master;

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

int sharp_install_lsps_helper(bool install_p, bool update_p,
			      const struct prefix *p, uint8_t type,
			      int instance, uint32_t in_label,
			      const struct nexthop_group *nhg,
			      const struct nexthop_group *backup_nhg)
{
	struct zapi_labels zl = {};
	struct zapi_nexthop *znh;
	const struct nexthop *nh;
	int i, cmd, ret;

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
			if (i >= MULTIPATH_NUM)
				break;
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
			if (i >= MULTIPATH_NUM)
				break;
		}

		if (i > 0)
			SET_FLAG(zl.message, ZAPI_LABELS_HAS_BACKUPS);

		zl.backup_nexthop_num = i;
	}


	if (install_p) {
		if (update_p)
			cmd = ZEBRA_MPLS_LABELS_REPLACE;
		else
			cmd = ZEBRA_MPLS_LABELS_ADD;
	} else {
		cmd = ZEBRA_MPLS_LABELS_DELETE;
	}

	if (zebra_send_mpls_labels(zclient, cmd, &zl) == ZCLIENT_SEND_FAILURE)
		return -1;

	return 0;
}

enum where_to_restart {
	SHARP_INSTALL_ROUTES_RESTART,
	SHARP_DELETE_ROUTES_RESTART,
};

struct buffer_delay {
	struct prefix p;
	uint32_t count;
	uint32_t routes;
	vrf_id_t vrf_id;
	uint8_t instance;
	uint32_t nhgid;
	uint32_t flags;
	const struct nexthop_group *nhg;
	const struct nexthop_group *backup_nhg;
	enum where_to_restart restart;
	char *opaque;
} wb;

/*
 * route_add - Encodes a route to zebra
 *
 * This function returns true when the route was buffered
 * by the underlying stream system
 */
static bool route_add(const struct prefix *p, vrf_id_t vrf_id, uint8_t instance,
		      uint32_t nhgid, const struct nexthop_group *nhg,
		      const struct nexthop_group *backup_nhg, uint32_t flags,
		      char *opaque)
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

	api.flags = flags;

	/* Only send via ID if nhgroup has been successfully installed */
	if (nhgid && sharp_nhgroup_id_is_installed(nhgid)) {
		zapi_route_set_nhg_id(&api, &nhgid);
	} else {
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		for (ALL_NEXTHOPS_PTR(nhg, nh)) {
			/* Check if we set a VNI label */
			if (nh->nh_label &&
			    (nh->nh_label_type == ZEBRA_LSP_EVPN))
				SET_FLAG(api.flags, ZEBRA_FLAG_EVPN_ROUTE);

			api_nh = &api.nexthops[i];

			zapi_nexthop_from_nexthop(api_nh, nh);

			i++;
		}
		api.nexthop_num = i;
	}

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

	if (strlen(opaque)) {
		SET_FLAG(api.message, ZAPI_MESSAGE_OPAQUE);
		api.opaque.length = strlen(opaque) + 1;
		assert(api.opaque.length <= ZAPI_MESSAGE_OPAQUE_LENGTH);
		memcpy(api.opaque.data, opaque, api.opaque.length);
	}

	if (zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api) ==
	    ZCLIENT_SEND_BUFFERED)
		return true;
	else
		return false;
}

/*
 * route_delete - Encodes a route for deletion to zebra
 *
 * This function returns true when the route sent was
 * buffered by the underlying stream system.
 */
static bool route_delete(struct prefix *p, vrf_id_t vrf_id, uint8_t instance)
{
	struct zapi_route api;

	memset(&api, 0, sizeof(api));
	api.vrf_id = vrf_id;
	api.type = ZEBRA_ROUTE_SHARP;
	api.safi = SAFI_UNICAST;
	api.instance = instance;
	memcpy(&api.prefix, p, sizeof(*p));

	if (zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api) ==
	    ZCLIENT_SEND_BUFFERED)
		return true;
	else
		return false;
}

static void sharp_install_routes_restart(struct prefix *p, uint32_t count,
					 vrf_id_t vrf_id, uint8_t instance,
					 uint32_t nhgid,
					 const struct nexthop_group *nhg,
					 const struct nexthop_group *backup_nhg,
					 uint32_t routes, uint32_t flags,
					 char *opaque)
{
	uint32_t temp, i;
	bool v4 = false;

	if (p->family == AF_INET) {
		v4 = true;
		temp = ntohl(p->u.prefix4.s_addr);
	} else
		temp = ntohl(p->u.val32[3]);

	for (i = count; i < routes; i++) {
		bool buffered = route_add(p, vrf_id, (uint8_t)instance, nhgid,
					  nhg, backup_nhg, flags, opaque);
		if (v4)
			p->u.prefix4.s_addr = htonl(++temp);
		else
			p->u.val32[3] = htonl(++temp);

		if (buffered) {
			wb.p = *p;
			wb.count = i + 1;
			wb.routes = routes;
			wb.vrf_id = vrf_id;
			wb.instance = instance;
			wb.nhgid = nhgid;
			wb.nhg = nhg;
			wb.flags = flags;
			wb.backup_nhg = backup_nhg;
			wb.opaque = opaque;
			wb.restart = SHARP_INSTALL_ROUTES_RESTART;

			return;
		}
	}
}

void sharp_install_routes_helper(struct prefix *p, vrf_id_t vrf_id,
				 uint8_t instance, uint32_t nhgid,
				 const struct nexthop_group *nhg,
				 const struct nexthop_group *backup_nhg,
				 uint32_t routes, uint32_t flags, char *opaque)
{
	zlog_debug("Inserting %u routes", routes);

	/* Only use backup route/nexthops if present */
	if (backup_nhg && (backup_nhg->nexthop == NULL))
		backup_nhg = NULL;

	monotime(&sg.r.t_start);
	sharp_install_routes_restart(p, 0, vrf_id, instance, nhgid, nhg,
				     backup_nhg, routes, flags, opaque);
}

static void sharp_remove_routes_restart(struct prefix *p, uint32_t count,
					vrf_id_t vrf_id, uint8_t instance,
					uint32_t routes)
{
	uint32_t temp, i;
	bool v4 = false;

	if (p->family == AF_INET) {
		v4 = true;
		temp = ntohl(p->u.prefix4.s_addr);
	} else
		temp = ntohl(p->u.val32[3]);

	for (i = count; i < routes; i++) {
		bool buffered = route_delete(p, vrf_id, (uint8_t)instance);

		if (v4)
			p->u.prefix4.s_addr = htonl(++temp);
		else
			p->u.val32[3] = htonl(++temp);

		if (buffered) {
			wb.p = *p;
			wb.count = i + 1;
			wb.vrf_id = vrf_id;
			wb.instance = instance;
			wb.routes = routes;
			wb.restart = SHARP_DELETE_ROUTES_RESTART;

			return;
		}
	}
}

void sharp_remove_routes_helper(struct prefix *p, vrf_id_t vrf_id,
				uint8_t instance, uint32_t routes)
{
	zlog_debug("Removing %u routes", routes);

	monotime(&sg.r.t_start);

	sharp_remove_routes_restart(p, 0, vrf_id, instance, routes);
}

static void handle_repeated(bool installed)
{
	struct prefix p = sg.r.orig_prefix;
	sg.r.repeat--;

	if (sg.r.repeat <= 0)
		return;

	if (installed) {
		sg.r.removed_routes = 0;
		sharp_remove_routes_helper(&p, sg.r.vrf_id, sg.r.inst,
					   sg.r.total_routes);
	}

	if (!installed) {
		sg.r.installed_routes = 0;
		sharp_install_routes_helper(
			&p, sg.r.vrf_id, sg.r.inst, sg.r.nhgid,
			&sg.r.nhop_group, &sg.r.backup_nhop_group,
			sg.r.total_routes, sg.r.flags, sg.r.opaque);
	}
}

static void sharp_zclient_buffer_ready(void)
{
	switch (wb.restart) {
	case SHARP_INSTALL_ROUTES_RESTART:
		sharp_install_routes_restart(
			&wb.p, wb.count, wb.vrf_id, wb.instance, wb.nhgid,
			wb.nhg, wb.backup_nhg, wb.routes, wb.flags, wb.opaque);
		return;
	case SHARP_DELETE_ROUTES_RESTART:
		sharp_remove_routes_restart(&wb.p, wb.count, wb.vrf_id,
					    wb.instance, wb.routes);
		return;
	}
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct timeval r;
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table, &note, NULL,
				      NULL))
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
	zebra_route_notify_send(ZEBRA_ROUTE_NOTIFY_REQUEST, zclient, true);
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

void nhg_add(uint32_t id, const struct nexthop_group *nhg,
	     const struct nexthop_group *backup_nhg)
{
	struct zapi_nhg api_nhg = {};
	struct zapi_nexthop *api_nh;
	struct nexthop *nh;
	bool is_valid = true;

	api_nhg.id = id;

	api_nhg.resilience = nhg->nhgr;

	for (ALL_NEXTHOPS_PTR(nhg, nh)) {
		if (api_nhg.nexthop_num >= MULTIPATH_NUM) {
			zlog_warn(
				"%s: number of nexthops greater than max multipath size, truncating",
				__func__);
			break;
		}

		/* Unresolved nexthops will lead to failure - only send
		 * nexthops that zebra will consider valid.
		 */
		if (nh->ifindex == 0)
			continue;

		api_nh = &api_nhg.nexthops[api_nhg.nexthop_num];

		zapi_nexthop_from_nexthop(api_nh, nh);
		api_nhg.nexthop_num++;
	}

	if (api_nhg.nexthop_num == 0) {
		if (sharp_nhgroup_id_is_installed(id)) {
			zlog_debug("%s: nhg %u: no nexthops, deleting nexthop group", __func__,
				   id);
			zclient_nhg_send(zclient, ZEBRA_NHG_DEL, &api_nhg);
			return;
		}
		zlog_debug("%s: nhg %u not sent: no valid nexthops", __func__,
			   id);
		is_valid = false;
		goto done;
	}

	if (backup_nhg) {
		for (ALL_NEXTHOPS_PTR(backup_nhg, nh)) {
			if (api_nhg.backup_nexthop_num >= MULTIPATH_NUM) {
				zlog_warn(
					"%s: number of backup nexthops greater than max multipath size, truncating",
					__func__);
				break;
			}

			/* Unresolved nexthop: will be rejected by zebra.
			 * That causes a problem, since the primary nexthops
			 * rely on array indexing into the backup nexthops. If
			 * that array isn't valid, the backup indexes won't be
			 * valid.
			 */
			if (nh->ifindex == 0) {
				zlog_debug("%s: nhg %u: invalid backup nexthop",
					   __func__, id);
				is_valid = false;
				break;
			}

			api_nh = &api_nhg.backup_nexthops
					  [api_nhg.backup_nexthop_num];

			zapi_backup_nexthop_from_nexthop(api_nh, nh);
			api_nhg.backup_nexthop_num++;
		}
	}

done:
	if (is_valid)
		zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
}

void nhg_del(uint32_t id)
{
	struct zapi_nhg api_nhg = {};

	api_nhg.id = id;

	zclient_nhg_send(zclient, ZEBRA_NHG_DEL, &api_nhg);
}

void sharp_zebra_nexthop_watch(struct prefix *p, vrf_id_t vrf_id, bool import, bool watch,
			       bool connected, bool mrib)
{
	int command = ZEBRA_NEXTHOP_REGISTER;
	safi_t safi = mrib ? SAFI_MULTICAST : SAFI_UNICAST;

	command = ZEBRA_NEXTHOP_REGISTER;

	if (!watch)
		command = ZEBRA_NEXTHOP_UNREGISTER;

	if (zclient_send_rnh(zclient, command, p, safi, connected, false, vrf_id) ==
	    ZCLIENT_SEND_FAILURE)
		zlog_warn("%s: Failure to send nexthop to zebra", __func__);
}

static int sharp_debug_nexthops(struct zapi_route *api)
{
	int i;

	if (api->nexthop_num == 0) {
		zlog_debug("        Not installed");
		return 0;
	}

	for (i = 0; i < api->nexthop_num; i++) {
		struct zapi_nexthop *znh = &api->nexthops[i];

		switch (znh->type) {
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			zlog_debug(
				"        Nexthop %pI4, type: %d, ifindex: %d, vrf: %d, label_num: %d",
				&znh->gate.ipv4.s_addr, znh->type, znh->ifindex,
				znh->vrf_id, znh->label_num);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IPV6:
			zlog_debug(
				"        Nexthop %pI6, type: %d, ifindex: %d, vrf: %d, label_num: %d",
				&znh->gate.ipv6, znh->type, znh->ifindex,
				znh->vrf_id, znh->label_num);
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

static void sharp_nexthop_update(struct vrf *vrf, struct prefix *matched,
				 struct zapi_route *nhr)
{
	struct sharp_nh_tracker *nht;

	zlog_debug("Received update for %pFX actual match: %pFX metric: %u",
		   matched, &nhr->prefix, nhr->metric);

	nht = sharp_nh_tracker_get(matched);
	nht->nhop_num = nhr->nexthop_num;
	nht->updates++;

	sharp_debug_nexthops(nhr);
}

static int sharp_redistribute_route(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route api;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		zlog_warn("%s: Decode of redistribute failed: %d", __func__,
			  ZEBRA_REDISTRIBUTE_ROUTE_ADD);

	zlog_debug("%s: %pFX (%s)", zserv_command_string(cmd), &api.prefix,
		   zebra_route_string(api.type));

	sharp_debug_nexthops(&api);

	return 0;
}

void sharp_redistribute_vrf(struct vrf *vrf, int type, bool turn_on)
{
	zebra_redistribute_send(turn_on ? ZEBRA_REDISTRIBUTE_ADD
					: ZEBRA_REDISTRIBUTE_DELETE,
				zclient, AFI_IP, type, 0, vrf->vrf_id);
}

static zclient_handler *const sharp_opaque_handlers[] = {
	[ZEBRA_OPAQUE_MESSAGE] = sharp_opaque_handler,
};

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

	client = zclient_new(master, &zclient_options_default,
			     sharp_opaque_handlers,
			     array_size(sharp_opaque_handlers));
	client->sock = -1;
	client->session_id = session_id;

	zclient_init(client, ZEBRA_ROUTE_SHARP, 0, &sharp_privs);

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

static const char *const type2txt[] = {"Generic", "Vertex", "Edge", "Subnet"};
static const char *const status2txt[] = {"Unknown", "New",  "Update",
					 "Delete",  "Sync", "Orphan"};
/* Handler for opaque messages */
static int sharp_opaque_handler(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct zapi_opaque_msg info;
	struct ls_element *lse;

	s = zclient->ibuf;

	if (zclient_opaque_decode(s, &info) != 0)
		return -1;

	zlog_debug("%s: [%u] received opaque type %u", __func__,
		   zclient->session_id, info.type);

	if (info.type == LINK_STATE_UPDATE) {
		lse = ls_stream2ted(sg.ted, s, true);
		if (lse) {
			zlog_debug(" |- Got %s %s from Link State Database",
				   status2txt[lse->status],
				   type2txt[lse->type]);
			lse->status = SYNC;
		} else
			zlog_debug(
				"%s: Error to convert Stream into Link State",
				__func__);
	}

	return 0;
}

/* Handler for opaque notification messages */
static int sharp_opq_notify_handler(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct zapi_opaque_notif_info info;

	s = zclient->ibuf;

	if (zclient_opaque_notif_decode(s, &info) != 0)
		return -1;

	if (info.reg)
		zlog_debug("%s: received opaque notification REG, type %u => %d/%d/%d",
			   __func__, info.msg_type, info.proto, info.instance,
			   info.session_id);
	else
		zlog_debug("%s: received opaque notification UNREG, type %u",
			   __func__, info.msg_type);

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
		if (ret == ZCLIENT_SEND_FAILURE) {
			zlog_debug("%s: send_opaque() failed => %d", __func__,
				   ret);
			break;
		}
	}
}

/*
 * Register/unregister for opaque notifications from zebra about 'type'.
 */
void sharp_zebra_opaque_notif_reg(bool is_reg, uint32_t type)
{
	if (is_reg)
		zclient_opaque_request_notify(zclient, type);
	else
		zclient_opaque_drop_notify(zclient, type);
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

/* Link State registration */
void sharp_zebra_register_te(void)
{
	/* First register to received Link State Update messages */
	zclient_register_opaque(zclient, LINK_STATE_UPDATE);

	/* Then, request initial TED with SYNC message */
	ls_request_sync(zclient);
}

void sharp_zebra_send_arp(const struct interface *ifp, const struct prefix *p)
{
	zclient_send_neigh_discovery_req(zclient, ifp, p);
}

static int nhg_notify_owner(ZAPI_CALLBACK_ARGS)
{
	enum zapi_nhg_notify_owner note;
	uint32_t id;

	if (!zapi_nhg_notify_decode(zclient->ibuf, &id, &note))
		return -1;

	switch (note) {
	case ZAPI_NHG_INSTALLED:
		sharp_nhgroup_id_set_installed(id, true);
		zlog_debug("Installed nhg %u", id);
		break;
	case ZAPI_NHG_FAIL_INSTALL:
		zlog_debug("Failed install of nhg %u", id);
		break;
	case ZAPI_NHG_REMOVED:
		sharp_nhgroup_id_set_installed(id, false);
		zlog_debug("Removed nhg %u", id);
		break;
	case ZAPI_NHG_REMOVE_FAIL:
		zlog_debug("Failed removal of nhg %u", id);
		break;
	}

	return 0;
}

int sharp_zebra_srv6_manager_get_locator_chunk(const char *locator_name)
{
	return srv6_manager_get_locator_chunk(zclient, locator_name);
}

int sharp_zebra_srv6_manager_release_locator_chunk(const char *locator_name)
{
	return srv6_manager_release_locator_chunk(zclient, locator_name);
}

static int sharp_zebra_process_srv6_locator_chunk(ZAPI_CALLBACK_ARGS)
{
	struct stream *s = NULL;
	struct srv6_locator_chunk s6c = {};
	struct listnode *node, *nnode;
	struct sharp_srv6_locator *loc;

	s = zclient->ibuf;
	zapi_srv6_locator_chunk_decode(s, &s6c);

	for (ALL_LIST_ELEMENTS(sg.srv6_locators, node, nnode, loc)) {
		struct prefix_ipv6 *chunk = NULL;
		struct listnode *chunk_node;
		struct prefix_ipv6 *c;

		if (strcmp(loc->name, s6c.locator_name) != 0) {
			zlog_err("%s: Locator name unmatch %s:%s", __func__,
				 loc->name, s6c.locator_name);
			continue;
		}

		for (ALL_LIST_ELEMENTS_RO(loc->chunks, chunk_node, c))
			if (!prefix_cmp(c, &s6c.prefix))
				return 0;

		chunk = prefix_ipv6_new();
		*chunk = s6c.prefix;
		listnode_add(loc->chunks, chunk);
		return 0;
	}

	zlog_err("%s: can't get locator_chunk!!", __func__);
	return 0;
}

static int sharp_zebra_process_neigh(ZAPI_CALLBACK_ARGS)
{
	union sockunion addr = {}, lladdr = {};
	struct zapi_neigh_ip api = {};
	struct interface *ifp;

	zlog_debug("Received a neighbor event");
	zclient_neigh_ip_decode(zclient->ibuf, &api);

	if (api.ip_in.ipa_type == AF_UNSPEC)
		return 0;

	sockunion_family(&addr) = api.ip_in.ipa_type;
	memcpy((uint8_t *)sockunion_get_addr(&addr), &api.ip_in.ip.addr,
	       family2addrsize(api.ip_in.ipa_type));

	sockunion_family(&lladdr) = api.ip_out.ipa_type;
	if (api.ip_out.ipa_type != AF_UNSPEC)
		memcpy((uint8_t *)sockunion_get_addr(&lladdr),
		       &api.ip_out.ip.addr,
		       family2addrsize(api.ip_out.ipa_type));
	ifp = if_lookup_by_index(api.index, vrf_id);
	if (!ifp) {
		zlog_debug("Failed to lookup interface for neighbor entry: %u for %u",
			   api.index, vrf_id);
		return 0;
	}

	zlog_debug("Received: %s %pSU dev %s lladr %pSU",
		   (cmd == ZEBRA_NEIGH_ADDED) ? "NEW" : "DEL", &addr, ifp->name,
		   &lladdr);

	return 0;
}

int sharp_zebra_send_interface_protodown(struct interface *ifp, bool down)
{
	zlog_debug("Sending zebra to set %s protodown %s", ifp->name,
		   down ? "on" : "off");

	if (zclient_send_interface_protodown(zclient, ifp->vrf->vrf_id, ifp,
					     down) == ZCLIENT_SEND_FAILURE)
		return -1;

	return 0;
}

int sharp_zebra_send_tc_filter_rate(struct interface *ifp,
				    const struct prefix *source,
				    const struct prefix *destination,
				    uint8_t ip_proto, uint16_t src_port,
				    uint16_t dst_port, uint64_t rate)
{
#define SHARPD_TC_HANDLE 0x0001
	struct stream *s;

	s = zclient->obuf;

	struct tc_qdisc q = {.ifindex = ifp->ifindex, .kind = TC_QDISC_HTB};

	zapi_tc_qdisc_encode(ZEBRA_TC_QDISC_INSTALL, s, &q);
	if (zclient_send_message(zclient) == ZCLIENT_SEND_FAILURE)
		return -1;

	struct tc_class c = {.ifindex = ifp->ifindex,
			     .handle = SHARPD_TC_HANDLE & 0xffff,
			     .kind = TC_QDISC_HTB,
			     .u.htb.ceil = rate,
			     .u.htb.rate = rate};

	zapi_tc_class_encode(ZEBRA_TC_CLASS_ADD, s, &c);
	if (zclient_send_message(zclient) == ZCLIENT_SEND_FAILURE)
		return -1;

	struct tc_filter f = {.ifindex = ifp->ifindex,
			      .handle = SHARPD_TC_HANDLE,
			      .priority = 0x1,
			      .kind = TC_FILTER_FLOWER,
			      .u.flower.filter_bm = 0};

#ifdef ETH_P_IP
	f.protocol = ETH_P_IP;
#else
	f.protocol = 0x0800;
#endif

	f.u.flower.filter_bm |= TC_FLOWER_IP_PROTOCOL;
	f.u.flower.ip_proto = ip_proto;
	f.u.flower.filter_bm |= TC_FLOWER_SRC_IP;
	prefix_copy(&f.u.flower.src_ip, source);
	f.u.flower.filter_bm |= TC_FLOWER_DST_IP;
	prefix_copy(&f.u.flower.dst_ip, destination);
	f.u.flower.filter_bm |= TC_FLOWER_SRC_PORT;
	f.u.flower.src_port_min = f.u.flower.src_port_max = src_port;
	f.u.flower.filter_bm |= TC_FLOWER_DST_PORT;
	f.u.flower.dst_port_min = f.u.flower.dst_port_max = dst_port;
	f.u.flower.classid = SHARPD_TC_HANDLE & 0xffff;

	zapi_tc_filter_encode(ZEBRA_TC_FILTER_ADD, s, &f);
	if (zclient_send_message(zclient) == ZCLIENT_SEND_FAILURE)
		return -1;

	return 0;
}

void sharp_zebra_register_neigh(vrf_id_t vrf_id, afi_t afi, bool reg)
{
	zclient_register_neigh(zclient, vrf_id, afi, reg);
}


static zclient_handler *const sharp_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = interface_address_delete,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = route_notify_owner,
	[ZEBRA_NHG_NOTIFY_OWNER] = nhg_notify_owner,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = sharp_redistribute_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = sharp_redistribute_route,
	[ZEBRA_OPAQUE_MESSAGE] = sharp_opaque_handler,
	[ZEBRA_OPAQUE_NOTIFY] = sharp_opq_notify_handler,
	[ZEBRA_SRV6_MANAGER_GET_LOCATOR_CHUNK] =
		sharp_zebra_process_srv6_locator_chunk,
	[ZEBRA_NEIGH_ADDED] = sharp_zebra_process_neigh,
	[ZEBRA_NEIGH_REMOVED] = sharp_zebra_process_neigh,
};

void sharp_zebra_init(void)
{
	hook_register_prio(if_real, 0, sharp_ifp_create);
	hook_register_prio(if_up, 0, sharp_ifp_up);
	hook_register_prio(if_down, 0, sharp_ifp_down);
	hook_register_prio(if_unreal, 0, sharp_ifp_destroy);

	zclient = zclient_new(master, &zclient_options_default, sharp_handlers,
			      array_size(sharp_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_SHARP, 0, &sharp_privs);
	zclient->zebra_connected = zebra_connected;
	zclient->zebra_buffer_write_ready = sharp_zclient_buffer_ready;
	zclient->nexthop_update = sharp_nexthop_update;
}

void sharp_zebra_terminate(void)
{
	struct sharp_zclient *node = sharp_clients_head;

	while (node) {
		sharp_zclient_delete(node->client->session_id);

		node = sharp_clients_head;
	}

	zclient_stop(zclient);
	zclient_free(zclient);
}
