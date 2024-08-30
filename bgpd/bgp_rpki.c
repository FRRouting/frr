// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP RPKI
 * Copyright (C) 2013 Michael Mester (m.mester@fu-berlin.de), for FU Berlin
 * Copyright (C) 2014-2017 Andreas Reuter (andreas.reuter@fu-berlin.de), for FU
 * Berlin
 * Copyright (C) 2016-2017 Colin Sames (colin.sames@haw-hamburg.de), for HAW
 * Hamburg
 * Copyright (C) 2017-2018 Marcel Röthke (marcel.roethke@haw-hamburg.de),
 * for HAW Hamburg
 */

/* If rtrlib compiled with ssh support, don`t fail build */
#define LIBSSH_LEGACY_0_4

#include <zebra.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include "prefix.h"
#include "log.h"
#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "frrevent.h"
#include "filter.h"
#include "lib_errors.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgp_advertise.h"
#include "bgp_label.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_rpki.h"
#include "bgpd/bgp_debug.h"
#include "northbound_cli.h"

#include "lib/network.h"
#include "rtrlib/rtrlib.h"
#include "hook.h"
#include "libfrr.h"
#include "lib/version.h"

#include "bgpd/bgp_rpki_clippy.c"

DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_TEMP, "BGP RPKI Intermediate Buffer");
DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_CACHE, "BGP RPKI Cache server");
DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_CACHE_GROUP, "BGP RPKI Cache server group");
DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_RTRLIB, "BGP RPKI RTRLib");
DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_REVALIDATE, "BGP RPKI Revalidation");

#define STR_SEPARATOR 10

#define POLLING_PERIOD_DEFAULT 3600
#define EXPIRE_INTERVAL_DEFAULT 7200
#define RETRY_INTERVAL_DEFAULT 600
#define BGP_RPKI_CACHE_SERVER_SYNC_RETRY_TIMEOUT 3

#define RPKI_DEBUG(...)                                                        \
	if (rpki_debug_conf || rpki_debug_term) {                              \
		zlog_debug("RPKI: " __VA_ARGS__);                              \
	}

#define RPKI_OUTPUT_STRING "Control rpki specific settings\n"

struct cache {
	enum {
		TCP,
#if defined(FOUND_SSH)
		SSH
#endif
	} type;
	struct tr_socket *tr_socket;
	union {
		struct tr_tcp_config *tcp_config;
		struct tr_ssh_config *ssh_config;
	} tr_config;
	struct rtr_socket *rtr_socket;
	uint8_t preference;
	struct rpki_vrf *rpki_vrf;
};

enum return_values { SUCCESS = 0, ERROR = -1 };

struct rpki_for_each_record_arg {
	struct vty *vty;
	unsigned int *prefix_amount;
	as_t as;
	json_object *json;
	enum asnotation_mode asnotation;
};

struct rpki_vrf {
	struct rtr_mgr_config *rtr_config;
	struct list *cache_list;
	bool rtr_is_running;
	bool rtr_is_stopping;
	bool rtr_is_synced;
	_Atomic int rtr_update_overflow;
	unsigned int polling_period;
	unsigned int expire_interval;
	unsigned int retry_interval;
	int rpki_sync_socket_rtr;
	int rpki_sync_socket_bgpd;
	char *vrfname;
	struct event *t_rpki_sync;

	QOBJ_FIELDS;
};

static pthread_key_t rpki_pthread;

static struct rpki_vrf *find_rpki_vrf(const char *vrfname);
static int bgp_rpki_vrf_update(struct vrf *vrf, bool enabled);
static int bgp_rpki_write_vrf(struct vty *vty, struct vrf *vrf);
static int bgp_rpki_hook_write_vrf(struct vty *vty, struct vrf *vrf);
static int bgp_rpki_write_debug(struct vty *vty, bool running);
static int start(struct rpki_vrf *rpki_vrf);
static void stop(struct rpki_vrf *rpki_vrf);
static int reset(bool force, struct rpki_vrf *rpki_vrf);
static struct rtr_mgr_group *get_connected_group(struct rpki_vrf *rpki_vrf);
static void print_prefix_table(struct vty *vty, struct rpki_vrf *rpki_vrf,
			       json_object *json, bool count_only);
static void install_cli_commands(void);
static int config_write(struct vty *vty);
static int config_on_exit(struct vty *vty);
static void free_cache(struct cache *cache);
static struct rtr_mgr_group *get_groups(struct list *cache_list);
#if defined(FOUND_SSH)
static int add_ssh_cache(struct rpki_vrf *rpki_vrf, const char *host,
			 const unsigned int port, const char *username,
			 const char *client_privkey_path,
			 const char *server_pubkey_path,
			 const uint8_t preference, const char *bindaddr);
#endif
static struct rtr_socket *create_rtr_socket(struct tr_socket *tr_socket);
static struct cache *find_cache(const uint8_t preference,
				struct list *cache_list);
static void rpki_delete_all_cache_nodes(struct rpki_vrf *rpki_vrf);
static int add_tcp_cache(struct rpki_vrf *rpki_vrf, const char *host,
			 const char *port, const uint8_t preference,
			 const char *bindaddr);
static void print_record(const struct pfx_record *record, struct vty *vty,
			 json_object *json, enum asnotation_mode asnotation);
static bool is_synchronized(struct rpki_vrf *rpki_vrf);
static bool is_running(struct rpki_vrf *rpki_vrf);
static bool is_stopping(struct rpki_vrf *rpki_vrf);
static void route_match_free(void *rule);
static enum route_map_cmd_result_t route_match(void *rule,
					       const struct prefix *prefix,

					       void *object);
static void *route_match_compile(const char *arg);
static void revalidate_bgp_node(struct bgp_dest *dest, afi_t afi, safi_t safi);
static void revalidate_all_routes(struct rpki_vrf *rpki_vrf);

static bool rpki_debug_conf, rpki_debug_term;

DECLARE_QOBJ_TYPE(rpki_vrf);
DEFINE_QOBJ_TYPE(rpki_vrf);

struct list *rpki_vrf_list;

static struct cmd_node rpki_node = {
	.name = "rpki",
	.node = RPKI_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-rpki)# ",
	.config_write = config_write,
	.node_exit = config_on_exit,
};

static struct cmd_node rpki_vrf_node = {
	.name = "rpki",
	.node = RPKI_VRF_NODE,
	.parent_node = VRF_NODE,
	.prompt = "%s(config-vrf-rpki)# ",
	.config_write = NULL,
	.node_exit = config_on_exit,
};

static const struct route_map_rule_cmd route_match_rpki_cmd = {
	"rpki", route_match, route_match_compile, route_match_free};

static void *malloc_wrapper(size_t size)
{
	return XMALLOC(MTYPE_BGP_RPKI_RTRLIB, size);
}

static void *realloc_wrapper(void *ptr, size_t size)
{
	return XREALLOC(MTYPE_BGP_RPKI_RTRLIB, ptr, size);
}

static void free_wrapper(void *ptr)
{
	XFREE(MTYPE_BGP_RPKI_RTRLIB, ptr);
}

static void init_tr_socket(struct cache *cache)
{
	if (cache->type == TCP)
		tr_tcp_init(cache->tr_config.tcp_config,
			    cache->tr_socket);
#if defined(FOUND_SSH)
	else
		tr_ssh_init(cache->tr_config.ssh_config,
			    cache->tr_socket);
#endif
}

static void free_tr_socket(struct cache *cache)
{
	if (cache->type == TCP)
		tr_tcp_init(cache->tr_config.tcp_config,
			    cache->tr_socket);
#if defined(FOUND_SSH)
	else
		tr_ssh_init(cache->tr_config.ssh_config,
			    cache->tr_socket);
#endif
}

static int rpki_validate_prefix(struct peer *peer, struct attr *attr,
				const struct prefix *prefix);

static void ipv6_addr_to_network_byte_order(const uint32_t *src, uint32_t *dest)
{
	int i;

	for (i = 0; i < 4; i++)
		dest[i] = htonl(src[i]);
}

static void ipv6_addr_to_host_byte_order(const uint32_t *src, uint32_t *dest)
{
	int i;

	for (i = 0; i < 4; i++)
		dest[i] = ntohl(src[i]);
}

static enum route_map_cmd_result_t route_match(void *rule,
					       const struct prefix *prefix,
					       void *object)
{
	int *rpki_status = rule;
	struct bgp_path_info *path;

	path = object;

	if (rpki_validate_prefix(path->peer, path->attr, prefix)
	    == *rpki_status) {
		return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

static void *route_match_compile(const char *arg)
{
	int *rpki_status;

	rpki_status = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(int));

	if (strcmp(arg, "valid") == 0)
		*rpki_status = RPKI_VALID;
	else if (strcmp(arg, "invalid") == 0)
		*rpki_status = RPKI_INVALID;
	else
		*rpki_status = RPKI_NOTFOUND;

	return rpki_status;
}

static void route_match_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct rtr_socket *create_rtr_socket(struct tr_socket *tr_socket)
{
	struct rtr_socket *rtr_socket =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct rtr_socket));
	rtr_socket->tr_socket = tr_socket;
	return rtr_socket;
}

static int bgp_rpki_vrf_update(struct vrf *vrf, bool enabled)
{
	struct rpki_vrf *rpki;

	if (vrf->vrf_id == VRF_DEFAULT)
		rpki = find_rpki_vrf(NULL);
	else
		rpki = find_rpki_vrf(vrf->name);
	if (!rpki)
		return 0;

	if (enabled)
		start(rpki);
	else
		stop(rpki);
	return 1;
}

/* tcp identifier : <HOST>:<PORT>
 * ssh identifier : <user>@<HOST>:<PORT>
 */
static struct rpki_vrf *find_rpki_vrf_from_ident(const char *ident)
{
#if defined(FOUND_SSH)
	struct tr_ssh_config *ssh_config;
#endif
	struct tr_tcp_config *tcp_config;
	struct listnode *rpki_vrf_nnode;
	unsigned int cache_port, port;
	struct listnode *cache_node;
	struct rpki_vrf *rpki_vrf;
	struct cache *cache;
	bool is_tcp = true;
	size_t host_len;
	char *endptr;
	char *host;
	char *ptr;
	char *buf;

	/* extract the <SOCKET> */
	ptr = strrchr(ident, ':');
	if (!ptr)
		return NULL;

	ptr++;
	/* extract port */
	port = atoi(ptr);
	if (port == 0)
		/* not ours */
		return NULL;

	/* extract host */
	ptr--;
	host_len = (size_t)(ptr - ident);
	buf = XCALLOC(MTYPE_BGP_RPKI_TEMP, host_len + 1);
	memcpy(buf, ident, host_len);
	buf[host_len] = '\0';
	endptr = strrchr(buf, '@');

	/* ssh session */
	if (endptr) {
		host = XCALLOC(MTYPE_BGP_RPKI_TEMP,
			       (size_t)(buf + host_len - endptr) + 1);
		memcpy(host, endptr + 1, (size_t)(buf + host_len - endptr) + 1);
		is_tcp = false;
	} else {
		host = buf;
		buf = NULL;
	}

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf_list, rpki_vrf_nnode, rpki_vrf)) {
		for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node,
					  cache)) {
			if ((cache->type == TCP && !is_tcp)
#if defined(FOUND_SSH)
			    || (cache->type == SSH && is_tcp)
#endif
			)
				continue;

			if (is_tcp) {
				tcp_config = cache->tr_config.tcp_config;
				cache_port = atoi(tcp_config->port);
				if (cache_port != port)
					continue;
				if (strlen(tcp_config->host) != strlen(host))
					continue;
				if (memcmp(tcp_config->host, host, host_len) ==
				    0)
					break;
			}
#if defined(FOUND_SSH)
			else {
				ssh_config = cache->tr_config.ssh_config;
				if (port != ssh_config->port)
					continue;
				if (strmatch(ssh_config->host, host))
					break;
			}
#endif
		}
		if (cache)
			break;
	}
	if (host)
		XFREE(MTYPE_BGP_RPKI_TEMP, host);
	if (buf)
		XFREE(MTYPE_BGP_RPKI_TEMP, buf);
	return rpki_vrf;
}

static struct rpki_vrf *find_rpki_vrf(const char *vrfname)
{
	struct listnode *rpki_vrf_nnode;
	struct rpki_vrf *rpki_vrf;

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf_list, rpki_vrf_nnode, rpki_vrf)) {
		if (!vrfname && !rpki_vrf->vrfname)
			/* rpki_vrf struct of the default VRF */
			return rpki_vrf;
		if (vrfname && rpki_vrf->vrfname &&
		    strmatch(vrfname, rpki_vrf->vrfname))
			return rpki_vrf;
	}
	return NULL;
}

static struct cache *find_cache(const uint8_t preference,
				struct list *cache_list)
{
	struct listnode *cache_node;
	struct cache *cache;

	if (!cache_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		if (cache->preference == preference)
			return cache;
	}
	return NULL;
}

static void rpki_delete_all_cache_nodes(struct rpki_vrf *rpki_vrf)
{
	struct listnode *cache_node, *cache_next;
	struct cache *cache;

	for (ALL_LIST_ELEMENTS(rpki_vrf->cache_list, cache_node, cache_next,
			       cache)) {
		if (is_running(rpki_vrf))
			rtr_mgr_remove_group(rpki_vrf->rtr_config,
					     cache->preference);
		listnode_delete(rpki_vrf->cache_list, cache);
	}
}

static void print_record(const struct pfx_record *record, struct vty *vty,
			 json_object *json, enum asnotation_mode asnotation)
{
	char ip[INET6_ADDRSTRLEN];
	json_object *json_record = NULL;

	lrtr_ip_addr_to_str(&record->prefix, ip, sizeof(ip));

	if (!json) {
		vty_out(vty, "%-40s   %3u - %3u   ", ip, record->min_len,
			record->max_len);
		vty_out(vty, ASN_FORMAT(asnotation), (as_t *)&record->asn);
		vty_out(vty, "\n");
	} else {
		json_record = json_object_new_object();
		json_object_string_add(json_record, "prefix", ip);
		json_object_int_add(json_record, "prefixLenMin",
				    record->min_len);
		json_object_int_add(json_record, "prefixLenMax",
				    record->max_len);
		asn_asn2json(json_record, "asn", record->asn, asnotation);
		json_object_array_add(json, json_record);
	}
}

static void print_record_by_asn(const struct pfx_record *record, void *data)
{
	struct rpki_for_each_record_arg *arg = data;
	struct vty *vty = arg->vty;

	if (record->asn == arg->as) {
		(*arg->prefix_amount)++;
		print_record(record, vty, arg->json, arg->asnotation);
	}
}

static void print_record_cb(const struct pfx_record *record, void *data)
{
	struct rpki_for_each_record_arg *arg = data;
	struct vty *vty = arg->vty;

	(*arg->prefix_amount)++;

	print_record(record, vty, arg->json, arg->asnotation);
}

static void count_record_cb(const struct pfx_record *record, void *data)
{
	struct rpki_for_each_record_arg *arg = data;

	(*arg->prefix_amount)++;
}

static struct rtr_mgr_group *get_groups(struct list *cache_list)
{
	struct listnode *cache_node;
	struct rtr_mgr_group *rtr_mgr_groups;
	struct cache *cache;

	int group_count = listcount(cache_list);

	if (group_count == 0)
		return NULL;

	rtr_mgr_groups = XMALLOC(MTYPE_BGP_RPKI_CACHE_GROUP,
				 group_count * sizeof(struct rtr_mgr_group));

	size_t i = 0;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		rtr_mgr_groups[i].sockets = &cache->rtr_socket;
		rtr_mgr_groups[i].sockets_len = 1;
		rtr_mgr_groups[i].preference = cache->preference;

		init_tr_socket(cache);

		i++;
	}

	return rtr_mgr_groups;
}

inline bool is_synchronized(struct rpki_vrf *rpki_vrf)
{
	return rpki_vrf->rtr_is_synced;
}

inline bool is_running(struct rpki_vrf *rpki_vrf)
{
	return rpki_vrf->rtr_is_running;
}

inline bool is_stopping(struct rpki_vrf *rpki_vrf)
{
	return rpki_vrf->rtr_is_stopping;
}

static void pfx_record_to_prefix(struct pfx_record *record,
				 struct prefix *prefix)
{
	prefix->prefixlen = record->min_len;

	if (record->prefix.ver == LRTR_IPV4) {
		prefix->family = AF_INET;
		prefix->u.prefix4.s_addr = htonl(record->prefix.u.addr4.addr);
	} else {
		prefix->family = AF_INET6;
		ipv6_addr_to_network_byte_order(record->prefix.u.addr6.addr,
						prefix->u.prefix6.s6_addr32);
	}
}

struct rpki_revalidate_prefix {
	struct bgp *bgp;
	struct prefix prefix;
	afi_t afi;
	safi_t safi;
};

static void rpki_revalidate_prefix(struct event *thread)
{
	struct rpki_revalidate_prefix *rrp = EVENT_ARG(thread);
	struct bgp_dest *match, *node;

	match = bgp_table_subtree_lookup(rrp->bgp->rib[rrp->afi][rrp->safi],
					 &rrp->prefix);

	node = match;

	while (node) {
		if (bgp_dest_has_bgp_path_info_data(node)) {
			revalidate_bgp_node(node, rrp->afi, rrp->safi);
		}

		node = bgp_route_next_until(node, match);
	}

	XFREE(MTYPE_BGP_RPKI_REVALIDATE, rrp);
}

static void bgpd_sync_callback(struct event *thread)
{
	struct bgp *bgp;
	struct listnode *node;
	struct prefix prefix;
	struct pfx_record rec;
	struct rpki_vrf *rpki_vrf = EVENT_ARG(thread);
	struct vrf *vrf = NULL;

	event_add_read(bm->master, bgpd_sync_callback, rpki_vrf,
		       rpki_vrf->rpki_sync_socket_bgpd, NULL);

	if (atomic_load_explicit(&rpki_vrf->rtr_update_overflow,
				 memory_order_seq_cst)) {
		while (read(rpki_vrf->rpki_sync_socket_bgpd, &rec,
			    sizeof(struct pfx_record)) != -1)
			;

		atomic_store_explicit(&rpki_vrf->rtr_update_overflow, 0,
				      memory_order_seq_cst);
		revalidate_all_routes(rpki_vrf);
		return;
	}

	int retval = read(rpki_vrf->rpki_sync_socket_bgpd, &rec,
			  sizeof(struct pfx_record));
	if (retval != sizeof(struct pfx_record)) {
		RPKI_DEBUG("Could not read from rpki_sync_socket_bgpd");
		return;
	}
	pfx_record_to_prefix(&rec, &prefix);

	afi_t afi = (rec.prefix.ver == LRTR_IPV4) ? AFI_IP : AFI_IP6;

	if (rpki_vrf->vrfname) {
		vrf = vrf_lookup_by_name(rpki_vrf->vrfname);
		if (!vrf) {
			zlog_err("%s(): vrf for rpki %s not found", __func__,
				 rpki_vrf->vrfname);
			return;
		}
	}

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		safi_t safi;

		if (!vrf && bgp->vrf_id != VRF_DEFAULT)
			continue;
		if (vrf && bgp->vrf_id != vrf->vrf_id)
			continue;

		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			struct bgp_table *table = bgp->rib[afi][safi];
			struct rpki_revalidate_prefix *rrp;

			if (!table)
				continue;

			rrp = XCALLOC(MTYPE_BGP_RPKI_REVALIDATE, sizeof(*rrp));
			rrp->bgp = bgp;
			rrp->prefix = prefix;
			rrp->afi = afi;
			rrp->safi = safi;
			event_add_event(bm->master, rpki_revalidate_prefix, rrp,
					0, &bgp->t_revalidate[afi][safi]);
		}
	}
}

static void revalidate_bgp_node(struct bgp_dest *bgp_dest, afi_t afi,
				safi_t safi)
{
	struct bgp_adj_in *ain;
	mpls_label_t *label;
	uint8_t num_labels;

	for (ain = bgp_dest->adj_in; ain; ain = ain->next) {
		struct bgp_path_info *path =
			bgp_dest_get_bgp_path_info(bgp_dest);

		num_labels = BGP_PATH_INFO_NUM_LABELS(path);
		label = num_labels ? path->extra->labels->label : NULL;

		(void)bgp_update(ain->peer, bgp_dest_get_prefix(bgp_dest),
				 ain->addpath_rx_id, ain->attr, afi, safi,
				 ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, label,
				 num_labels, 1, NULL);
	}
}

/*
 * The act of a soft reconfig in revalidation is really expensive
 * coupled with the fact that the download of a full rpki state
 * from a rpki server can be expensive, let's break up the revalidation
 * to a point in time in the future to allow other bgp events
 * to take place too.
 */
struct rpki_revalidate_peer {
	afi_t afi;
	safi_t safi;
	struct peer *peer;
};

static void bgp_rpki_revalidate_peer(struct event *thread)
{
	struct rpki_revalidate_peer *rvp = EVENT_ARG(thread);

	/*
	 * Here's the expensive bit of gnomish deviousness
	 */
	bgp_soft_reconfig_in(rvp->peer, rvp->afi, rvp->safi);

	XFREE(MTYPE_BGP_RPKI_REVALIDATE, rvp);
}

static void revalidate_all_routes(struct rpki_vrf *rpki_vrf)
{
	struct bgp *bgp;
	struct listnode *node;
	struct vrf *vrf = NULL;

	if (rpki_vrf->vrfname) {
		vrf = vrf_lookup_by_name(rpki_vrf->vrfname);
		if (!vrf) {
			zlog_err("%s(): vrf for rpki %s not found", __func__,
				 rpki_vrf->vrfname);
			return;
		}
	}

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct peer *peer;
		struct listnode *peer_listnode;

		if (!vrf && bgp->vrf_id != VRF_DEFAULT)
			continue;
		if (vrf && bgp->vrf_id != vrf->vrf_id)
			continue;

		for (ALL_LIST_ELEMENTS_RO(bgp->peer, peer_listnode, peer)) {
			afi_t afi;
			safi_t safi;

			FOREACH_AFI_SAFI (afi, safi) {
				struct rpki_revalidate_peer *rvp;

				if (!bgp->rib[afi][safi])
					continue;

				if (!peer_established(peer->connection))
					continue;

				rvp = XCALLOC(MTYPE_BGP_RPKI_REVALIDATE,
					      sizeof(*rvp));
				rvp->peer = peer;
				rvp->afi = afi;
				rvp->safi = safi;

				event_add_event(
					bm->master, bgp_rpki_revalidate_peer,
					rvp, 0,
					&peer->t_revalidate_all[afi][safi]);
			}
		}
	}
}

static void rpki_update_cb_sync_rtr(struct pfx_table *p __attribute__((unused)),
				    const struct pfx_record rec,
				    const bool added __attribute__((unused)))
{
	struct rpki_vrf *rpki_vrf;
	const char *msg;
	const struct rtr_socket *rtr = rec.socket;
	const char *ident;

	if (!rtr) {
		msg = "could not find rtr_socket from cb_sync_rtr";
		goto err;
	}
	if (!rtr->tr_socket) {
		msg = "could not find tr_socket from cb_sync_rtr";
		goto err;
	}
	ident = rtr->tr_socket->ident_fp(rtr->tr_socket->socket);
	if (!ident) {
		msg = "could not find ident from cb_sync_rtr";
		goto err;
	}
	rpki_vrf = find_rpki_vrf_from_ident(ident);
	if (!rpki_vrf) {
		msg = "could not find rpki_vrf";
		goto err;
	}

	if (is_stopping(rpki_vrf) ||
	    atomic_load_explicit(&rpki_vrf->rtr_update_overflow,
				 memory_order_seq_cst))
		return;

	int retval = write(rpki_vrf->rpki_sync_socket_rtr, &rec,
			   sizeof(struct pfx_record));
	if (retval == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
		atomic_store_explicit(&rpki_vrf->rtr_update_overflow, 1,
				      memory_order_seq_cst);

	else if (retval != sizeof(struct pfx_record))
		RPKI_DEBUG("Could not write to rpki_sync_socket_rtr");
	return;
err:
	zlog_err("RPKI: %s", msg);
}

static void rpki_init_sync_socket(struct rpki_vrf *rpki_vrf)
{
	int fds[2];
	const char *msg;

	RPKI_DEBUG("initializing sync socket");
	if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, fds) != 0) {
		msg = "could not open rpki sync socketpair";
		goto err;
	}
	rpki_vrf->rpki_sync_socket_rtr = fds[0];
	rpki_vrf->rpki_sync_socket_bgpd = fds[1];

	if (set_nonblocking(rpki_vrf->rpki_sync_socket_rtr) != 0) {
		msg = "could not set rpki_sync_socket_rtr to non blocking";
		goto err;
	}

	if (set_nonblocking(rpki_vrf->rpki_sync_socket_bgpd) != 0) {
		msg = "could not set rpki_sync_socket_bgpd to non blocking";
		goto err;
	}


	event_add_read(bm->master, bgpd_sync_callback, rpki_vrf,
		       rpki_vrf->rpki_sync_socket_bgpd, NULL);

	return;

err:
	zlog_err("RPKI: %s", msg);
	abort();

}

static struct rpki_vrf *bgp_rpki_allocate(const char *vrfname)
{
	struct rpki_vrf *rpki_vrf;

	/* initialise default vrf cache list */
	rpki_vrf = XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct rpki_vrf));

	rpki_vrf->cache_list = list_new();
	rpki_vrf->cache_list->del = (void (*)(void *)) & free_cache;
	rpki_vrf->polling_period = POLLING_PERIOD_DEFAULT;
	rpki_vrf->expire_interval = EXPIRE_INTERVAL_DEFAULT;
	rpki_vrf->retry_interval = RETRY_INTERVAL_DEFAULT;

	if (vrfname && !strmatch(vrfname, VRF_DEFAULT_NAME))
		rpki_vrf->vrfname = XSTRDUP(MTYPE_BGP_RPKI_CACHE, vrfname);
	QOBJ_REG(rpki_vrf, rpki_vrf);
	listnode_add(rpki_vrf_list, rpki_vrf);

	return rpki_vrf;
}

static int bgp_rpki_init(struct event_loop *master)
{
	rpki_debug_conf = false;
	rpki_debug_term = false;

	rpki_vrf_list = list_new();

	install_cli_commands();

	return 0;
}

static int bgp_rpki_fini(void)
{
	struct listnode *node, *nnode;
	struct rpki_vrf *rpki_vrf;

	for (ALL_LIST_ELEMENTS(rpki_vrf_list, node, nnode, rpki_vrf)) {
		stop(rpki_vrf);
		list_delete(&rpki_vrf->cache_list);

		close(rpki_vrf->rpki_sync_socket_rtr);
		close(rpki_vrf->rpki_sync_socket_bgpd);

		listnode_delete(rpki_vrf_list, rpki_vrf);
		QOBJ_UNREG(rpki_vrf);
		if (rpki_vrf->vrfname)
			XFREE(MTYPE_BGP_RPKI_CACHE, rpki_vrf->vrfname);
		XFREE(MTYPE_BGP_RPKI_CACHE, rpki_vrf);
	}

	return 0;
}

static int bgp_rpki_module_init(void)
{
	pthread_key_create(&rpki_pthread, NULL);

	lrtr_set_alloc_functions(malloc_wrapper, realloc_wrapper, free_wrapper);

	hook_register(bgp_rpki_prefix_status, rpki_validate_prefix);
	hook_register(frr_late_init, bgp_rpki_init);
	hook_register(frr_early_fini, bgp_rpki_fini);
	hook_register(bgp_hook_config_write_debug, &bgp_rpki_write_debug);
	hook_register(bgp_hook_vrf_update, &bgp_rpki_vrf_update);
	hook_register(bgp_hook_config_write_vrf, &bgp_rpki_hook_write_vrf);

	return 0;
}

static void sync_expired(struct event *thread)
{
	struct rpki_vrf *rpki_vrf = EVENT_ARG(thread);

	if (!rtr_mgr_conf_in_sync(rpki_vrf->rtr_config)) {
		RPKI_DEBUG("rtr_mgr is not synced, retrying.");
		event_add_timer(bm->master, sync_expired, rpki_vrf,
				BGP_RPKI_CACHE_SERVER_SYNC_RETRY_TIMEOUT,
				&rpki_vrf->t_rpki_sync);
		return;
	}

	RPKI_DEBUG("rtr_mgr sync is done.");

	rpki_vrf->rtr_is_synced = true;
}

static int start(struct rpki_vrf *rpki_vrf)
{
	struct list *cache_list = NULL;
	struct vrf *vrf;
	int ret;

	rpki_vrf->rtr_is_stopping = false;
	rpki_vrf->rtr_is_synced = false;
	rpki_vrf->rtr_update_overflow = 0;
	cache_list = rpki_vrf->cache_list;
	rpki_vrf->rtr_update_overflow = 0;

	if (!cache_list || list_isempty(cache_list)) {
		RPKI_DEBUG(
			"No caches were found in config. Prefix validation is off.");
		return ERROR;
	}

	if (rpki_vrf->vrfname)
		vrf = vrf_lookup_by_name(rpki_vrf->vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf || !CHECK_FLAG(vrf->status, VRF_ACTIVE)) {
		RPKI_DEBUG("VRF %s not present or disabled", rpki_vrf->vrfname);
		return ERROR;
	}

	RPKI_DEBUG("Init rtr_mgr (%s).", vrf->name);
	int groups_len = listcount(cache_list);
	struct rtr_mgr_group *groups = get_groups(rpki_vrf->cache_list);

	RPKI_DEBUG("Polling period: %d", rpki_vrf->polling_period);
	ret = rtr_mgr_init(&rpki_vrf->rtr_config, groups, groups_len,
			   rpki_vrf->polling_period, rpki_vrf->expire_interval,
			   rpki_vrf->retry_interval, rpki_update_cb_sync_rtr,
			   NULL, NULL, NULL);
	if (ret == RTR_ERROR) {
		RPKI_DEBUG("Init rtr_mgr failed (%s).", vrf->name);
		return ERROR;
	}

	RPKI_DEBUG("Starting rtr_mgr (%s).", vrf->name);
	ret = rtr_mgr_start(rpki_vrf->rtr_config);
	if (ret == RTR_ERROR) {
		RPKI_DEBUG("Starting rtr_mgr failed (%s).", vrf->name);
		rtr_mgr_free(rpki_vrf->rtr_config);
		return ERROR;
	}

	event_add_timer(bm->master, sync_expired, rpki_vrf, 0,
			&rpki_vrf->t_rpki_sync);

	XFREE(MTYPE_BGP_RPKI_CACHE_GROUP, groups);

	rpki_vrf->rtr_is_running = true;

	return SUCCESS;
}

static void stop(struct rpki_vrf *rpki_vrf)
{
	rpki_vrf->rtr_is_stopping = true;
	if (is_running(rpki_vrf)) {
		EVENT_OFF(rpki_vrf->t_rpki_sync);
		rtr_mgr_stop(rpki_vrf->rtr_config);
		rtr_mgr_free(rpki_vrf->rtr_config);
		rpki_vrf->rtr_is_running = false;
	}
}

static int reset(bool force, struct rpki_vrf *rpki_vrf)
{
	if (is_running(rpki_vrf) && !force)
		return SUCCESS;

	RPKI_DEBUG("Resetting RPKI Session");
	stop(rpki_vrf);
	return start(rpki_vrf);
}

static struct rtr_mgr_group *get_connected_group(struct rpki_vrf *rpki_vrf)
{
	struct list *cache_list;

	if (!rpki_vrf)
		return NULL;

	cache_list = rpki_vrf->cache_list;
	if (!cache_list || list_isempty(cache_list))
		return NULL;

	return rtr_mgr_get_first_group(rpki_vrf->rtr_config);
}

static void print_prefix_table_by_asn(struct vty *vty, as_t as,
				      struct rpki_vrf *rpki_vrf,
				      json_object *json)
{
	unsigned int number_of_ipv4_prefixes = 0;
	unsigned int number_of_ipv6_prefixes = 0;
	struct rtr_mgr_group *group = get_connected_group(rpki_vrf);
	struct rpki_for_each_record_arg arg;
	json_object *json_records = NULL;

	arg.vty = vty;
	arg.as = as;
	arg.json = NULL;
	arg.asnotation = bgp_get_asnotation(bgp_lookup_by_vrf_id(VRF_DEFAULT));

	if (!rpki_vrf)
		return;

	if (!group) {
		if (json) {
			json_object_string_add(json, "error", "Cannot find a connected group.");
			vty_json(vty, json);
		} else
			vty_out(vty, "Cannot find a connected group.\n");
		return;
	}

	struct pfx_table *pfx_table = group->sockets[0]->pfx_table;

	if (!json) {
		vty_out(vty, "RPKI/RTR prefix table\n");
		vty_out(vty, "%-40s %s  %s\n", "Prefix", "Prefix Length",
			"Origin-AS");
	} else {
		json_records = json_object_new_array();
		json_object_object_add(json, "prefixes", json_records);
		arg.json = json_records;
	}

	arg.prefix_amount = &number_of_ipv4_prefixes;
	pfx_table_for_each_ipv4_record(pfx_table, print_record_by_asn, &arg);

	arg.prefix_amount = &number_of_ipv6_prefixes;
	pfx_table_for_each_ipv6_record(pfx_table, print_record_by_asn, &arg);

	if (!json) {
		vty_out(vty, "Number of IPv4 Prefixes: %u\n",
			number_of_ipv4_prefixes);
		vty_out(vty, "Number of IPv6 Prefixes: %u\n",
			number_of_ipv6_prefixes);
	} else {
		json_object_int_add(json, "ipv4PrefixCount",
				    number_of_ipv4_prefixes);
		json_object_int_add(json, "ipv6PrefixCount",
				    number_of_ipv6_prefixes);
	}

	if (json)
		vty_json(vty, json);
}

static void print_prefix_table(struct vty *vty, struct rpki_vrf *rpki_vrf,
			       json_object *json, bool count_only)
{
	struct rpki_for_each_record_arg arg;

	unsigned int number_of_ipv4_prefixes = 0;
	unsigned int number_of_ipv6_prefixes = 0;
	struct rtr_mgr_group *group;
	json_object *json_records = NULL;

	if (!rpki_vrf)
		return;

	group = get_connected_group(rpki_vrf);
	arg.vty = vty;
	arg.json = NULL;
	arg.asnotation = bgp_get_asnotation(bgp_lookup_by_vrf_id(VRF_DEFAULT));

	if (!group) {
		if (json) {
			json_object_string_add(json, "error", "Cannot find a connected group.");
			vty_json(vty, json);
		} else
			vty_out(vty, "Cannot find a connected group.\n");
		return;
	}

	struct pfx_table *pfx_table = group->sockets[0]->pfx_table;

	if (!count_only) {
		if (!json) {
			vty_out(vty, "RPKI/RTR prefix table\n");
			vty_out(vty, "%-40s %s  %s\n", "Prefix",
				"Prefix Length", "Origin-AS");
		} else {
			json_records = json_object_new_array();
			json_object_object_add(json, "prefixes", json_records);
			arg.json = json_records;
		}
	}

	arg.prefix_amount = &number_of_ipv4_prefixes;
	if (count_only)
		pfx_table_for_each_ipv4_record(pfx_table, count_record_cb, &arg);
	else
		pfx_table_for_each_ipv4_record(pfx_table, print_record_cb, &arg);

	arg.prefix_amount = &number_of_ipv6_prefixes;
	if (count_only)
		pfx_table_for_each_ipv6_record(pfx_table, count_record_cb, &arg);
	else
		pfx_table_for_each_ipv6_record(pfx_table, print_record_cb, &arg);

	if (!json) {
		vty_out(vty, "Number of IPv4 Prefixes: %u\n",
			number_of_ipv4_prefixes);
		vty_out(vty, "Number of IPv6 Prefixes: %u\n",
			number_of_ipv6_prefixes);
	} else {
		json_object_int_add(json, "ipv4PrefixCount",
				    number_of_ipv4_prefixes);
		json_object_int_add(json, "ipv6PrefixCount",
				    number_of_ipv6_prefixes);
	}

	if (json)
		vty_json(vty, json);
}

static int rpki_validate_prefix(struct peer *peer, struct attr *attr,
				const struct prefix *prefix)
{
	struct assegment *as_segment;
	as_t as_number = 0;
	struct lrtr_ip_addr ip_addr_prefix;
	enum pfxv_state result;
	struct bgp *bgp = peer->bgp;
	struct vrf *vrf;
	struct rpki_vrf *rpki_vrf;

	if (!bgp)
		return 0;

	vrf = vrf_lookup_by_id(bgp->vrf_id);
	if (!vrf)
		return 0;

	if (vrf->vrf_id == VRF_DEFAULT)
		rpki_vrf = find_rpki_vrf(NULL);
	else
		rpki_vrf = find_rpki_vrf(vrf->name);
	if (!rpki_vrf || !is_synchronized(rpki_vrf))
		return 0;

	if (!is_synchronized(rpki_vrf))
		return RPKI_NOT_BEING_USED;

	// No aspath means route comes from iBGP
	if (!attr->aspath || !attr->aspath->segments) {
		// Set own as number
		as_number = peer->bgp->as;
	} else {
		as_segment = attr->aspath->segments;
		// Find last AsSegment
		while (as_segment->next)
			as_segment = as_segment->next;

		if (as_segment->type == AS_SEQUENCE) {
			// Get rightmost asn
			as_number = as_segment->as[as_segment->length - 1];
		} else if (as_segment->type == AS_CONFED_SEQUENCE
			   || as_segment->type == AS_CONFED_SET) {
			// Set own as number
			as_number = peer->bgp->as;
		} else {
			// RFC says: "Take distinguished value NONE as asn"
			// which means state is unknown
			return RPKI_NOTFOUND;
		}
	}

	// Get the prefix in requested format
	switch (prefix->family) {
	case AF_INET:
		ip_addr_prefix.ver = LRTR_IPV4;
		ip_addr_prefix.u.addr4.addr = ntohl(prefix->u.prefix4.s_addr);
		break;

	case AF_INET6:
		ip_addr_prefix.ver = LRTR_IPV6;
		ipv6_addr_to_host_byte_order(prefix->u.prefix6.s6_addr32,
					     ip_addr_prefix.u.addr6.addr);
		break;

	default:
		return RPKI_NOT_BEING_USED;
	}

	// Do the actual validation
	rtr_mgr_validate(rpki_vrf->rtr_config, as_number, &ip_addr_prefix,
			 prefix->prefixlen, &result);

	// Print Debug output
	switch (result) {
	case BGP_PFXV_STATE_VALID:
		RPKI_DEBUG(
			"Validating Prefix %pFX from asn %u    Result: VALID",
			prefix, as_number);
		return RPKI_VALID;
	case BGP_PFXV_STATE_NOT_FOUND:
		RPKI_DEBUG(
			"Validating Prefix %pFX from asn %u    Result: NOT FOUND",
			prefix, as_number);
		return RPKI_NOTFOUND;
	case BGP_PFXV_STATE_INVALID:
		RPKI_DEBUG(
			"Validating Prefix %pFX from asn %u    Result: INVALID",
			prefix, as_number);
		return RPKI_INVALID;
	default:
		RPKI_DEBUG(
			"Validating Prefix %pFX from asn %u    Result: CANNOT VALIDATE",
			prefix, as_number);
		break;
	}
	return RPKI_NOT_BEING_USED;
}

static int add_cache(struct cache *cache)
{
	uint8_t preference = cache->preference;
	struct rtr_mgr_group group;
	struct list *cache_list;
	struct rpki_vrf *rpki_vrf;

	rpki_vrf = cache->rpki_vrf;
	if (!rpki_vrf)
		return ERROR;

	group.preference = preference;
	group.sockets_len = 1;
	group.sockets = &cache->rtr_socket;

	cache_list = rpki_vrf->cache_list;
	if (!cache_list)
		return ERROR;

	if (is_running(rpki_vrf)) {
		init_tr_socket(cache);

		if (rtr_mgr_add_group(rpki_vrf->rtr_config, &group) !=
		    RTR_SUCCESS) {
			free_tr_socket(cache);
			return ERROR;
		}
	}

	listnode_add(cache_list, cache);

	return SUCCESS;
}

static int rpki_create_socket(void *_cache)
{
	struct timeval prev_snd_tmout, prev_rcv_tmout, timeout;
	struct cache *cache = (struct cache *)_cache;
	struct rpki_vrf *rpki_vrf;
	struct tr_tcp_config *tcp_config;
	struct addrinfo *res = NULL;
	struct addrinfo hints = {};
	socklen_t optlen;
	char *host, *port;
	struct vrf *vrf;
	int cancel_state;
	int socket;
	int ret;
#if defined(FOUND_SSH)
	struct tr_ssh_config *ssh_config;
	char s_port[10];
#endif

	if (!cache)
		return -1;

	rpki_vrf = cache->rpki_vrf;

	/*
	 * the rpki infrastructure can call this function
	 * multiple times per pthread.  Why?  I have absolutely
	 * no idea, and I am not sure I care a whole bunch.
	 * Why does this matter?  Well when we attempt to
	 * hook this pthread into the rcu structure multiple
	 * times the rcu code asserts on shutdown.  Clearly
	 * upset that you have rcu data associated with a pthread
	 * that has not been cleaned up.  And frankly this is rightly so.
	 *
	 * At this point we know that this function is not
	 * called a million bajillion times so let's just
	 * add a bit of insurance by looking to see if
	 * some thread specific code has been set for this
	 * pthread.  If not, hook into the rcu code and
	 * make things happy.
	 *
	 * IF YOU PUT A ZLOG_XXXX prior to the call into
	 * frr_pthread_non_controlled_startup in this function
	 * BGP WILL CRASH. You have been warned.
	 */
	if (!pthread_getspecific(rpki_pthread) &&
	    frr_pthread_non_controlled_startup(cache->rtr_socket->thread_id,
					       "RPKI RTRLIB socket",
					       "rpki_create_socket") < 0)
		return -1;

	pthread_setspecific(rpki_pthread, &rpki_pthread);

	if (rpki_vrf->vrfname == NULL)
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	else
		vrf = vrf_lookup_by_name(rpki_vrf->vrfname);
	if (!vrf)
		return -1;

	if (!CHECK_FLAG(vrf->status, VRF_ACTIVE) || vrf->vrf_id == VRF_UNKNOWN)
		return -1;

	if (cache->type == TCP) {
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_ADDRCONFIG;

		tcp_config = cache->tr_config.tcp_config;
		host = tcp_config->host;
		port = tcp_config->port;
	}
#if defined(FOUND_SSH)
	else {
		ssh_config = cache->tr_config.ssh_config;
		host = ssh_config->host;
		snprintf(s_port, sizeof(s_port), "%u", ssh_config->port);
		port = s_port;

		hints.ai_flags |= AI_NUMERICHOST;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
	}
#endif

	frr_with_privs (&bgpd_privs) {
		ret = vrf_getaddrinfo(host, port, &hints, &res, vrf->vrf_id);
	}
	if (ret != 0) {
		flog_err_sys(EC_LIB_SOCKET, "getaddrinfo: %s",
			     gai_strerror(ret));
		return -1;
	}

	frr_with_privs (&bgpd_privs) {
		socket = vrf_socket(res->ai_family, res->ai_socktype,
				    res->ai_protocol, vrf->vrf_id, NULL);
	}
	if (socket < 0) {
		freeaddrinfo(res);
		return -1;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &cancel_state);
	timeout.tv_sec = 30;
	timeout.tv_usec = 0;

	optlen = sizeof(prev_rcv_tmout);
	ret = getsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &prev_rcv_tmout,
			 &optlen);
	if (ret < 0)
		zlog_warn("%s: failed to getsockopt SO_RCVTIMEO for socket %d",
			  __func__, socket);
	ret = getsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &prev_snd_tmout,
			 &optlen);
	if (ret < 0)
		zlog_warn("%s: failed to getsockopt SO_SNDTIMEO for socket %d",
			  __func__, socket);
	ret = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
			 sizeof(timeout));
	if (ret < 0)
		zlog_warn("%s: failed to setsockopt SO_RCVTIMEO for socket %d",
			  __func__, socket);

	ret = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
			 sizeof(timeout));
	if (ret < 0)
		zlog_warn("%s: failed to setsockopt SO_SNDTIMEO for socket %d",
			  __func__, socket);

	if (connect(socket, res->ai_addr, res->ai_addrlen) == -1) {
		freeaddrinfo(res);
		close(socket);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	freeaddrinfo(res);
	pthread_setcancelstate(cancel_state, NULL);

	ret = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &prev_rcv_tmout,
			 sizeof(prev_rcv_tmout));
	if (ret < 0)
		zlog_warn("%s: failed to setsockopt SO_RCVTIMEO for socket %d",
			  __func__, socket);

	ret = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &prev_snd_tmout,
			 sizeof(prev_snd_tmout));
	if (ret < 0)
		zlog_warn("%s: failed to setsockopt SO_SNDTIMEO for socket %d",
			  __func__, socket);

	return socket;
}

static int add_tcp_cache(struct rpki_vrf *rpki_vrf, const char *host,
			 const char *port, const uint8_t preference,
			 const char *bindaddr)
{
	struct rtr_socket *rtr_socket;
	struct tr_tcp_config *tcp_config =
		XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_tcp_config));
	struct tr_socket *tr_socket =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_socket));
	struct cache *cache =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct cache));

	tcp_config->host = XSTRDUP(MTYPE_BGP_RPKI_CACHE, host);
	tcp_config->port = XSTRDUP(MTYPE_BGP_RPKI_CACHE, port);
	if (bindaddr)
		tcp_config->bindaddr = XSTRDUP(MTYPE_BGP_RPKI_CACHE, bindaddr);
	else
		tcp_config->bindaddr = NULL;

	tcp_config->data = cache;
	tcp_config->new_socket = rpki_create_socket;
	rtr_socket = create_rtr_socket(tr_socket);

	cache->rpki_vrf = rpki_vrf;
	cache->type = TCP;
	cache->tr_socket = tr_socket;
	cache->tr_config.tcp_config = tcp_config;
	cache->rtr_socket = rtr_socket;
	cache->preference = preference;

	int ret = add_cache(cache);
	if (ret != SUCCESS) {
		tcp_config->data = NULL;
		free_cache(cache);
	}
	return ret;
}

#if defined(FOUND_SSH)
static int add_ssh_cache(struct rpki_vrf *rpki_vrf, const char *host,
			 const unsigned int port, const char *username,
			 const char *client_privkey_path,
			 const char *server_pubkey_path,
			 const uint8_t preference, const char *bindaddr)
{
	struct tr_ssh_config *ssh_config =
		XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_ssh_config));
	struct cache *cache =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct cache));
	struct tr_socket *tr_socket =
		XMALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_socket));
	struct rtr_socket *rtr_socket;

	ssh_config->port = port;
	ssh_config->host = XSTRDUP(MTYPE_BGP_RPKI_CACHE, host);
	if (bindaddr)
		ssh_config->bindaddr = XSTRDUP(MTYPE_BGP_RPKI_CACHE, bindaddr);
	else
		ssh_config->bindaddr = NULL;
	ssh_config->data = cache;
	ssh_config->new_socket = rpki_create_socket;

	ssh_config->username = XSTRDUP(MTYPE_BGP_RPKI_CACHE, username);
	ssh_config->client_privkey_path =
		XSTRDUP(MTYPE_BGP_RPKI_CACHE, client_privkey_path);
	ssh_config->server_hostkey_path =
		XSTRDUP(MTYPE_BGP_RPKI_CACHE, server_pubkey_path);

	rtr_socket = create_rtr_socket(tr_socket);

	cache->rpki_vrf = rpki_vrf;
	cache->type = SSH;
	cache->tr_socket = tr_socket;
	cache->tr_config.ssh_config = ssh_config;
	cache->rtr_socket = rtr_socket;
	cache->preference = preference;

	int ret = add_cache(cache);
	if (ret != SUCCESS) {
		ssh_config->data = NULL;
		free_cache(cache);
	}

	return ret;
}
#endif

static void free_cache(struct cache *cache)
{
	if (cache->type == TCP) {
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.tcp_config->host);
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.tcp_config->port);
		XFREE(MTYPE_BGP_RPKI_CACHE,
		      cache->tr_config.tcp_config->bindaddr);
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.tcp_config);
	}
#if defined(FOUND_SSH)
	else {
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.ssh_config->host);
		XFREE(MTYPE_BGP_RPKI_CACHE,
		      cache->tr_config.ssh_config->username);
		XFREE(MTYPE_BGP_RPKI_CACHE,
		      cache->tr_config.ssh_config->client_privkey_path);
		XFREE(MTYPE_BGP_RPKI_CACHE,
		      cache->tr_config.ssh_config->server_hostkey_path);
		XFREE(MTYPE_BGP_RPKI_CACHE,
		      cache->tr_config.ssh_config->bindaddr);
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.ssh_config);
	}
#endif
	XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_socket);
	XFREE(MTYPE_BGP_RPKI_CACHE, cache->rtr_socket);
	XFREE(MTYPE_BGP_RPKI_CACHE, cache);
}

static int bgp_rpki_write_debug(struct vty *vty, bool running)
{
	if (rpki_debug_conf && running) {
		vty_out(vty, "debug rpki\n");
		return 1;
	}
	if ((rpki_debug_conf || rpki_debug_term) && !running) {
		vty_out(vty, "  BGP RPKI debugging is on\n");
		return 1;
	}
	return 0;
}

static int bgp_rpki_hook_write_vrf(struct vty *vty, struct vrf *vrf)
{
	int ret;

	ret = bgp_rpki_write_vrf(vty, vrf);
	if (ret == ERROR)
		return 0;
	return ret;
}

static int bgp_rpki_write_vrf(struct vty *vty, struct vrf *vrf)
{
	struct listnode *cache_node;
	struct cache *cache;
	struct rpki_vrf *rpki_vrf = NULL;
	char sep[STR_SEPARATOR];
	vrf_id_t vrf_id = VRF_DEFAULT;

	if (!vrf) {
		rpki_vrf = find_rpki_vrf(NULL);
		snprintf(sep, sizeof(sep), "%s", "");
	} else if (vrf->vrf_id != VRF_DEFAULT) {
		rpki_vrf = find_rpki_vrf(vrf->name);
		snprintf(sep, sizeof(sep), "%s", " ");
		vrf_id = vrf->vrf_id;
	} else
		return ERROR;

	if (!rpki_vrf)
		return ERROR;

	if (rpki_vrf->cache_list && list_isempty(rpki_vrf->cache_list) &&
	    rpki_vrf->polling_period == POLLING_PERIOD_DEFAULT &&
	    rpki_vrf->retry_interval == RETRY_INTERVAL_DEFAULT &&
	    rpki_vrf->expire_interval == EXPIRE_INTERVAL_DEFAULT)
		/* do not display the default config values */
		return 0;

	if (vrf_id == VRF_DEFAULT)
		vty_out(vty, "%s!\n", sep);
	vty_out(vty, "%srpki\n", sep);

	if (rpki_vrf->polling_period != POLLING_PERIOD_DEFAULT)
		vty_out(vty, "%s rpki polling_period %d\n", sep,
			rpki_vrf->polling_period);
	if (rpki_vrf->retry_interval != RETRY_INTERVAL_DEFAULT)
		vty_out(vty, "%s rpki retry_interval %d\n", sep,
			rpki_vrf->retry_interval);
	if (rpki_vrf->expire_interval != EXPIRE_INTERVAL_DEFAULT)
		vty_out(vty, "%s rpki expire_interval %d\n", sep,
			rpki_vrf->expire_interval);

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node, cache)) {
		switch (cache->type) {
			struct tr_tcp_config *tcp_config;
#if defined(FOUND_SSH)
			struct tr_ssh_config *ssh_config;
#endif
		case TCP:
			tcp_config = cache->tr_config.tcp_config;
			vty_out(vty, "%s rpki cache tcp %s %s ", sep,
				tcp_config->host, tcp_config->port);
			if (tcp_config->bindaddr)
				vty_out(vty, "source %s ",
					tcp_config->bindaddr);
			break;
#if defined(FOUND_SSH)
		case SSH:
			ssh_config = cache->tr_config.ssh_config;
			vty_out(vty, "%s rpki cache ssh %s %u %s %s %s ", sep,
				ssh_config->host, ssh_config->port,
				ssh_config->username,
				ssh_config->client_privkey_path,
				ssh_config->server_hostkey_path != NULL
					? ssh_config->server_hostkey_path
					: "");
			if (ssh_config->bindaddr)
				vty_out(vty, "source %s ",
					ssh_config->bindaddr);
			break;
#endif
		default:
			break;
		}

		vty_out(vty, "preference %hhu\n", cache->preference);
	}

	vty_out(vty, "%sexit\n%s", sep, vrf_id == VRF_DEFAULT ? "!\n" : "");

	return 1;
}

static int config_write(struct vty *vty)
{
	return bgp_rpki_write_vrf(vty, NULL);
}

static struct rpki_vrf *get_rpki_vrf(const char *vrfname)
{
	struct rpki_vrf *rpki_vrf = NULL;
	struct vrf *vrf = NULL;

	if (vrfname && !strmatch(vrfname, VRF_DEFAULT_NAME)) {
		vrf = vrf_lookup_by_name(vrfname);
		if (!vrf)
			return NULL;
		rpki_vrf = find_rpki_vrf(vrf->name);
	} else
		/* default VRF */
		rpki_vrf = find_rpki_vrf(NULL);

	return rpki_vrf;
}

DEFUN_NOSH (rpki,
	    rpki_cmd,
	    "rpki",
	    "Enable rpki and enter rpki configuration mode\n")
{
	struct rpki_vrf *rpki_vrf;
	char *vrfname = NULL;
	struct vrf *vrf;

	if (vty->node == CONFIG_NODE)
		vty->node = RPKI_NODE;
	else {
		vrf = VTY_GET_CONTEXT(vrf);

		if (!vrf)
			return CMD_WARNING;

		vty->node = RPKI_VRF_NODE;
		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}

	rpki_vrf = find_rpki_vrf(vrfname);
	if (!rpki_vrf) {
		rpki_vrf = bgp_rpki_allocate(vrfname);

		rpki_init_sync_socket(rpki_vrf);
	}
	if (vty->node == RPKI_VRF_NODE)
		VTY_PUSH_CONTEXT_SUB(vty->node, rpki_vrf);
	else
		VTY_PUSH_CONTEXT(vty->node, rpki_vrf);
	return CMD_SUCCESS;
}

DEFPY (no_rpki,
       no_rpki_cmd,
       "no rpki",
       NO_STR
       "Enable rpki and enter rpki configuration mode\n")
{
	struct rpki_vrf *rpki_vrf;
	char *vrfname = NULL;

	if (vty->node == VRF_NODE) {
		VTY_DECLVAR_CONTEXT(vrf, vrf);

		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}

	rpki_vrf = find_rpki_vrf(vrfname);

	rpki_delete_all_cache_nodes(rpki_vrf);
	stop(rpki_vrf);
	rpki_vrf->polling_period = POLLING_PERIOD_DEFAULT;
	rpki_vrf->expire_interval = EXPIRE_INTERVAL_DEFAULT;
	rpki_vrf->retry_interval = RETRY_INTERVAL_DEFAULT;

	return CMD_SUCCESS;
}

DEFPY (bgp_rpki_start,
       bgp_rpki_start_cmd,
       "rpki start [vrf NAME$vrfname]",
       RPKI_OUTPUT_STRING
       "start rpki support\n"
       VRF_CMD_HELP_STR)
{
	struct list *cache_list = NULL;
	struct rpki_vrf *rpki_vrf;

	rpki_vrf = get_rpki_vrf(vrfname);

	if (!rpki_vrf)
		return CMD_WARNING;

	cache_list = rpki_vrf->cache_list;
	if (!cache_list || listcount(cache_list) == 0)
		vty_out(vty,
			"Could not start rpki because no caches are configured\n");

	if (!is_running(rpki_vrf)) {
		if (start(rpki_vrf) == ERROR) {
			RPKI_DEBUG("RPKI failed to start");
			return CMD_WARNING;
		}
	}
	return CMD_SUCCESS;
}

DEFPY (bgp_rpki_stop,
       bgp_rpki_stop_cmd,
       "rpki stop [vrf NAME$vrfname]",
       RPKI_OUTPUT_STRING
       "start rpki support\n"
       VRF_CMD_HELP_STR)
{
	struct rpki_vrf *rpki_vrf;

	rpki_vrf = get_rpki_vrf(vrfname);

	if (rpki_vrf && is_running(rpki_vrf))
		stop(rpki_vrf);

	return CMD_SUCCESS;
}

DEFPY (rpki_polling_period,
       rpki_polling_period_cmd,
       "rpki polling_period (1-86400)$pp",
       RPKI_OUTPUT_STRING
       "Set polling period\n"
       "Polling period value\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	rpki_vrf->polling_period = pp;
	return CMD_SUCCESS;
}

DEFUN (no_rpki_polling_period,
       no_rpki_polling_period_cmd,
       "no rpki polling_period [(1-86400)]",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set polling period back to default\n"
       "Polling period value\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	rpki_vrf->polling_period = POLLING_PERIOD_DEFAULT;
	return CMD_SUCCESS;
}

DEFPY (rpki_expire_interval,
       rpki_expire_interval_cmd,
       "rpki expire_interval (600-172800)$tmp",
       RPKI_OUTPUT_STRING
       "Set expire interval\n"
       "Expire interval value\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	if ((unsigned int)tmp >= rpki_vrf->polling_period) {
		rpki_vrf->expire_interval = tmp;
		return CMD_SUCCESS;
	}

	vty_out(vty, "%% Expiry interval must be polling period or larger\n");
	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (no_rpki_expire_interval,
       no_rpki_expire_interval_cmd,
       "no rpki expire_interval [(600-172800)]",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set expire interval back to default\n"
       "Expire interval value\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	rpki_vrf->expire_interval = rpki_vrf->polling_period * 2;
	return CMD_SUCCESS;
}

DEFPY (rpki_retry_interval,
       rpki_retry_interval_cmd,
       "rpki retry_interval (1-7200)$tmp",
       RPKI_OUTPUT_STRING
       "Set retry interval\n"
       "retry interval value\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	rpki_vrf->retry_interval = tmp;
	return CMD_SUCCESS;
}

DEFUN (no_rpki_retry_interval,
       no_rpki_retry_interval_cmd,
       "no rpki retry_interval [(1-7200)]",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set retry interval back to default\n"
       "retry interval value\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	rpki_vrf->retry_interval = RETRY_INTERVAL_DEFAULT;
	return CMD_SUCCESS;
}

#if CONFDATE > 20240916
CPP_NOTICE("Remove rpki_cache_cmd")
#endif
DEFPY(rpki_cache, rpki_cache_cmd,
      "rpki cache <A.B.C.D|WORD> <TCPPORT|(1-65535)$sshport SSH_UNAME SSH_PRIVKEY [KNOWN_HOSTS_PATH]> [source <A.B.C.D>$bindaddr] preference (1-255)",
      RPKI_OUTPUT_STRING
      "Install a cache server to current group\n"
      "IP address of cache server\n"
      "Hostname of cache server\n"
      "TCP port number\n"
      "SSH port number\n"
      "SSH user name\n"
      "Path to own SSH private key\n"
      "Path to the known hosts file\n"
      "Configure source IP address of RPKI connection\n"
      "Define a Source IP Address\n"
      "Preference of the cache server\n"
      "Preference value\n")
{
	int return_value;
	struct listnode *cache_node;
	struct cache *current_cache;
	struct rpki_vrf *rpki_vrf;
	bool init;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	if (!rpki_vrf || !rpki_vrf->cache_list)
		return CMD_WARNING;

	init = !!list_isempty(rpki_vrf->cache_list);

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node,
				  current_cache)) {
		if (current_cache->preference == preference) {
			vty_out(vty,
				"Cache with preference %ld is already configured\n",
				preference);
			return CMD_WARNING;
		}
	}

	// use ssh connection
	if (ssh_uname) {
#if defined(FOUND_SSH)
		return_value = add_ssh_cache(rpki_vrf, cache, sshport, ssh_uname,
					     ssh_privkey, known_hosts_path,
					     preference, bindaddr_str);
#else
		return_value = SUCCESS;
		vty_out(vty,
			"ssh sockets are not supported. Please recompile rtrlib and frr with ssh support. If you want to use it\n");
#endif
	} else { // use tcp connection
		return_value = add_tcp_cache(rpki_vrf, cache, tcpport,
					     preference, bindaddr_str);
	}

	if (return_value == ERROR) {
		vty_out(vty, "Could not create new rpki cache\n");
		return CMD_WARNING;
	}

	if (init)
		start(rpki_vrf);

	return CMD_SUCCESS;
}

DEFPY(rpki_cache_tcp, rpki_cache_tcp_cmd,
      "rpki cache tcp <A.B.C.D|WORD>$cache TCPPORT [source <A.B.C.D>$bindaddr] preference (1-255)",
      RPKI_OUTPUT_STRING
      "Install a cache server to current group\n"
      "Use TCP\n"
      "IP address of cache server\n"
      "Hostname of cache server\n"
      "TCP port number\n"
      "Configure source IP address of RPKI connection\n"
      "Define a Source IP Address\n"
      "Preference of the cache server\n"
      "Preference value\n")
{
	int return_value;
	struct listnode *cache_node;
	struct cache *current_cache;
	struct rpki_vrf *rpki_vrf;
	bool init;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	if (!rpki_vrf || !rpki_vrf->cache_list)
		return CMD_WARNING;

	init = !!list_isempty(rpki_vrf->cache_list);

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node,
				  current_cache)) {
		if (current_cache->preference == preference) {
			vty_out(vty,
				"Cache with preference %ld is already configured\n",
				preference);
			return CMD_WARNING;
		}
	}

	return_value = add_tcp_cache(rpki_vrf, cache, tcpport, preference,
				     bindaddr_str);

	if (return_value == ERROR) {
		vty_out(vty, "Could not create new rpki cache\n");
		return CMD_WARNING;
	}

	if (init)
		start(rpki_vrf);

	return CMD_SUCCESS;
}

DEFPY(rpki_cache_ssh, rpki_cache_ssh_cmd,
      "rpki cache ssh <A.B.C.D|WORD>$cache (1-65535)$sshport SSH_UNAME SSH_PRIVKEY [KNOWN_HOSTS_PATH] [source <A.B.C.D>$bindaddr] preference (1-255)",
      RPKI_OUTPUT_STRING
      "Install a cache server to current group\n"
      "Use SSH\n"
      "IP address of cache server\n"
      "Hostname of cache server\n"
      "SSH port number\n"
      "SSH user name\n"
      "Path to own SSH private key\n"
      "Path to the known hosts file\n"
      "Configure source IP address of RPKI connection\n"
      "Define a Source IP Address\n"
      "Preference of the cache server\n"
      "Preference value\n")
{
	int return_value;
	struct listnode *cache_node;
	struct cache *current_cache;
	struct rpki_vrf *rpki_vrf;
	bool init;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	if (!rpki_vrf || !rpki_vrf->cache_list)
		return CMD_WARNING;

	init = !!list_isempty(rpki_vrf->cache_list);

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node,
				  current_cache)) {
		if (current_cache->preference == preference) {
			vty_out(vty,
				"Cache with preference %ld is already configured\n",
				preference);
			return CMD_WARNING;
		}
	}

#if defined(FOUND_SSH)
	return_value = add_ssh_cache(rpki_vrf, cache, sshport, ssh_uname,
				     ssh_privkey, known_hosts_path, preference,
				     bindaddr_str);
#else
	return_value = SUCCESS;
	vty_out(vty,
		"ssh sockets are not supported. Please recompile rtrlib and frr with ssh support. If you want to use it\n");
#endif

	if (return_value == ERROR) {
		vty_out(vty, "Could not create new rpki cache\n");
		return CMD_WARNING;
	}

	if (init)
		start(rpki_vrf);

	return CMD_SUCCESS;
}

DEFPY (no_rpki_cache,
       no_rpki_cache_cmd,
       "no rpki cache <tcp|ssh> <A.B.C.D|WORD> <TCPPORT|(1-65535)$sshport SSH_UNAME SSH_PRIVKEY [KNOWN_HOSTS_PATH]> [source <A.B.C.D>$bindaddr] preference (1-255)",
       NO_STR
       RPKI_OUTPUT_STRING
       "Install a cache server to current group\n"
       "Use TCP\n"
       "Use SSH\n"
       "IP address of cache server\n"
       "Hostname of cache server\n"
       "TCP port number\n"
       "SSH port number\n"
       "SSH user name\n"
       "Path to own SSH private key\n"
       "Path to the known hosts file\n"
       "Configure source IP address of RPKI connection\n"
       "Define a Source IP Address\n"
       "Preference of the cache server\n"
       "Preference value\n")
{
	struct cache *cache_p;
	struct list *cache_list = NULL;
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	cache_list = rpki_vrf->cache_list;
	cache_p = find_cache(preference, cache_list);
	if (!rpki_vrf || !cache_p) {
		vty_out(vty, "Could not find cache with preference %ld\n",
			preference);
		return CMD_WARNING;
	}

	if (is_running(rpki_vrf) && listcount(cache_list) == 1) {
		stop(rpki_vrf);
	} else if (is_running(rpki_vrf)) {
		if (rtr_mgr_remove_group(rpki_vrf->rtr_config, preference) ==
		    RTR_ERROR) {
			vty_out(vty,
				"Could not remove cache with preference %ld\n",
				preference);
			return CMD_WARNING;
		}
	}

	listnode_delete(cache_list, cache_p);
	free_cache(cache_p);

	return CMD_SUCCESS;
}

DEFPY (show_rpki_prefix_table,
       show_rpki_prefix_table_cmd,
       "show rpki <prefix-table|prefix-count>$prefixkind [vrf NAME$vrfname] [json$uj]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show validated prefixes which were received from RPKI Cache\n"
       "Show prefixes count which were received from RPKI Cache\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct json_object *json = NULL;
	struct rpki_vrf *rpki_vrf;

	if (uj)
		json = json_object_new_object();

	rpki_vrf = get_rpki_vrf(vrfname);
	if (!rpki_vrf) {
		if (uj)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	if (is_synchronized(rpki_vrf)) {
		if (strmatch(prefixkind, "prefix-count"))
			print_prefix_table(vty, rpki_vrf, json, true);
		else
			print_prefix_table(vty, rpki_vrf, json, false);
	} else {
		if (json) {
			json_object_string_add(json, "error", "No Connection to RPKI cache server.");
			vty_json(vty, json);
		} else
			vty_out(vty, "No connection to RPKI cache server.\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFPY (show_rpki_as_number,
       show_rpki_as_number_cmd,
       "show rpki as-number <0$zero|ASNUM$by_asn> [vrf NAME$vrfname] [json$uj]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Lookup by ASN in prefix table\n"
       "AS Number of 0, see RFC-7607\n"
       "AS Number\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct json_object *json = NULL;
	struct rpki_vrf *rpki_vrf;
	as_t as;

	if (uj)
		json = json_object_new_object();

	rpki_vrf = get_rpki_vrf(vrfname);
	if (!rpki_vrf) {
		if (uj)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	if (!is_synchronized(rpki_vrf)) {
		if (json) {
			json_object_string_add(json, "error", "No Connection to RPKI cache server.");
			vty_json(vty, json);
		} else
			vty_out(vty, "No Connection to RPKI cache server.\n");
		return CMD_WARNING;
	}

	if (zero)
		as = 0;
	else
		as = by_asn;

	print_prefix_table_by_asn(vty, as, rpki_vrf, json);
	return CMD_SUCCESS;
}

DEFPY (show_rpki_prefix,
       show_rpki_prefix_cmd,
       "show rpki prefix <A.B.C.D/M|X:X::X:X/M> [0$zero|ASNUM$asn] [vrf NAME$vrfname] [json$uj]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Lookup IP prefix and optionally ASN in prefix table\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "AS Number of 0, see RFC-7607\n"
       "AS Number\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	json_object *json = NULL;
	json_object *json_records = NULL;
	enum asnotation_mode asnotation;
	struct rpki_vrf *rpki_vrf;
	as_t as;

	if (uj)
		json = json_object_new_object();

	rpki_vrf = get_rpki_vrf(vrfname);

	if (!rpki_vrf || !is_synchronized(rpki_vrf)) {
		if (json) {
			json_object_string_add(json, "error", "No Connection to RPKI cache server.");
			vty_json(vty, json);
		} else
			vty_out(vty, "No Connection to RPKI cache server.\n");
		return CMD_WARNING;
	}

	if (zero)
		as = 0;
	else
		as = asn;

	struct lrtr_ip_addr addr;
	char addr_str[INET6_ADDRSTRLEN];
	size_t addr_len = strchr(prefix_str, '/') - prefix_str;

	memset(addr_str, 0, sizeof(addr_str));
	memcpy(addr_str, prefix_str, addr_len);

	if (lrtr_ip_str_to_addr(addr_str, &addr) != 0) {
		if (json) {
			json_object_string_add(json, "error", "Invalid IP prefix.");
			vty_json(vty, json);
		} else
			vty_out(vty, "Invalid IP prefix\n");
		return CMD_WARNING;
	}

	struct pfx_record *matches = NULL;
	unsigned int match_count = 0;
	enum pfxv_state result;

	if (pfx_table_validate_r(rpki_vrf->rtr_config->pfx_table, &matches,
				 &match_count, as, &addr, prefix->prefixlen,
				 &result) != PFX_SUCCESS) {
		if (json) {
			json_object_string_add(json, "error", "Prefix lookup failed.");
			vty_json(vty, json);
		} else
			vty_out(vty, "Prefix lookup failed\n");
		return CMD_WARNING;
	}


	if (!json) {
		vty_out(vty, "%-40s %s  %s\n", "Prefix", "Prefix Length",
			"Origin-AS");
	} else {
		json_records = json_object_new_array();
		json_object_object_add(json, "prefixes", json_records);
	}

	asnotation = bgp_get_asnotation(bgp_lookup_by_vrf_id(VRF_DEFAULT));
	for (size_t i = 0; i < match_count; ++i) {
		const struct pfx_record *record = &matches[i];

		if (record->max_len >= prefix->prefixlen &&
		    ((as != 0 && (uint32_t)as == record->asn) || asn == 0)) {
			print_record(&matches[i], vty, json_records,
				     asnotation);
		}
	}

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFPY (show_rpki_cache_server,
       show_rpki_cache_server_cmd,
       "show rpki cache-server [vrf NAME$vrfname] [json$uj]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show configured cache server\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct json_object *json = NULL;
	struct json_object *json_server = NULL;
	struct json_object *json_servers = NULL;
	struct listnode *cache_node;
	struct cache *cache;
	struct rpki_vrf *rpki_vrf;

	if (uj) {
		json = json_object_new_object();
		json_servers = json_object_new_array();
		json_object_object_add(json, "servers", json_servers);
	}

	rpki_vrf = get_rpki_vrf(vrfname);
	if (!rpki_vrf) {
		if (json)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node, cache)) {
		if (cache->type == TCP) {
			if (!json) {
				vty_out(vty,
					"host: %s port: %s, preference: %hhu, protocol: tcp",
					cache->tr_config.tcp_config->host,
					cache->tr_config.tcp_config->port,
					cache->preference);
				if (cache->tr_config.tcp_config->bindaddr)
					vty_out(vty, ", source: %s\n",
						cache->tr_config.tcp_config
							->bindaddr);
				else
					vty_out(vty, "\n");
			} else {
				json_server = json_object_new_object();
				json_object_string_add(json_server, "mode",
						       "tcp");
				json_object_string_add(
					json_server, "host",
					cache->tr_config.tcp_config->host);
				json_object_string_add(
					json_server, "port",
					cache->tr_config.tcp_config->port);
				json_object_int_add(json_server, "preference",
						    cache->preference);
				if (cache->tr_config.tcp_config->bindaddr)
					json_object_string_add(json_server,
							       "source",
							       cache->tr_config
								       .tcp_config
								       ->bindaddr);
				json_object_array_add(json_servers,
						      json_server);
			}

#if defined(FOUND_SSH)
		} else if (cache->type == SSH) {
			if (!json) {
				vty_out(vty,
					"host: %s, port: %d, username: %s, server_hostkey_path: %s, client_privkey_path: %s, preference: %hhu, protocol: ssh",
					cache->tr_config.ssh_config->host,
					cache->tr_config.ssh_config->port,
					cache->tr_config.ssh_config->username,
					cache->tr_config.ssh_config
						->server_hostkey_path,
					cache->tr_config.ssh_config
						->client_privkey_path,
					cache->preference);
				if (cache->tr_config.ssh_config->bindaddr)
					vty_out(vty, ", source: %s\n",
						cache->tr_config.ssh_config
							->bindaddr);
				else
					vty_out(vty, "\n");
			} else {
				json_server = json_object_new_object();
				json_object_string_add(json_server, "mode",
						       "ssh");
				json_object_string_add(
					json_server, "host",
					cache->tr_config.ssh_config->host);
				json_object_int_add(
					json_server, "port",
					cache->tr_config.ssh_config->port);
				json_object_string_add(
					json_server, "username",
					cache->tr_config.ssh_config->username);
				json_object_string_add(
					json_server, "serverHostkeyPath",
					cache->tr_config.ssh_config
						->server_hostkey_path);
				json_object_string_add(
					json_server, "clientPrivkeyPath",
					cache->tr_config.ssh_config
						->client_privkey_path);
				json_object_int_add(json_server, "preference",
						    cache->preference);
				if (cache->tr_config.ssh_config->bindaddr)
					json_object_string_add(json_server,
							       "source",
							       cache->tr_config
								       .ssh_config
								       ->bindaddr);
				json_object_array_add(json_servers,
						      json_server);
			}
#endif
		}
	}

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFPY (show_rpki_cache_connection,
       show_rpki_cache_connection_cmd,
       "show rpki cache-connection [vrf NAME$vrfname] [json$uj]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show to which RPKI Cache Servers we have a connection\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct json_object *json = NULL;
	struct json_object *json_conn = NULL;
	struct json_object *json_conns = NULL;
	struct listnode *cache_node;
	struct cache *cache;
	struct rtr_mgr_group *group;
	struct rpki_vrf *rpki_vrf;

	if (uj)
		json = json_object_new_object();

	rpki_vrf = get_rpki_vrf(vrfname);
	if (!rpki_vrf) {
		if (json)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	if (!is_synchronized(rpki_vrf)) {
		if (json) {
			json_object_string_add(json, "error", "No connection to RPKI cache server.");
			vty_json(vty, json);
		} else
			vty_out(vty, "No connection to RPKI cache server.\n");

		return CMD_SUCCESS;
	}

	group = get_connected_group(rpki_vrf);
	if (!group) {
		if (json) {
			json_object_string_add(json, "error", "Cannot find a connected group.");
			vty_json(vty, json);
		} else
			vty_out(vty, "Cannot find a connected group.\n");

		return CMD_SUCCESS;
	}

	if (!json) {
		vty_out(vty, "Connected to group %d\n", group->preference);
	} else {
		json_conns = json_object_new_array();
		json_object_int_add(json, "connectedGroup", group->preference);
		json_object_object_add(json, "connections", json_conns);
	}

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node, cache)) {
		struct tr_tcp_config *tcp_config;
#if defined(FOUND_SSH)
		struct tr_ssh_config *ssh_config;
#endif
		switch (cache->type) {
		case TCP:
			tcp_config = cache->tr_config.tcp_config;

			if (!json) {
				vty_out(vty,
					"rpki tcp cache %s %s pref %hhu%s\n",
					tcp_config->host, tcp_config->port,
					cache->preference,
					cache->rtr_socket->state ==
							RTR_ESTABLISHED
						? " (connected)"
						: "");
			} else {
				json_conn = json_object_new_object();
				json_object_string_add(json_conn, "mode",
						       "tcp");
				json_object_string_add(json_conn, "host",
						       tcp_config->host);
				json_object_string_add(json_conn, "port",
						       tcp_config->port);
				json_object_int_add(json_conn, "preference",
						    cache->preference);
				json_object_string_add(
					json_conn, "state",
					cache->rtr_socket->state ==
							RTR_ESTABLISHED
						? "connected"
						: "disconnected");
				json_object_array_add(json_conns, json_conn);
			}
			break;
#if defined(FOUND_SSH)
		case SSH:
			ssh_config = cache->tr_config.ssh_config;

			if (!json) {
				vty_out(vty,
					"rpki ssh cache %s %u pref %hhu%s\n",
					ssh_config->host, ssh_config->port,
					cache->preference,
					cache->rtr_socket->state ==
							RTR_ESTABLISHED
						? " (connected)"
						: "");
			} else {
				json_conn = json_object_new_object();
				json_object_string_add(json_conn, "mode",
						       "ssh");
				json_object_string_add(json_conn, "host",
						       ssh_config->host);
				json_object_int_add(json_conn, "port",
						    ssh_config->port);
				json_object_int_add(json_conn, "preference",
						    cache->preference);
				json_object_string_add(
					json_conn, "state",
					cache->rtr_socket->state ==
							RTR_ESTABLISHED
						? "connected"
						: "disconnected");
				json_object_array_add(json_conns, json_conn);
			}
			break;
#endif
		default:
			break;
		}
	}

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFPY(show_rpki_configuration, show_rpki_configuration_cmd,
      "show rpki configuration [vrf NAME$vrfname] [json$uj]",
      SHOW_STR RPKI_OUTPUT_STRING
      "Show RPKI configuration\n"
      VRF_CMD_HELP_STR
      JSON_STR)
{
	struct json_object *json = NULL;
	struct rpki_vrf *rpki_vrf;

	if (uj)
		json = json_object_new_object();

	rpki_vrf = find_rpki_vrf(vrfname);
	if (!rpki_vrf) {
		if (uj)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	if (uj) {
		json_object_boolean_add(json, "enabled",
					!!listcount(rpki_vrf->cache_list));
		json_object_int_add(json, "serversCount",
				    listcount(rpki_vrf->cache_list));
		json_object_int_add(json, "pollingPeriodSeconds",
				    rpki_vrf->polling_period);
		json_object_int_add(json, "retryIntervalSeconds",
				    rpki_vrf->retry_interval);
		json_object_int_add(json, "expireIntervalSeconds",
				    rpki_vrf->expire_interval);

		vty_json(vty, json);

		return CMD_SUCCESS;
	}

	vty_out(vty, "rpki is %s",
		listcount(rpki_vrf->cache_list) ? "Enabled" : "Disabled");

	if (list_isempty(rpki_vrf->cache_list)) {
		vty_out(vty, "\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, " (%d cache servers configured)",
		listcount(rpki_vrf->cache_list));
	vty_out(vty, "\n");
	vty_out(vty, "\tpolling period %d\n", rpki_vrf->polling_period);
	vty_out(vty, "\tretry interval %d\n", rpki_vrf->retry_interval);
	vty_out(vty, "\texpire interval %d\n", rpki_vrf->expire_interval);

	return CMD_SUCCESS;
}

static int config_on_exit(struct vty *vty)
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	reset(false, rpki_vrf);
	return 1;
}

DEFPY(rpki_reset,
       rpki_reset_cmd,
       "rpki reset [vrf NAME$vrfname]",
       RPKI_OUTPUT_STRING
       "reset rpki\n"
       VRF_CMD_HELP_STR)
{
	struct rpki_vrf *rpki_vrf;

	rpki_vrf = find_rpki_vrf(vrfname);
	if (!rpki_vrf)
		return CMD_WARNING;

	return reset(true, rpki_vrf) == SUCCESS ? CMD_SUCCESS : CMD_WARNING;
}

DEFPY (rpki_reset_config_mode,
       rpki_reset_config_mode_cmd,
       "rpki reset",
       RPKI_OUTPUT_STRING
       "reset rpki\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	return reset(true, rpki_vrf) == SUCCESS ? CMD_SUCCESS : CMD_WARNING;
}

DEFUN (debug_rpki,
       debug_rpki_cmd,
       "debug rpki",
       DEBUG_STR
       "Enable debugging for rpki\n")
{
	if (vty->node == CONFIG_NODE)
		rpki_debug_conf = true;
	else
		rpki_debug_term = true;
	return CMD_SUCCESS;
}

DEFUN (no_debug_rpki,
       no_debug_rpki_cmd,
       "no debug rpki",
       NO_STR
       DEBUG_STR
       "Disable debugging for rpki\n")
{
	if (vty->node == CONFIG_NODE)
		rpki_debug_conf = false;
	else
		rpki_debug_term = false;
	return CMD_SUCCESS;
}

DEFUN_YANG (match_rpki,
       match_rpki_cmd,
       "match rpki <valid|invalid|notfound>",
       MATCH_STR
       RPKI_OUTPUT_STRING
       "Valid prefix\n"
       "Invalid prefix\n"
       "Prefix not found\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:rpki']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:rpki", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[2]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_rpki,
       no_match_rpki_cmd,
       "no match rpki <valid|invalid|notfound>",
       NO_STR
       MATCH_STR
       RPKI_OUTPUT_STRING
       "Valid prefix\n"
       "Invalid prefix\n"
       "Prefix not found\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:rpki']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void install_cli_commands(void)
{
	// TODO: make config write work
	install_node(&rpki_node);
	install_default(RPKI_NODE);
	install_node(&rpki_vrf_node);
	install_default(RPKI_VRF_NODE);
	install_element(CONFIG_NODE, &rpki_cmd);
	install_element(CONFIG_NODE, &no_rpki_cmd);


	install_element(ENABLE_NODE, &bgp_rpki_start_cmd);
	install_element(ENABLE_NODE, &bgp_rpki_stop_cmd);

	/* Install rpki reset command */
	install_element(ENABLE_NODE, &rpki_reset_cmd);
	install_element(RPKI_NODE, &rpki_reset_config_mode_cmd);

	/* Install rpki polling period commands */
	install_element(RPKI_NODE, &rpki_polling_period_cmd);
	install_element(RPKI_NODE, &no_rpki_polling_period_cmd);

	/* Install rpki expire interval commands */
	install_element(RPKI_NODE, &rpki_expire_interval_cmd);
	install_element(RPKI_NODE, &no_rpki_expire_interval_cmd);

	/* Install rpki retry interval commands */
	install_element(RPKI_NODE, &rpki_retry_interval_cmd);
	install_element(RPKI_NODE, &no_rpki_retry_interval_cmd);

	/* Install rpki cache commands */
	install_element(RPKI_NODE, &rpki_cache_tcp_cmd);
	install_element(RPKI_NODE, &rpki_cache_ssh_cmd);
	install_element(RPKI_NODE, &rpki_cache_cmd);
	install_element(RPKI_NODE, &no_rpki_cache_cmd);

	/* RPKI_VRF_NODE commands */
	install_element(VRF_NODE, &rpki_cmd);
	install_element(VRF_NODE, &no_rpki_cmd);
	/* Install rpki reset command */
	install_element(RPKI_VRF_NODE, &rpki_reset_config_mode_cmd);

	/* Install rpki polling period commands */
	install_element(RPKI_VRF_NODE, &rpki_polling_period_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_polling_period_cmd);

	/* Install rpki expire interval commands */
	install_element(RPKI_VRF_NODE, &rpki_expire_interval_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_expire_interval_cmd);

	/* Install rpki retry interval commands */
	install_element(RPKI_VRF_NODE, &rpki_retry_interval_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_retry_interval_cmd);

	/* Install rpki cache commands */
	install_element(RPKI_VRF_NODE, &rpki_cache_tcp_cmd);
	install_element(RPKI_VRF_NODE, &rpki_cache_ssh_cmd);
	install_element(RPKI_VRF_NODE, &rpki_cache_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_cache_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_rpki_prefix_table_cmd);
	install_element(VIEW_NODE, &show_rpki_cache_connection_cmd);
	install_element(VIEW_NODE, &show_rpki_cache_server_cmd);
	install_element(VIEW_NODE, &show_rpki_prefix_cmd);
	install_element(VIEW_NODE, &show_rpki_as_number_cmd);
	install_element(VIEW_NODE, &show_rpki_configuration_cmd);

	/* Install debug commands */
	install_element(CONFIG_NODE, &debug_rpki_cmd);
	install_element(ENABLE_NODE, &debug_rpki_cmd);
	install_element(CONFIG_NODE, &no_debug_rpki_cmd);
	install_element(ENABLE_NODE, &no_debug_rpki_cmd);

	/* Install route match */
	route_map_install_match(&route_match_rpki_cmd);
	install_element(RMAP_NODE, &match_rpki_cmd);
	install_element(RMAP_NODE, &no_match_rpki_cmd);
}

FRR_MODULE_SETUP(.name = "bgpd_rpki", .version = "0.3.6",
		 .description = "Enable RPKI support for FRR.",
		 .init = bgp_rpki_module_init,
);
