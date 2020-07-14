/*
 * BGP RPKI
 * Copyright (C) 2013 Michael Mester (m.mester@fu-berlin.de), for FU Berlin
 * Copyright (C) 2014-2017 Andreas Reuter (andreas.reuter@fu-berlin.de), for FU
 * Berlin
 * Copyright (C) 2016-2017 Colin Sames (colin.sames@haw-hamburg.de), for HAW
 * Hamburg
 * Copyright (C) 2017-2018 Marcel Röthke (marcel.roethke@haw-hamburg.de),
 * for HAW Hamburg
 * Copyright (C) 2019 6WIND
 *
 * This file is part of FRRouting.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "thread.h"
#include "filter.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgp_advertise.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "lib/network.h"
#include "lib/thread.h"
#ifndef VTYSH_EXTRACT_PL
#include "rtrlib/rtrlib.h"
#endif
#include "hook.h"
#include "libfrr.h"
#include "version.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_rpki_clippy.c"
#endif

DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_TEMP, "BGP RPKI Intermediate Buffer")
DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_CACHE, "BGP RPKI Cache server")
DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_CACHE_GROUP, "BGP RPKI Cache server group")

#define RPKI_VALID      1
#define RPKI_NOTFOUND   2
#define RPKI_INVALID    3

#define STR_SEPARATOR 10

#define POLLING_PERIOD_DEFAULT 3600
#define EXPIRE_INTERVAL_DEFAULT 7200
#define RETRY_INTERVAL_DEFAULT 600

#define RPKI_DEBUG(...)                                                        \
	if (rpki_debug_conf || rpki_debug_term) {                              \
		zlog_debug("RPKI: " __VA_ARGS__);                              \
	}

#define RPKI_OUTPUT_STRING "Control rpki specific settings\n"

struct cache {
	enum { TCP, SSH } type;
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

extern struct zebra_privs_t bgpd_privs;

struct rpki_for_each_record_arg {
	struct vty *vty;
	unsigned int *prefix_amount;
	as_t as;
};

struct rpki_vrf {
	struct rtr_mgr_config *rtr_config;
	struct list *cache_list;
	bool rtr_is_running;
	bool rtr_is_stopping;
	_Atomic int rtr_update_overflow;
	unsigned int polling_period;
	unsigned int expire_interval;
	unsigned int retry_interval;
	int rpki_sync_socket_rtr;
	int rpki_sync_socket_bgpd;
	char *vrfname;
	QOBJ_FIELDS
};

static struct rpki_vrf *find_rpki_vrf(const char *vrfname);
static int bgp_rpki_vrf_update(struct vrf *vrf, bool enabled);
static int bgp_rpki_write_vrf(struct vty *vty, struct vrf *vrf);
static int bgp_rpki_hook_write_vrf(struct vty *vty, struct vrf *vrf);
static int bgp_rpki_write_debug(struct vty *vty, bool running);
static int start(struct rpki_vrf *rpki_vrf);
static void stop(struct rpki_vrf *rpki_vrf);
static int reset(bool force, struct rpki_vrf *rpki_vrf);
static struct rtr_mgr_group *get_connected_group(struct rpki_vrf *rpki_vrf);
static void print_prefix_table(struct vty *vty, struct rpki_vrf *rpki_vrf);
static void install_cli_commands(void);
static int config_write(struct vty *vty);
static int config_on_exit(struct vty *vty);
static void free_cache(struct cache *cache);
static struct rtr_mgr_group *get_groups(struct list *cache_list);
#if defined(FOUND_SSH)
static int add_ssh_cache(struct rpki_vrf *rpki_vrf,
			 const char *host,
			 const unsigned int port,
			 const char *username, const char *client_privkey_path,
			 const char *client_pubkey_path,
			 const char *server_pubkey_path,
			 const uint8_t preference);
#endif
static struct rtr_socket *create_rtr_socket(struct tr_socket *tr_socket);
static struct cache *find_cache(const uint8_t preference,
				struct list *cache_list);
static int add_tcp_cache(struct rpki_vrf *rpki_vrf, const char *host,
			  const char *port, const uint8_t preference);
static void print_record(const struct pfx_record *record, struct vty *vty);
static int is_synchronized(struct rpki_vrf *rpki);
static int is_running(struct rpki_vrf *rpki);
static void route_match_free(void *rule);
static enum route_map_cmd_result_t route_match(void *rule,
					       const struct prefix *prefix,
					       route_map_object_t type,
					       void *object);
static void *route_match_compile(const char *arg);
static void revalidate_bgp_node(struct bgp_dest *dest, afi_t afi, safi_t safi);
static void revalidate_all_routes(struct rpki_vrf *rpki_vrf);

static int rpki_debug_conf, rpki_debug_term;

DECLARE_QOBJ_TYPE(rpki_vrf)
DEFINE_QOBJ_TYPE(rpki_vrf)

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
	.config_write = config_write,
	.node_exit = config_on_exit,
};

static const struct route_map_rule_cmd route_match_rpki_cmd = {
	"rpki", route_match, route_match_compile, route_match_free};

static void *malloc_wrapper(size_t size)
{
	return XMALLOC(MTYPE_BGP_RPKI_CACHE, size);
}

static void *realloc_wrapper(void *ptr, size_t size)
{
	return XREALLOC(MTYPE_BGP_RPKI_CACHE, ptr, size);
}

static void free_wrapper(void *ptr)
{
	XFREE(MTYPE_BGP_RPKI_CACHE, ptr);
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
					       route_map_object_t type,
					       void *object)
{
	int *rpki_status = rule;
	struct bgp_path_info *path;

	if (type == RMAP_BGP) {
		path = object;

		if (rpki_validate_prefix(path->peer, path->attr, prefix)
		    == *rpki_status) {
			return RMAP_MATCH;
		}
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
	char *ptr;
	unsigned int port;
	char *endptr;
	struct listnode *rpki_vrf_nnode;
	struct rpki_vrf *rpki_vrf;
	struct listnode *cache_node;
	struct cache *cache;
	char *buf, *host;
	bool is_tcp = true;
	size_t host_len;

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
		host = XCALLOC(MTYPE_BGP_RPKI_TEMP, (size_t)(buf + host_len - endptr) + 1);
		memcpy(host, endptr + 1, (size_t)(buf + host_len - endptr) + 1);
		is_tcp = false;
	} else {
		host = buf;
		buf = NULL;
	}

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf_list, rpki_vrf_nnode, rpki_vrf)) {
		for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list,
					  cache_node, cache)) {
			if ((cache->type == TCP && !is_tcp) ||
			    (cache->type == SSH && is_tcp))
				continue;
			if (is_tcp) {
				struct tr_tcp_config *tcp_config = cache->tr_config.tcp_config;
				unsigned int cache_port;

				cache_port = atoi(tcp_config->port);
				if (cache_port != port)
					continue;
				if (strlen(tcp_config->host) != strlen(host))
					continue;
				if (0 == memcmp(tcp_config->host, host, host_len))
					break;
			} else {
				struct tr_ssh_config *ssh_config = cache->tr_config.ssh_config;

				if (port != ssh_config->port)
					continue;
				if (strmatch(ssh_config->host, host))
					break;
			}
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
		if ((!vrfname && rpki_vrf->vrfname) ||
		    (vrfname && !rpki_vrf->vrfname) ||
		    (vrfname && rpki_vrf->vrfname &&
		     !strmatch(vrfname, rpki_vrf->vrfname)))
			continue;
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

static void print_record(const struct pfx_record *record, struct vty *vty)
{
	char ip[INET6_ADDRSTRLEN];

	lrtr_ip_addr_to_str(&record->prefix, ip, sizeof(ip));
	vty_out(vty, "%-40s   %3u - %3u   %10u\n", ip, record->min_len,
		record->max_len, record->asn);
}

static void print_record_by_asn(const struct pfx_record *record, void *data)
{
	struct rpki_for_each_record_arg *arg = data;
	struct vty *vty = arg->vty;

	if (record->asn == arg->as) {
		(*arg->prefix_amount)++;
		print_record(record, vty);
	}
}

static void print_record_cb(const struct pfx_record *record, void *data)
{
	struct rpki_for_each_record_arg *arg = data;
	struct vty *vty = arg->vty;

	(*arg->prefix_amount)++;

	print_record(record, vty);
}

static struct rtr_mgr_group *get_groups(struct list *cache_list)
{
	struct listnode *cache_node;
	struct rtr_mgr_group *rtr_mgr_groups;
	struct cache *cache;
	int group_count;

	group_count = listcount(cache_list);
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

inline int is_synchronized(struct rpki_vrf *rpki_vrf)
{
	return rpki_vrf->rtr_is_running &&
		rtr_mgr_conf_in_sync(rpki_vrf->rtr_config);
}

inline int is_running(struct rpki_vrf *rpki_vrf)
{
	return rpki_vrf->rtr_is_running;
}

static struct prefix *pfx_record_to_prefix(struct pfx_record *record)
{
	struct prefix *prefix = prefix_new();

	prefix->prefixlen = record->min_len;

	if (record->prefix.ver == LRTR_IPV4) {
		prefix->family = AF_INET;
		prefix->u.prefix4.s_addr = htonl(record->prefix.u.addr4.addr);
	} else {
		prefix->family = AF_INET6;
		ipv6_addr_to_network_byte_order(record->prefix.u.addr6.addr,
						prefix->u.prefix6.s6_addr32);
	}

	return prefix;
}

static int bgpd_sync_callback(struct thread *thread)
{
	struct bgp *bgp;
	struct listnode *node;
	struct prefix *prefix;
	struct pfx_record rec;
	struct rpki_vrf *rpki_vrf = THREAD_ARG(thread);
	struct vrf *vrf = NULL;

	thread_add_read(bm->master, bgpd_sync_callback, rpki_vrf,
			rpki_vrf->rpki_sync_socket_bgpd, NULL);

	if (atomic_load_explicit(&rpki_vrf->rtr_update_overflow,
				 memory_order_seq_cst)) {
		while (read(rpki_vrf->rpki_sync_socket_bgpd, &rec,
			    sizeof(struct pfx_record))
		       != -1)
			;

		atomic_store_explicit(&rpki_vrf->rtr_update_overflow, 0,
				      memory_order_seq_cst);
		revalidate_all_routes(rpki_vrf);
		return 0;
	}

	int retval =
		read(rpki_vrf->rpki_sync_socket_bgpd, &rec,
		     sizeof(struct pfx_record));
	if (retval != sizeof(struct pfx_record)) {
		RPKI_DEBUG("Could not read from rpki_sync_socket_bgpd");
		return retval;
	}
	prefix = pfx_record_to_prefix(&rec);

	afi_t afi = (rec.prefix.ver == LRTR_IPV4) ? AFI_IP : AFI_IP6;

	if (rpki_vrf->vrfname) {
		vrf = vrf_lookup_by_name(rpki_vrf->vrfname);
		if (!vrf) {
			zlog_err("%s(): vrf for rpki %s not found",
				 __func__, rpki_vrf->vrfname);
			return 0;
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
			safi_t safi;

			for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
				if (!peer->bgp->rib[afi][safi])
					continue;

				struct bgp_dest *match;
				struct bgp_dest *node;

				match = bgp_table_subtree_lookup(
					peer->bgp->rib[afi][safi], prefix);
				node = match;

				while (node) {
					if (bgp_dest_has_bgp_path_info_data(
						    node)) {
						revalidate_bgp_node(node, afi,
								    safi);
					}

					node = bgp_route_next_until(node,
								    match);
				}
			}
		}
	}

	prefix_free(&prefix);
	return 0;
}

static void revalidate_bgp_node(struct bgp_dest *bgp_dest, afi_t afi,
				safi_t safi)
{
	struct bgp_adj_in *ain;

	for (ain = bgp_dest->adj_in; ain; ain = ain->next) {
		int ret;
		struct bgp_path_info *path =
			bgp_dest_get_bgp_path_info(bgp_dest);
		mpls_label_t *label = NULL;
		uint32_t num_labels = 0;

		if (path && path->extra) {
			label = path->extra->label;
			num_labels = path->extra->num_labels;
		}
		ret = bgp_update(ain->peer, bgp_dest_get_prefix(bgp_dest),
				 ain->addpath_rx_id, ain->attr, afi, safi,
				 ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, label,
				 num_labels, 1, NULL);

		if (ret < 0)
			return;
	}
}

static void revalidate_all_routes(struct rpki_vrf *rpki_vrf)
{
	struct bgp *bgp;
	struct listnode *node;
	struct vrf *vrf = NULL;

	if (rpki_vrf->vrfname) {
		vrf = vrf_lookup_by_name(rpki_vrf->vrfname);
		if (!vrf) {
			zlog_err("%s(): vrf for rpki %s not found",
				 __func__, rpki_vrf->vrfname);
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

			for (size_t i = 0; i < 2; i++) {
				safi_t safi;
				afi_t afi = (i == 0) ? AFI_IP : AFI_IP6;

				for (safi = SAFI_UNICAST; safi < SAFI_MAX;
				     safi++) {
					if (!peer->bgp->rib[afi][safi])
						continue;

					bgp_soft_reconfig_in(peer, afi, safi);
				}
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
	struct tr_socket *tr;
	const char *ident;
	int retval;

	if (!rtr) {
		msg = "could not find rtr_socket from cb_sync_rtr";
		goto err;
	}
	tr = rtr->tr_socket;
	if (!tr) {
		msg = "could not find tr_socket from cb_sync_rtr";
		goto err;
	}
	ident = tr->ident_fp(tr->socket);
	if (!ident) {
		msg = "could not find rpki_vrf ident";
		goto err;
	}
	rpki_vrf = find_rpki_vrf_from_ident(ident);
	if (!rpki_vrf) {
		msg = "could not find rpki_vrf";
		goto err;
	}
	if (rpki_vrf->rtr_is_stopping
	    || atomic_load_explicit(&rpki_vrf->rtr_update_overflow,
				    memory_order_seq_cst))
		return;
	retval =
		write(rpki_vrf->rpki_sync_socket_rtr, &rec,
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


	thread_add_read(bm->master, bgpd_sync_callback, rpki_vrf,
			rpki_vrf->rpki_sync_socket_bgpd, NULL);

	return;

err:
	zlog_err("RPKI: %s", msg);
	abort();

}

static struct rpki_vrf *bgp_rpki_allocate(const char *vrfname)
{
	struct rpki_vrf *rpki_vrf;

	rpki_vrf =  XCALLOC(MTYPE_BGP_RPKI_CACHE,
				sizeof(struct rpki_vrf));

	rpki_vrf->rtr_is_running = false;
	rpki_vrf->rtr_is_stopping = false;
	rpki_vrf->cache_list = list_new();
	rpki_vrf->cache_list->del = (void (*)(void *)) & free_cache;
	rpki_vrf->polling_period = POLLING_PERIOD_DEFAULT;
	rpki_vrf->expire_interval = EXPIRE_INTERVAL_DEFAULT;
	rpki_vrf->retry_interval = RETRY_INTERVAL_DEFAULT;

	if (vrfname && !strmatch(vrfname, VRF_DEFAULT_NAME))
		rpki_vrf->vrfname = XSTRDUP(MTYPE_BGP_RPKI_CACHE,
						vrfname);
	QOBJ_REG(rpki_vrf, rpki_vrf);
	listnode_add(rpki_vrf_list, rpki_vrf);
	return rpki_vrf;
}

static int bgp_rpki_init(struct thread_master *master)
{
	rpki_debug_conf = 0;
	rpki_debug_term = 0;

	rpki_vrf_list = list_new();
	install_cli_commands();

	return 0;
}

static void bgp_rpki_finish(struct rpki_vrf *rpki_vrf)
{
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

static int bgp_rpki_fini(void)
{
	struct rpki_vrf *rpki_vrf;

	/* assume default vrf */
	rpki_vrf = find_rpki_vrf(NULL);
	if (!rpki_vrf)
		return 0;
	bgp_rpki_finish(rpki_vrf);

	return 0;
}

static int bgp_rpki_module_init(void)
{
	lrtr_set_alloc_functions(malloc_wrapper, realloc_wrapper, free_wrapper);

	hook_register(frr_late_init, bgp_rpki_init);
	hook_register(frr_early_fini, &bgp_rpki_fini);
	hook_register(bgp_hook_config_write_debug, &bgp_rpki_write_debug);
	hook_register(bgp_hook_vrf_update, &bgp_rpki_vrf_update);
	hook_register(bgp_hook_config_write_vrf, &bgp_rpki_hook_write_vrf);

	return 0;
}

static int start(struct rpki_vrf *rpki_vrf)
{
	int ret;
	struct list *cache_list = NULL;
	struct vrf *vrf;

	cache_list = rpki_vrf->cache_list;
	rpki_vrf->rtr_is_stopping = false;
	rpki_vrf->rtr_update_overflow = 0;

	if (!cache_list || list_isempty(cache_list)) {
		RPKI_DEBUG("No caches were found in config."
			   "Prefix validation is off.");
		return ERROR;
	}

	if (rpki_vrf->vrfname)
		vrf = vrf_lookup_by_name(rpki_vrf->vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf || !CHECK_FLAG(vrf->status, VRF_ACTIVE)) {
		RPKI_DEBUG("VRF %s not present or disabled",
			   rpki_vrf->vrfname);
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
	rpki_vrf->rtr_is_running = true;

	XFREE(MTYPE_BGP_RPKI_CACHE_GROUP, groups);

	return SUCCESS;
}

static void stop(struct rpki_vrf *rpki_vrf)
{
	rpki_vrf->rtr_is_stopping = true;
	if (rpki_vrf->rtr_is_running) {
		rtr_mgr_stop(rpki_vrf->rtr_config);
		rtr_mgr_free(rpki_vrf->rtr_config);
		rpki_vrf->rtr_is_running = false;
	}
}

static int reset(bool force, struct rpki_vrf *rpki_vrf)
{
	if (rpki_vrf->rtr_is_running && !force)
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

static void print_prefix_table_by_asn(struct vty *vty, as_t as, struct rpki_vrf *rpki_vrf)
{
	unsigned int number_of_ipv4_prefixes = 0;
	unsigned int number_of_ipv6_prefixes = 0;
	struct rtr_mgr_group *group = get_connected_group(rpki_vrf);
	struct rpki_for_each_record_arg arg;

	arg.vty = vty;
	arg.as = as;

	if (!rpki_vrf)
		return;

	if (!group) {
		vty_out(vty, "Cannot find a connected group.\n");
		return;
	}

	struct pfx_table *pfx_table = group->sockets[0]->pfx_table;

	vty_out(vty, "RPKI/RTR prefix table\n");
	vty_out(vty, "%-40s %s  %s\n", "Prefix", "Prefix Length", "Origin-AS");

	arg.prefix_amount = &number_of_ipv4_prefixes;
	pfx_table_for_each_ipv4_record(pfx_table, print_record_by_asn, &arg);

	arg.prefix_amount = &number_of_ipv6_prefixes;
	pfx_table_for_each_ipv6_record(pfx_table, print_record_by_asn, &arg);

	vty_out(vty, "Number of IPv4 Prefixes: %u\n", number_of_ipv4_prefixes);
	vty_out(vty, "Number of IPv6 Prefixes: %u\n", number_of_ipv6_prefixes);
}

static void print_prefix_table(struct vty *vty, struct rpki_vrf *rpki_vrf)
{
	struct rpki_for_each_record_arg arg;

	unsigned int number_of_ipv4_prefixes = 0;
	unsigned int number_of_ipv6_prefixes = 0;
	struct rtr_mgr_group *group;

	if (!rpki_vrf)
		return;
	group = get_connected_group(rpki_vrf);
	arg.vty = vty;

	if (!group)
		return;

	struct pfx_table *pfx_table = group->sockets[0]->pfx_table;

	vty_out(vty, "RPKI/RTR prefix table\n");
	vty_out(vty, "%-40s %s  %s\n", "Prefix", "Prefix Length", "Origin-AS");

	arg.prefix_amount = &number_of_ipv4_prefixes;
	pfx_table_for_each_ipv4_record(pfx_table, print_record_cb, &arg);

	arg.prefix_amount = &number_of_ipv6_prefixes;
	pfx_table_for_each_ipv6_record(pfx_table, print_record_cb, &arg);

	vty_out(vty, "Number of IPv4 Prefixes: %u\n", number_of_ipv4_prefixes);
	vty_out(vty, "Number of IPv6 Prefixes: %u\n", number_of_ipv6_prefixes);
}

static int rpki_validate_prefix(struct peer *peer, struct attr *attr,
				const struct prefix *prefix)
{
	struct assegment *as_segment;
	as_t as_number = 0;
	struct lrtr_ip_addr ip_addr_prefix;
	enum pfxv_state result;
	char buf[BUFSIZ];
	const char *prefix_string;
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
		return 0;
	}

	// Do the actual validation
	rtr_mgr_validate(rpki_vrf->rtr_config, as_number, &ip_addr_prefix,
			 prefix->prefixlen, &result);

	// Print Debug output
	prefix_string = prefix2str(prefix, buf, sizeof(buf));
	switch (result) {
	case BGP_PFXV_STATE_VALID:
		RPKI_DEBUG(
			"Validating Prefix %s from asn %u    Result: VALID",
			prefix_string, as_number);
		return RPKI_VALID;
	case BGP_PFXV_STATE_NOT_FOUND:
		RPKI_DEBUG(
			"Validating Prefix %s from asn %u    Result: NOT FOUND",
			prefix_string, as_number);
		return RPKI_NOTFOUND;
	case BGP_PFXV_STATE_INVALID:
		RPKI_DEBUG(
			"Validating Prefix %s from asn %u    Result: INVALID",
			prefix_string, as_number);
		return RPKI_INVALID;
	default:
		RPKI_DEBUG(
			"Validating Prefix %s from asn %u    Result: CANNOT VALIDATE",
			prefix_string, as_number);
		break;
	}
	return 0;
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

	if (rpki_vrf->rtr_is_running) {
		init_tr_socket(cache);

		if (rtr_mgr_add_group(rpki_vrf->rtr_config, &group)
		    != RTR_SUCCESS) {
			free_tr_socket(cache);
			return ERROR;
		}
	}

	listnode_add(cache_list, cache);

	return SUCCESS;
}

static int rpki_create_socket(struct cache *cache)
{
	struct vrf *vrf;
	int socket;
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	char *host, *port;
	struct rpki_vrf *rpki_vrf = cache->rpki_vrf;
	int ret;

	if (rpki_vrf->vrfname == NULL)
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	else
		vrf = vrf_lookup_by_name(rpki_vrf->vrfname);
	if (!vrf)
		return 0;

	if (!CHECK_FLAG(vrf->status, VRF_ACTIVE) ||
	    vrf->vrf_id == VRF_UNKNOWN)
		return 0;

	bzero(&hints, sizeof(hints));

	if (cache->type == TCP) {
		struct tr_tcp_config *tcp_config;

		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_ADDRCONFIG;

		tcp_config = cache->tr_config.tcp_config;
		host = tcp_config->host;
		port = tcp_config->port;
	} else {
		char s_port[10];
		struct tr_ssh_config *ssh_config;

		ssh_config = cache->tr_config.ssh_config;
		host = ssh_config->host;
		snprintf(s_port, sizeof(s_port), "%hu",
			 ssh_config->port);
		port = s_port;

		hints.ai_flags |= AI_NUMERICHOST;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
	}
	frr_with_privs(&bgpd_privs) {
		ret = vrf_getaddrinfo(host, port,
				      &hints, &res, vrf->vrf_id);
	}
	if (ret != 0) {
		zlog_err("getaddrinfo error, %u", errno);
		return 0;
	}
	frr_with_privs(&bgpd_privs) {
		socket = vrf_socket(res->ai_family, res->ai_socktype,
				    res->ai_protocol, vrf->vrf_id, NULL);
	}
	if (socket <= 0) {
		zlog_err("vrf socket error, %u", errno);
		return 0;
	}

	if (connect(socket, res->ai_addr, res->ai_addrlen) == -1) {
		zlog_err("Couldn't establish TCP connection, %s", strerror(errno));
		if (res)
			freeaddrinfo(res);
		return 0;
	}
	if (res)
		freeaddrinfo(res);
	return socket;
}

static int rpki_get_socket(void *_cache)
{
	int sock;
	struct cache *cache = (struct cache *)_cache;

	if (!cache)
		return -1;
	sock = rpki_create_socket(cache);
	if (sock <= 0)
		return -1;
	return sock;
}

static int add_tcp_cache(struct rpki_vrf *rpki_vrf, const char *host,
			 const char *port, const uint8_t preference)
{
	struct rtr_socket *rtr_socket;
	struct tr_tcp_config *tcp_config;
	struct tr_socket *tr_socket;
	struct cache *cache;
	int ret;

	tcp_config = XCALLOC(MTYPE_BGP_RPKI_CACHE,
			     sizeof(struct tr_tcp_config));
	tr_socket = XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_socket));
	cache = XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct cache));

	tcp_config->host = XSTRDUP(MTYPE_BGP_RPKI_CACHE, host);
	tcp_config->port = XSTRDUP(MTYPE_BGP_RPKI_CACHE, port);
	tcp_config->bindaddr = NULL;
	tcp_config->data = cache;
	tcp_config->new_socket = rpki_get_socket;
	rtr_socket = create_rtr_socket(tr_socket);

	cache->rpki_vrf = rpki_vrf;
	cache->type = TCP;
	cache->tr_socket = tr_socket;
	cache->tr_config.tcp_config = tcp_config;
	cache->rtr_socket = rtr_socket;
	cache->preference = preference;

	ret = add_cache(cache);
	if (ret != SUCCESS) {
		free_cache(cache);
	}
	return ret;
}

#if defined(FOUND_SSH)
static int add_ssh_cache(struct rpki_vrf *rpki_vrf,
			 const char *host,
			 const unsigned int port,
			 const char *username, const char *client_privkey_path,
			 const char *client_pubkey_path,
			 const char *server_pubkey_path,
			 const uint8_t preference)
{
	struct tr_ssh_config *ssh_config;
	struct cache *cache;
	struct tr_socket *tr_socket;
	struct rtr_socket *rtr_socket;
	int ret;

	ssh_config = XCALLOC(MTYPE_BGP_RPKI_CACHE,
			     sizeof(struct tr_ssh_config));
	cache = XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct cache));
	tr_socket = XCALLOC(MTYPE_BGP_RPKI_CACHE, sizeof(struct tr_socket));

	ssh_config->port = port;
	ssh_config->host = XSTRDUP(MTYPE_BGP_RPKI_CACHE, host);
	ssh_config->bindaddr = NULL;
	ssh_config->data = cache;
	ssh_config->new_socket = rpki_get_socket;

	ssh_config->username = XSTRDUP(MTYPE_BGP_RPKI_CACHE, username);
	/* public key path is derived from private key path
	 * by appending '.pub' to the private key name
	 */
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

	ret = add_cache(cache);
	if (ret != SUCCESS) {
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
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.ssh_config);
	}
#endif
	XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_socket);
	XFREE(MTYPE_BGP_RPKI_CACHE, cache->rtr_socket);
	XFREE(MTYPE_BGP_RPKI_CACHE, cache);
}

/* return true if config changed from default */
static bool config_changed(struct rpki_vrf *rpki_vrf)
{
	if (rpki_vrf->cache_list && listcount(rpki_vrf->cache_list))
		return true;
	if (rpki_vrf->polling_period != POLLING_PERIOD_DEFAULT)
		return true;
	if (rpki_vrf->retry_interval != RETRY_INTERVAL_DEFAULT)
		return true;
	if (rpki_vrf->expire_interval != EXPIRE_INTERVAL_DEFAULT)
		return true;
	return false;
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
	char *host_key_pub = NULL;
	int len_host_key_pub;

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
	if (!config_changed(rpki_vrf))
		return 0;
	if (vrf_id == VRF_DEFAULT)
		vty_out(vty, "%s!\n", sep);
	vty_out(vty, "%srpki\n", sep);
	if (rpki_vrf->polling_period != POLLING_PERIOD_DEFAULT)
		vty_out(vty, "%s rpki polling_period %d\n",
			sep, rpki_vrf->polling_period);
	if (rpki_vrf->retry_interval != RETRY_INTERVAL_DEFAULT)
		vty_out(vty, "%s rpki retry-interval %d\n",
			sep, rpki_vrf->retry_interval);
	if (rpki_vrf->expire_interval != EXPIRE_INTERVAL_DEFAULT)
		vty_out(vty, "%s rpki expire_interval %d\n",
			sep, rpki_vrf->expire_interval);

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node, cache)) {
		switch (cache->type) {
			struct tr_tcp_config *tcp_config;
#if defined(FOUND_SSH)
			struct tr_ssh_config *ssh_config;
#endif
		case TCP:
			tcp_config = cache->tr_config.tcp_config;
			vty_out(vty, "%s rpki cache %s %s ", sep,
				tcp_config->host, tcp_config->port);
			break;
#if defined(FOUND_SSH)
		case SSH:
			ssh_config = cache->tr_config.ssh_config;
			if (ssh_config->client_privkey_path) {
				len_host_key_pub = strlen(ssh_config->client_privkey_path) + 4 /* strlen(".pub")*/ + 1;
				host_key_pub = XCALLOC(MTYPE_BGP_RPKI_CACHE, len_host_key_pub);
				snprintf(host_key_pub, len_host_key_pub, "%s.pub", ssh_config->client_privkey_path);
			}
			vty_out(vty, "%s rpki cache %s %u %s %s %s %s ",
				sep, ssh_config->host,
				ssh_config->port,
				ssh_config->username,
				ssh_config->client_privkey_path,
				host_key_pub ? host_key_pub : "",
				ssh_config->server_hostkey_path != NULL
				? ssh_config
				->server_hostkey_path
				: "");
			if (host_key_pub) {
				XFREE(MTYPE_BGP_RPKI_CACHE, host_key_pub);
				host_key_pub = NULL;
			}
			break;
#endif
		default:
			break;
		}

		vty_out(vty, "preference %hhu\n", cache->preference);
	}
	vty_out(vty, "%s exit\n%s", sep,
		vrf_id == VRF_DEFAULT ? "!\n" : "");
	return 1;
}

static int config_write(struct vty *vty)
{
	return bgp_rpki_write_vrf(vty, NULL);
}

DEFUN_NOSH (rpki,
	    rpki_cmd,
	    "rpki",
	    "Enable rpki and enter rpki configuration mode\n")
{
	struct rpki_vrf *rpki_vrf;
	char *vrfname = NULL;

	if (vty->node == CONFIG_NODE)
		vty->node = RPKI_NODE;
	else {
		struct vrf *vrf = VTY_GET_CONTEXT(vrf);

		vty->node = RPKI_VRF_NODE;
		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}
	/* assume default vrf */
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

DEFUN_NOSH (no_rpki,
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

	if (rpki_vrf)
		bgp_rpki_finish(rpki_vrf);
	return CMD_SUCCESS;
}

DEFUN (bgp_rpki_start,
       bgp_rpki_start_cmd,
       "rpki start [vrf NAME]",
       RPKI_OUTPUT_STRING
       "start rpki support\n"
       VRF_CMD_HELP_STR)
{
	struct list *cache_list = NULL;
	struct rpki_vrf *rpki_vrf;
	int idx_vrf = 3;
	struct vrf *vrf;
	char *vrfname = NULL;

	if (argc == 4) {
		vrf = vrf_lookup_by_name(argv[idx_vrf]->arg);
		if (!vrf)
			return CMD_SUCCESS;
		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}
	rpki_vrf = find_rpki_vrf(vrfname);
	if (!rpki_vrf)
		return CMD_SUCCESS;
	cache_list = rpki_vrf->cache_list;
	if (!cache_list || listcount(cache_list) == 0)
		vty_out(vty, "Could not start rpki"
			" because no caches are configured\n");

	if (!is_running(rpki_vrf)) {
		if (start(rpki_vrf) == ERROR) {
			RPKI_DEBUG("RPKI failed to start");
			return CMD_WARNING;
		}
	}
	return CMD_SUCCESS;
}

DEFUN (bgp_rpki_stop,
       bgp_rpki_stop_cmd,
       "rpki stop [vrf NAME]",
       RPKI_OUTPUT_STRING
       "start rpki support\n"
       VRF_CMD_HELP_STR)
{
	int idx_vrf = 3;
	struct vrf *vrf;
	char *vrfname = NULL;
	struct rpki_vrf *rpki_vrf;

	if (argc == 4) {
		vrf = vrf_lookup_by_name(argv[idx_vrf]->arg);
		if (!vrf)
			return CMD_SUCCESS;
		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}
	rpki_vrf = find_rpki_vrf(vrfname);
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

	rpki_vrf->polling_period = pp;
	return CMD_SUCCESS;
}

DEFUN (no_rpki_polling_period,
       no_rpki_polling_period_cmd,
       "no rpki polling_period",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set polling period back to default\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

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

	if ((unsigned int)tmp >= rpki_vrf->polling_period) {
		rpki_vrf->expire_interval = tmp;
		return CMD_SUCCESS;
	}

	vty_out(vty, "%% Expiry interval must be polling period or larger\n");
	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (no_rpki_expire_interval,
       no_rpki_expire_interval_cmd,
       "no rpki expire_interval",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set expire interval back to default\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

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

	rpki_vrf->retry_interval = tmp;
	return CMD_SUCCESS;
}

DEFUN (no_rpki_retry_interval,
       no_rpki_retry_interval_cmd,
       "no rpki retry_interval",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set retry interval back to default\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	rpki_vrf->retry_interval = RETRY_INTERVAL_DEFAULT;
	return CMD_SUCCESS;
}

#if (CONFDATE > 20200901)
CPP_NOTICE("bgpd: time to remove rpki timeout")
CPP_NOTICE("bgpd: this includes rpki_timeout and rpki_synchronisation_timeout")
#endif

DEFPY_HIDDEN (rpki_timeout,
       rpki_timeout_cmd,
       "rpki timeout (1-4294967295)$to_arg",
       RPKI_OUTPUT_STRING
       "Set timeout\n"
       "Timeout value\n")
{
	vty_out(vty,
		"This config option is deprecated, and is scheduled for removal.\n");
	vty_out(vty,
		"This functionality has also already been removed because it caused bugs and was pointless\n");
	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_rpki_timeout,
       no_rpki_timeout_cmd,
       "no rpki timeout",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set timeout back to default\n")
{
	vty_out(vty,
		"This config option is deprecated, and is scheduled for removal.\n");
	vty_out(vty,
		"This functionality has also already been removed because it caused bugs and was pointless\n");
	return CMD_SUCCESS;
}

DEFPY_HIDDEN (rpki_synchronisation_timeout,
       rpki_synchronisation_timeout_cmd,
       "rpki initial-synchronisation-timeout (1-4294967295)$ito_arg",
       RPKI_OUTPUT_STRING
       "Set a timeout for the initial synchronisation of prefix validation data\n"
       "Timeout value\n")
{
	vty_out(vty,
		"This config option is deprecated, and is scheduled for removal.\n");
	vty_out(vty,
		"This functionality has also already been removed because it caused bugs and was pointless\n");
	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_rpki_synchronisation_timeout,
       no_rpki_synchronisation_timeout_cmd,
       "no rpki initial-synchronisation-timeout",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set the initial synchronisation timeout back to default (30 sec.)\n")
{
	vty_out(vty,
		"This config option is deprecated, and is scheduled for removal.\n");
	vty_out(vty,
		"This functionality has also already been removed because it caused bugs and was pointless\n");
	return CMD_SUCCESS;
}

DEFPY (rpki_cache,
       rpki_cache_cmd,
       "rpki cache <A.B.C.D|WORD>"
       "<TCPPORT|(1-65535)$sshport SSH_UNAME SSH_PRIVKEY SSH_PUBKEY [SERVER_PUBKEY]> "
       "preference (1-255)",
       RPKI_OUTPUT_STRING
       "Install a cache server to current group\n"
       "IP address of cache server\n Hostname of cache server\n"
       "TCP port number\n"
       "SSH port number\n"
       "SSH user name\n"
       "Path to own SSH private key\n"
       "Path to own SSH public key\n"
       "Path to Public key of cache server\n"
       "Preference of the cache server\n"
       "Preference value\n")
{
	int return_value;
	struct listnode *cache_node;
	struct cache *current_cache;
	char *pub = NULL;
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);

	if (!rpki_vrf->cache_list)
		return CMD_WARNING;
	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node,
				  current_cache)) {
		if (current_cache->preference == preference) {
			vty_out(vty, "Cache with preference %ld "
				"is already configured\n",
				preference);
			return CMD_WARNING;
		}
	}

	// use ssh connection
	if (ssh_uname) {
#if defined(FOUND_SSH)
		if (ssh_privkey && ssh_pubkey) {
			pub =  XCALLOC(MTYPE_BGP_RPKI_CACHE,
					     strlen(ssh_privkey) + 5);
			snprintf(pub, strlen(ssh_privkey) + 5, "%s.pub",
				 ssh_privkey);
			if (!strmatch(pub, ssh_pubkey)) {
				vty_out(vty,
					"ssh public key overriden: %s.pub\n",
					ssh_privkey);
			}
		}
		return_value =
		add_ssh_cache(rpki_vrf, cache, sshport, ssh_uname, ssh_privkey,
			      pub, server_pubkey, preference);
		if (pub)
			XFREE(MTYPE_BGP_RPKI_CACHE, pub);
#else
		return_value = SUCCESS;
		vty_out(vty,
			"ssh sockets are not supported. "
			"Please recompile rtrlib and frr with ssh support. "
			"If you want to use it\n");
#endif
	} else { // use tcp connection
		return_value = add_tcp_cache(rpki_vrf, cache, tcpport,
					     preference);
	}

	if (return_value == ERROR) {
		vty_out(vty, "Could not create new rpki cache\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFPY (no_rpki_cache,
       no_rpki_cache_cmd,
       "no rpki cache <A.B.C.D|WORD> <TCPPORT|(1-65535)$sshport> preference (1-255)$preference",
       NO_STR
       RPKI_OUTPUT_STRING
       "Remove a cache server\n"
       "IP address of cache server\n Hostname of cache server\n"
       "TCP port number\n"
       "SSH port number\n"
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

	cache_list = rpki_vrf->cache_list;
	cache_p = find_cache(preference, cache_list);
	if (!rpki_vrf || !cache_p) {
		vty_out(vty, "Could not find cache %ld\n", preference);
		return CMD_WARNING;
	}

	if (rpki_vrf->rtr_is_running && listcount(rpki_vrf->cache_list) == 1) {
		stop(rpki_vrf);
	} else if (rpki_vrf->rtr_is_running) {
		if (rtr_mgr_remove_group(rpki_vrf->rtr_config, preference)
		    == RTR_ERROR) {
			vty_out(vty, "Could not remove cache %ld", preference);

			vty_out(vty, "\n");
			return CMD_WARNING;
		}
	}

	listnode_delete(cache_list, cache_p);
	free_cache(cache_p);

	return CMD_SUCCESS;
}

DEFUN (show_rpki_prefix_table,
       show_rpki_prefix_table_cmd,
       "show rpki prefix-table [vrf NAME]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show validated prefixes which were received from RPKI Cache\n"
       VRF_CMD_HELP_STR)
{
	struct listnode *cache_node;
	struct cache *cache;
	struct rpki_vrf *rpki_vrf;
	int idx_vrf = 4;
	struct vrf *vrf;
	char *vrfname = NULL;

	if (argc == 5) {
		vrf = vrf_lookup_by_name(argv[idx_vrf]->arg);
		if (!vrf)
			return CMD_SUCCESS;
		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}

	rpki_vrf = find_rpki_vrf(vrfname);
	if (!rpki_vrf)
		return CMD_SUCCESS;
	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node, cache)) {
		if (cache->type == TCP)
			vty_out(vty, "host: %s port: %s\n",
				cache->tr_config.tcp_config->host,
				cache->tr_config.tcp_config->port);
		else
			vty_out(vty, "host: %s port: %u SSH\n",
				cache->tr_config.ssh_config->host,
				cache->tr_config.ssh_config->port);
	}
	if (is_synchronized(rpki_vrf))
		print_prefix_table(vty, rpki_vrf);
	else
		vty_out(vty, "No connection to RPKI cache server.\n");

	return CMD_SUCCESS;
}

DEFPY(show_rpki_as_number, show_rpki_as_number_cmd,
      "show rpki as-number (1-4294967295)$by_asn [vrf NAME$vrfname]",
      SHOW_STR RPKI_OUTPUT_STRING
      "Lookup by ASN in prefix table\n"
      "AS Number\n")
{
	struct rpki_vrf *rpki_vrf;
	char *vrf_name = NULL;
	struct vrf *vrf;

	if (vrfname && !strmatch(vrfname, VRF_DEFAULT_NAME)) {
		vrf = vrf_lookup_by_name(vrfname);
		if (!vrf)
			return CMD_SUCCESS;
		vrf_name = vrf->name;
	}
	/* assume default vrf */
	rpki_vrf = find_rpki_vrf(vrf_name);

	if (!is_synchronized(rpki_vrf)) {
		vty_out(vty, "No Connection to RPKI cache server.\n");
		return CMD_WARNING;
	}

	print_prefix_table_by_asn(vty, by_asn, rpki_vrf);
	return CMD_SUCCESS;
}

DEFPY (show_rpki_prefix,
       show_rpki_prefix_cmd,
       "show rpki prefix <A.B.C.D/M|X:X::X:X/M> [(1-4294967295)$asn] [vrf NAME$vrfname]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Lookup IP prefix and optionally ASN in prefix table\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "AS Number\n"
       VRF_CMD_HELP_STR)
{
	struct rpki_vrf *rpki_vrf;
	struct vrf *vrf;
	char *vrf_name = NULL;

	if (vrfname && !strmatch(vrfname, VRF_DEFAULT_NAME)) {
		vrf = vrf_lookup_by_name(vrfname);
		if (!vrf)
			return CMD_SUCCESS;
		vrf_name = vrf->name;
	}

	rpki_vrf = find_rpki_vrf(vrf_name);

	if (!rpki_vrf || !is_synchronized(rpki_vrf)) {
		vty_out(vty, "No Connection to RPKI cache server.\n");
		return CMD_WARNING;
	}

	struct lrtr_ip_addr addr;
	char addr_str[INET6_ADDRSTRLEN];
	size_t addr_len = strchr(prefix_str, '/') - prefix_str;

	memset(addr_str, 0, sizeof(addr_str));
	memcpy(addr_str, prefix_str, addr_len);

	if (lrtr_ip_str_to_addr(addr_str, &addr) != 0) {
		vty_out(vty, "Invalid IP prefix\n");
		return CMD_WARNING;
	}

	struct pfx_record *matches = NULL;
	unsigned int match_count = 0;
	enum pfxv_state result;

	if (pfx_table_validate_r(rpki_vrf->rtr_config->pfx_table, &matches,
				  &match_count, asn, &addr,
				 prefix->prefixlen, &result)
	    != PFX_SUCCESS) {
		vty_out(vty, "Prefix lookup failed");
		return CMD_WARNING;
	}

	vty_out(vty, "%-40s %s  %s\n", "Prefix", "Prefix Length", "Origin-AS");
	for (size_t i = 0; i < match_count; ++i) {
		const struct pfx_record *record = &matches[i];

		if (record->max_len >= prefix->prefixlen
		    && ((asn != 0 && (uint32_t)asn == record->asn)
			|| asn == 0)) {
			print_record(&matches[i], vty);
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_rpki_cache_server,
       show_rpki_cache_server_cmd,
       "show rpki cache-server [vrf NAME]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "SHOW configured cache server\n"
       VRF_CMD_HELP_STR)
{
	struct listnode *cache_node;
	struct cache *cache;
	struct rpki_vrf *rpki_vrf;
	int idx_vrf = 4;
	struct vrf *vrf;
	char *vrfname = NULL;

	if (argc == 5) {
		vrf = vrf_lookup_by_name(argv[idx_vrf]->arg);
		if (!vrf)
			return CMD_SUCCESS;
		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}

	rpki_vrf = find_rpki_vrf(vrfname);
	if (!rpki_vrf)
		return CMD_SUCCESS;

	for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list, cache_node, cache)) {
		if (cache->type == TCP) {
			vty_out(vty, "host: %s port: %s\n",
				cache->tr_config.tcp_config->host,
				cache->tr_config.tcp_config->port);

#if defined(FOUND_SSH)
		} else if (cache->type == SSH) {
			vty_out(vty,
				"host: %s port: %d username: %s "
				"server_hostkey_path: %s client_privkey_path: %s\n",
				cache->tr_config.ssh_config->host,
				cache->tr_config.ssh_config->port,
				cache->tr_config.ssh_config->username,
				cache->tr_config.ssh_config
					->server_hostkey_path,
				cache->tr_config.ssh_config
					->client_privkey_path);
#endif
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_rpki_cache_connection,
       show_rpki_cache_connection_cmd,
       "show rpki cache-connection [vrf NAME]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show to which RPKI Cache Servers we have a connection\n"
       VRF_CMD_HELP_STR)
{
	struct rpki_vrf *rpki_vrf;
	int idx_vrf = 4;
	struct vrf *vrf;
	char *vrfname = NULL;

	if (argc == 5) {
		vrf = vrf_lookup_by_name(argv[idx_vrf]->arg);
		if (!vrf)
			return CMD_SUCCESS;
		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}

	rpki_vrf = find_rpki_vrf(vrfname);
	if (!rpki_vrf)
		return CMD_SUCCESS;

	if (is_synchronized(rpki_vrf)) {
		struct listnode *cache_node;
		struct cache *cache;
		struct rtr_mgr_group *group = get_connected_group(rpki_vrf);

		if (!group || !rpki_vrf->cache_list) {
			vty_out(vty, "Cannot find a connected group.\n");
			return CMD_SUCCESS;
		}
		vty_out(vty, "Connected to group %d\n", group->preference);
		for (ALL_LIST_ELEMENTS_RO(rpki_vrf->cache_list,
					  cache_node, cache)) {
			if (cache->preference == group->preference) {
				struct tr_tcp_config *tcp_config;
#if defined(FOUND_SSH)
				struct tr_ssh_config *ssh_config;
#endif

				switch (cache->type) {
				case TCP:
					tcp_config =
						cache->tr_config.tcp_config;
					vty_out(vty,
						"rpki tcp cache %s %s pref %hhu\n",
						tcp_config->host,
						tcp_config->port,
						cache->preference);
					break;

#if defined(FOUND_SSH)
				case SSH:
					ssh_config =
						cache->tr_config.ssh_config;
					vty_out(vty,
						"rpki ssh cache %s %u pref %hhu\n",
						ssh_config->host,
						ssh_config->port,
						cache->preference);
					break;
#endif

				default:
					break;
				}
			}
		}
	} else {
		vty_out(vty, "No connection to RPKI cache server.\n");
	}

	return CMD_SUCCESS;
}

DEFUN (show_rpki_configuration,
       show_rpki_configuration_cmd,
       "show rpki configuration [vrf NAME]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show RPKI configuration\n"
       VRF_CMD_HELP_STR)
{
	struct rpki_vrf *rpki_vrf;
	int idx_vrf = 4;
	struct vrf *vrf;
	char *vrfname = NULL;

	if (argc == 5) {
		vrf = vrf_lookup_by_name(argv[idx_vrf]->arg);
		if (!vrf)
			return CMD_SUCCESS;
		if (vrf->vrf_id != VRF_DEFAULT)
			vrfname = vrf->name;
	}

	rpki_vrf = find_rpki_vrf(vrfname);
	if (!rpki_vrf)
		return CMD_SUCCESS;
	vty_out(vty, "rpki is %s",
		listcount(rpki_vrf->cache_list) ? "Enabled" : "Disabled");
	if (!listcount(rpki_vrf->cache_list))
		return CMD_SUCCESS;
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
	reset(false, rpki_vrf);
	return 1;
}

DEFUN (rpki_reset,
       rpki_reset_cmd,
       "rpki reset",
       RPKI_OUTPUT_STRING
       "reset rpki\n")
{
	struct rpki_vrf *rpki_vrf;

	if (vty->node == RPKI_VRF_NODE)
		rpki_vrf = VTY_GET_CONTEXT_SUB(rpki_vrf);
	else
		rpki_vrf = VTY_GET_CONTEXT(rpki_vrf);
	return reset(true, rpki_vrf) == SUCCESS ? CMD_SUCCESS : CMD_WARNING;
}

DEFUN (debug_rpki,
       debug_rpki_cmd,
       "debug rpki",
       DEBUG_STR
       "Enable debugging for rpki\n")
{
	if (vty->node == CONFIG_NODE)
		rpki_debug_conf = 1;
	else
		rpki_debug_term = 1;
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
		rpki_debug_conf = 0;
	else
		rpki_debug_term = 0;
	return CMD_SUCCESS;
}

DEFUN (match_rpki,
       match_rpki_cmd,
       "match rpki <valid|invalid|notfound>",
       MATCH_STR
       RPKI_OUTPUT_STRING
       "Valid prefix\n"
       "Invalid prefix\n"
       "Prefix not found\n")
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	enum rmap_compile_rets ret;

	ret = route_map_add_match(index, "rpki", argv[2]->arg,
				  RMAP_EVENT_MATCH_ADDED);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% BGP Can't find rule.\n");
		return CMD_WARNING_CONFIG_FAILED;
	case RMAP_COMPILE_ERROR:
		vty_out(vty, "%% BGP Argument is malformed.\n");
		return CMD_WARNING_CONFIG_FAILED;
	case RMAP_COMPILE_SUCCESS:
		return CMD_SUCCESS;
		break;
	}

	return CMD_SUCCESS;
}

DEFUN (no_match_rpki,
       no_match_rpki_cmd,
       "no match rpki <valid|invalid|notfound>",
       NO_STR
       MATCH_STR
       RPKI_OUTPUT_STRING
       "Valid prefix\n"
       "Invalid prefix\n"
       "Prefix not found\n")
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	enum rmap_compile_rets ret;

	ret = route_map_delete_match(index, "rpki", argv[3]->arg,
				     RMAP_EVENT_MATCH_DELETED);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% BGP Can't find rule.\n");
		return CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty, "%% BGP Argument is malformed.\n");
		return CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		return CMD_SUCCESS;
		break;
	}

	return CMD_SUCCESS;
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
	install_element(RPKI_NODE, &rpki_reset_cmd);

	/* Install rpki polling period commands */
	install_element(RPKI_NODE, &rpki_polling_period_cmd);
	install_element(RPKI_NODE, &no_rpki_polling_period_cmd);

	/* Install rpki expire interval commands */
	install_element(RPKI_NODE, &rpki_expire_interval_cmd);
	install_element(RPKI_NODE, &no_rpki_expire_interval_cmd);

	/* Install rpki retry interval commands */
	install_element(RPKI_NODE, &rpki_retry_interval_cmd);
	install_element(RPKI_NODE, &no_rpki_retry_interval_cmd);

	/* Install rpki timeout commands */
	install_element(RPKI_NODE, &rpki_timeout_cmd);
	install_element(RPKI_NODE, &no_rpki_timeout_cmd);

	/* Install rpki synchronisation timeout commands */
	install_element(RPKI_NODE, &rpki_synchronisation_timeout_cmd);
	install_element(RPKI_NODE, &no_rpki_synchronisation_timeout_cmd);

	/* Install rpki cache commands */
	install_element(RPKI_NODE, &rpki_cache_cmd);
	install_element(RPKI_NODE, &no_rpki_cache_cmd);

	/* RPKI_VRF_NODE commands */
	install_element(VRF_NODE, &rpki_cmd);
	install_element(VRF_NODE, &no_rpki_cmd);
	/* Install rpki reset command */
	install_element(RPKI_VRF_NODE, &rpki_reset_cmd);

	/* Install rpki polling period commands */
	install_element(RPKI_VRF_NODE, &rpki_polling_period_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_polling_period_cmd);

	/* Install rpki expire interval commands */
	install_element(RPKI_VRF_NODE, &rpki_expire_interval_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_expire_interval_cmd);

	/* Install rpki retry interval commands */
	install_element(RPKI_VRF_NODE, &rpki_retry_interval_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_retry_interval_cmd);

	/* Install rpki timeout commands */
	install_element(RPKI_VRF_NODE, &rpki_timeout_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_timeout_cmd);

	/* Install rpki synchronisation timeout commands */
	install_element(RPKI_VRF_NODE, &rpki_synchronisation_timeout_cmd);
	install_element(RPKI_VRF_NODE, &no_rpki_synchronisation_timeout_cmd);

	/* Install rpki cache commands */
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
		 .init = bgp_rpki_module_init)
