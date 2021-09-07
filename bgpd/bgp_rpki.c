/*
 * BGP RPKI
 * Copyright (C) 2013 Michael Mester (m.mester@fu-berlin.de), for FU Berlin
 * Copyright (C) 2014-2017 Andreas Reuter (andreas.reuter@fu-berlin.de), for FU
 * Berlin
 * Copyright (C) 2016-2017 Colin Sames (colin.sames@haw-hamburg.de), for HAW
 * Hamburg
 * Copyright (C) 2017-2018 Marcel Röthke (marcel.roethke@haw-hamburg.de),
 * for HAW Hamburg
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
#include "bgpd/bgp_rpki.h"
#include "northbound_cli.h"

#include "lib/network.h"
#include "lib/thread.h"
#ifndef VTYSH_EXTRACT_PL
#include "rtrlib/rtrlib.h"
#endif
#include "hook.h"
#include "libfrr.h"
#include "lib/version.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_rpki_clippy.c"
#endif

DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_CACHE, "BGP RPKI Cache server");
DEFINE_MTYPE_STATIC(BGPD, BGP_RPKI_CACHE_GROUP, "BGP RPKI Cache server group");

#define POLLING_PERIOD_DEFAULT 3600
#define EXPIRE_INTERVAL_DEFAULT 7200
#define RETRY_INTERVAL_DEFAULT 600

#define RPKI_DEBUG(...)                                                        \
	if (rpki_debug) {                                                      \
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
};

enum return_values { SUCCESS = 0, ERROR = -1 };

struct rpki_for_each_record_arg {
	struct vty *vty;
	unsigned int *prefix_amount;
	as_t as;
};

static int start(void);
static void stop(void);
static int reset(bool force);
static struct rtr_mgr_group *get_connected_group(void);
static void print_prefix_table(struct vty *vty);
static void install_cli_commands(void);
static int config_write(struct vty *vty);
static int config_on_exit(struct vty *vty);
static void free_cache(struct cache *cache);
static struct rtr_mgr_group *get_groups(void);
#if defined(FOUND_SSH)
static int add_ssh_cache(const char *host, const unsigned int port,
			 const char *username, const char *client_privkey_path,
			 const char *client_pubkey_path,
			 const char *server_pubkey_path,
			 const uint8_t preference, const char *bindaddr);
#endif
static struct rtr_socket *create_rtr_socket(struct tr_socket *tr_socket);
static struct cache *find_cache(const uint8_t preference);
static int add_tcp_cache(const char *host, const char *port,
			 const uint8_t preference, const char *bindaddr);
static void print_record(const struct pfx_record *record, struct vty *vty);
static int is_synchronized(void);
static int is_running(void);
static void route_match_free(void *rule);
static enum route_map_cmd_result_t route_match(void *rule,
					       const struct prefix *prefix,

					       void *object);
static void *route_match_compile(const char *arg);
static void revalidate_bgp_node(struct bgp_dest *dest, afi_t afi, safi_t safi);
static void revalidate_all_routes(void);

static struct rtr_mgr_config *rtr_config;
static struct list *cache_list;
static int rtr_is_running;
static int rtr_is_stopping;
static _Atomic int rtr_update_overflow;
static int rpki_debug;
static unsigned int polling_period;
static unsigned int expire_interval;
static unsigned int retry_interval;
static int rpki_sync_socket_rtr;
static int rpki_sync_socket_bgpd;

static struct cmd_node rpki_node = {
	.name = "rpki",
	.node = RPKI_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-rpki)# ",
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

static struct cache *find_cache(const uint8_t preference)
{
	struct listnode *cache_node;
	struct cache *cache;

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

static struct rtr_mgr_group *get_groups(void)
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

inline int is_synchronized(void)
{
	return rtr_is_running && rtr_mgr_conf_in_sync(rtr_config);
}

inline int is_running(void)
{
	return rtr_is_running;
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

	thread_add_read(bm->master, bgpd_sync_callback, NULL,
			rpki_sync_socket_bgpd, NULL);

	if (atomic_load_explicit(&rtr_update_overflow, memory_order_seq_cst)) {
		while (read(rpki_sync_socket_bgpd, &rec,
			    sizeof(struct pfx_record))
		       != -1)
			;

		atomic_store_explicit(&rtr_update_overflow, 0,
				      memory_order_seq_cst);
		revalidate_all_routes();
		return 0;
	}

	int retval =
		read(rpki_sync_socket_bgpd, &rec, sizeof(struct pfx_record));
	if (retval != sizeof(struct pfx_record)) {
		RPKI_DEBUG("Could not read from rpki_sync_socket_bgpd");
		return retval;
	}
	prefix = pfx_record_to_prefix(&rec);

	afi_t afi = (rec.prefix.ver == LRTR_IPV4) ? AFI_IP : AFI_IP6;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		safi_t safi;

		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			if (!bgp->rib[afi][safi])
				continue;

			struct bgp_dest *match;
			struct bgp_dest *node;

			match = bgp_table_subtree_lookup(bgp->rib[afi][safi],
							 prefix);
			node = match;

			while (node) {
				if (bgp_dest_has_bgp_path_info_data(node)) {
					revalidate_bgp_node(node, afi, safi);
				}

				node = bgp_route_next_until(node, match);
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
		struct bgp_path_info *path =
			bgp_dest_get_bgp_path_info(bgp_dest);
		mpls_label_t *label = NULL;
		uint32_t num_labels = 0;

		if (path && path->extra) {
			label = path->extra->label;
			num_labels = path->extra->num_labels;
		}
		(void)bgp_update(ain->peer, bgp_dest_get_prefix(bgp_dest),
				 ain->addpath_rx_id, ain->attr, afi, safi,
				 ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, label,
				 num_labels, 1, NULL);
	}
}

static void revalidate_all_routes(void)
{
	struct bgp *bgp;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct peer *peer;
		struct listnode *peer_listnode;

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
	if (rtr_is_stopping
	    || atomic_load_explicit(&rtr_update_overflow, memory_order_seq_cst))
		return;

	int retval =
		write(rpki_sync_socket_rtr, &rec, sizeof(struct pfx_record));
	if (retval == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
		atomic_store_explicit(&rtr_update_overflow, 1,
				      memory_order_seq_cst);

	else if (retval != sizeof(struct pfx_record))
		RPKI_DEBUG("Could not write to rpki_sync_socket_rtr");
}

static void rpki_init_sync_socket(void)
{
	int fds[2];
	const char *msg;

	RPKI_DEBUG("initializing sync socket");
	if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, fds) != 0) {
		msg = "could not open rpki sync socketpair";
		goto err;
	}
	rpki_sync_socket_rtr = fds[0];
	rpki_sync_socket_bgpd = fds[1];

	if (set_nonblocking(rpki_sync_socket_rtr) != 0) {
		msg = "could not set rpki_sync_socket_rtr to non blocking";
		goto err;
	}

	if (set_nonblocking(rpki_sync_socket_bgpd) != 0) {
		msg = "could not set rpki_sync_socket_bgpd to non blocking";
		goto err;
	}


	thread_add_read(bm->master, bgpd_sync_callback, NULL,
			rpki_sync_socket_bgpd, NULL);

	return;

err:
	zlog_err("RPKI: %s", msg);
	abort();

}

static int bgp_rpki_init(struct thread_master *master)
{
	rpki_debug = 0;
	rtr_is_running = 0;
	rtr_is_stopping = 0;

	cache_list = list_new();
	cache_list->del = (void (*)(void *)) & free_cache;

	polling_period = POLLING_PERIOD_DEFAULT;
	expire_interval = EXPIRE_INTERVAL_DEFAULT;
	retry_interval = RETRY_INTERVAL_DEFAULT;
	install_cli_commands();
	rpki_init_sync_socket();
	return 0;
}

static int bgp_rpki_fini(void)
{
	stop();
	list_delete(&cache_list);

	close(rpki_sync_socket_rtr);
	close(rpki_sync_socket_bgpd);

	return 0;
}

static int bgp_rpki_module_init(void)
{
	lrtr_set_alloc_functions(malloc_wrapper, realloc_wrapper, free_wrapper);

	hook_register(bgp_rpki_prefix_status, rpki_validate_prefix);
	hook_register(frr_late_init, bgp_rpki_init);
	hook_register(frr_early_fini, &bgp_rpki_fini);

	return 0;
}

static int start(void)
{
	int ret;

	rtr_is_stopping = 0;
	rtr_update_overflow = 0;

	if (list_isempty(cache_list)) {
		RPKI_DEBUG(
			"No caches were found in config. Prefix validation is off.");
		return ERROR;
	}
	RPKI_DEBUG("Init rtr_mgr.");
	int groups_len = listcount(cache_list);
	struct rtr_mgr_group *groups = get_groups();

	RPKI_DEBUG("Polling period: %d", polling_period);
	ret = rtr_mgr_init(&rtr_config, groups, groups_len, polling_period,
			   expire_interval, retry_interval,
			   rpki_update_cb_sync_rtr, NULL, NULL, NULL);
	if (ret == RTR_ERROR) {
		RPKI_DEBUG("Init rtr_mgr failed.");
		return ERROR;
	}

	RPKI_DEBUG("Starting rtr_mgr.");
	ret = rtr_mgr_start(rtr_config);
	if (ret == RTR_ERROR) {
		RPKI_DEBUG("Starting rtr_mgr failed.");
		rtr_mgr_free(rtr_config);
		return ERROR;
	}
	rtr_is_running = 1;

	XFREE(MTYPE_BGP_RPKI_CACHE_GROUP, groups);

	return SUCCESS;
}

static void stop(void)
{
	rtr_is_stopping = 1;
	if (rtr_is_running) {
		rtr_mgr_stop(rtr_config);
		rtr_mgr_free(rtr_config);
		rtr_is_running = 0;
	}
}

static int reset(bool force)
{
	if (rtr_is_running && !force)
		return SUCCESS;

	RPKI_DEBUG("Resetting RPKI Session");
	stop();
	return start();
}

static struct rtr_mgr_group *get_connected_group(void)
{
	if (!cache_list || list_isempty(cache_list))
		return NULL;

	return rtr_mgr_get_first_group(rtr_config);
}

static void print_prefix_table_by_asn(struct vty *vty, as_t as)
{
	unsigned int number_of_ipv4_prefixes = 0;
	unsigned int number_of_ipv6_prefixes = 0;
	struct rtr_mgr_group *group = get_connected_group();
	struct rpki_for_each_record_arg arg;

	arg.vty = vty;
	arg.as = as;

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

static void print_prefix_table(struct vty *vty)
{
	struct rpki_for_each_record_arg arg;

	unsigned int number_of_ipv4_prefixes = 0;
	unsigned int number_of_ipv6_prefixes = 0;
	struct rtr_mgr_group *group = get_connected_group();

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

	if (!is_synchronized())
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
	rtr_mgr_validate(rtr_config, as_number, &ip_addr_prefix,
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
	return 0;
}

static int add_cache(struct cache *cache)
{
	uint8_t preference = cache->preference;
	struct rtr_mgr_group group;

	group.preference = preference;
	group.sockets_len = 1;
	group.sockets = &cache->rtr_socket;

	if (rtr_is_running) {
		init_tr_socket(cache);

		if (rtr_mgr_add_group(rtr_config, &group) != RTR_SUCCESS) {
			free_tr_socket(cache);
			return ERROR;
		}
	}

	listnode_add(cache_list, cache);

	return SUCCESS;
}

static int add_tcp_cache(const char *host, const char *port,
			 const uint8_t preference, const char *bindaddr)
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

	rtr_socket = create_rtr_socket(tr_socket);

	cache->type = TCP;
	cache->tr_socket = tr_socket;
	cache->tr_config.tcp_config = tcp_config;
	cache->rtr_socket = rtr_socket;
	cache->preference = preference;

	int ret = add_cache(cache);
	if (ret != SUCCESS) {
		free_cache(cache);
	}

	return ret;
}

#if defined(FOUND_SSH)
static int add_ssh_cache(const char *host, const unsigned int port,
			 const char *username, const char *client_privkey_path,
			 const char *client_pubkey_path,
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

	ssh_config->username = XSTRDUP(MTYPE_BGP_RPKI_CACHE, username);
	ssh_config->client_privkey_path =
		XSTRDUP(MTYPE_BGP_RPKI_CACHE, client_privkey_path);
	ssh_config->server_hostkey_path =
		XSTRDUP(MTYPE_BGP_RPKI_CACHE, server_pubkey_path);

	rtr_socket = create_rtr_socket(tr_socket);

	cache->type = SSH;
	cache->tr_socket = tr_socket;
	cache->tr_config.ssh_config = ssh_config;
	cache->rtr_socket = rtr_socket;
	cache->preference = preference;

	int ret = add_cache(cache);
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
		if (cache->tr_config.tcp_config->bindaddr)
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
		if (cache->tr_config.ssh_config->bindaddr)
			XFREE(MTYPE_BGP_RPKI_CACHE,
			      cache->tr_config.ssh_config->bindaddr);
		XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_config.ssh_config);
	}
#endif
	XFREE(MTYPE_BGP_RPKI_CACHE, cache->tr_socket);
	XFREE(MTYPE_BGP_RPKI_CACHE, cache->rtr_socket);
	XFREE(MTYPE_BGP_RPKI_CACHE, cache);
}

static int config_write(struct vty *vty)
{
	struct listnode *cache_node;
	struct cache *cache;

	if (!listcount(cache_list))
		return 0;

	if (rpki_debug)
		vty_out(vty, "debug rpki\n");

	vty_out(vty, "!\n");
	vty_out(vty, "rpki\n");
	vty_out(vty, " rpki polling_period %d\n", polling_period);

	if (retry_interval != RETRY_INTERVAL_DEFAULT)
		vty_out(vty, " rpki retry_interval %d\n", retry_interval);
	if (expire_interval != EXPIRE_INTERVAL_DEFAULT)
		vty_out(vty, " rpki expire_interval %d\n", expire_interval);

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		switch (cache->type) {
			struct tr_tcp_config *tcp_config;
#if defined(FOUND_SSH)
			struct tr_ssh_config *ssh_config;
#endif
		case TCP:
			tcp_config = cache->tr_config.tcp_config;
			vty_out(vty, " rpki cache %s %s ", tcp_config->host,
				tcp_config->port);
			if (tcp_config->bindaddr)
				vty_out(vty, "source %s ",
					tcp_config->bindaddr);
			break;
#if defined(FOUND_SSH)
		case SSH:
			ssh_config = cache->tr_config.ssh_config;
			vty_out(vty, " rpki cache %s %u %s %s %s ",
				ssh_config->host, ssh_config->port,
				ssh_config->username,
				ssh_config->client_privkey_path,
				ssh_config->server_hostkey_path != NULL
					? ssh_config->server_hostkey_path
					: " ");
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
	vty_out(vty, "exit\n");

	return 1;
}

DEFUN_NOSH (rpki,
	    rpki_cmd,
	    "rpki",
	    "Enable rpki and enter rpki configuration mode\n")
{
	vty->node = RPKI_NODE;
	return CMD_SUCCESS;
}

DEFUN (bgp_rpki_start,
       bgp_rpki_start_cmd,
       "rpki start",
       RPKI_OUTPUT_STRING
       "start rpki support\n")
{
	if (listcount(cache_list) == 0)
		vty_out(vty,
			"Could not start rpki because no caches are configured\n");

	if (!is_running()) {
		if (start() == ERROR) {
			RPKI_DEBUG("RPKI failed to start");
			return CMD_WARNING;
		}
	}
	return CMD_SUCCESS;
}

DEFUN (bgp_rpki_stop,
       bgp_rpki_stop_cmd,
       "rpki stop",
       RPKI_OUTPUT_STRING
       "start rpki support\n")
{
	if (is_running())
		stop();

	return CMD_SUCCESS;
}

DEFPY (rpki_polling_period,
       rpki_polling_period_cmd,
       "rpki polling_period (1-86400)$pp",
       RPKI_OUTPUT_STRING
       "Set polling period\n"
       "Polling period value\n")
{
	polling_period = pp;
	return CMD_SUCCESS;
}

DEFUN (no_rpki_polling_period,
       no_rpki_polling_period_cmd,
       "no rpki polling_period",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set polling period back to default\n")
{
	polling_period = POLLING_PERIOD_DEFAULT;
	return CMD_SUCCESS;
}

DEFPY (rpki_expire_interval,
       rpki_expire_interval_cmd,
       "rpki expire_interval (600-172800)$tmp",
       RPKI_OUTPUT_STRING
       "Set expire interval\n"
       "Expire interval value\n")
{
	if ((unsigned int)tmp >= polling_period) {
		expire_interval = tmp;
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
	expire_interval = polling_period * 2;
	return CMD_SUCCESS;
}

DEFPY (rpki_retry_interval,
       rpki_retry_interval_cmd,
       "rpki retry_interval (1-7200)$tmp",
       RPKI_OUTPUT_STRING
       "Set retry interval\n"
       "retry interval value\n")
{
	retry_interval = tmp;
	return CMD_SUCCESS;
}

DEFUN (no_rpki_retry_interval,
       no_rpki_retry_interval_cmd,
       "no rpki retry_interval",
       NO_STR
       RPKI_OUTPUT_STRING
       "Set retry interval back to default\n")
{
	retry_interval = RETRY_INTERVAL_DEFAULT;
	return CMD_SUCCESS;
}

DEFPY(rpki_cache, rpki_cache_cmd,
      "rpki cache <A.B.C.D|WORD> <TCPPORT|(1-65535)$sshport SSH_UNAME SSH_PRIVKEY SSH_PUBKEY [SERVER_PUBKEY]> [source <A.B.C.D>$bindaddr] preference (1-255)",
      RPKI_OUTPUT_STRING
      "Install a cache server to current group\n"
      "IP address of cache server\n Hostname of cache server\n"
      "TCP port number\n"
      "SSH port number\n"
      "SSH user name\n"
      "Path to own SSH private key\n"
      "Path to own SSH public key\n"
      "Path to Public key of cache server\n"
      "Configure source IP address of RPKI connection\n"
      "Define a Source IP Address\n"
      "Preference of the cache server\n"
      "Preference value\n")
{
	int return_value;
	struct listnode *cache_node;
	struct cache *current_cache;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, current_cache)) {
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
		return_value = add_ssh_cache(
			cache, sshport, ssh_uname, ssh_privkey, ssh_pubkey,
			server_pubkey, preference, bindaddr_str);
#else
		return_value = SUCCESS;
		vty_out(vty,
			"ssh sockets are not supported. Please recompile rtrlib and frr with ssh support. If you want to use it\n");
#endif
	} else { // use tcp connection
		return_value =
			add_tcp_cache(cache, tcpport, preference, bindaddr_str);
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
	struct cache *cache_p = find_cache(preference);

	if (!cache_p) {
		vty_out(vty, "Could not find cache %ld\n", preference);
		return CMD_WARNING;
	}

	if (rtr_is_running && listcount(cache_list) == 1) {
		stop();
	} else if (rtr_is_running) {
		if (rtr_mgr_remove_group(rtr_config, preference) == RTR_ERROR) {
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
       "show rpki prefix-table",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show validated prefixes which were received from RPKI Cache\n")
{
	struct listnode *cache_node;
	struct cache *cache;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		vty_out(vty, "host: %s port: %s\n",
			cache->tr_config.tcp_config->host,
			cache->tr_config.tcp_config->port);
	}
	if (is_synchronized())
		print_prefix_table(vty);
	else
		vty_out(vty, "No connection to RPKI cache server.\n");

	return CMD_SUCCESS;
}

DEFPY (show_rpki_as_number, show_rpki_as_number_cmd,
      "show rpki as-number (1-4294967295)$by_asn",
      SHOW_STR RPKI_OUTPUT_STRING
      "Lookup by ASN in prefix table\n"
      "AS Number\n")
{
	if (!is_synchronized()) {
		vty_out(vty, "No Connection to RPKI cache server.\n");
		return CMD_WARNING;
	}

	print_prefix_table_by_asn(vty, by_asn);
	return CMD_SUCCESS;
}

DEFPY (show_rpki_prefix,
       show_rpki_prefix_cmd,
       "show rpki prefix <A.B.C.D/M|X:X::X:X/M> [(1-4294967295)$asn]",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Lookup IP prefix and optionally ASN in prefix table\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n"
       "AS Number\n")
{

	if (!is_synchronized()) {
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

	if (pfx_table_validate_r(rtr_config->pfx_table, &matches, &match_count,
				 asn, &addr, prefix->prefixlen, &result)
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
       "show rpki cache-server",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "SHOW configured cache server\n")
{
	struct listnode *cache_node;
	struct cache *cache;

	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		if (cache->type == TCP) {
			vty_out(vty, "host: %s port: %s\n",
				cache->tr_config.tcp_config->host,
				cache->tr_config.tcp_config->port);

#if defined(FOUND_SSH)
		} else if (cache->type == SSH) {
			vty_out(vty,
				"host: %s port: %d username: %s server_hostkey_path: %s client_privkey_path: %s\n",
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
       "show rpki cache-connection",
       SHOW_STR
       RPKI_OUTPUT_STRING
       "Show to which RPKI Cache Servers we have a connection\n")
{
	if (!is_synchronized()) {
		vty_out(vty, "No connection to RPKI cache server.\n");

		return CMD_SUCCESS;
	}

	struct listnode *cache_node;
	struct cache *cache;
	struct rtr_mgr_group *group = get_connected_group();

	if (!group) {
		vty_out(vty, "Cannot find a connected group.\n");
		return CMD_SUCCESS;
	}
	vty_out(vty, "Connected to group %d\n", group->preference);
	for (ALL_LIST_ELEMENTS_RO(cache_list, cache_node, cache)) {
		if (cache->preference == group->preference) {
			struct tr_tcp_config *tcp_config;
#if defined(FOUND_SSH)
			struct tr_ssh_config *ssh_config;
#endif

			switch (cache->type) {
			case TCP:
				tcp_config = cache->tr_config.tcp_config;
				vty_out(vty, "rpki tcp cache %s %s pref %hhu\n",
					tcp_config->host, tcp_config->port,
					cache->preference);
				break;

#if defined(FOUND_SSH)
			case SSH:
				ssh_config = cache->tr_config.ssh_config;
				vty_out(vty, "rpki ssh cache %s %u pref %hhu\n",
					ssh_config->host, ssh_config->port,
					cache->preference);
				break;
#endif

			default:
				break;
			}
		}
	}

	return CMD_SUCCESS;
}

static int config_on_exit(struct vty *vty)
{
	reset(false);
	return 1;
}

DEFUN (rpki_reset,
       rpki_reset_cmd,
       "rpki reset",
       RPKI_OUTPUT_STRING
       "reset rpki\n")
{
	return reset(true) == SUCCESS ? CMD_SUCCESS : CMD_WARNING;
}

DEFUN (debug_rpki,
       debug_rpki_cmd,
       "debug rpki",
       DEBUG_STR
       "Enable debugging for rpki\n")
{
	rpki_debug = 1;
	return CMD_SUCCESS;
}

DEFUN (no_debug_rpki,
       no_debug_rpki_cmd,
       "no debug rpki",
       NO_STR
       DEBUG_STR
       "Disable debugging for rpki\n")
{
	rpki_debug = 0;
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

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void install_cli_commands(void)
{
	// TODO: make config write work
	install_node(&rpki_node);
	install_default(RPKI_NODE);
	install_element(CONFIG_NODE, &rpki_cmd);
	install_element(ENABLE_NODE, &rpki_cmd);

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

	/* Install rpki cache commands */
	install_element(RPKI_NODE, &rpki_cache_cmd);
	install_element(RPKI_NODE, &no_rpki_cache_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_rpki_prefix_table_cmd);
	install_element(VIEW_NODE, &show_rpki_cache_connection_cmd);
	install_element(VIEW_NODE, &show_rpki_cache_server_cmd);
	install_element(VIEW_NODE, &show_rpki_prefix_cmd);
	install_element(VIEW_NODE, &show_rpki_as_number_cmd);

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
