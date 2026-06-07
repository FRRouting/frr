// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Client Connection Adapter
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023-2025, LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include <libyang/plugins_types.h>

#include "darr.h"
#include "frrevent.h"
#include "frrstr.h"
#include "sockopt.h"
#include "network.h"
#include "libfrr.h"
#include "yang.h"
#include "mgmt_msg.h"
#include "mgmt_msg_native.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmt_be_client.h"
#include "mgmtd/mgmt_be_adapter.h"

#define _dbg_nf(fmt, ...)   DEBUGD(&mgmt_debug_be, "BE-ADAPTER: " fmt, ##__VA_ARGS__)
#define _dbg(fmt, ...)	    DEBUGD(&mgmt_debug_be, "BE-ADAPTER: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_warn(fmt, ...) zlog_warn("BE-ADAPTER: %s: WARNING: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...)  zlog_err("BE-ADAPTER: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)

/* ----- */
/* Types */
/* ----- */

/*
 * Mapping of YANG XPath prefixes to their corresponding backend clients.
 */
struct mgmt_be_xpath_map {
	char *xpath_prefix;
	uint64_t clients;
};

/* ---------- */
/* Prototypes */
/* ---------- */

/* Forward declarations */
static void be_adapter_sched_init_event(struct mgmt_be_client_adapter *adapter);

static void be_adapter_delete(struct mgmt_be_client_adapter *adapter);

/* --------- */
/* Constants */
/* --------- */

/*
 * Client IDs
 */

/* ---------------- */
/* Global Variables */
/* ---------------- */

/*
 * We would like to have a better ADT than one with O(n) comparisons
 *
 * Perhaps it's possible to sort this array in a way that allows binary search
 * to find the start, then walk until no possible match can follow? Intuition
 * says this probably involves exact match/no-match on a stem in the map array
 * or something like that.
 */

static struct mgmt_be_xpath_map *be_cfg_xpath_map;
static struct mgmt_be_xpath_map *be_oper_xpath_map;
static struct mgmt_be_xpath_map *be_notif_xpath_map;
static struct mgmt_be_xpath_map *be_rpc_xpath_map;

static struct event_loop *mgmt_loop;
static struct msg_server mgmt_be_server = {.fd = -1};

LIST_HEAD(be_adapter_list_head, mgmt_be_client_adapter) be_adapters;

typedef uint mgmt_be_client_id_t;
static char **mgmt_be_client_names;
struct mgmt_be_client_adapter **mgmt_be_adapters_by_id;

/*
 * Mgmtd has it's own special "interested-in" xpath maps since it's not actually
 * a backend client of itself; it's own tree is modified directly when
 * processing changes from the front end clients
 */
static const char *const mgmtd_config_xpaths[] = {
	"/frr-logging:logging",
};


/* ---------------- */
/* Lookup Functions */
/* ---------------- */

static struct mgmt_be_client_adapter *mgmt_be_find_adapter_by_fd(int conn_fd)
{
	struct mgmt_be_client_adapter *adapter;

	LIST_FOREACH (adapter, &be_adapters, link)
		if (adapter->conn->fd == conn_fd)
			return adapter;
	return NULL;
}

struct mgmt_be_client_adapter *mgmt_be_get_adapter_by_id(mgmt_be_client_id_t id)
{
	if (id < darr_len(mgmt_be_adapters_by_id))
		return mgmt_be_adapters_by_id[id];
	return NULL;
}

printfrr_ext_autoreg_p("MBI", printfrr_be_id);
static ssize_t printfrr_be_id(struct fbuf *buf, struct printfrr_eargs *ea, const void *ptr)
{
	mgmt_be_client_id_t id = *(mgmt_be_client_id_t *)ptr;

	if (id < darr_len(mgmt_be_client_names))
		return bputs(buf, mgmt_be_client_names[id]);
	return bprintfrr(buf, "unknown-client-id-%d", id);
}

printfrr_ext_autoreg_p("MBM", printfrr_be_mask);
static ssize_t printfrr_be_mask(struct fbuf *buf, struct printfrr_eargs *ea, const void *ptr)
{
	uint64_t bits = *(const uint64_t *)ptr;
	mgmt_be_client_id_t id;
	size_t total_len = 0;
	bool first = true;

	for (id = 0; id < 64; id++) {
		if (IS_IDBIT_UNSET(bits, id))
			continue;
		if (!first)
			total_len += bputch(buf, '|');
		if (id >= darr_len(mgmt_be_client_names))
			total_len += bprintfrr(buf, "unknown-client-id-%d", id);
		else
			total_len += bputs(buf, mgmt_be_client_names[id]);
		first = false;
	}
	return total_len;
}

/* ======================= */
/* XPath Mapping Functions */
/* ======================= */

static const char *mgmt_be_xpath_segment_end(const char *segment)
{
	const char *p;

	for (p = segment; *p && *p != '/'; p++) {
		if (*p == '[') {
			p = frrstr_skip_over_char(p + 1, ']');
			if (!p)
				return NULL;
			p--;
		}
	}

	return p;
}

static size_t mgmt_be_xpath_segment_name_len(const char *segment)
{
	const char *p;

	for (p = segment; *p && *p != '/' && *p != '['; p++)
		;

	return p - segment;
}

static bool mgmt_be_xpath_segment_names_equal(const char *a, size_t a_len, const char *b,
					      size_t b_len)
{
	return a_len == b_len && strncmp(a, b, a_len) == 0;
}

static bool mgmt_be_xpath_segment_module_prefix(const char *prefix, size_t prefix_len,
						const char *segment, size_t segment_len)
{
	return prefix_len < segment_len && segment[prefix_len] == ':' &&
	       strncmp(prefix, segment, prefix_len) == 0;
}

static bool mgmt_be_xpath_append_segment(char *path, size_t path_len, const char *segment,
					 size_t segment_len)
{
	size_t len = strlen(path);

	if (len + segment_len + 2 > path_len)
		return false;

	path[len++] = '/';
	memcpy(path + len, segment, segment_len);
	path[len + segment_len] = '\0';

	return true;
}

static bool mgmt_be_xpath_identity_is_allowed(const struct lysc_type_identityref *type,
					      const struct lysc_ident *ident)
{
	uint64_t i;

	LY_ARRAY_FOR(type->bases, i)
	{
		const struct lysc_ident *base = type->bases[i];

		if (ident == base || lyplg_type_identity_isderived(base, ident) == LY_SUCCESS)
			return true;
	}

	return false;
}

static bool mgmt_be_xpath_name_match(const char *str, const char *name, size_t name_len)
{
	return strlen(str) == name_len && strncmp(str, name, name_len) == 0;
}

static const struct lysc_ident *
mgmt_be_xpath_resolve_identity(const struct lysc_type_identityref *type, const char *value,
			       size_t value_len)
{
	const char *colon = memchr(value, ':', value_len);
	const struct lysc_ident *ident = NULL;
	const char *module = NULL;
	size_t module_len = 0;
	const char *name = value;
	size_t name_len = value_len;
	const struct lys_module *mod;
	uint32_t idx = 0;
	uint64_t i;

	if (colon) {
		module = value;
		module_len = colon - value;
		name = colon + 1;
		name_len = value + value_len - name;
	}

	while ((mod = ly_ctx_get_module_iter(ly_native_ctx, &idx))) {
		if (module && !mgmt_be_xpath_name_match(mod->name, module, module_len) &&
		    !mgmt_be_xpath_name_match(mod->prefix, module, module_len))
			continue;

		LY_ARRAY_FOR(mod->identities, i)
		{
			const struct lysc_ident *candidate = &mod->identities[i];

			if (!mgmt_be_xpath_name_match(candidate->name, name, name_len) ||
			    !mgmt_be_xpath_identity_is_allowed(type, candidate))
				continue;

			if (ident && ident != candidate)
				return NULL;
			ident = candidate;
		}
	}

	return ident;
}

static bool mgmt_be_xpath_identityref_values_match(const struct lysc_type *type,
						   const char *map_value, size_t map_value_len,
						   const char *xpath_value, size_t xpath_value_len)
{
	const struct lysc_type_identityref *ident_type = (const struct lysc_type_identityref *)type;
	const struct lysc_ident *map_ident;
	const struct lysc_ident *xpath_ident;

	map_ident = mgmt_be_xpath_resolve_identity(ident_type, map_value, map_value_len);
	xpath_ident = mgmt_be_xpath_resolve_identity(ident_type, xpath_value, xpath_value_len);
	if (!map_ident || !xpath_ident)
		return false;

	return map_ident == xpath_ident;
}

static const struct lysc_node *mgmt_be_xpath_key_snode(const struct lysc_node *list_snode,
						       const char *key, size_t key_len)
{
	const struct lysc_node *child;
	const char *key_name = key;
	size_t key_name_len = key_len;
	const char *colon;

	if (!list_snode || list_snode->nodetype != LYS_LIST)
		return NULL;

	colon = memchr(key, ':', key_len);
	if (colon) {
		key_name = colon + 1;
		key_name_len = key + key_len - key_name;
	}

	LY_LIST_FOR (lysc_node_child(list_snode), child) {
		if (!lysc_is_key(child))
			continue;

		if (strlen(child->name) == key_name_len &&
		    strncmp(child->name, key_name, key_name_len) == 0)
			return child;
	}

	return NULL;
}

static bool mgmt_be_xpath_values_match(const struct lysc_node *key_snode, const char *map_value,
				       size_t map_value_len, const char *xpath_value,
				       size_t xpath_value_len)
{
	const struct lysc_type *type;
	const char *map_canon = NULL;
	const char *xpath_canon = NULL;
	LY_ERR map_err, xpath_err;
	bool match;

	if (!key_snode)
		return map_value_len == xpath_value_len &&
		       strncmp(map_value, xpath_value, map_value_len) == 0;

	type = yang_snode_get_type(key_snode);
	if (!type)
		return false;

	if (type->basetype == LY_TYPE_IDENT)
		return mgmt_be_xpath_identityref_values_match(type, map_value, map_value_len,
							      xpath_value, xpath_value_len);

	map_err = lyd_value_validate(NULL, key_snode, map_value, map_value_len, NULL, NULL,
				     &map_canon);
	xpath_err = lyd_value_validate(NULL, key_snode, xpath_value, xpath_value_len, NULL, NULL,
				       &xpath_canon);
	if (map_err || xpath_err || !map_canon || !xpath_canon) {
		match = false;
		goto out;
	}

	match = strcmp(map_canon, xpath_canon) == 0;

out:
	lydict_remove(ly_native_ctx, map_canon);
	lydict_remove(ly_native_ctx, xpath_canon);
	return match;
}

static bool mgmt_be_xpath_predicate_parse(const char *predicate, const char *segment_end,
					  const char **key, size_t *key_len, const char **value,
					  size_t *value_len, const char **next)
{
	const char *key_start;
	const char *key_end;
	const char *predicate_end;
	const char *close;
	const char *equals;
	const char *value_start;
	const char *value_end;

	predicate_end = frrstr_skip_over_char(predicate + 1, ']');
	if (!predicate_end || predicate_end > segment_end)
		return false;

	close = predicate_end - 1;
	equals = memchr(predicate + 1, '=', close - predicate - 1);
	if (!equals)
		return false;

	key_start = predicate + 1;
	while (key_start < equals && isspace((unsigned char)*key_start))
		key_start++;
	key_end = equals;
	while (key_end > key_start && isspace((unsigned char)key_end[-1]))
		key_end--;
	if (key_start == key_end)
		return false;

	*key = key_start;
	*key_len = key_end - key_start;

	value_start = equals + 1;
	while (value_start < close && isspace((unsigned char)*value_start))
		value_start++;
	value_end = close;
	while (value_end > value_start && isspace((unsigned char)value_end[-1]))
		value_end--;
	if (value_start == value_end)
		return false;

	if (value_start < value_end && (*value_start == '\'' || *value_start == '"')) {
		char quote = *value_start;

		value_start++;
		value_end = memchr(value_start, quote, close - value_start);
		if (!value_end)
			return false;
		if (value_end + 1 != close) {
			const char *p = value_end + 1;

			while (p < close && isspace((unsigned char)*p))
				p++;
			if (p != close)
				return false;
		}
	} else if (memchr(value_start, '\'', value_end - value_start) ||
		   memchr(value_start, '"', value_end - value_start)) {
		return false;
	}

	*value = value_start;
	*value_len = value_end - value_start;
	*next = predicate_end;

	return true;
}

static bool mgmt_be_xpath_find_predicate(const char *segment, const char *segment_end,
					 const char *key, size_t key_len, const char **value,
					 size_t *value_len, bool *found)
{
	const char *p = segment + mgmt_be_xpath_segment_name_len(segment);

	*found = false;
	while (p < segment_end) {
		const char *predicate_key;
		const char *predicate_value;
		const char *next;
		size_t predicate_key_len;
		size_t predicate_value_len;

		while (p < segment_end && *p != '[')
			p++;
		if (p >= segment_end)
			return true;

		if (!mgmt_be_xpath_predicate_parse(p, segment_end, &predicate_key,
						   &predicate_key_len, &predicate_value,
						   &predicate_value_len, &next))
			return false;

		if (predicate_key_len == key_len && strncmp(predicate_key, key, key_len) == 0) {
			*value = predicate_value;
			*value_len = predicate_value_len;
			*found = true;
			return true;
		}

		p = next;
	}

	return true;
}

static bool mgmt_be_xpath_segment_predicates_compatible(const char *map_segment,
							const char *map_end,
							const char *xpath_segment,
							const char *xpath_end,
							const struct lysc_node *snode)
{
	const char *p = map_segment + mgmt_be_xpath_segment_name_len(map_segment);

	while (p < map_end) {
		const char *map_key;
		const char *map_value;
		const char *xpath_value;
		const char *next;
		size_t map_key_len;
		size_t map_value_len;
		size_t xpath_value_len;
		bool found;

		while (p < map_end && *p != '[')
			p++;
		if (p >= map_end)
			return true;

		if (!mgmt_be_xpath_predicate_parse(p, map_end, &map_key, &map_key_len, &map_value,
						   &map_value_len, &next))
			return false;

		if (!mgmt_be_xpath_find_predicate(xpath_segment, xpath_end, map_key, map_key_len,
						  &xpath_value, &xpath_value_len, &found))
			return false;

		if (found && !mgmt_be_xpath_values_match(mgmt_be_xpath_key_snode(snode, map_key,
										 map_key_len),
							 map_value, map_value_len, xpath_value,
							 xpath_value_len))
			return false;

		p = next;
	}

	return true;
}

/*
 * Check if either map_path or xpath is a prefix of the other along path
 * boundaries. The same segment walk handles both predicate-free and predicated
 * registrations.
 *
 * Predicated registrations are used when multiple backends own entries under a
 * shared YANG list, such as OSPFv2 and OSPFv3 under RFC 9129's
 * ietf-routing control-plane-protocol list. In that case predicates constrain
 * backend ownership only when the query also specifies the same predicate key,
 * using the key schema when possible so identityrefs and other YANG values are
 * compared by type rather than by raw bytes. A conflicting value rejects the
 * backend, but a missing query predicate is a wildcard: unkeyed list and parent
 * queries still dispatch to every matching backend so the frontend can merge
 * their entries.
 *
 * For configuration changes, mgmtd also has the changed data node available.
 * The prefix walk is then only a structural pre-filter and a libyang lookup
 * against the candidate tree refines predicated registrations. Operational,
 * notification and RPC dispatch remain tree-free because those paths do not
 * have candidate data at backend-selection time.
 */
static bool mgmt_be_xpath_prefix(const char *map_path, const char *xpath, bool check_predicates)
{
	const char *map = map_path;
	const char *path = xpath;
	char schema_path[XPATH_MAXLEN] = "";

	if (strnlen(map_path, XPATH_MAXLEN) == XPATH_MAXLEN ||
	    strnlen(xpath, XPATH_MAXLEN) == XPATH_MAXLEN) {
		_log_warn("xpath too long for backend dispatch: %s", xpath);
		return false;
	}

	while (*map == '/')
		map++;
	while (*path == '/')
		path++;

	while (*map && *path) {
		const char *map_end;
		const char *path_end;
		size_t map_name_len;
		size_t path_name_len;
		const struct lysc_node *snode = NULL;
		bool map_module_prefix;
		bool path_module_prefix;

		map_end = mgmt_be_xpath_segment_end(map);
		path_end = mgmt_be_xpath_segment_end(path);
		if (!map_end || !path_end)
			return false;

		map_name_len = mgmt_be_xpath_segment_name_len(map);
		path_name_len = mgmt_be_xpath_segment_name_len(path);
		if (!mgmt_be_xpath_segment_names_equal(map, map_name_len, path, path_name_len)) {
			map_module_prefix = mgmt_be_xpath_segment_module_prefix(map, map_name_len,
										path,
										path_name_len);
			path_module_prefix =
				mgmt_be_xpath_segment_module_prefix(path, path_name_len, map,
								    map_name_len);

			if (map_module_prefix)
				return *map_end == '\0';
			if (path_module_prefix)
				return *path_end == '\0';

			return false;
		}

		if (!mgmt_be_xpath_append_segment(schema_path, sizeof(schema_path), map,
						  map_name_len))
			return false;
		if (check_predicates &&
		    memchr(map + map_name_len, '[', map_end - map_name_len - map))
			snode = lys_find_path(ly_native_ctx, NULL, schema_path, 0);

		if (check_predicates &&
		    !mgmt_be_xpath_segment_predicates_compatible(map, map_end, path, path_end,
								 snode))
			return false;

		map = *map_end == '/' ? map_end + 1 : map_end;
		path = *path_end == '/' ? path_end + 1 : path_end;
	}

	return true;
}

static const struct lyd_node *mgmt_be_xpath_root_dnode(const struct lyd_node *dnode)
{
	while (lyd_parent(dnode))
		dnode = lyd_parent(dnode);

	return lyd_first_sibling(dnode);
}

static bool mgmt_be_xpath_dnode_contains(const struct lyd_node *ancestor,
					 const struct lyd_node *dnode)
{
	for (; dnode; dnode = lyd_parent(dnode))
		if (dnode == ancestor)
			return true;

	return false;
}

static bool mgmt_be_xpath_dnodes_overlap(const struct lyd_node *a, const struct lyd_node *b)
{
	return mgmt_be_xpath_dnode_contains(a, b) || mgmt_be_xpath_dnode_contains(b, a);
}

static LY_ERR mgmt_be_lyd_find_xpath3(const struct lyd_node *tree, const char *xpath,
				      struct ly_set **set)
{
#if (LY_VERSION_MAJOR < 3)
	return lyd_find_xpath3(NULL, tree, xpath, NULL, set);
#else
	return lyd_find_xpath3(NULL, tree, xpath, LY_VALUE_JSON, NULL, NULL, set);
#endif
}

static bool mgmt_be_xpath_cfg_dnode_matches(const char *map_path, const struct lyd_node *dnode)
{
	const struct lyd_node *root;
	struct ly_set *set = NULL;
	LY_ERR err;
	uint32_t i;
	bool match = false;

	if (!dnode || !strchr(map_path, '['))
		return true;

	root = mgmt_be_xpath_root_dnode(dnode);
	err = mgmt_be_lyd_find_xpath3(root, map_path, &set);
	if (err) {
		_log_warn("failed to evaluate backend xpath '%s': %s", map_path, ly_last_errmsg());
		ly_set_free(set, NULL);
		return true;
	}
	if (!set)
		return false;

	for (i = 0; i < set->count; i++) {
		if (set->dnodes[i] && mgmt_be_xpath_dnodes_overlap(set->dnodes[i], dnode)) {
			match = true;
			break;
		}
	}

	ly_set_free(set, NULL);
	return match;
}

/*
 * Get the mask of clients interested in an xpath.
 */
uint64_t mgmt_be_interested_clients(const char *xpath, enum mgmt_be_xpath_subscr_type type,
				    const char *dbg_user, const struct lyd_node *dnode)
{
	struct mgmt_be_xpath_map *maps = NULL, *map;
	uint64_t clients = 0;
	bool wild_root;

	switch (type) {
	case MGMT_BE_XPATH_SUBSCR_TYPE_CFG:
		maps = be_cfg_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_OPER:
		maps = be_oper_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF:
		maps = be_notif_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_RPC:
		maps = be_rpc_xpath_map;
		break;
	}

	/* wild_root will select all clients that advertise op-state */
	wild_root = !strcmp(xpath, "/") || !strcmp(xpath, "/*");
	darr_foreach_p (maps, map) {
		bool refine_cfg = type == MGMT_BE_XPATH_SUBSCR_TYPE_CFG && dnode;

		if (!wild_root && !mgmt_be_xpath_prefix(map->xpath_prefix, xpath, !refine_cfg))
			continue;
		if (!wild_root && refine_cfg &&
		    !mgmt_be_xpath_cfg_dnode_matches(map->xpath_prefix, dnode))
			continue;

		_dbg_nf("%s: xpath: '%s' matched map-prefix: '%s' clients: %pMBM", dbg_user, xpath,
			map->xpath_prefix, &map->clients);
		clients |= map->clients;
	}

	if (clients)
		_dbg_nf("%s: xpath: '%s' registered clients: %pMBM", dbg_user, xpath, &clients);
	else
		_dbg_nf("%s: no registered clients for xpath: '%s'", dbg_user, xpath);

	return clients;
}

/*
 * Test for interest by mgmtd in xpath.
 *
 * Mgmtd handles it's own config directly vs as a backend client of
 * itself. This function supports that.
 */
bool mgmt_is_mgmtd_interested(const char *xpath)
{
	const char *const *match = mgmtd_config_xpaths;
	const char *const *ematch = match + array_size(mgmtd_config_xpaths);

	for (; match < ematch; match++) {
		if (mgmt_be_xpath_prefix(*match, xpath, true)) {
			_dbg("mgmtd: subscribed to %s", xpath);
			return true;
		}
	}
	return false;
}


/*
 * This function is inefficient. For each xpath it walks the global map list.
 * We should keep a separate per-client map and use that here.
 *
 * NOTE: Fix this when removing the global constant maps used for bootstrapping.
 */
static bool be_client_wants_cfg(const char *xpath, mgmt_be_client_id_t id)
{
	struct mgmt_be_xpath_map *map;

	darr_foreach_p (be_cfg_xpath_map, map) {
		if (IS_IDBIT_SET(map->clients, id) &&
		    mgmt_be_xpath_prefix(map->xpath_prefix, xpath, true)) {
			_dbg_nf("init-config: %pMBI: WANTS: %s", &id, xpath);
			return true;
		}
	}
	_dbg_nf("init-config: %pMBI: unwanted: %s", &id, xpath);
	return false;
}

/*
 * Get full config changes for adapter.
 *
 * Walk the entire running config building a set of create-changes to send to
 * the adapter and return a set of config changes.
 */
struct nb_config_cbs mgmt_be_adapter_get_config(struct mgmt_be_client_adapter *adapter)
{
	struct nb_config_cbs changes = { 0 };
	const struct lyd_node *root, *dnode;
	uint32_t seq = 0;
	char *xpath;

	_dbg("Getting initial config for backend client: %s", adapter->name);

	LY_LIST_FOR (running_config->dnode, root) {
		LYD_TREE_DFS_BEGIN (root, dnode) {
			if (lysc_is_key(dnode->schema))
				goto walk_cont;

			xpath = lyd_path(dnode, LYD_PATH_STD, NULL, 0);
			if (be_client_wants_cfg(xpath, adapter->id))
				nb_config_diff_add_change(&changes, NB_CB_CREATE, &seq, dnode);
			else
				LYD_TREE_DFS_continue = 1; /* skip any subtree */
			free(xpath);
walk_cont:
			LYD_TREE_DFS_END(root, dnode);
		}
	}
	return changes;
}

static void be_adapter_register_client_xpath(mgmt_be_client_id_t id, const char *xpath,
					     enum mgmt_be_xpath_subscr_type type)
{
	struct mgmt_be_xpath_map **maps, *map;
	const char *interest = "interest in";
	const char *typ;

	maps = NULL;

	switch (type) {
	case MGMT_BE_XPATH_SUBSCR_TYPE_CFG:
		typ = "CONFIG";
		maps = &be_cfg_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_OPER:
		interest = "to provide";
		typ = "OPER-STATE";
		maps = &be_oper_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF:
		typ = "NOTIFICATION";
		maps = &be_notif_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_RPC:
		typ = "RPC";
		maps = &be_rpc_xpath_map;
		break;
	}

	darr_foreach_p (*maps, map) {
		if (!strcmp(xpath, map->xpath_prefix)) {
			_dbg("%pMBI registers %s %s xpath: '%s' joining: %pMBM", &id, interest,
			     typ, xpath, &map->clients);
			SET_IDBIT(map->clients, id);
			return;
		}
	}
	/* we didn't find a matching entry */
	map = darr_append(*maps);
	map->xpath_prefix = darr_strdup(xpath);
	map->clients = (1ul << id);
	_dbg("%pMBI registers %s %s xpath: '%s'", &id, interest, typ, xpath);
}

static void be_adapter_xpath_maps_init(void)
{
	be_adapter_register_client_xpath(MGMTD_BE_CLIENT_ID_MGMTD, "/frr-backend:clients",
					 MGMT_BE_XPATH_SUBSCR_TYPE_OPER);
	be_adapter_register_client_xpath(MGMTD_BE_CLIENT_ID_MGMTD, "/frr-logging",
					 MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
}

/*
 * Cleanup the xpath maps.
 */
static void be_adapter_xpath_maps_cleanup(void)
{
	struct mgmt_be_xpath_map *map;

	darr_foreach_p (be_cfg_xpath_map, map)
		darr_free(map->xpath_prefix);
	darr_free(be_cfg_xpath_map);

	darr_foreach_p (be_oper_xpath_map, map)
		darr_free(map->xpath_prefix);
	darr_free(be_oper_xpath_map);

	darr_foreach_p (be_notif_xpath_map, map)
		darr_free(map->xpath_prefix);
	darr_free(be_notif_xpath_map);

	darr_foreach_p (be_rpc_xpath_map, map)
		darr_free(map->xpath_prefix);
	darr_free(be_rpc_xpath_map);
}


/* ============================== */
/* Backend Message (API) Handling */
/* ============================== */

/*
 * The TXN module is the primary producer/consumer of messages to/from backend
 * clients so that is where you will find most of the backend message handling
 * functions.
 */

int mgmt_be_adapter_send(struct mgmt_be_client_adapter *adapter, void *_msg)
{
	struct mgmt_msg_header *msg = (struct mgmt_msg_header *)_msg;
	uint64_t txn_id = msg->refer_id;
	int ret;

	_dbg("Sending %s to '%s' txn-id: %Lu", mgmt_msg_code_name(msg->code), adapter->name,
	     txn_id);

	ret = mgmt_msg_native_send_msg(adapter->conn, msg, false);
	if (ret)
		_log_err("Failed sending %s to '%s' txn-id: %Lu", mgmt_msg_code_name(msg->code),
			 adapter->name, txn_id);
	return ret;
}

struct msg_conn *mgmt_be_get_notify_conn(uint client_id, LYD_FORMAT *format)
{
	struct mgmt_be_client_adapter *adapter = mgmt_be_get_adapter_by_id(client_id);

	*format = LYD_JSON;
	if (!adapter)
		return NULL;
	return adapter->conn;
}

static void be_adapter_handle_subscribe(struct mgmt_msg_subscribe *msg, size_t msg_len,
					struct mgmt_be_client_adapter *adapter)
{
	mgmt_be_client_id_t id;
	struct mgmt_be_client_adapter *old;
	const char **s = NULL;
	const char *new_name;
	uint i = 0;

	_dbg("SUBSCRIBE '%s' to register xpaths config: %u oper: %u notif: %u rpc: %u",
	     adapter->name, msg->nconfig, msg->noper, msg->nnotify, msg->nrpc);

	s = mgmt_msg_native_strings_decode(msg, msg_len, msg->strings);
	if (!s) {
		_log_err("Corrupt subscribe msg from '%s'", adapter->name);
		msg_conn_disconnect(adapter->conn, false);
		return;
	}
	if (darr_len(s) != (1u + msg->nconfig + msg->noper + msg->nnotify + msg->nrpc)) {
		_log_err("Corrupt subscribe msg from '%s': len == %u", adapter->name, darr_len(s));
		msg_conn_disconnect(adapter->conn, false);
		goto done;
	}

	new_name = s[i++];
	_dbg("\"%s\" now known as \"%s\"", adapter->name, new_name);
	darr_in_strdup(adapter->name, new_name);

	/* Get or allocate the ID based on the name */
	for (id = 0; id < darr_len(mgmt_be_client_names); id++)
		if (!strcmp(mgmt_be_client_names[id], adapter->name))
			break;
	/* Only allow new ID if we have space in uin64_t bitmask i.e., 64 */
	if (id >= MGMTD_BE_CLIENT_ID_MAX) {
		_log_err("No available client IDs for '%s', disconnecting.", adapter->name);
		be_adapter_delete(adapter);
		goto done;
	}
	/* Allocate new ID */
	if (id == darr_len(mgmt_be_client_names))
		*darr_append(mgmt_be_client_names) = darr_strdup(adapter->name);

	adapter->id = id;
	if (id >= darr_len(mgmt_be_adapters_by_id))
		darr_ensure_i(mgmt_be_adapters_by_id, id);
	else if (mgmt_be_adapters_by_id[id]) {
		old = mgmt_be_adapters_by_id[id];
		_dbg("client: %s using fd: %d reconnected with fd: %d", old->name, old->conn->fd,
		     adapter->conn->fd);
		be_adapter_delete(old);
	}
	mgmt_be_adapters_by_id[adapter->id] = adapter;

	_dbg("\"%s\" backend has client id: %u", adapter->name, id);

	/* schedule INIT sequence now that it is registered */
	be_adapter_sched_init_event(adapter);

	for (uint j = 0; j < msg->nconfig; j++)
		be_adapter_register_client_xpath(adapter->id, s[i++],
						 MGMT_BE_XPATH_SUBSCR_TYPE_CFG);

	for (uint j = 0; j < msg->noper; j++)
		be_adapter_register_client_xpath(adapter->id, s[i++],
						 MGMT_BE_XPATH_SUBSCR_TYPE_OPER);

	darr_ensure_avail(adapter->notify_xpaths, msg->nnotify);
	for (uint j = 0; j < msg->nnotify; i++, j++)
		*darr_append(adapter->notify_xpaths) = darr_strdup(s[i]);

	for (uint j = 0; j < msg->nrpc; j++)
		be_adapter_register_client_xpath(adapter->id, s[i++],
						 MGMT_BE_XPATH_SUBSCR_TYPE_RPC);

	/* Now add our notify-select strings to the global ADT */
	if (darr_len(adapter->notify_xpaths))
		mgmt_fe_ns_string_add_be_client(id, (const char **)adapter->notify_xpaths);

	/*
	 * Need to update the backend with its notify selectors, it can then
	 * resend it's operational state to keep everyone interested up-to-date.
	 */
	mgmt_txn_send_notify_selectors(0, 0, IDBIT_MASK(id), true, NULL);

	zlog_notice("Backend daemon: %s registers with mgmtd (client-id: %u)", adapter->name,
		    adapter->id);
done:
	darr_free_free(s);
}


static void be_adapter_process_msg(uint8_t version, uint8_t *data, size_t msg_len,
				   struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;
	struct mgmt_msg_header *msg = (typeof(msg))data;
	struct mgmt_msg_error *error_msg;

	if (version != MGMT_MSG_VERSION_NATIVE) {
		_log_err("Protobuf not supported for backend messages (adapter: %s)",
			 adapter->name);
		return;
	}
	if (msg_len < sizeof(*msg)) {
		_log_err("native message to adapter %s too short %zu", adapter->name, msg_len);
		return;
	}

	/*
	 * Most messages are sent to the TXN module for processing.
	 *
	 * NOTE: Handling the config messages may lead to disconnect and
	 * deletion of the adapater. So don't do with it after calling the txn
	 * function.
	 */

	_dbg("Got %s from '%s' txn-id %Lu", mgmt_msg_code_name(msg->code), adapter->name,
	     msg->refer_id);

	assert(adapter->id != MGMTD_BE_CLIENT_ID_MAX || msg->code == MGMT_MSG_CODE_SUBSCRIBE);
	if (adapter->id == MGMTD_BE_CLIENT_ID_MAX && msg->code != MGMT_MSG_CODE_SUBSCRIBE) {
		_log_err("backend client '%s' sent message type %s without subscribing first",
			 adapter->name, mgmt_msg_code_name(msg->code));
		msg_conn_disconnect(adapter->conn, false);
		return;
	}

	switch (msg->code) {
	case MGMT_MSG_CODE_SUBSCRIBE:
		be_adapter_handle_subscribe((struct mgmt_msg_subscribe *)msg, msg_len, adapter);
		return;
	case MGMT_MSG_CODE_TXN_REPLY:
		assert(0);
		return;
	case MGMT_MSG_CODE_CFG_REPLY:
		mgmt_txn_handle_cfg_reply(msg->refer_id, adapter);
		return;
	case MGMT_MSG_CODE_CFG_APPLY_REPLY: {
		const char *errmsg = NULL;

		if (msg_len > sizeof(struct mgmt_msg_cfg_apply_reply)) {
			if (!MGMT_MSG_VALIDATE_NUL_TERM((struct mgmt_msg_cfg_apply_reply *)msg,
							msg_len)) {
				_log_err("Corrupt CFG_APPLY_REPLY from adapter %s", adapter->name);
				msg_conn_disconnect(adapter->conn, false);
				return;
			}
			errmsg = (const char *)(msg + 1);
		}
		mgmt_txn_handle_cfg_apply_reply(msg->refer_id, adapter, errmsg);
		return;
	}
	case MGMT_MSG_CODE_ERROR:
		error_msg = (typeof(error_msg))msg;
		mgmt_txn_handle_error_reply(adapter, msg->refer_id, msg->req_id, error_msg->error,
					    error_msg->errstr);
		return;
	case MGMT_MSG_CODE_TREE_DATA:
		mgmt_txn_handle_tree_data_reply(adapter, (struct mgmt_msg_tree_data *)msg, msg_len);
		return;
	case MGMT_MSG_CODE_RPC_REPLY:
		mgmt_txn_handle_rpc_reply(adapter, (struct mgmt_msg_rpc_reply *)msg, msg_len);
		return;
	case MGMT_MSG_CODE_NOTIFY:
		mgmt_fe_adapter_send_notify(adapter->id, (struct mgmt_msg_notify_data *)msg,
					    msg_len);
		return;
	default:
		_log_err("unknown native message txn-id %" PRIu64 " req-id %" PRIu64
			 " code %u from BE client for adapter %s",
			 msg->refer_id, msg->req_id, msg->code, adapter->name);
		return;
	}
}

/* =================== */
/* Backend VTY support */
/* =================== */

void mgmt_be_adapter_status_write(struct vty *vty)
{
	struct mgmt_be_client_adapter *adapter;
	uint count = 0;

	vty_out(vty, "MGMTD Backend Adapters\n");

	LIST_FOREACH (adapter, &be_adapters, link) {
		vty_out(vty, "  Client: \t\t\t%s\n", adapter->name);
		vty_out(vty, "    Conn-FD: \t\t\t%d\n", adapter->conn->fd);
		vty_out(vty, "    Client-Id: \t\t\t%d\n", adapter->id);
		vty_out(vty, "    Msg-Recvd: \t\t\t%Lu\n", adapter->conn->mstate.nrxm);
		vty_out(vty, "    Bytes-Recvd: \t\t%Lu\n", adapter->conn->mstate.nrxb);
		vty_out(vty, "    Msg-Sent: \t\t\t%Lu\n", adapter->conn->mstate.ntxm);
		vty_out(vty, "    Bytes-Sent: \t\t%Lu\n", adapter->conn->mstate.ntxb);
		count++;
	}
	vty_out(vty, "  Total: %u\n", count);
}

static void _show_xpath_map(struct vty *vty, const char *tag, const char *xpath, uint64_t clients)
{
	mgmt_be_client_id_t id;

	FOREACH_BE_CLIENT_BITS (id, clients) {
		if (!mgmt_be_get_adapter_by_id(id))
			UNSET_IDBIT(clients, id);
	}
	vty_out(vty, "%s: %s: %pMBM\n", tag, xpath, &clients);
}

void mgmt_be_xpath_register_write(struct vty *vty, const char *type_str)
{
	struct mgmt_be_xpath_map *map;

	if (!type_str || type_str[0] == 'c')
		darr_foreach_p (be_cfg_xpath_map, map)
			_show_xpath_map(vty, "config", map->xpath_prefix, map->clients);

	if (!type_str || type_str[0] == 'o')
		darr_foreach_p (be_oper_xpath_map, map)
			_show_xpath_map(vty, "oper", map->xpath_prefix, map->clients);

	if (!type_str || type_str[0] == 'n')
		mgmt_fe_show_be_notify_selectors(vty);

	if (!type_str || type_str[0] == 'r')
		darr_foreach_p (be_rpc_xpath_map, map)
			_show_xpath_map(vty, "rpc", map->xpath_prefix, map->clients);
}

/*
 * Should replace this with proper YANG module
 */
void mgmt_be_adapter_show_xpath_registries(struct vty *vty, const char *xpath)
{
	mgmt_be_client_id_t id;
	struct mgmt_be_client_adapter *adapter;
	uint64_t cclients, nclients, oclients, rclients, combined;

	cclients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_CFG, "SHOW", NULL);
	oclients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_OPER, "SHOW", NULL);
	nclients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF, "SHOW", NULL);
	rclients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_RPC, "SHOW", NULL);
	combined = cclients | nclients | oclients | rclients;

	vty_out(vty, "XPath: '%s'\n", xpath);
	FOREACH_BE_CLIENT_BITS (id, combined) {
		vty_out(vty, "  -- Client: %pMBI\tconfig:%d notify:%d oper:%d rpc:%d\n", &id,
			IS_IDBIT_SET(cclients, id), IS_IDBIT_SET(nclients, id),
			IS_IDBIT_SET(oclients, id), IS_IDBIT_SET(rclients, id));
		adapter = mgmt_be_get_adapter_by_id(id);
		if (adapter)
			vty_out(vty, "    -- Adapter: %p\n", adapter);
	}
}

/* ========================== */
/* Backend Adapter Management */
/* ========================== */

void mgmt_be_adapter_toggle_client_debug(bool set)
{
	struct mgmt_be_client_adapter *adapter;

	LIST_FOREACH (adapter, &be_adapters, link)
		adapter->conn->debug = set;
}

/*
 * Delete a BE client adapter
 */
static void be_adapter_delete(struct mgmt_be_client_adapter *adapter)
{
	_dbg("deleting client adapter '%s'", adapter->name);

	if (adapter->id < darr_len(mgmt_be_adapters_by_id)) {
		mgmt_fe_ns_string_remove_be_client(adapter->id);
		mgmt_txn_handle_be_adapter_connect(adapter, false);
		mgmt_be_adapters_by_id[adapter->id] = NULL;
	}
	darr_free_free(adapter->notify_xpaths);
	LIST_REMOVE(adapter, link);
	event_cancel(&adapter->conn_init_ev);
	msg_server_conn_delete(adapter->conn);
	darr_free(adapter->name);
	XFREE(MTYPE_MGMTD_BE_ADPATER, adapter);
}

static int mgmt_be_adapter_notify_disconnect(struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;

	_dbg("notify disconnect for client adapter '%s'", adapter->name);

	be_adapter_delete(adapter);

	return 0;
}

/*
 * Initialize a BE client over a new connection
 */
static void be_adapter_conn_init(struct event *event)
{
	struct mgmt_be_client_adapter *adapter;
	mgmt_be_client_id_t id;

	adapter = (struct mgmt_be_client_adapter *)EVENT_ARG(event);
	assert(adapter && adapter->conn->fd >= 0);
	id = adapter->id;

	/*
	 * Notify TXN module to create a CONFIG transaction and
	 * download the CONFIGs identified for this new client.
	 * If the TXN module fails to initiate the CONFIG transaction
	 * retry a bit later. It only fails if there's an existing config
	 * transaction in progress.
	 */
	if (mgmt_txn_handle_be_adapter_connect(adapter, true) != 0) {
		/* Deal with a disconnect happening */
		if (id >= darr_len(mgmt_be_adapters_by_id) || !mgmt_be_adapters_by_id[id])
			return;
		_log_warn("Couldn't send initial config to adapter: %s will retry", adapter->name);
		be_adapter_sched_init_event(adapter);
	}
}

/*
 * Schedule the initialization of the BE client connection.
 */
static void be_adapter_sched_init_event(struct mgmt_be_client_adapter *adapter)
{
	event_add_timer_msec(mgmt_loop, be_adapter_conn_init, adapter,
			     MGMTD_BE_CONN_INIT_DELAY_MSEC, &adapter->conn_init_ev);
}

/*
 * The server accepted a new connection
 */
static struct msg_conn *be_adapter_create(int conn_fd, union sockunion *from)
{
	struct mgmt_be_client_adapter *adapter = NULL;

	assert(!mgmt_be_find_adapter_by_fd(conn_fd));

	adapter = XCALLOC(MTYPE_MGMTD_BE_ADPATER, sizeof(struct mgmt_be_client_adapter));
	adapter->id = MGMTD_BE_CLIENT_ID_MAX;
	adapter->name = darr_sprintf("init-client-fd-%d", conn_fd);

	LIST_INSERT_HEAD(&be_adapters, adapter, link);

	adapter->conn = msg_server_conn_create(mgmt_loop, conn_fd,
					       mgmt_be_adapter_notify_disconnect,
					       be_adapter_process_msg, MGMTD_BE_MAX_NUM_MSG_PROC,
					       MGMTD_BE_MAX_NUM_MSG_WRITE, MGMTD_BE_MAX_MSG_LEN,
					       adapter, "BE-adapter");

	adapter->conn->debug = DEBUG_MODE_CHECK(&mgmt_debug_be, DEBUG_MODE_ALL);

	_dbg("Added new MGMTD Backend adapter '%s'", adapter->name);

	return adapter->conn;
}

/*
 * Initialize the BE adapter module
 */
void mgmt_be_adapter_init(struct event_loop *tm)
{
	char server_path[MAXPATHLEN];

	assert(!mgmt_loop);
	mgmt_loop = tm;

	*darr_append(mgmt_be_client_names) = darr_strdup("mgmtd"); /* reserve ID 0 */
	be_adapter_xpath_maps_init();

	snprintf(server_path, sizeof(server_path), MGMTD_BE_SOCK_NAME);

	if (msg_server_init(&mgmt_be_server, server_path, tm, be_adapter_create, "backend",
			    &mgmt_debug_be)) {
		zlog_err("cannot initialize backend server");
		exit(1);
	}
}

/*
 * Destroy the BE adapter module
 */
void mgmt_be_adapter_destroy(void)
{
	struct mgmt_be_client_adapter *adapter, *next;

	msg_server_cleanup(&mgmt_be_server);
	LIST_FOREACH_SAFE (adapter, &be_adapters, link, next)
		be_adapter_delete(adapter);
	be_adapter_xpath_maps_cleanup();
	darr_free_free(mgmt_be_client_names);
	darr_free(mgmt_be_adapters_by_id);
}
