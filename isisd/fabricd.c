/*
 * IS-IS Rout(e)ing protocol - OpenFabric extensions
 *
 * Copyright (C) 2018 Christian Franke
 *
 * This file is part of FRRouting (FRR)
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
#include "isisd/fabricd.h"
#include "isisd/isisd.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_tx_queue.h"
#include "isisd/isis_csm.h"

DEFINE_MTYPE_STATIC(ISISD, FABRICD_STATE, "ISIS OpenFabric");
DEFINE_MTYPE_STATIC(ISISD, FABRICD_NEIGHBOR, "ISIS OpenFabric Neighbor Entry");
DEFINE_MTYPE_STATIC(ISISD, FABRICD_FLOODING_INFO, "ISIS OpenFabric Flooding Log");

/* Tracks initial synchronization as per section 2.4
 *
 * We declare the sync complete once we have seen at least one
 * CSNP and there are no more LSPs with SSN or SRM set.
 */
enum fabricd_sync_state {
	FABRICD_SYNC_PENDING,
	FABRICD_SYNC_STARTED,
	FABRICD_SYNC_COMPLETE
};

struct fabricd {
	struct isis_area *area;

	enum fabricd_sync_state initial_sync_state;
	time_t initial_sync_start;
	struct isis_circuit *initial_sync_circuit;
	struct thread *initial_sync_timeout;

	struct isis_spftree *spftree;
	struct skiplist *neighbors;
	struct hash *neighbors_neighbors;

	uint8_t tier;
	uint8_t tier_config;
	uint8_t tier_pending;
	struct thread *tier_calculation_timer;
	struct thread *tier_set_timer;

	int csnp_delay;
	bool always_send_csnp;
};

/* Code related to maintaining the neighbor lists */

struct neighbor_entry {
	uint8_t id[ISIS_SYS_ID_LEN];
	struct isis_adjacency *adj;
	bool present;
};

static struct neighbor_entry *neighbor_entry_new(const uint8_t *id,
						 struct isis_adjacency *adj)
{
	struct neighbor_entry *rv = XMALLOC(MTYPE_FABRICD_NEIGHBOR,
					    sizeof(*rv));

	memcpy(rv->id, id, sizeof(rv->id));
	rv->adj = adj;

	return rv;
}

static void neighbor_entry_del(struct neighbor_entry *neighbor)
{
	XFREE(MTYPE_FABRICD_NEIGHBOR, neighbor);
}

static void neighbor_entry_del_void(void *arg)
{
	neighbor_entry_del((struct neighbor_entry *)arg);
}

static void neighbor_lists_clear(struct fabricd *f)
{
	while (!skiplist_empty(f->neighbors))
		skiplist_delete_first(f->neighbors);

	hash_clean(f->neighbors_neighbors, neighbor_entry_del_void);
}

static unsigned neighbor_entry_hash_key(const void *np)
{
	const struct neighbor_entry *n = np;

	return jhash(n->id, sizeof(n->id), 0x55aa5a5a);
}

static bool neighbor_entry_hash_cmp(const void *a, const void *b)
{
	const struct neighbor_entry *na = a, *nb = b;

	return memcmp(na->id, nb->id, sizeof(na->id)) == 0;
}

static int neighbor_entry_list_cmp(const void *a, const void *b)
{
	const struct neighbor_entry *na = a, *nb = b;

	return -memcmp(na->id, nb->id, sizeof(na->id));
}

static struct neighbor_entry *neighbor_entry_lookup_list(struct skiplist *list,
							 const uint8_t *id)
{
	struct neighbor_entry n = { {0} };

	memcpy(n.id, id, sizeof(n.id));

	struct neighbor_entry *rv;

	if (skiplist_search(list, &n, (void**)&rv))
		return NULL;

	if (!rv->present)
		return NULL;

	return rv;
}

static struct neighbor_entry *neighbor_entry_lookup_hash(struct hash *hash,
							 const uint8_t *id)
{
	struct neighbor_entry n = {{0}};

	memcpy(n.id, id, sizeof(n.id));

	struct neighbor_entry *rv = hash_lookup(hash, &n);

	if (!rv || !rv->present)
		return NULL;

	return rv;
}

static int fabricd_handle_adj_state_change(struct isis_adjacency *arg)
{
	struct fabricd *f = arg->circuit->area->fabricd;

	if (!f)
		return 0;

	while (!skiplist_empty(f->neighbors))
		skiplist_delete_first(f->neighbors);

	struct listnode *node;
	struct isis_circuit *circuit;

	for (ALL_LIST_ELEMENTS_RO(f->area->circuit_list, node, circuit)) {
		if (circuit->state != C_STATE_UP)
			continue;

		struct isis_adjacency *adj = circuit->u.p2p.neighbor;

		if (!adj || adj->adj_state != ISIS_ADJ_UP)
			continue;

		struct neighbor_entry *n = neighbor_entry_new(adj->sysid, adj);

		skiplist_insert(f->neighbors, n, n);
	}

	return 0;
}

static void neighbors_neighbors_update(struct fabricd *f)
{
	hash_clean(f->neighbors_neighbors, neighbor_entry_del_void);

	struct listnode *node;
	struct isis_vertex *v;

	for (ALL_QUEUE_ELEMENTS_RO(&f->spftree->paths, node, v)) {
		if (v->d_N < 2 || !VTYPE_IS(v->type))
			continue;

		if (v->d_N > 2)
			break;

		struct neighbor_entry *n = neighbor_entry_new(v->N.id, NULL);
		struct neighbor_entry *inserted;
		inserted = hash_get(f->neighbors_neighbors, n,
				    hash_alloc_intern);
		assert(inserted == n);
	}
}

struct fabricd *fabricd_new(struct isis_area *area)
{
	struct fabricd *rv = XCALLOC(MTYPE_FABRICD_STATE, sizeof(*rv));

	rv->area = area;
	rv->initial_sync_state = FABRICD_SYNC_PENDING;

	rv->spftree =
		isis_spftree_new(area, &area->lspdb[IS_LEVEL_2 - 1],
				 area->isis->sysid, ISIS_LEVEL2, SPFTREE_IPV4,
				 SPF_TYPE_FORWARD, F_SPFTREE_HOPCOUNT_METRIC);
	rv->neighbors = skiplist_new(0, neighbor_entry_list_cmp,
				     neighbor_entry_del_void);
	rv->neighbors_neighbors = hash_create(neighbor_entry_hash_key,
					      neighbor_entry_hash_cmp,
					      "Fabricd Neighbors");

	rv->tier = rv->tier_config = ISIS_TIER_UNDEFINED;

	rv->csnp_delay = FABRICD_DEFAULT_CSNP_DELAY;
	return rv;
};

void fabricd_finish(struct fabricd *f)
{
	THREAD_OFF(f->initial_sync_timeout);

	THREAD_OFF(f->tier_calculation_timer);

	THREAD_OFF(f->tier_set_timer);

	isis_spftree_del(f->spftree);
	neighbor_lists_clear(f);
	skiplist_free(f->neighbors);
	hash_free(f->neighbors_neighbors);
}

static void fabricd_initial_sync_timeout(struct thread *thread)
{
	struct fabricd *f = THREAD_ARG(thread);

	if (IS_DEBUG_ADJ_PACKETS)
		zlog_debug(
			"OpenFabric: Initial synchronization on %s timed out!",
			f->initial_sync_circuit->interface->name);
	f->initial_sync_state = FABRICD_SYNC_PENDING;
	f->initial_sync_circuit = NULL;
}

void fabricd_initial_sync_hello(struct isis_circuit *circuit)
{
	struct fabricd *f = circuit->area->fabricd;

	if (!f)
		return;

	if (f->initial_sync_state > FABRICD_SYNC_PENDING)
		return;

	f->initial_sync_state = FABRICD_SYNC_STARTED;

	long timeout = 2 * circuit->hello_interval[1] * circuit->hello_multiplier[1];

	f->initial_sync_circuit = circuit;
	if (f->initial_sync_timeout)
		return;

	thread_add_timer(master, fabricd_initial_sync_timeout, f,
			 timeout, &f->initial_sync_timeout);
	f->initial_sync_start = monotime(NULL);

	if (IS_DEBUG_ADJ_PACKETS)
		zlog_debug(
			"OpenFabric: Started initial synchronization with %s on %s",
			sysid_print(circuit->u.p2p.neighbor->sysid),
			circuit->interface->name);
}

bool fabricd_initial_sync_is_in_progress(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return false;

	if (f->initial_sync_state > FABRICD_SYNC_PENDING
	    && f->initial_sync_state < FABRICD_SYNC_COMPLETE)
		return true;

	return false;
}

bool fabricd_initial_sync_is_complete(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return false;

	return f->initial_sync_state == FABRICD_SYNC_COMPLETE;
}

struct isis_circuit *fabricd_initial_sync_circuit(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;
	if (!f)
		return NULL;

	return f->initial_sync_circuit;
}

void fabricd_initial_sync_finish(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return;

	if (monotime(NULL) - f->initial_sync_start < 5)
		return;

	zlog_info("OpenFabric: Initial synchronization on %s complete.",
		  f->initial_sync_circuit->interface->name);
	f->initial_sync_state = FABRICD_SYNC_COMPLETE;
	f->initial_sync_circuit = NULL;
	THREAD_OFF(f->initial_sync_timeout);
}

static void fabricd_bump_tier_calculation_timer(struct fabricd *f);
static void fabricd_set_tier(struct fabricd *f, uint8_t tier);

static uint8_t fabricd_calculate_fabric_tier(struct isis_area *area)
{
	struct isis_spftree *local_tree = fabricd_spftree(area);
	struct listnode *node;

	struct isis_vertex *furthest_t0 = NULL,
			   *second_furthest_t0 = NULL;

	struct isis_vertex *v;

	for (ALL_QUEUE_ELEMENTS_RO(&local_tree->paths, node, v)) {
		struct isis_lsp *lsp = lsp_for_vertex(local_tree, v);

		if (!lsp || !lsp->tlvs
		    || !lsp->tlvs->spine_leaf
		    || !lsp->tlvs->spine_leaf->has_tier
		    || lsp->tlvs->spine_leaf->tier != 0)
			continue;

		second_furthest_t0 = furthest_t0;
		furthest_t0 = v;
	}

	if (!second_furthest_t0) {
		zlog_info("OpenFabric: Could not find two T0 routers");
		return ISIS_TIER_UNDEFINED;
	}

	zlog_info("OpenFabric: Found %s as furthest t0 from local system, dist == %u", rawlspid_print(furthest_t0->N.id), furthest_t0->d_N);

	struct isis_spftree *remote_tree =
		isis_run_hopcount_spf(area, furthest_t0->N.id, NULL);

	struct isis_vertex *furthest_from_remote =
		isis_vertex_queue_last(&remote_tree->paths);

	if (!furthest_from_remote) {
		zlog_info("OpenFabric: Found no furthest node in remote spf");
		isis_spftree_del(remote_tree);
		return ISIS_TIER_UNDEFINED;
	} else {
		zlog_info("OpenFabric: Found %s as furthest from remote dist == %u", rawlspid_print(furthest_from_remote->N.id),
			  furthest_from_remote->d_N);
	}

	int64_t tier = furthest_from_remote->d_N - furthest_t0->d_N;
	isis_spftree_del(remote_tree);

	if (tier < 0 || tier >= ISIS_TIER_UNDEFINED) {
		zlog_info("OpenFabric: Calculated tier %" PRId64 " seems implausible",
			  tier);
		return ISIS_TIER_UNDEFINED;
	}

	zlog_info("OpenFabric: Calculated %" PRId64 " as tier", tier);
	return tier;
}

static void fabricd_tier_set_timer(struct thread *thread)
{
	struct fabricd *f = THREAD_ARG(thread);

	fabricd_set_tier(f, f->tier_pending);
}

static void fabricd_tier_calculation_cb(struct thread *thread)
{
	struct fabricd *f = THREAD_ARG(thread);
	uint8_t tier = ISIS_TIER_UNDEFINED;

	tier = fabricd_calculate_fabric_tier(f->area);
	if (tier == ISIS_TIER_UNDEFINED)
		return;

	zlog_info("OpenFabric: Got tier %hhu from algorithm. Arming timer.",
		  tier);
	f->tier_pending = tier;
	thread_add_timer(master, fabricd_tier_set_timer, f,
			 f->area->lsp_gen_interval[ISIS_LEVEL2 - 1],
			 &f->tier_set_timer);

}

static void fabricd_bump_tier_calculation_timer(struct fabricd *f)
{
	/* Cancel timer if we already know our tier */
	if (f->tier != ISIS_TIER_UNDEFINED || f->tier_set_timer) {
		THREAD_OFF(f->tier_calculation_timer);
		return;
	}

	/* If we need to calculate the tier, wait some
	 * time for the topology to settle before running
	 * the calculation */
	THREAD_OFF(f->tier_calculation_timer);

	thread_add_timer(master, fabricd_tier_calculation_cb, f,
			 2 * f->area->lsp_gen_interval[ISIS_LEVEL2 - 1],
			 &f->tier_calculation_timer);
}

static void fabricd_set_tier(struct fabricd *f, uint8_t tier)
{
	if (f->tier == tier)
		return;

	zlog_info("OpenFabric: Set own tier to %hhu", tier);
	f->tier = tier;

	fabricd_bump_tier_calculation_timer(f);
	lsp_regenerate_schedule(f->area, ISIS_LEVEL2, 0);
}

void fabricd_run_spf(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return;

	isis_run_hopcount_spf(area, area->isis->sysid, f->spftree);
	neighbors_neighbors_update(f);
	fabricd_bump_tier_calculation_timer(f);
}

struct isis_spftree *fabricd_spftree(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return NULL;

	return f->spftree;
}

void fabricd_configure_tier(struct isis_area *area, uint8_t tier)
{
	struct fabricd *f = area->fabricd;

	if (!f || f->tier_config == tier)
		return;

	f->tier_config = tier;
	fabricd_set_tier(f, tier);
}

uint8_t fabricd_tier(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return ISIS_TIER_UNDEFINED;

	return f->tier;
}

int fabricd_write_settings(struct isis_area *area, struct vty *vty)
{
	struct fabricd *f = area->fabricd;
	int written = 0;

	if (!f)
		return written;

	if (f->tier_config != ISIS_TIER_UNDEFINED) {
		vty_out(vty, " fabric-tier %hhu\n", f->tier_config);
		written++;
	}

	if (f->csnp_delay != FABRICD_DEFAULT_CSNP_DELAY
	    || f->always_send_csnp) {
		vty_out(vty, " triggered-csnp-delay %d%s\n", f->csnp_delay,
			f->always_send_csnp ? " always" : "");
	}

	return written;
}

static void move_to_queue(struct isis_lsp *lsp, struct neighbor_entry *n,
			  enum isis_tx_type type, struct isis_circuit *circuit)
{
	n->present = false;

	if (n->adj && n->adj->circuit == circuit)
		return;

	if (IS_DEBUG_FLOODING) {
		zlog_debug("OpenFabric: Adding %s to %s",
			   print_sys_hostname(n->id),
			   (type == TX_LSP_NORMAL) ? "RF" : "DNR");
	}

	if (n->adj)
		isis_tx_queue_add(n->adj->circuit->tx_queue, lsp, type);

	uint8_t *neighbor_id = XMALLOC(MTYPE_FABRICD_FLOODING_INFO,
				       sizeof(n->id));

	memcpy(neighbor_id, n->id, sizeof(n->id));
	listnode_add(lsp->flooding_neighbors[type], neighbor_id);
}

static void mark_neighbor_as_present(struct hash_bucket *bucket, void *arg)
{
	struct neighbor_entry *n = bucket->data;

	n->present = true;
}

static void handle_firsthops(struct hash_bucket *bucket, void *arg)
{
	struct isis_lsp *lsp = arg;
	struct fabricd *f = lsp->area->fabricd;
	struct isis_vertex *vertex = bucket->data;

	struct neighbor_entry *n;

	n = neighbor_entry_lookup_list(f->neighbors, vertex->N.id);
	if (n) {
		if (IS_DEBUG_FLOODING) {
			zlog_debug("Removing %s from NL as its in the reverse path",
				   print_sys_hostname(n->id));
		}
		n->present = false;
	}

	n = neighbor_entry_lookup_hash(f->neighbors_neighbors, vertex->N.id);
	if (n) {
		if (IS_DEBUG_FLOODING) {
			zlog_debug("Removing %s from NN as its in the reverse path",
				   print_sys_hostname(n->id));
		}
		n->present = false;
	}
}

static struct isis_lsp *lsp_for_neighbor(struct fabricd *f,
					 struct neighbor_entry *n)
{
	uint8_t id[ISIS_SYS_ID_LEN + 1] = {0};

	memcpy(id, n->id, sizeof(n->id));

	struct isis_vertex vertex = {0};

	isis_vertex_id_init(&vertex, id, VTYPE_NONPSEUDO_TE_IS);

	return lsp_for_vertex(f->spftree, &vertex);
}

static void fabricd_free_lsp_flooding_info(void *val)
{
	XFREE(MTYPE_FABRICD_FLOODING_INFO, val);
}

static void fabricd_lsp_reset_flooding_info(struct isis_lsp *lsp,
					    struct isis_circuit *circuit)
{
	lsp->flooding_time = time(NULL);

	XFREE(MTYPE_FABRICD_FLOODING_INFO, lsp->flooding_interface);
	for (enum isis_tx_type type = TX_LSP_NORMAL;
	     type <= TX_LSP_CIRCUIT_SCOPED; type++) {
		if (lsp->flooding_neighbors[type]) {
			list_delete_all_node(lsp->flooding_neighbors[type]);
			continue;
		}

		lsp->flooding_neighbors[type] = list_new();
		lsp->flooding_neighbors[type]->del =
			fabricd_free_lsp_flooding_info;
	}

	if (circuit) {
		lsp->flooding_interface = XSTRDUP(MTYPE_FABRICD_FLOODING_INFO,
						  circuit->interface->name);
	}

	lsp->flooding_circuit_scoped = false;
}

void fabricd_lsp_flood(struct isis_lsp *lsp, struct isis_circuit *circuit)
{
	struct fabricd *f = lsp->area->fabricd;
	assert(f);

	fabricd_lsp_reset_flooding_info(lsp, circuit);

	void *cursor = NULL;
	struct neighbor_entry *n;

	/* Mark all elements in NL as present */
	while (!skiplist_next(f->neighbors, NULL, (void **)&n, &cursor))
		n->present = true;

	/* Mark all elements in NN as present */
	hash_iterate(f->neighbors_neighbors, mark_neighbor_as_present, NULL);

	struct isis_vertex *originator =
		isis_find_vertex(&f->spftree->paths,
				 lsp->hdr.lsp_id,
				 VTYPE_NONPSEUDO_TE_IS);

	/* Remove all IS from NL and NN in the shortest path
	 * to the IS that originated the LSP */
	if (originator)
		hash_iterate(originator->firsthops, handle_firsthops, lsp);

	/* Iterate over all remaining IS in NL */
	cursor = NULL;
	while (!skiplist_next(f->neighbors, NULL, (void **)&n, &cursor)) {
		if (!n->present)
			continue;

		struct isis_lsp *nlsp = lsp_for_neighbor(f, n);
		if (!nlsp || !nlsp->tlvs) {
			if (IS_DEBUG_FLOODING) {
				zlog_debug("Moving %s to DNR as it has no LSP",
					   print_sys_hostname(n->id));
			}

			move_to_queue(lsp, n, TX_LSP_CIRCUIT_SCOPED, circuit);
			continue;
		}

		if (IS_DEBUG_FLOODING) {
			zlog_debug("Considering %s from NL...",
				   print_sys_hostname(n->id));
		}

		/* For all neighbors of the NL IS check whether they are present
		 * in NN. If yes, remove from NN and set need_reflood. */
		bool need_reflood = false;
		struct isis_extended_reach *er;
		for (er = (struct isis_extended_reach *)nlsp->tlvs->extended_reach.head;
		     er; er = er->next) {
			struct neighbor_entry *nn;

			nn = neighbor_entry_lookup_hash(f->neighbors_neighbors,
							er->id);

			if (nn) {
				if (IS_DEBUG_FLOODING) {
					zlog_debug("Found neighbor %s in NN, removing it from NN and setting reflood.",
						   print_sys_hostname(nn->id));
				}

				nn->present = false;
				need_reflood = true;
			}
		}

		move_to_queue(lsp, n, need_reflood ?
			      TX_LSP_NORMAL : TX_LSP_CIRCUIT_SCOPED,
			      circuit);
	}

	if (IS_DEBUG_FLOODING) {
		zlog_debug("OpenFabric: Flooding algorithm complete.");
	}
}

void fabricd_trigger_csnp(struct isis_area *area, bool circuit_scoped)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return;

	if (!circuit_scoped && !f->always_send_csnp)
		return;

	struct listnode *node;
	struct isis_circuit *circuit;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if (!circuit->t_send_csnp[1])
			continue;

		THREAD_OFF(circuit->t_send_csnp[ISIS_LEVEL2 - 1]);
		thread_add_timer_msec(master, send_l2_csnp, circuit,
				      isis_jitter(f->csnp_delay, CSNP_JITTER),
				      &circuit->t_send_csnp[ISIS_LEVEL2 - 1]);
	}
}

struct list *fabricd_ip_addrs(struct isis_circuit *circuit)
{
	if (listcount(circuit->ip_addrs))
		return circuit->ip_addrs;

	if (!fabricd || !circuit->area || !circuit->area->circuit_list)
		return NULL;

	struct listnode *node;
	struct isis_circuit *c;

	for (ALL_LIST_ELEMENTS_RO(circuit->area->circuit_list, node, c)) {
		if (c->circ_type != CIRCUIT_T_LOOPBACK)
			continue;

		if (!listcount(c->ip_addrs))
			return NULL;

		return c->ip_addrs;
	}

	return NULL;
}

void fabricd_lsp_free(struct isis_lsp *lsp)
{
	XFREE(MTYPE_FABRICD_FLOODING_INFO, lsp->flooding_interface);
	for (enum isis_tx_type type = TX_LSP_NORMAL;
	     type <= TX_LSP_CIRCUIT_SCOPED; type++) {
		if (!lsp->flooding_neighbors[type])
			continue;

		list_delete(&lsp->flooding_neighbors[type]);
	}
}

void fabricd_update_lsp_no_flood(struct isis_lsp *lsp,
				 struct isis_circuit *circuit)
{
	if (!fabricd)
		return;

	fabricd_lsp_reset_flooding_info(lsp, circuit);
	lsp->flooding_circuit_scoped = true;
}

void fabricd_configure_triggered_csnp(struct isis_area *area, int delay,
				      bool always_send_csnp)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return;

	f->csnp_delay = delay;
	f->always_send_csnp = always_send_csnp;
}

void fabricd_init(void)
{
	hook_register(isis_adj_state_change_hook,
		      fabricd_handle_adj_state_change);
}
