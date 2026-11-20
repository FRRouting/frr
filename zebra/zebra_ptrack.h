// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra prefix tracking (ptrack): subscriptions of zebra clients to the
 * reachability of an exact prefix in a VRF.
 */

#ifndef _ZEBRA_PTRACK_H
#define _ZEBRA_PTRACK_H

#include "prefix.h"
#include "table.h"
#include "zclient.h"
#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Hard limit of cookies per client per VRF, shared by IPv4 and IPv6. Used as
 * the default of a variable so that it can become configurable later.
 */
#define ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT 16384

/*
 * The VRF context, one per VRF name. It holds all the subscriptions of the
 * VRF and outlives the zebra_vrf: the vrf_id changes across VRF delete and
 * add, the name does not. The structure is private to zebra_ptrack.c.
 */
struct ptrack_vrf_ctx;

/* One tracked prefix: its state and its subscribers. Private as well. */
struct ptrack_entry;

enum zebra_ptrack_result {
	ZEBRA_PTRACK_SUCCESS = 0,
	/* Adding the cookies would exceed the per client per VRF limit */
	ZEBRA_PTRACK_LIMIT,
	/* Bad VRF name or prefix family */
	ZEBRA_PTRACK_INVALID,
};

/* Initialize the module at startup */
extern void zebra_ptrack_init(void);

/* Free all the module data, called when zebra is shutting down */
extern void zebra_ptrack_terminate(void);

/*
 * Find the context of a VRF name. Returns NULL if there is none.
 */
extern struct ptrack_vrf_ctx *zebra_ptrack_ctx_lookup(const char *vrf_name);

/*
 * Find the context for a VRF name, or create it.
 */
extern struct ptrack_vrf_ctx *zebra_ptrack_ctx_get(const char *vrf_name);

/*
 * Free the context if it has no subscription left. Returns true if it was
 * freed, the pointer is not valid then.
 */
extern bool zebra_ptrack_ctx_free_if_unused(struct ptrack_vrf_ctx *ctx);

/*
 * Add cookies of a client to a prefix of the context. The prefix is masked
 * here, so it does not have to be canonical. The cookies that already exist
 * are not changed or counted. The cookie limit is checked against the cookies
 * that are new, and nothing is changed if it would be exceeded.
 *
 * On success *entry is the entry of the prefix (it is created if needed).
 * Its state is UNREACHABLE until the caller sets it.
 */
extern enum zebra_ptrack_result
zebra_ptrack_add_cookies(struct ptrack_vrf_ctx *ctx, struct zserv *client,
			 const struct prefix *p, const uint64_t *cookies,
			 uint16_t count, struct ptrack_entry **entry);

/*
 * Remove cookies of a client from a prefix of the context. The prefix is
 * masked here. The cookies that do not exist are skipped. The client, the
 * prefix entry and the per VRF client counter are freed when they become
 * empty. The context is not freed, see zebra_ptrack_ctx_free_if_unused().
 */
extern void zebra_ptrack_del_cookies(struct ptrack_vrf_ctx *ctx,
				     struct zserv *client, const struct prefix *p,
				     const uint64_t *cookies, uint16_t count);

/* Find the entry of a prefix (masked here). Returns NULL if it is not tracked. */
extern struct ptrack_entry *zebra_ptrack_entry_lookup(struct ptrack_vrf_ctx *ctx,
						      const struct prefix *p);

extern enum zapi_ptrack_state
zebra_ptrack_entry_state(const struct ptrack_entry *entry);
extern void zebra_ptrack_entry_set_state(struct ptrack_entry *entry,
					 enum zapi_ptrack_state state);

/* Number of cookies of a client in the context, shared by IPv4 and IPv6 */
extern uint32_t zebra_ptrack_client_cookie_count(struct ptrack_vrf_ctx *ctx,
						 struct zserv *client);

/*
 * Ptrack register
 */
extern void zebra_ptrack_register(struct zserv *client,
				  const struct zapi_ptrack *api);

/*
 * Ptrack unregister
 */
extern void zebra_ptrack_unregister(struct zserv *client,
				    const struct zapi_ptrack *api);

/*
 * Ptrack evaluate: called with a route node the RIB just processed, sends
 * UPDATE to the clients of the prefix if its state flipped
 */
extern void zebra_ptrack_evaluate(struct zebra_vrf *zvrf, struct route_node *rn);

/*
 * Ptrack rib sweep
 */
extern void zebra_ptrack_rib_sweep(void);

/*
 * Ptrack vrf enable: attach the context of the VRF name to the zebra_vrf and
 * re-evaluate all its prefixes, sends UPDATE for the flips
 */
extern void zebra_ptrack_vrf_enable(struct zebra_vrf *zvrf);

/*
 * Ptrack vrf disable: force all the prefixes of the VRF to UNREACHABLE and
 * send UPDATE for the flips, even if the routes are retained
 */
extern void zebra_ptrack_vrf_disable(struct zebra_vrf *zvrf);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_PTRACK_H */
