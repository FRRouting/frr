// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra prefix tracking (ptrack) header
 *
 * Copyright (C) 2026 Nokia
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


/* Limit cookies per client per VRF (both AF included) */
#define ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT 16384

/* Per vrf ptrack context */
struct ptrack_vrf_ctx;

/* Single tracked prefix */
struct ptrack_entry;

enum zebra_ptrack_result {
	ZEBRA_PTRACK_SUCCESS = 0,
	ZEBRA_PTRACK_LIMIT,
	ZEBRA_PTRACK_INVALID,
};

extern void zebra_ptrack_init(void);
extern void zebra_ptrack_terminate(void);

extern struct ptrack_vrf_ctx *zebra_ptrack_ctx_lookup(const char *vrf_name);
extern struct ptrack_vrf_ctx *zebra_ptrack_ctx_get(const char *vrf_name);
extern bool zebra_ptrack_ctx_free_if_unused(struct ptrack_vrf_ctx *ctx);

extern enum zebra_ptrack_result
zebra_ptrack_add_cookies(struct ptrack_vrf_ctx *ctx, struct zserv *client,
			 const struct prefix *p, const uint64_t *cookies,
			 uint16_t count, struct ptrack_entry **entry);
extern void zebra_ptrack_del_cookies(struct ptrack_vrf_ctx *ctx,
				     struct zserv *client, const struct prefix *p,
				     const uint64_t *cookies, uint16_t count);
extern struct ptrack_entry *zebra_ptrack_entry_lookup(struct ptrack_vrf_ctx *ctx,
						      const struct prefix *p);

extern enum zapi_ptrack_state
zebra_ptrack_entry_get_state(const struct ptrack_entry *entry);
extern void zebra_ptrack_entry_set_state(struct ptrack_entry *entry,
					 enum zapi_ptrack_state state);
extern uint32_t zebra_ptrack_client_cookie_count(struct ptrack_vrf_ctx *ctx,
						 struct zserv *client);

extern void zebra_ptrack_register(struct zserv *client,
				  const struct zapi_ptrack *api);
extern void zebra_ptrack_unregister(struct zserv *client,
				    const struct zapi_ptrack *api);


extern void zebra_ptrack_evaluate(struct zebra_vrf *zvrf, struct route_node *rn);

/* Ptrack rib sweep */
extern void zebra_ptrack_rib_sweep(void);

extern void zebra_ptrack_vrf_enable(struct zebra_vrf *zvrf);
extern void zebra_ptrack_vrf_disable(struct zebra_vrf *zvrf);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_PTRACK_H */
