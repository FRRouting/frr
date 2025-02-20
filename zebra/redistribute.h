// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Redistribution Handler
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_REDISTRIBUTE_H
#define _ZEBRA_REDISTRIBUTE_H

#include "table.h"
#include "vty.h"
#include "vrf.h"

#include "zebra/zserv.h"
#include "zebra/rib.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ZAPI command handlers */
extern void zebra_redistribute_add(ZAPI_HANDLER_ARGS);
extern void zebra_redistribute_delete(ZAPI_HANDLER_ARGS);
extern void zebra_redistribute_default_add(ZAPI_HANDLER_ARGS);
extern void zebra_redistribute_default_delete(ZAPI_HANDLER_ARGS);
/* ----------------- */

extern void redistribute_update(const struct route_node *rn,
				const struct route_entry *re,
				const struct route_entry *prev_re);
/*
 * During a route delete, where 'new_re' is NULL, redist a delete to all
 * clients registered for the type of 'old_re'.
 * During a route update, redist a delete to any clients who will not see
 * an update when the new route is installed. There are cases when a client
 * may have seen a redist for 'old_re', but will not see
 * the redist for 'new_re'.
 */
void redistribute_delete(const struct route_node *rn,
			 const struct route_entry *old_re,
			 const struct route_entry *new_re);

extern void zebra_interface_up_update(struct interface *ifp);
extern void zebra_interface_down_update(struct interface *ifp);

extern void zebra_interface_add_update(struct interface *ifp);
extern void zebra_interface_delete_update(struct interface *ifp);

extern void zebra_interface_address_add_update(struct interface *ifp,
					       struct connected *c);
extern void zebra_interface_address_delete_update(struct interface *ifp,
						  struct connected *c);
extern void zebra_interface_parameters_update(struct interface *ifp);
extern void zebra_interface_vrf_update_del(struct interface *ifp,
					   vrf_id_t new_vrf_id);
extern void zebra_interface_vrf_update_add(struct interface *ifp,
					   vrf_id_t old_vrf_id);

extern int zebra_import_table(afi_t afi, safi_t safi, vrf_id_t vrf_id, uint32_t table_id,
			      uint32_t distance, const char *rmap_name, bool add);

extern int zebra_add_import_table_entry(struct zebra_vrf *zvrf, safi_t safi, struct route_node *rn,
					struct route_entry *re, const char *rmap_name);
extern int zebra_del_import_table_entry(struct zebra_vrf *zvrf, safi_t safi, struct route_node *rn,
					struct route_entry *re);
extern int is_zebra_import_table_enabled(afi_t, safi_t safi, vrf_id_t vrf_id, uint32_t table_id);

extern int zebra_import_table_config(struct vty *, vrf_id_t vrf_id);

extern void zebra_import_table_rm_update(const char *rmap);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_REDISTRIBUTE_H */
