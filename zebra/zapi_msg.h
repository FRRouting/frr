// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra API message creation & consumption.
 * Portions:
 *   Copyright (C) 1997-1999  Kunihiro Ishiguro
 *   Copyright (C) 2015-2018  Cumulus Networks, Inc.
 *   et al.
 */

#include "lib/if.h"
#include "lib/vrf.h"
#include "lib/zclient.h"
#include "lib/pbr.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_errors.h"
#include "zebra/label_manager.h"
#include "zebra/zebra_srv6.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is called to process inbound ZAPI messages.
 *
 * client
 *    the client datastructure
 *
 * fifo
 *    a batch of messages
 */
extern void zserv_handle_commands(struct zserv *client,
				  struct stream_fifo *fifo);

extern int zsend_vrf_add(struct zserv *zclient, struct zebra_vrf *zvrf);
extern int zsend_vrf_delete(struct zserv *zclient, struct zebra_vrf *zvrf);
extern int zsend_interface_add(struct zserv *zclient, struct interface *ifp);
extern int zsend_interface_delete(struct zserv *zclient, struct interface *ifp);
extern int zsend_interface_addresses(struct zserv *zclient,
				     struct interface *ifp);
extern int zsend_interface_address(int cmd, struct zserv *zclient,
				   struct interface *ifp,
				   struct connected *ifc);
extern void nbr_connected_add_ipv6(struct interface *ifp,
				   struct in6_addr *address);
extern void nbr_connected_delete_ipv6(struct interface *ifp,
				      struct in6_addr *address);
extern int zsend_interface_update(int cmd, struct zserv *client,
				  struct interface *ifp);
extern int zsend_redistribute_route(int cmd, struct zserv *zclient,
				    const struct route_node *rn,
				    const struct route_entry *re,
				    bool is_table_direct);

extern int zsend_router_id_update(struct zserv *zclient, afi_t afi,
				  struct prefix *p, vrf_id_t vrf_id);
extern int zsend_interface_link_params(struct zserv *zclient,
				       struct interface *ifp);
extern int zsend_pw_update(struct zserv *client, struct zebra_pw *pw);
extern int zsend_route_notify_owner(const struct route_node *rn,
				    struct route_entry *re,
				    enum zapi_route_notify_owner note,
				    afi_t afi, safi_t safi);
extern int zsend_route_notify_owner_ctx(const struct zebra_dplane_ctx *ctx,
					enum zapi_route_notify_owner note);

extern void zsend_rule_notify_owner(const struct zebra_dplane_ctx *ctx,
				    enum zapi_rule_notify_owner note);

extern void zsend_iptable_notify_owner(const struct zebra_dplane_ctx *ctx,
				       enum zapi_iptable_notify_owner note);
extern void zsend_ipset_notify_owner(const struct zebra_dplane_ctx *ctx,
				     enum zapi_ipset_notify_owner note);
extern void
zsend_ipset_entry_notify_owner(const struct zebra_dplane_ctx *ctx,
			       enum zapi_ipset_entry_notify_owner note);
extern bool zserv_nexthop_num_warn(const char *caller, const struct prefix *p,
				   const unsigned int nexthop_num);

extern void zsend_capabilities_all_clients(void);
extern int zsend_assign_label_chunk_response(struct zserv *client,
					     vrf_id_t vrf_id,
					     struct label_manager_chunk *lmc);
extern int zsend_label_manager_connect_response(struct zserv *client,
						vrf_id_t vrf_id,
						unsigned short result);
extern int zsend_sr_policy_notify_status(uint32_t color,
					 struct ipaddr *endpoint, char *name,
					 int status);
extern void zsend_neighbor_notify(int cmd, struct interface *ifp,
				  struct ipaddr *ipaddr, int ndm_state,
				  union sockunion *link_layer_ipv4, int ip_len);
extern void zsend_srv6_sid_notify(struct zserv *client,
				  const struct srv6_sid_ctx *ctx,
				  struct in6_addr *sid_value, uint32_t func,
				  uint32_t wide_func, const char *locator_name,
				  enum zapi_srv6_sid_notify note);

extern int zsend_client_close_notify(struct zserv *client,
				     struct zserv *closed_client);

int zsend_nhg_notify(uint16_t type, uint16_t instance, uint32_t session_id,
		     uint32_t id, enum zapi_nhg_notify_owner note);

extern void zapi_re_opaque_free(struct route_entry *re);

extern int zsend_zebra_srv6_locator_add(struct zserv *client,
					struct srv6_locator *loc);
extern int zsend_zebra_srv6_locator_delete(struct zserv *client,
					   struct srv6_locator *loc);
extern int zsend_srv6_manager_get_locator_chunk_response(struct zserv *client,
		vrf_id_t vrf_id, struct srv6_locator *loc);

extern int zsend_srv6_manager_get_locator_response(struct zserv *client,
						   struct srv6_locator *locator);

extern int zsend_srv6_manager_get_locator_sid_response(struct zserv *client, vrf_id_t vrf_id,
						       struct srv6_locator *loc);
extern int zsend_srv6_manager_del_sid(struct zserv *client, vrf_id_t vrf_id,
				      struct srv6_locator *loc, struct seg6_sid *sid);

#ifdef __cplusplus
}
#endif
