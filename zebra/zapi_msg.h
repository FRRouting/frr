/*
 * Zebra API message creation & consumption.
 * Portions:
 *   Copyright (C) 1997-1999  Kunihiro Ishiguro
 *   Copyright (C) 2015-2018  Cumulus Networks, Inc.
 *   et al.
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

#include "lib/if.h"
#include "lib/vrf.h"
#include "lib/zclient.h"
#include "lib/pbr.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_errors.h"

/*
 * This is called to process inbound ZAPI messages.
 *
 * client
 *    the client datastructure
 *
 * msg
 *    the message
 */
extern void zserv_handle_commands(struct zserv *client, struct stream *msg);

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
				    const struct prefix *p,
				    const struct prefix *src_p,
				    struct route_entry *re);
extern int zsend_router_id_update(struct zserv *zclient, struct prefix *p,
				  vrf_id_t vrf_id);
extern int zsend_interface_vrf_update(struct zserv *zclient,
				      struct interface *ifp, vrf_id_t vrf_id);
extern int zsend_interface_link_params(struct zserv *zclient,
				       struct interface *ifp);
extern int zsend_pw_update(struct zserv *client, struct zebra_pw *pw);
extern int zsend_route_notify_owner(struct route_entry *re,
				    const struct prefix *p,
				    enum zapi_route_notify_owner note);
extern int zsend_route_notify_owner_ctx(const struct zebra_dplane_ctx *ctx,
					enum zapi_route_notify_owner note);

extern void zsend_rule_notify_owner(struct zebra_pbr_rule *rule,
				    enum zapi_rule_notify_owner note);
extern void zsend_ipset_notify_owner(struct zebra_pbr_ipset *ipset,
				     enum zapi_ipset_notify_owner note);
extern void
zsend_ipset_entry_notify_owner(struct zebra_pbr_ipset_entry *ipset,
			       enum zapi_ipset_entry_notify_owner note);
extern void zsend_iptable_notify_owner(struct zebra_pbr_iptable *iptable,
				       enum zapi_iptable_notify_owner note);
extern void zserv_nexthop_num_warn(const char *caller, const struct prefix *p,
				   const unsigned int nexthop_num);

extern void zsend_capabilities_all_clients(void);
