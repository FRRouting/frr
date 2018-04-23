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

/*
 * This is called to process inbound ZAPI messages.
 *
 * client
 *    the client datastructure
 *
 * hdr
 *    the message header
 *
 * msg
 *    the message contents, without the header
 *
 * zvrf
 *    the vrf
 */
extern void zserv_handle_commands(struct zserv *client, struct zmsghdr *hdr,
				  struct stream *msg, struct zebra_vrf *zvrf);

extern int zsend_vrf_add(struct zserv *, struct zebra_vrf *);
extern int zsend_vrf_delete(struct zserv *, struct zebra_vrf *);
extern int zsend_interface_add(struct zserv *, struct interface *);
extern int zsend_interface_delete(struct zserv *, struct interface *);
extern int zsend_interface_addresses(struct zserv *, struct interface *);
extern int zsend_interface_address(int, struct zserv *, struct interface *,
				   struct connected *);
extern void nbr_connected_add_ipv6(struct interface *, struct in6_addr *);
extern void nbr_connected_delete_ipv6(struct interface *, struct in6_addr *);
extern int zsend_interface_update(int, struct zserv *, struct interface *);
extern int zsend_redistribute_route(int, struct zserv *, struct prefix *,
				    struct prefix *, struct route_entry *);
extern int zsend_router_id_update(struct zserv *, struct prefix *, vrf_id_t);
extern int zsend_interface_vrf_update(struct zserv *, struct interface *,
				      vrf_id_t);
extern int zsend_interface_link_params(struct zserv *, struct interface *);
extern int zsend_pw_update(struct zserv *, struct zebra_pw *);
extern int zsend_route_notify_owner(struct route_entry *re, struct prefix *p,
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
extern void zserv_nexthop_num_warn(const char *, const struct prefix *,
				   const unsigned int);
