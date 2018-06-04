/* zebra connection and redistribute fucntions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_ZEBRA_H
#define _QUAGGA_BGP_ZEBRA_H

#include "vxlan.h"

extern void bgp_zebra_init(struct thread_master *master);
extern void bgp_zebra_init_tm_connect(struct bgp *bgp);
extern uint32_t bgp_zebra_tm_get_id(void);
extern bool bgp_zebra_tm_chunk_obtained(void);
extern void bgp_zebra_destroy(void);
extern int bgp_zebra_get_table_range(uint32_t chunk_size,
				     uint32_t *start, uint32_t *end);
extern int bgp_if_update_all(void);
extern void bgp_config_write_maxpaths(struct vty *, struct bgp *, afi_t,
				      safi_t);
extern void bgp_config_write_redistribute(struct vty *, struct bgp *, afi_t,
					  safi_t);
extern void bgp_zebra_announce(struct bgp_node *, struct prefix *,
			       struct bgp_info *, struct bgp *, afi_t, safi_t);
extern void bgp_zebra_announce_table(struct bgp *, afi_t, safi_t);
extern void bgp_zebra_withdraw(struct prefix *, struct bgp_info *,
			       struct bgp *, safi_t);

extern void bgp_zebra_initiate_radv(struct bgp *bgp, struct peer *peer);
extern void bgp_zebra_terminate_radv(struct bgp *bgp, struct peer *peer);

extern void bgp_zebra_instance_register(struct bgp *);
extern void bgp_zebra_instance_deregister(struct bgp *);

extern struct bgp_redist *bgp_redist_lookup(struct bgp *, afi_t, uint8_t,
					    unsigned short);
extern struct bgp_redist *bgp_redist_add(struct bgp *, afi_t, uint8_t,
					 unsigned short);
extern int bgp_redistribute_set(struct bgp *, afi_t, int, unsigned short);
extern int bgp_redistribute_resend(struct bgp *, afi_t, int, unsigned short);
extern int bgp_redistribute_rmap_set(struct bgp_redist *, const char *);
extern int bgp_redistribute_metric_set(struct bgp *, struct bgp_redist *, afi_t,
				       int, uint32_t);
extern int bgp_redistribute_unset(struct bgp *, afi_t, int, unsigned short);
extern int bgp_redistribute_unreg(struct bgp *, afi_t, int, unsigned short);

extern struct interface *if_lookup_by_ipv4(struct in_addr *, vrf_id_t);
extern struct interface *if_lookup_by_ipv4_exact(struct in_addr *, vrf_id_t);
extern struct interface *if_lookup_by_ipv6(struct in6_addr *, ifindex_t,
					   vrf_id_t);
extern struct interface *if_lookup_by_ipv6_exact(struct in6_addr *, ifindex_t,
						 vrf_id_t);
extern int bgp_zebra_advertise_subnet(struct bgp *bgp, int advertise,
				      vni_t vni);
extern int bgp_zebra_advertise_gw_macip(struct bgp *, int, vni_t);
extern int bgp_zebra_advertise_all_vni(struct bgp *, int);

extern int bgp_zebra_num_connects(void);

struct bgp_pbr_action;
struct bgp_pbr_match;
struct bgp_pbr_match_entry;
extern void bgp_send_pbr_rule_action(struct bgp_pbr_action *pbra,
				bool install);
extern void bgp_send_pbr_ipset_match(struct bgp_pbr_match *pbrim,
				     bool install);
extern void bgp_send_pbr_ipset_entry_match(struct bgp_pbr_match_entry *pbrime,
				    bool install);
extern void bgp_send_pbr_iptable(struct bgp_pbr_action *pba,
			  struct bgp_pbr_match *pbm,
			  bool install);

extern void bgp_zebra_announce_default(struct bgp *bgp, struct nexthop *nh,
				afi_t afi, uint32_t table_id, bool announce);

#endif /* _QUAGGA_BGP_ZEBRA_H */
