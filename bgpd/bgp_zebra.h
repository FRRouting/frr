// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra connection and redistribute fucntions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_ZEBRA_H
#define _QUAGGA_BGP_ZEBRA_H

#include "vxlan.h"

/* Macro to update bgp_original based on bpg_path_info */
#define BGP_ORIGINAL_UPDATE(_bgp_orig, _mpinfo, _bgp)                          \
	((_mpinfo->extra && _mpinfo->extra->vrfleak &&                        \
	  _mpinfo->extra->vrfleak->bgp_orig &&                                \
	  _mpinfo->sub_type == BGP_ROUTE_IMPORTED)                             \
		 ? (_bgp_orig = _mpinfo->extra->vrfleak->bgp_orig)            \
		 : (_bgp_orig = _bgp))

/* Default weight for next hop, if doing weighted ECMP. */
#define BGP_ZEBRA_DEFAULT_NHOP_WEIGHT 1

extern void bgp_zebra_init(struct event_loop *master, unsigned short instance);
extern void bgp_if_init(void);
extern void bgp_zebra_init_tm_connect(struct bgp *bgp);
extern uint32_t bgp_zebra_tm_get_id(void);
extern bool bgp_zebra_tm_chunk_obtained(void);
extern void bgp_zebra_destroy(void);
extern int bgp_zebra_get_table_range(struct zclient *zc, uint32_t chunk_size,
				     uint32_t *start, uint32_t *end);
extern int bgp_if_update_all(void);
extern void bgp_zebra_announce(struct bgp_dest *dest, const struct prefix *p,
			       struct bgp_path_info *path, struct bgp *bgp,
			       afi_t afi, safi_t safi);
extern void bgp_zebra_announce_table(struct bgp *bgp, afi_t afi, safi_t safi);
extern void bgp_zebra_withdraw(const struct prefix *p,
			       struct bgp_path_info *path, struct bgp *bgp,
			       safi_t safi);

/* Announce routes of any bgp subtype of a table to zebra */
extern void bgp_zebra_announce_table_all_subtypes(struct bgp *bgp, afi_t afi,
						  safi_t safi);

/* Withdraw all entries of any subtype in a BGP instances RIB table from Zebra */
extern void bgp_zebra_withdraw_table_all_subtypes(struct bgp *bgp, afi_t afi,
						  safi_t safi);

extern void bgp_zebra_initiate_radv(struct bgp *bgp, struct peer *peer);
extern void bgp_zebra_terminate_radv(struct bgp *bgp, struct peer *peer);

extern void bgp_zebra_instance_register(struct bgp *bgp);
extern void bgp_zebra_instance_deregister(struct bgp *bgp);

extern void bgp_redistribute_redo(struct bgp *bgp);
extern struct bgp_redist *bgp_redist_lookup(struct bgp *bgp, afi_t afi,
					    uint8_t type,
					    unsigned short instance);
extern struct bgp_redist *bgp_redist_add(struct bgp *bgp, afi_t afi,
					 uint8_t type, unsigned short instance);
extern int bgp_redistribute_set(struct bgp *bgp, afi_t afi, int type,
				unsigned short instance, bool changed);
extern int bgp_redistribute_resend(struct bgp *bgp, afi_t afi, int type,
				   unsigned short instance);
extern bool bgp_redistribute_rmap_set(struct bgp_redist *red, const char *name,
				      struct route_map *route_map);
extern bool bgp_redistribute_metric_set(struct bgp *bgp, struct bgp_redist *red,
					afi_t afi, int type, uint32_t metric);
extern void bgp_redistribute_unset(struct bgp *bgp, afi_t afi, int type,
				   unsigned short instance);
extern int bgp_redistribute_unreg(struct bgp *bgp, afi_t afi, int type,
				  unsigned short instance);

extern struct interface *if_lookup_by_ipv4(struct in_addr *addr,
					   vrf_id_t vrf_id);
extern struct interface *if_lookup_by_ipv4_exact(struct in_addr *addr,
						 vrf_id_t vrf_id);
extern struct interface *if_lookup_by_ipv6(struct in6_addr *addr,
					   ifindex_t ifindex, vrf_id_t vrf_id);
extern struct interface *if_lookup_by_ipv6_exact(struct in6_addr *addr,
						 ifindex_t ifindex,
						 vrf_id_t vrf_id);
extern int bgp_zebra_advertise_subnet(struct bgp *bgp, int advertise,
				      vni_t vni);
extern int bgp_zebra_advertise_gw_macip(struct bgp *bgp, int advertise,
					vni_t vni);
extern int bgp_zebra_advertise_svi_macip(struct bgp *bgp, int advertise,
					 vni_t vni);
extern int bgp_zebra_advertise_all_vni(struct bgp *bgp, int advertise);
extern int bgp_zebra_dup_addr_detection(struct bgp *bgp);
extern int bgp_zebra_vxlan_flood_control(struct bgp *bgp,
					 enum vxlan_flood_control flood_ctrl);

extern int bgp_zebra_num_connects(void);

extern bool bgp_zebra_nexthop_set(union sockunion *local,
				  union sockunion *remote,
				  struct bgp_nexthop *nexthop,
				  struct peer *peer);
struct bgp_pbr_action;
struct bgp_pbr_match;
struct bgp_pbr_rule;
struct bgp_pbr_match_entry;

extern void bgp_send_pbr_rule_action(struct bgp_pbr_action *pbra,
				     struct bgp_pbr_rule *pbr,
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
extern int bgp_zebra_send_capabilities(struct bgp *bgp, bool disable);
extern int bgp_zebra_update(struct bgp *bgp, afi_t afi, safi_t safi,
			    enum zserv_client_capabilities);
extern int bgp_zebra_stale_timer_update(struct bgp *bgp);
extern int bgp_zebra_srv6_manager_get_locator_chunk(const char *name);
extern int bgp_zebra_srv6_manager_release_locator_chunk(const char *name);
extern void bgp_zebra_send_nexthop_label(int cmd, mpls_label_t label,
					 ifindex_t index, vrf_id_t vrfid,
					 enum lsp_types_t ltype,
					 struct prefix *p, uint32_t num_labels,
					 mpls_label_t out_labels[]);
extern bool bgp_zebra_request_label_range(uint32_t base, uint32_t chunk_size);
extern void bgp_zebra_release_label_range(uint32_t start, uint32_t end);
#endif /* _QUAGGA_BGP_ZEBRA_H */
