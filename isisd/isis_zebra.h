// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_zebra.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */
#ifndef _ZEBRA_ISIS_ZEBRA_H
#define _ZEBRA_ISIS_ZEBRA_H

#include "isisd.h"

extern struct zclient *zclient;

struct label_chunk {
	uint32_t start;
	uint32_t end;
	uint64_t used_mask;
};
#define CHUNK_SIZE 64

void isis_zebra_init(struct event_loop *master, int instance);
void isis_zebra_stop(void);

struct isis_route_info;
struct sr_adjacency;

void isis_zebra_route_add_route(struct isis *isis,
				struct prefix *prefix,
				struct prefix_ipv6 *src_p,
				struct isis_route_info *route_info);
void isis_zebra_route_del_route(struct isis *isis,
				struct prefix *prefix,
				struct prefix_ipv6 *src_p,
				struct isis_route_info *route_info);
void isis_zebra_prefix_sid_install(struct isis_area *area,
				   struct prefix *prefix,
				   struct isis_sr_psid_info *psid);
void isis_zebra_prefix_sid_uninstall(struct isis_area *area,
				     struct prefix *prefix,
				     struct isis_route_info *rinfo,
				     struct isis_sr_psid_info *psid);
void isis_zebra_send_adjacency_sid(int cmd, const struct sr_adjacency *sra);
int isis_distribute_list_update(int routetype);
void isis_zebra_redistribute_set(afi_t afi, int type, vrf_id_t vrf_id,
				 uint16_t tableid);
void isis_zebra_redistribute_unset(afi_t afi, int type, vrf_id_t vrf_id,
				   uint16_t tableid);
int isis_zebra_rlfa_register(struct isis_spftree *spftree, struct rlfa *rlfa);
void isis_zebra_rlfa_unregister_all(struct isis_spftree *spftree);
bool isis_zebra_label_manager_ready(void);
int isis_zebra_label_manager_connect(void);
int isis_zebra_request_label_range(uint32_t base, uint32_t chunk_size);
int isis_zebra_release_label_range(uint32_t start, uint32_t end);
void isis_zebra_vrf_register(struct isis *isis);
void isis_zebra_vrf_deregister(struct isis *isis);
int isis_zebra_ls_register(bool up);

extern void isis_zebra_srv6_sid_install(struct isis_area *area,
					struct isis_srv6_sid *sid);
extern void isis_zebra_srv6_sid_uninstall(struct isis_area *area,
					  struct isis_srv6_sid *sid);

void isis_zebra_srv6_adj_sid_install(struct srv6_adjacency *sra);
void isis_zebra_srv6_adj_sid_uninstall(struct srv6_adjacency *sra);

extern int isis_zebra_srv6_manager_get_locator_chunk(const char *name);
extern int isis_zebra_srv6_manager_release_locator_chunk(const char *name);

#endif /* _ZEBRA_ISIS_ZEBRA_H */
