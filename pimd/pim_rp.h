// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
 */
#ifndef PIM_RP_H
#define PIM_RP_H

#include <zebra.h>
#include "prefix.h"
#include "vty.h"
#include "plist.h"
#include "pim_rpf.h"
#include "lib/json.h"

struct pim_interface;

enum rp_source { RP_SRC_NONE = 0, RP_SRC_STATIC, RP_SRC_BSR, RP_SRC_AUTORP };

struct rp_info {
	struct prefix group;
	struct pim_rpf rp;
	enum rp_source rp_src;
	int i_am_rp;
	char *plist;
};

void pim_rp_init(struct pim_instance *pim);
void pim_rp_free(struct pim_instance *pim);

void pim_rp_list_hash_clean(void *data);

int pim_rp_new(struct pim_instance *pim, pim_addr rp_addr, struct prefix group,
	       const char *plist, enum rp_source rp_src_flag);
void pim_rp_del_config(struct pim_instance *pim, pim_addr rp_addr,
		       const char *group, const char *plist);
int pim_rp_del(struct pim_instance *pim, pim_addr rp_addr, struct prefix group,
	       const char *plist, enum rp_source rp_src_flag);
int pim_rp_change(struct pim_instance *pim, pim_addr new_rp_addr,
		  struct prefix group, enum rp_source rp_src_flag);
void pim_rp_prefix_list_update(struct pim_instance *pim,
			       struct prefix_list *plist);

int pim_rp_config_write(struct pim_instance *pim, struct vty *vty);

void pim_rp_setup(struct pim_instance *pim);

int pim_rp_i_am_rp(struct pim_instance *pim, pim_addr group);
void pim_rp_check_on_if_add(struct pim_interface *pim_ifp);
void pim_i_am_rp_re_evaluate(struct pim_instance *pim);

bool pim_rp_check_is_my_ip_address(struct pim_instance *pim,
				   struct in_addr dest_addr);

int pim_rp_set_upstream_addr(struct pim_instance *pim, pim_addr *up,
			     pim_addr source, pim_addr group);

struct pim_rpf *pim_rp_g(struct pim_instance *pim, pim_addr group);

#define I_am_RP(P, G)  pim_rp_i_am_rp ((P), (G))
#define RP(P, G)       pim_rp_g ((P), (G))

void pim_rp_show_information(struct pim_instance *pim, struct prefix *range,
			     struct vty *vty, json_object *json);
void pim_resolve_rp_nh(struct pim_instance *pim, struct pim_neighbor *nbr);
int pim_rp_list_cmp(void *v1, void *v2);
struct rp_info *pim_rp_find_match_group(struct pim_instance *pim,
					const struct prefix *group);
void pim_upstream_update(struct pim_instance *pim, struct pim_upstream *up);
void pim_rp_refresh_group_to_rp_mapping(struct pim_instance *pim);
#endif
