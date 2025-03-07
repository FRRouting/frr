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

enum rp_source {
	RP_SRC_NONE = 0,
	RP_SRC_STATIC,
	RP_SRC_BSR,
	RP_SRC_AUTORP,
#if PIM_IPV == 6
	RP_SRC_EMBEDDED_RP,
#endif /* PIM_IPV == 6*/
};

struct rp_info {
	struct prefix group;
	struct pim_rpf rp;
	enum rp_source rp_src;
	int i_am_rp;
	char *plist;
};

#if PIM_IPV == 6
/** Default maximum simultaneous embedded RPs at one time. */
#define PIM_EMBEDDED_RP_MAXIMUM 25
#endif /* PIM_IPV == 6 */

void pim_rp_init(struct pim_instance *pim);
void pim_rp_free(struct pim_instance *pim);

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

#if PIM_IPV == 6
/** Check if address has valid embedded RP value. */
bool pim_embedded_rp_is_embedded(const pim_addr *group) __attribute__((nonnull(1)));

/** Test address against embedded RP group list filter. */
bool pim_embedded_rp_filter_match(const struct pim_instance *pim, const pim_addr *group)
	__attribute__((nonnull(1, 2)));

/**
 * Extract embedded RP address from multicast group.
 *
 * Returns true if successful otherwise false.
 */
bool pim_embedded_rp_extract(const pim_addr *group, pim_addr *rp) __attribute__((nonnull(1, 2)));

/** Allocate new embedded RP. */
void pim_embedded_rp_new(struct pim_instance *pim, const pim_addr *group, const pim_addr *rp)
	__attribute__((nonnull(1, 2, 3)));

/** Remove and free allocated embedded RP. */
void pim_embedded_rp_delete(struct pim_instance *pim, const pim_addr *group)
	__attribute__((nonnull(1, 2)));

/** Free memory allocated by embedded RP information. */
extern void pim_embedded_rp_free(struct pim_instance *pim, struct rp_info *rp_info)
	__attribute__((nonnull(1, 2)));

/** Toggle embedded RP state. */
extern void pim_embedded_rp_enable(struct pim_instance *pim, bool enable)
	__attribute__((nonnull(1)));

/** Configure embedded RP group prefix list. */
extern void pim_embedded_rp_set_group_list(struct pim_instance *pim, const char *group_list)
	__attribute__((nonnull(1)));

/** Configure maximum number of embedded RPs to learn. */
extern void pim_embedded_rp_set_maximum_rps(struct pim_instance *pim, uint32_t maximum)
	__attribute__((nonnull(1)));
#endif /* PIM_IPV == 6 */

#endif
