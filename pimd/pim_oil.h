// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_OIL_H
#define PIM_OIL_H

struct pim_interface;

#include "pim_mroute.h"

/*
 * Where did we get this (S,G) from?
 *
 * GM - Learned from IGMP/MLD
 * PIM - Learned from PIM
 * SOURCE - Learned from Source multicast packet received
 * STAR - Inherited
 */
#define PIM_OIF_FLAG_PROTO_GM     (1 << 0)
#define PIM_OIF_FLAG_PROTO_PIM    (1 << 1)
#define PIM_OIF_FLAG_PROTO_STAR   (1 << 2)
#define PIM_OIF_FLAG_PROTO_VXLAN  (1 << 3)
#define PIM_OIF_FLAG_PROTO_ANY                                                 \
	(PIM_OIF_FLAG_PROTO_GM | PIM_OIF_FLAG_PROTO_PIM |                      \
	 PIM_OIF_FLAG_PROTO_STAR | PIM_OIF_FLAG_PROTO_VXLAN)

/* OIF is present in the OIL but must not be used for forwarding traffic */
#define PIM_OIF_FLAG_MUTE         (1 << 4)
/*
 * We need a pimreg vif id from the kernel.
 * Since ifindex == vif id for most cases and the number
 * of expected interfaces is at most 100, using MAXVIFS -1
 * is probably ok.
 * Don't come running to me if this assumption is bad,
 * fix it.
 */
#define PIM_OIF_PIM_REGISTER_VIF   0
#define PIM_MAX_USABLE_VIFS        (MAXVIFS - 1)

struct channel_counts {
	unsigned long long lastused;
	unsigned long origpktcnt;
	unsigned long pktcnt;
	unsigned long oldpktcnt;
	unsigned long origbytecnt;
	unsigned long bytecnt;
	unsigned long oldbytecnt;
	unsigned long origwrong_if;
	unsigned long wrong_if;
	unsigned long oldwrong_if;
};

/*
  qpim_channel_oil_list holds a list of struct channel_oil.

  Each channel_oil.oil is used to control an (S,G) entry in the Kernel
  Multicast Forwarding Cache.

  There is a case when we create a channel_oil but don't install in the kernel

  Case where (S, G) entry not installed in the kernel:
    FRR receives IGMP/PIM (*, G) join and RP is not configured or
    not-reachable, then create a channel_oil for the group G with the incoming
    interface(channel_oil.oil.mfcc_parent) as invalid i.e "MAXVIF" and populate
    the outgoing interface where join is received. Keep this entry in the stack,
    but don't install in the kernel(channel_oil.installed = 0).

  Case where (S, G) entry installed in the kernel:
    When RP is configured and is reachable for the group G, and receiving a
    join if channel_oil is already present then populate the incoming interface
    and install the entry in the kernel, if channel_oil not present, then create
    a new_channel oil(channel_oil.installed = 1).

  is_valid: indicate if this entry is valid to get installed in kernel.
  installed: indicate if this entry is installed in the kernel.

*/
PREDECL_RBTREE_UNIQ(rb_pim_oil);

struct channel_oil {
	struct pim_instance *pim;

	struct rb_pim_oil_item oil_rb;

#if PIM_IPV == 4
	struct mfcctl oil;
#else
	struct mf6cctl oil;
#endif
	int installed;
	int oil_inherited_rescan;
	int oil_size;
	int oil_ref_count;
	time_t oif_creation[MAXVIFS];
	uint32_t oif_flags[MAXVIFS];
	struct channel_counts cc;
	struct pim_upstream *up;
	time_t mroute_creation;
};

#if PIM_IPV == 4
static inline pim_addr *oil_origin(struct channel_oil *c_oil)
{
	return &c_oil->oil.mfcc_origin;
}

static inline pim_addr *oil_mcastgrp(struct channel_oil *c_oil)
{
	return &c_oil->oil.mfcc_mcastgrp;
}

static inline vifi_t *oil_incoming_vif(struct channel_oil *c_oil)
{
	return &c_oil->oil.mfcc_parent;
}

static inline bool oil_if_has(struct channel_oil *c_oil, vifi_t ifi)
{
	return !!c_oil->oil.mfcc_ttls[ifi];
}

static inline void oil_if_set(struct channel_oil *c_oil, vifi_t ifi, uint8_t set)
{
	c_oil->oil.mfcc_ttls[ifi] = set;
}

static inline int oil_if_cmp(struct mfcctl *oil1, struct mfcctl *oil2)
{
	return memcmp(&oil1->mfcc_ttls[0], &oil2->mfcc_ttls[0],
		      sizeof(oil1->mfcc_ttls));
}
#else
static inline pim_addr *oil_origin(struct channel_oil *c_oil)
{
	return &c_oil->oil.mf6cc_origin.sin6_addr;
}

static inline pim_addr *oil_mcastgrp(struct channel_oil *c_oil)
{
	return &c_oil->oil.mf6cc_mcastgrp.sin6_addr;
}

static inline mifi_t *oil_incoming_vif(struct channel_oil *c_oil)
{
	return &c_oil->oil.mf6cc_parent;
}

static inline bool oil_if_has(struct channel_oil *c_oil, mifi_t ifi)
{
	return !!IF_ISSET(ifi, &c_oil->oil.mf6cc_ifset);
}

static inline void oil_if_set(struct channel_oil *c_oil, mifi_t ifi,
			      uint8_t set)
{
	if (set)
		IF_SET(ifi, &c_oil->oil.mf6cc_ifset);
	else
		IF_CLR(ifi, &c_oil->oil.mf6cc_ifset);
}

static inline int oil_if_cmp(struct mf6cctl *oil1, struct mf6cctl *oil2)
{
	return memcmp(&oil1->mf6cc_ifset, &oil2->mf6cc_ifset,
		      sizeof(oil1->mf6cc_ifset));
}
#endif

extern int pim_channel_oil_compare(const struct channel_oil *c1,
				   const struct channel_oil *c2);
DECLARE_RBTREE_UNIQ(rb_pim_oil, struct channel_oil, oil_rb,
                    pim_channel_oil_compare);

void pim_oil_init(struct pim_instance *pim);
void pim_oil_terminate(struct pim_instance *pim);

void pim_channel_oil_free(struct channel_oil *c_oil);
struct channel_oil *pim_find_channel_oil(struct pim_instance *pim,
					 pim_sgaddr *sg);
struct channel_oil *pim_channel_oil_add(struct pim_instance *pim,
					pim_sgaddr *sg, const char *name);
void pim_clear_nocache_state(struct pim_interface *pim_ifp);
struct channel_oil *pim_channel_oil_del(struct channel_oil *c_oil,
					const char *name);

int pim_channel_add_oif(struct channel_oil *c_oil, struct interface *oif,
			uint32_t proto_mask, const char *caller);
int pim_channel_del_oif(struct channel_oil *c_oil, struct interface *oif,
			uint32_t proto_mask, const char *caller);

int pim_channel_oil_empty(struct channel_oil *c_oil);

char *pim_channel_oil_dump(struct channel_oil *c_oil, char *buf, size_t size);

void pim_channel_update_oif_mute(struct channel_oil *c_oil,
		struct pim_interface *pim_ifp);

void pim_channel_oil_upstream_deref(struct channel_oil *c_oil);
void pim_channel_del_inherited_oif(struct channel_oil *c_oil,
				   struct interface *oif, const char *caller);

#endif /* PIM_OIL_H */
