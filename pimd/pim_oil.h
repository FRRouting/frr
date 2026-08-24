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
 * DM - Dense mode flooding
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
 * Dense mode holds its OIFs directly through `channel_oil_oif_add()` and
 * `channel_oil_oif_delete()` instead of `pim_channel_add_oif()` and
 * `pim_channel_del_oif()`, so it is deliberately left out of
 * `PIM_OIF_FLAG_PROTO_ANY` above: that mask means "a `pim_channel_add_oif()`
 * subscriber other than the one being removed still wants this OIF".
 */
#define PIM_OIF_FLAG_PROTO_DM (1 << 5)

/*
 * Dense mode lost the Assert election on this OIF (RFC 3973 4.6), so traffic
 * must not be forwarded onto that LAN until the Assert is over.
 *
 * This deliberately does not reuse `PIM_OIF_FLAG_MUTE`: that bit is recomputed
 * from scratch by `pim_channel_update_oif_mute()` whenever the MLAG DF role or
 * the VXLAN termination state changes, and that computation knows nothing
 * about the Assert. Sharing a single bit lets either owner drop the other's
 * suppression and resume forwarding a duplicate onto the LAN.
 */
#define PIM_OIF_FLAG_ASSERT_LOSER (1 << 6)

/*
 * Every flag that suppresses an OIF, for clearing them in one go.  Deciding
 * whether an OIF is actually suppressed is `channel_oif_no_forward()` below.
 */
#define PIM_OIF_FLAG_NO_FORWARD (PIM_OIF_FLAG_MUTE | PIM_OIF_FLAG_ASSERT_LOSER)

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

PREDECL_LIST(channel_oif_list);
struct channel_oif {
	struct channel_oif_list_item entry;

	/** Interface index. */
	ifindex_t index;
	/** Interface flags. \see `PIM_OIF_FLAG_*`. */
	uint32_t flags;
	/** Time of creation. */
	time_t creation;
};
DECLARE_LIST(channel_oif_list, struct channel_oif, entry);

extern struct channel_oif *channel_oil_oif_find(struct channel_oil *oil, ifindex_t index);
extern struct channel_oif *channel_oil_oif_add(struct channel_oil *oil, ifindex_t index,
					       uint32_t flags);
extern void channel_oil_oif_delete(struct channel_oil *oil, ifindex_t index, uint32_t flags);
#if PIM_IPV == 4
extern void channel_oil_to_mfcc(struct channel_oil *oil, struct mfcctl *mfcc);
#else
extern void channel_oil_to_mfcc(struct channel_oil *oil, struct mf6cctl *mf6cc);
#endif

/*
 * `PIM_OIF_FLAG_ASSERT_LOSER` only counts while dense mode still owns the OIF,
 * so do not fold this back into a `PIM_OIF_FLAG_NO_FORWARD` mask test.
 */
static inline bool channel_oif_no_forward(const struct channel_oif *oif)
{
	if (CHECK_FLAG(oif->flags, PIM_OIF_FLAG_MUTE))
		return true;

	return CHECK_FLAG(oif->flags, PIM_OIF_FLAG_ASSERT_LOSER) &&
	       CHECK_FLAG(oif->flags, PIM_OIF_FLAG_PROTO_DM);
}

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

	pim_addr source;
	pim_addr group;

	/* Input interface */
	struct channel_oif iif;
	/* List of output interfaces and their state */
	struct channel_oif_list_head oif_list;

	int installed;
	int oil_inherited_rescan;
	int oil_ref_count;
	struct channel_counts cc;
	struct pim_upstream *up;
	time_t mroute_creation;
};

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
extern struct channel_oif *pim_channel_add_dm_oif(struct channel_oil *c_oil, struct interface *ifp);
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
