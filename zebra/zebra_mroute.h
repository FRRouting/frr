// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra_mroute.h
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 */

#ifndef __ZEBRA_MROUTE_H__
#define __ZEBRA_MROUTE_H__

#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mcast_route_data {
	int family;
	struct ipaddr src;
	struct ipaddr grp;
	unsigned int ifindex;
	unsigned long long lastused;
};

void zebra_ipmr_route_stats(ZAPI_HANDLER_ARGS);

/** Custom netlink attribute value definition. */
#define RTA_MRT_EXTRA 64

/** Custom netlink attribute for passing extra multicast route information. */
struct mrt_extra_attr {
	/** Bandwidth threshold in kbps. */
	int32_t spt_threshold;
	/** RPF interface index. */
	int32_t notif_idx;
	/** Multicast flags. */
	uint32_t flags;
	/** RP encapsulated data: source. */
	struct in6_addr local;
	/** RP encapsulated data: destination. */
	struct in6_addr remote;
};

/** Multicast output interface argument. */
struct mroute_oif_arg {
	SLIST_ENTRY(mroute_oif_arg) entry;

	/** Interface index. */
	ifindex_t index;
};
SLIST_HEAD(mroute_oif_list, mroute_oif_arg);

struct mroute_oif_arg *mroute_oif_arg_new(struct mroute_oif_list *oif_list);
void mroute_oif_arg_free(struct mroute_oif_list *oif_list, struct mroute_oif_arg **oif);
void mroute_oif_list_free_all(struct mroute_oif_list *oif_list);

/** Multicast route argument represantation. */
struct mroute_args {
	/** Source address. */
	struct ipaddr source;
	/** Multicast group address. */
	struct ipaddr group;
	/** Flags to signalize different options. */
	uint32_t flags;
	/** Input interface index. */
	ifindex_t input;
	/** Amount of output interfaces. */
	size_t output_amount;
	/** Output interface indexes. */
	struct mroute_oif_list oif_list;
	/** RPF interface information. */
	ifindex_t notif_idx;

	/** Bandwidth threshold information (in kbps). */
	int32_t spt_threshold;

	/** RP encap local information. */
	struct ipaddr local;
	/** RP encap remote information. */
	struct ipaddr remote;

	/** Multicast route operation (`enum dplane_op_e`). */
	int mroute_op;

	/** VRF identification. */
	vrf_id_t vrf_id;
};

/** Handles the multicast route installations (`ZEBRA_MROUTE_EVENT`). */
extern void zmroute_event(struct zserv *client, struct zmsghdr *hdr, struct stream *msg,
			  struct zebra_vrf *zvrf);

/**
 * Starts tracking the multicast routes the clients install, so they are
 * withdrawn from the data plane when their client disconnects.
 */
extern void zebra_mroute_init(void);

/** Frees the multicast routes tracking. */
extern void zebra_mroute_terminate(void);

/**
 * Tell PIM clients that the forwarding plane lost its multicast state and
 * that every installed multicast route must be sent again.
 *
 * \param vrf_id the VRF whose routes must be resynchronized.
 */
extern void zmroute_sync(vrf_id_t vrf_id);

#ifdef __cplusplus
}
#endif

#endif
