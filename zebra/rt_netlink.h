// SPDX-License-Identifier: GPL-2.0-or-later
/* Header file exported by rt_netlink.c to zebra.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_RT_NETLINK_H
#define _ZEBRA_RT_NETLINK_H

#ifdef HAVE_NETLINK

#include "zebra/zebra_mpls.h"
#include "zebra/zebra_dplane.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Additional protocol strings to push into routes
 * If we add anything new here please make sure
 * to update:
 * zebra2proto                 Function
 * proto2zebra                 Function
 * is_selfroute                Function
 * tools/frr                   To flush the route upon exit
 *
 * Finally update this file to allow iproute2 to
 * know about this new route.
 * tools/etc/iproute2/rt_protos.d
 */
#define RTPROT_BGP         186
#define RTPROT_ISIS        187
#define RTPROT_OSPF        188
#define RTPROT_RIP         189
#define RTPROT_RIPNG       190
#if !defined(RTPROT_BABEL)
#define RTPROT_BABEL        42
#endif
#define RTPROT_NHRP        191
#define RTPROT_EIGRP       192
#define RTPROT_LDP         193
#define RTPROT_SHARP       194
#define RTPROT_PBR         195
#define RTPROT_ZSTATIC     196
#define RTPROT_OPENFABRIC  197
#define RTPROT_SRTE        198

void rt_netlink_init(void);

/* MPLS label forwarding table change, using dataplane context information. */
extern ssize_t netlink_mpls_multipath_msg_encode(int cmd,
						 struct zebra_dplane_ctx *ctx,
						 void *buf, size_t buflen);

extern ssize_t netlink_route_multipath_msg_encode(int cmd,
						  struct zebra_dplane_ctx *ctx,
						  uint8_t *data, size_t datalen,
						  bool fpm, bool force_nhg,
						  bool force_rr);
extern ssize_t netlink_macfdb_update_ctx(struct zebra_dplane_ctx *ctx,
					 void *data, size_t datalen);

extern int netlink_route_change(struct nlmsghdr *h, ns_id_t ns_id, int startup);
extern int netlink_route_read(struct zebra_ns *zns);

extern int netlink_nexthop_change(struct nlmsghdr *h, ns_id_t ns_id,
				  int startup);
extern int netlink_nexthop_read(struct zebra_ns *zns);
extern ssize_t netlink_nexthop_msg_encode(uint16_t cmd,
					  const struct zebra_dplane_ctx *ctx,
					  void *buf, size_t buflen, bool fpm);

extern ssize_t netlink_lsp_msg_encoder(struct zebra_dplane_ctx *ctx, void *buf,
				       size_t buflen);

extern int netlink_neigh_change(struct nlmsghdr *h, ns_id_t ns_id);
extern int netlink_macfdb_read(struct zebra_ns *zns);
extern int netlink_macfdb_read_for_bridge(struct zebra_ns *zns,
					  struct interface *ifp,
					  struct interface *br_if,
					  vlanid_t vid);
extern int netlink_macfdb_read_mcast_for_vni(struct zebra_ns *zns,
					     struct interface *ifp, vni_t vni);
extern int netlink_neigh_read(struct zebra_ns *zns);
extern int netlink_neigh_read_for_vlan(struct zebra_ns *zns,
				       struct interface *vlan_if);
extern int netlink_macfdb_read_specific_mac(struct zebra_ns *zns,
					    struct interface *br_if,
					    const struct ethaddr *mac,
					    uint16_t vid);
extern int netlink_neigh_read_specific_ip(const struct ipaddr *ip,
					  struct interface *vlan_if);

struct nl_batch;
extern enum netlink_msg_status
netlink_put_route_update_msg(struct nl_batch *bth,
			     struct zebra_dplane_ctx *ctx);
extern enum netlink_msg_status
netlink_put_nexthop_update_msg(struct nl_batch *bth,
			       struct zebra_dplane_ctx *ctx);
extern enum netlink_msg_status
netlink_put_mac_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx);
extern enum netlink_msg_status
netlink_put_neigh_update_msg(struct nl_batch *bth,
			     struct zebra_dplane_ctx *ctx);
extern enum netlink_msg_status
netlink_put_lsp_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx);
extern enum netlink_msg_status
netlink_put_pw_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx);

int netlink_route_change_read_unicast_internal(struct nlmsghdr *h,
					       ns_id_t ns_id, int startup,
					       struct zebra_dplane_ctx *ctx);

#ifdef NETLINK_DEBUG
const char *nlmsg_type2str(uint16_t type);
const char *af_type2str(int type);
const char *ifi_type2str(int type);
const char *rta_type2str(int type);
const char *rtm_type2str(int type);
const char *ifla_pdr_type2str(int type);
const char *ifla_info_type2str(int type);
const char *rtm_protocol2str(int type);
const char *rtm_scope2str(int type);
const char *rtm_rta2str(int type);
const char *neigh_rta2str(int type);
const char *ifa_rta2str(int type);
const char *nhm_rta2str(int type);
const char *frh_rta2str(int type);
const char *frh_action2str(uint8_t action);
const char *nlmsg_flags2str(uint16_t flags, char *buf, size_t buflen);
const char *if_flags2str(uint32_t flags, char *buf, size_t buflen);
const char *rtm_flags2str(uint32_t flags, char *buf, size_t buflen);
const char *neigh_state2str(uint32_t flags, char *buf, size_t buflen);
const char *neigh_flags2str(uint32_t flags, char *buf, size_t buflen);
const char *ifa_flags2str(uint32_t flags, char *buf, size_t buflen);
const char *nh_flags2str(uint32_t flags, char *buf, size_t buflen);

void nl_dump(void *msg, size_t msglen);

extern int zebra2proto(int proto);

#endif /* NETLINK_DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_RT_NETLINK_H */
