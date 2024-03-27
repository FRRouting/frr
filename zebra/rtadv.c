// SPDX-License-Identifier: GPL-2.0-or-later
/* Router advertisement
 * Copyright (C) 2016 Cumulus Networks
 * Copyright (C) 2005 6WIND <jean-mickael.guerin@6wind.com>
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>
#include <netinet/icmp6.h>

#include "memory.h"
#include "sockopt.h"
#include "frrevent.h"
#include "if.h"
#include "stream.h"
#include "log.h"
#include "prefix.h"
#include "linklist.h"
#include "command.h"
#include "privs.h"
#include "vrf.h"
#include "ns.h"
#include "lib_errors.h"

#include "zebra/interface.h"
#include "zebra/rtadv.h"
#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_router.h"

extern struct zebra_privs_t zserv_privs;

static uint32_t interfaces_configured_for_ra_from_bgp;
#define RTADV_ADATA_SIZE 1024

#if defined(HAVE_RTADV)

#include "zebra/rtadv_clippy.c"

DEFINE_MTYPE_STATIC(ZEBRA, RTADV_PREFIX, "Router Advertisement Prefix");
DEFINE_MTYPE_STATIC(ZEBRA, ADV_IF, "Advertised Interface");

#ifdef OPEN_BSD
#include <netinet/icmp6.h>
#endif

/* If RFC2133 definition is used. */
#ifndef IPV6_JOIN_GROUP
#define IPV6_JOIN_GROUP  IPV6_ADD_MEMBERSHIP
#endif
#ifndef IPV6_LEAVE_GROUP
#define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP
#endif

#define ALLNODE   "ff02::1"
#define ALLROUTER "ff02::2"

/* adv list node */
struct adv_if {
	char name[IFNAMSIZ];
	struct adv_if_list_item list_item;
};

static int adv_if_cmp(const struct adv_if *a, const struct adv_if *b)
{
	return if_cmp_name_func(a->name, b->name);
}

DECLARE_SORTLIST_UNIQ(adv_if_list, struct adv_if, list_item, adv_if_cmp);

static int rtadv_prefix_cmp(const struct rtadv_prefix *a,
			    const struct rtadv_prefix *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}

DECLARE_RBTREE_UNIQ(rtadv_prefixes, struct rtadv_prefix, item,
		    rtadv_prefix_cmp);

DEFINE_MTYPE_STATIC(ZEBRA, RTADV_RDNSS, "Router Advertisement RDNSS");
DEFINE_MTYPE_STATIC(ZEBRA, RTADV_DNSSL, "Router Advertisement DNSSL");

/* Order is intentional.  Matches RFC4191.  This array is also used for
   command matching, so only modify with care. */
static const char *const rtadv_pref_strs[] = {
	"medium", "high", "INVALID", "low", 0
};

enum rtadv_event {
	RTADV_START,
	RTADV_STOP,
	RTADV_TIMER,
	RTADV_TIMER_MSEC,
	RTADV_READ
};

static void rtadv_event(struct zebra_vrf *, enum rtadv_event, int);

static int if_join_all_router(int, struct interface *);
static int if_leave_all_router(int, struct interface *);

static struct zebra_vrf *rtadv_interface_get_zvrf(const struct interface *ifp)
{
	/* We use the default vrf for rtadv handling except in netns */
	if (!vrf_is_backend_netns())
		return vrf_info_lookup(VRF_DEFAULT);

	return ifp->vrf->info;
}

static int rtadv_increment_received(struct zebra_vrf *zvrf, ifindex_t *ifindex)
{
	int ret = -1;
	struct interface *iface;
	struct zebra_if *zif;

	iface = if_lookup_by_index(*ifindex, zvrf->vrf->vrf_id);
	if (iface && iface->info) {
		zif = iface->info;
		zif->ra_rcvd++;
		ret = 0;
	}
	return ret;
}

static int rtadv_recv_packet(struct zebra_vrf *zvrf, int sock, uint8_t *buf,
			     int buflen, struct sockaddr_in6 *from,
			     ifindex_t *ifindex, int *hoplimit)
{
	int ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsgptr;
	struct in6_addr dst;

	char adata[1024];

	/* Fill in message and iovec. */
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)from;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = sizeof(adata);
	iov.iov_base = buf;
	iov.iov_len = buflen;

	/* If recvmsg fail return minus value. */
	ret = recvmsg(sock, &msg, 0);
	if (ret < 0)
		return ret;

	for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL;
	     cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
		/* I want interface index which this packet comes from. */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6
		    && cmsgptr->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *ptr;

			ptr = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
			*ifindex = ptr->ipi6_ifindex;
			memcpy(&dst, &ptr->ipi6_addr, sizeof(ptr->ipi6_addr));
		}

		/* Incoming packet's hop limit. */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6
		    && cmsgptr->cmsg_type == IPV6_HOPLIMIT) {
			int *hoptr = (int *)CMSG_DATA(cmsgptr);
			*hoplimit = *hoptr;
		}
	}

	rtadv_increment_received(zvrf, ifindex);
	return ret;
}

#define RTADV_MSG_SIZE 4096

/* Send router advertisement packet. */
static void rtadv_send_packet(int sock, struct interface *ifp,
			      enum ipv6_nd_suppress_ra_status stop)
{
	struct msghdr msg = { 0 };
	struct iovec iov = { 0 };
	struct cmsghdr *cmsgptr;
	struct in6_pktinfo *pkt;
	struct sockaddr_in6 addr = { 0 };
	unsigned char buf[RTADV_MSG_SIZE] = { 0 };
	char adata[RTADV_ADATA_SIZE] = { 0 };

	struct nd_router_advert *rtadv;
	int ret;
	int len = 0;
	struct zebra_if *zif;
	struct rtadv_prefix *rprefix;
	uint8_t all_nodes_addr[] = {0xff, 0x02, 0, 0, 0, 0, 0, 0,
				    0,    0,    0, 0, 0, 0, 0, 1};
	struct listnode *node;
	uint16_t pkt_RouterLifetime;

	/* Logging of packet. */
	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s(%s:%u): Tx RA, socket %u", ifp->name,
			   ifp->vrf->name, ifp->ifindex, sock);

	/* Fill in sockaddr_in6. */
	memset(&addr, 0, sizeof(struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
#ifdef SIN6_LEN
	addr.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
	addr.sin6_port = htons(IPPROTO_ICMPV6);
	IPV6_ADDR_COPY(&addr.sin6_addr, all_nodes_addr);

	/* Fetch interface information. */
	zif = ifp->info;

	/* Make router advertisement message. */
	rtadv = (struct nd_router_advert *)buf;

	rtadv->nd_ra_type = ND_ROUTER_ADVERT;
	rtadv->nd_ra_code = 0;
	rtadv->nd_ra_cksum = 0;

	rtadv->nd_ra_curhoplimit = zif->rtadv.AdvCurHopLimit;

	/* RFC4191: Default Router Preference is 0 if Router Lifetime is 0. */
	rtadv->nd_ra_flags_reserved = zif->rtadv.AdvDefaultLifetime == 0
					      ? 0
					      : zif->rtadv.DefaultPreference;
	rtadv->nd_ra_flags_reserved <<= 3;

	if (zif->rtadv.AdvManagedFlag)
		rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_MANAGED;
	if (zif->rtadv.AdvOtherConfigFlag)
		rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;
	if (zif->rtadv.AdvHomeAgentFlag)
		rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_HOME_AGENT;
	/* Note that according to Neighbor Discovery (RFC 4861 [18]),
	 * AdvDefaultLifetime is by default based on the value of
	 * MaxRtrAdvInterval.  AdvDefaultLifetime is used in the Router Lifetime
	 * field of Router Advertisements.  Given that this field is expressed
	 * in seconds, a small MaxRtrAdvInterval value can result in a zero
	 * value for this field.  To prevent this, routers SHOULD keep
	 * AdvDefaultLifetime in at least one second, even if the use of
	 * MaxRtrAdvInterval would result in a smaller value. -- RFC6275, 7.5 */
	pkt_RouterLifetime =
		zif->rtadv.AdvDefaultLifetime != -1
			? zif->rtadv.AdvDefaultLifetime
			: MAX(1, 0.003 * zif->rtadv.MaxRtrAdvInterval);

	/* send RA lifetime of 0 before stopping. rfc4861/6.2.5 */
	rtadv->nd_ra_router_lifetime =
		(stop == RA_SUPPRESS) ? htons(0) : htons(pkt_RouterLifetime);
	rtadv->nd_ra_reachable = htonl(zif->rtadv.AdvReachableTime);
	rtadv->nd_ra_retransmit = htonl(zif->rtadv.AdvRetransTimer);

	len = sizeof(struct nd_router_advert);

	/* If both the Home Agent Preference and Home Agent Lifetime are set to
	 * their default values specified above, this option SHOULD NOT be
	 * included in the Router Advertisement messages sent by this home
	 * agent. -- RFC6275, 7.4 */
	if (zif->rtadv.AdvHomeAgentFlag
	    && (zif->rtadv.HomeAgentPreference
		|| zif->rtadv.HomeAgentLifetime != -1)) {
		struct nd_opt_homeagent_info *ndopt_hai =
			(struct nd_opt_homeagent_info *)(buf + len);
		ndopt_hai->nd_opt_hai_type = ND_OPT_HA_INFORMATION;
		ndopt_hai->nd_opt_hai_len = 1;
		ndopt_hai->nd_opt_hai_reserved = 0;
		ndopt_hai->nd_opt_hai_preference =
			htons(zif->rtadv.HomeAgentPreference);
		/* 16-bit unsigned integer.  The lifetime associated with the
		 * home
		 * agent in units of seconds.  The default value is the same as
		 * the
		 * Router Lifetime, as specified in the main body of the Router
		 * Advertisement.  The maximum value corresponds to 18.2 hours.
		 * A
		 * value of 0 MUST NOT be used. -- RFC6275, 7.5 */
		ndopt_hai->nd_opt_hai_lifetime =
			htons(zif->rtadv.HomeAgentLifetime != -1
				      ? zif->rtadv.HomeAgentLifetime
				      : MAX(1, pkt_RouterLifetime) /* 0 is OK
								      for RL,
								      but not
								      for HAL*/
			      );
		len += sizeof(struct nd_opt_homeagent_info);
	}

	if (zif->rtadv.AdvIntervalOption) {
		struct nd_opt_adv_interval *ndopt_adv =
			(struct nd_opt_adv_interval *)(buf + len);
		ndopt_adv->nd_opt_ai_type = ND_OPT_ADV_INTERVAL;
		ndopt_adv->nd_opt_ai_len = 1;
		ndopt_adv->nd_opt_ai_reserved = 0;
		ndopt_adv->nd_opt_ai_interval =
			htonl(zif->rtadv.MaxRtrAdvInterval);
		len += sizeof(struct nd_opt_adv_interval);
	}

	/* Fill in prefix. */
	frr_each (rtadv_prefixes, zif->rtadv.prefixes, rprefix) {
		struct nd_opt_prefix_info *pinfo;

		pinfo = (struct nd_opt_prefix_info *)(buf + len);

		pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		pinfo->nd_opt_pi_len = 4;
		pinfo->nd_opt_pi_prefix_len = rprefix->prefix.prefixlen;

		pinfo->nd_opt_pi_flags_reserved = 0;
		if (rprefix->AdvOnLinkFlag)
			pinfo->nd_opt_pi_flags_reserved |=
				ND_OPT_PI_FLAG_ONLINK;
		if (rprefix->AdvAutonomousFlag)
			pinfo->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
		if (rprefix->AdvRouterAddressFlag)
			pinfo->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_RADDR;

		pinfo->nd_opt_pi_valid_time = htonl(rprefix->AdvValidLifetime);
		pinfo->nd_opt_pi_preferred_time =
			htonl(rprefix->AdvPreferredLifetime);
		pinfo->nd_opt_pi_reserved2 = 0;

		IPV6_ADDR_COPY(&pinfo->nd_opt_pi_prefix,
			       &rprefix->prefix.prefix);

		len += sizeof(struct nd_opt_prefix_info);
	}

	/* Hardware address. */
	if (ifp->hw_addr_len != 0) {
		buf[len++] = ND_OPT_SOURCE_LINKADDR;

		/* Option length should be rounded up to next octet if
		   the link address does not end on an octet boundary. */
		buf[len++] = (ifp->hw_addr_len + 9) >> 3;

		memcpy(buf + len, ifp->hw_addr, ifp->hw_addr_len);
		len += ifp->hw_addr_len;

		/* Pad option to end on an octet boundary. */
		memset(buf + len, 0, -(ifp->hw_addr_len + 2) & 0x7);
		len += -(ifp->hw_addr_len + 2) & 0x7;
	}

	/* MTU */
	if (zif->rtadv.AdvLinkMTU) {
		struct nd_opt_mtu *opt = (struct nd_opt_mtu *)(buf + len);
		opt->nd_opt_mtu_type = ND_OPT_MTU;
		opt->nd_opt_mtu_len = 1;
		opt->nd_opt_mtu_reserved = 0;
		opt->nd_opt_mtu_mtu = htonl(zif->rtadv.AdvLinkMTU);
		len += sizeof(struct nd_opt_mtu);
	}

	/*
	 * There is no limit on the number of configurable recursive DNS
	 * servers or search list entries. We don't want the RA message
	 * to exceed the link's MTU (risking fragmentation) or even
	 * blow the stack buffer allocated for it.
	 */
	size_t max_len = MIN(ifp->mtu6 - 40, sizeof(buf));

	/* Recursive DNS servers */
	struct rtadv_rdnss *rdnss;

	for (ALL_LIST_ELEMENTS_RO(zif->rtadv.AdvRDNSSList, node, rdnss)) {
		size_t opt_len =
			sizeof(struct nd_opt_rdnss) + sizeof(struct in6_addr);

		if (len + opt_len > max_len) {
			zlog_warn(
				"%s(%s:%u): Tx RA: RDNSS option would exceed MTU, omitting it",
				ifp->name, ifp->vrf->name, ifp->ifindex);
			goto no_more_opts;
		}
		struct nd_opt_rdnss *opt = (struct nd_opt_rdnss *)(buf + len);

		opt->nd_opt_rdnss_type = ND_OPT_RDNSS;
		opt->nd_opt_rdnss_len = opt_len / 8;
		opt->nd_opt_rdnss_reserved = 0;
		opt->nd_opt_rdnss_lifetime = htonl(
			rdnss->lifetime_set
				? rdnss->lifetime
				: MAX(1, 0.003 * zif->rtadv.MaxRtrAdvInterval));

		len += sizeof(struct nd_opt_rdnss);

		IPV6_ADDR_COPY(buf + len, &rdnss->addr);
		len += sizeof(struct in6_addr);
	}

	/* DNS search list */
	struct rtadv_dnssl *dnssl;

	for (ALL_LIST_ELEMENTS_RO(zif->rtadv.AdvDNSSLList, node, dnssl)) {
		size_t opt_len = sizeof(struct nd_opt_dnssl)
				 + ((dnssl->encoded_len + 7) & ~7);

		if (len + opt_len > max_len) {
			zlog_warn(
				"%s(%u): Tx RA: DNSSL option would exceed MTU, omitting it",
				ifp->name, ifp->ifindex);
			goto no_more_opts;
		}
		struct nd_opt_dnssl *opt = (struct nd_opt_dnssl *)(buf + len);

		opt->nd_opt_dnssl_type = ND_OPT_DNSSL;
		opt->nd_opt_dnssl_len = opt_len / 8;
		opt->nd_opt_dnssl_reserved = 0;
		opt->nd_opt_dnssl_lifetime = htonl(
			dnssl->lifetime_set
				? dnssl->lifetime
				: MAX(1, 0.003 * zif->rtadv.MaxRtrAdvInterval));

		len += sizeof(struct nd_opt_dnssl);

		memcpy(buf + len, dnssl->encoded_name, dnssl->encoded_len);
		len += dnssl->encoded_len;

		/* Zero-pad to 8-octet boundary */
		while (len % 8)
			buf[len++] = '\0';
	}

no_more_opts:

	msg.msg_name = (void *)&addr;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	msg.msg_flags = 0;
	iov.iov_base = buf;
	iov.iov_len = len;

	cmsgptr = CMSG_FIRSTHDR(&msg);
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;

	pkt = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
	memset(&pkt->ipi6_addr, 0, sizeof(struct in6_addr));
	pkt->ipi6_ifindex = ifp->ifindex;

	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s(%u): Tx RA failed, socket %u error %d (%s)",
			     ifp->name, ifp->ifindex, sock, errno,
			     safe_strerror(errno));
	} else
		zif->ra_sent++;
}

static void rtadv_timer(struct event *thread)
{
	struct zebra_vrf *zvrf = EVENT_ARG(thread);
	struct vrf *vrf;
	struct interface *ifp;
	struct zebra_if *zif;
	int period;

	zvrf->rtadv.ra_timer = NULL;
	if (adv_if_list_count(&zvrf->rtadv.adv_msec_if) == 0) {
		period = 1000; /* 1 s */
		rtadv_event(zvrf, RTADV_TIMER, 1 /* 1 s */);
	} else {
		period = 10; /* 10 ms */
		rtadv_event(zvrf, RTADV_TIMER_MSEC, 10 /* 10 ms */);
	}

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id)
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (if_is_loopback(ifp) || !if_is_operative(ifp) ||
			    IS_ZEBRA_IF_BRIDGE_SLAVE(ifp) ||
			    !connected_get_linklocal(ifp) ||
			    (vrf_is_backend_netns() &&
			     ifp->vrf->vrf_id != zvrf->vrf->vrf_id))
				continue;

			zif = ifp->info;

			if (zif->rtadv.AdvSendAdvertisements) {
				if (zif->rtadv.inFastRexmit
				    && zif->rtadv.UseFastRexmit) {
					/* We assume we fast rexmit every sec so
					 * no
					 * additional vars */
					if (--zif->rtadv.NumFastReXmitsRemain
					    <= 0)
						zif->rtadv.inFastRexmit = 0;

					if (IS_ZEBRA_DEBUG_SEND)
						zlog_debug(
							"Fast RA Rexmit on interface %s(%s:%u)",
							ifp->name,
							ifp->vrf->name,
							ifp->ifindex);

					rtadv_send_packet(zvrf->rtadv.sock, ifp,
							  RA_ENABLE);
				} else {
					zif->rtadv.AdvIntervalTimer -= period;
					if (zif->rtadv.AdvIntervalTimer <= 0) {
						/* FIXME: using
						   MaxRtrAdvInterval each
						   time isn't what section
						   6.2.4 of RFC4861 tells to do.
						   */
						zif->rtadv.AdvIntervalTimer =
							zif->rtadv
								.MaxRtrAdvInterval;
						rtadv_send_packet(
							zvrf->rtadv.sock, ifp,
							RA_ENABLE);
					}
				}
			}
		}
}

static void rtadv_process_solicit(struct interface *ifp)
{
	struct zebra_vrf *zvrf;
	struct zebra_if *zif;

	zvrf = rtadv_interface_get_zvrf(ifp);
	assert(zvrf);
	zif = ifp->info;

	/*
	 * If FastRetransmit is enabled, send the RA immediately.
	 * If not enabled but it has been more than MIN_DELAY_BETWEEN_RAS
	 * (3 seconds) since the last RA was sent, send it now and reset
	 * the timer to start at the max (configured) again.
	 * If not enabled and it is less than 3 seconds since the last
	 * RA packet was sent, set the timer for 3 seconds so the next
	 * one will be sent with a minimum of 3 seconds between RAs.
	 * RFC4861 sec 6.2.6
	 */
	if ((zif->rtadv.UseFastRexmit)
	    || (zif->rtadv.AdvIntervalTimer <=
		(zif->rtadv.MaxRtrAdvInterval - MIN_DELAY_BETWEEN_RAS))) {
		rtadv_send_packet(zvrf->rtadv.sock, ifp, RA_ENABLE);
		zif->rtadv.AdvIntervalTimer = zif->rtadv.MaxRtrAdvInterval;
	} else
		zif->rtadv.AdvIntervalTimer = MIN_DELAY_BETWEEN_RAS;
}

static const char *rtadv_optionalhdr2str(uint8_t opt_type)
{
	switch (opt_type) {
	case ND_OPT_SOURCE_LINKADDR:
		return "Optional Source Link Address";
	case ND_OPT_TARGET_LINKADDR:
		return "Optional Target Link Address";
	case ND_OPT_PREFIX_INFORMATION:
		return "Optional Prefix Information";
	case ND_OPT_REDIRECTED_HEADER:
		return "Optional Redirected Header";
	case ND_OPT_MTU:
		return "Optional MTU";
	case ND_OPT_RTR_ADV_INTERVAL:
		return "Optional Advertisement Interval";
	case ND_OPT_HOME_AGENT_INFO:
		return "Optional Home Agent Information";
	}

	return "Unknown Optional Type";
}

/*
 * This function processes optional attributes off of
 * end of a RA packet received.  At this point in
 * time we only care about this in one situation
 * which is when a interface does not have a LL
 * v6 address.  We still need to be able to install
 * the mac address for v4 to v6 resolution
 */
static void rtadv_process_optional(uint8_t *optional, unsigned int len,
				   struct interface *ifp,
				   struct sockaddr_in6 *addr)
{
	char *mac;

	while (len > 0) {
		struct nd_opt_hdr *opt_hdr = (struct nd_opt_hdr *)optional;

		switch(opt_hdr->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
			mac = (char *)(optional+2);
			if_nbr_mac_to_ipv4ll_neigh_update(ifp, mac,
							  &addr->sin6_addr, 1);
			break;
		default:
			if (IS_ZEBRA_DEBUG_PACKET)
				zlog_debug(
					"%s:Received Packet with optional Header type %s(%u) that is being ignored",
					__func__,
					rtadv_optionalhdr2str(
						opt_hdr->nd_opt_type),
					opt_hdr->nd_opt_type);
			break;
		}

		len -= 8 * opt_hdr->nd_opt_len;
		optional += 8 * opt_hdr->nd_opt_len;
	}
}

static void rtadv_process_advert(uint8_t *msg, unsigned int len,
				 struct interface *ifp,
				 struct sockaddr_in6 *addr)
{
	struct nd_router_advert *radvert;
	char addr_str[INET6_ADDRSTRLEN];
	struct zebra_if *zif;
	struct prefix p;

	zif = ifp->info;

	inet_ntop(AF_INET6, &addr->sin6_addr, addr_str, INET6_ADDRSTRLEN);

	if (len < sizeof(struct nd_router_advert)) {
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_debug(
				"%s(%s:%u): Rx RA with invalid length %d from %s",
				ifp->name, ifp->vrf->name, ifp->ifindex, len,
				addr_str);
		return;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
		rtadv_process_optional(msg + sizeof(struct nd_router_advert),
				       len - sizeof(struct nd_router_advert),
				       ifp, addr);
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_debug(
				"%s(%s:%u): Rx RA with non-linklocal source address from %s",
				ifp->name, ifp->vrf->name, ifp->ifindex,
				addr_str);
		return;
	}

	radvert = (struct nd_router_advert *)msg;

#define SIXHOUR2USEC (int64_t)6 * 60 * 60 * 1000000

	if ((radvert->nd_ra_curhoplimit && zif->rtadv.AdvCurHopLimit) &&
	    (radvert->nd_ra_curhoplimit != zif->rtadv.AdvCurHopLimit) &&
	    (monotime_since(&zif->rtadv.lastadvcurhoplimit, NULL) >
		     SIXHOUR2USEC ||
	     zif->rtadv.lastadvcurhoplimit.tv_sec == 0)) {
		flog_warn(
			EC_ZEBRA_RA_PARAM_MISMATCH,
			"%s(%u): Rx RA - our AdvCurHopLimit (%u) doesn't agree with %s (%u)",
			ifp->name, ifp->ifindex, zif->rtadv.AdvCurHopLimit,
			addr_str, radvert->nd_ra_curhoplimit);
		monotime(&zif->rtadv.lastadvcurhoplimit);
	}

	if ((radvert->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED) &&
	    !zif->rtadv.AdvManagedFlag &&
	    (monotime_since(&zif->rtadv.lastadvmanagedflag, NULL) >
		     SIXHOUR2USEC ||
	     zif->rtadv.lastadvmanagedflag.tv_sec == 0)) {
		flog_warn(
			EC_ZEBRA_RA_PARAM_MISMATCH,
			"%s(%u): Rx RA - our AdvManagedFlag (%u) doesn't agree with %s (%u)",
			ifp->name, ifp->ifindex, zif->rtadv.AdvManagedFlag,
			addr_str,
			!!CHECK_FLAG(radvert->nd_ra_flags_reserved,
				     ND_RA_FLAG_MANAGED));
		monotime(&zif->rtadv.lastadvmanagedflag);
	}

	if ((radvert->nd_ra_flags_reserved & ND_RA_FLAG_OTHER) &&
	    !zif->rtadv.AdvOtherConfigFlag &&
	    (monotime_since(&zif->rtadv.lastadvotherconfigflag, NULL) >
		     SIXHOUR2USEC ||
	     zif->rtadv.lastadvotherconfigflag.tv_sec == 0)) {
		flog_warn(
			EC_ZEBRA_RA_PARAM_MISMATCH,
			"%s(%u): Rx RA - our AdvOtherConfigFlag (%u) doesn't agree with %s (%u)",
			ifp->name, ifp->ifindex, zif->rtadv.AdvOtherConfigFlag,
			addr_str,
			!!CHECK_FLAG(radvert->nd_ra_flags_reserved,
				     ND_RA_FLAG_OTHER));
		monotime(&zif->rtadv.lastadvotherconfigflag);
	}

	if ((radvert->nd_ra_reachable && zif->rtadv.AdvReachableTime) &&
	    (ntohl(radvert->nd_ra_reachable) != zif->rtadv.AdvReachableTime) &&
	    (monotime_since(&zif->rtadv.lastadvreachabletime, NULL) >
		     SIXHOUR2USEC ||
	     zif->rtadv.lastadvreachabletime.tv_sec == 0)) {
		flog_warn(
			EC_ZEBRA_RA_PARAM_MISMATCH,
			"%s(%u): Rx RA - our AdvReachableTime (%u) doesn't agree with %s (%u)",
			ifp->name, ifp->ifindex, zif->rtadv.AdvReachableTime,
			addr_str, ntohl(radvert->nd_ra_reachable));
		monotime(&zif->rtadv.lastadvreachabletime);
	}

	if ((radvert->nd_ra_retransmit && zif->rtadv.AdvRetransTimer) &&
	    (ntohl(radvert->nd_ra_retransmit) !=
	     (unsigned int)zif->rtadv.AdvRetransTimer) &&
	    (monotime_since(&zif->rtadv.lastadvretranstimer, NULL) >
		     SIXHOUR2USEC ||
	     zif->rtadv.lastadvretranstimer.tv_sec == 0)) {
		flog_warn(
			EC_ZEBRA_RA_PARAM_MISMATCH,
			"%s(%u): Rx RA - our AdvRetransTimer (%u) doesn't agree with %s (%u)",
			ifp->name, ifp->ifindex, zif->rtadv.AdvRetransTimer,
			addr_str, ntohl(radvert->nd_ra_retransmit));
		monotime(&zif->rtadv.lastadvretranstimer);
	}

	/* Create entry for neighbor if not known. */
	p.family = AF_INET6;
	IPV6_ADDR_COPY(&p.u.prefix6, &addr->sin6_addr);
	p.prefixlen = IPV6_MAX_BITLEN;

	if (!nbr_connected_check(ifp, &p))
		nbr_connected_add_ipv6(ifp, &addr->sin6_addr);
}


static void rtadv_process_packet(uint8_t *buf, unsigned int len,
				 ifindex_t ifindex, int hoplimit,
				 struct sockaddr_in6 *from,
				 struct zebra_vrf *zvrf)
{
	struct icmp6_hdr *icmph;
	struct interface *ifp;
	struct zebra_if *zif;
	char addr_str[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &from->sin6_addr, addr_str, INET6_ADDRSTRLEN);

	/* Interface search. */
	ifp = if_lookup_by_index(ifindex, zvrf->vrf->vrf_id);
	if (ifp == NULL) {
		flog_warn(EC_ZEBRA_UNKNOWN_INTERFACE,
			  "RA/RS received on unknown IF %u from %s", ifindex,
			  addr_str);
		return;
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s(%s:%u): Rx RA/RS len %d from %s", ifp->name,
			   ifp->vrf->name, ifp->ifindex, len, addr_str);

	if (if_is_loopback(ifp))
		return;

	/* Check interface configuration. */
	zif = ifp->info;
	if (!zif->rtadv.AdvSendAdvertisements)
		return;

	/* ICMP message length check. */
	if (len < sizeof(struct icmp6_hdr)) {
		zlog_debug(
			"%s(%s:%u): Rx RA with Invalid ICMPV6 packet length %d",
			ifp->name, ifp->vrf->name, ifp->ifindex, len);
		return;
	}

	icmph = (struct icmp6_hdr *)buf;

	/* ICMP message type check. */
	if (icmph->icmp6_type != ND_ROUTER_SOLICIT
	    && icmph->icmp6_type != ND_ROUTER_ADVERT) {
		zlog_debug("%s(%s:%u): Rx RA - Unwanted ICMPV6 message type %d",
			   ifp->name, ifp->vrf->name, ifp->ifindex,
			   icmph->icmp6_type);
		return;
	}

	/* Hoplimit check. */
	if (hoplimit >= 0 && hoplimit != 255) {
		zlog_debug("%s(%s:%u): Rx RA - Invalid hoplimit %d", ifp->name,
			   ifp->vrf->name, ifp->ifindex, hoplimit);
		return;
	}

	/* Check ICMP message type. */
	if (icmph->icmp6_type == ND_ROUTER_SOLICIT)
		rtadv_process_solicit(ifp);
	else if (icmph->icmp6_type == ND_ROUTER_ADVERT)
		rtadv_process_advert(buf, len, ifp, from);

	return;
}

static void rtadv_read(struct event *thread)
{
	int sock;
	int len;
	uint8_t buf[RTADV_MSG_SIZE];
	struct sockaddr_in6 from;
	ifindex_t ifindex = 0;
	int hoplimit = -1;
	struct zebra_vrf *zvrf = EVENT_ARG(thread);

	sock = EVENT_FD(thread);
	zvrf->rtadv.ra_read = NULL;

	/* Register myself. */
	rtadv_event(zvrf, RTADV_READ, 0);

	len = rtadv_recv_packet(zvrf, sock, buf, sizeof(buf), &from, &ifindex,
				&hoplimit);

	if (len < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "RA/RS recv failed, socket %u error %s", sock,
			     safe_strerror(errno));
		return;
	}

	rtadv_process_packet(buf, (unsigned)len, ifindex, hoplimit, &from, zvrf);
}

static int rtadv_make_socket(ns_id_t ns_id)
{
	int sock = -1;
	int ret = 0;
	struct icmp6_filter filter;
	int error;

	frr_with_privs(&zserv_privs) {

		sock = ns_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, ns_id);
		/*
		 * with privs might set errno too if it fails save
		 * to the side
		 */
		error = errno;
	}

	if (sock < 0) {
		zlog_warn("RTADV socket for ns: %u failure to create: %s(%u)",
			  ns_id, safe_strerror(error), error);
		return -1;
	}

	ret = setsockopt_ipv6_pktinfo(sock, 1);
	if (ret < 0) {
		zlog_warn("RTADV failure to set Packet Information");
		close(sock);
		return ret;
	}
	ret = setsockopt_ipv6_multicast_loop(sock, 0);
	if (ret < 0) {
		zlog_warn("RTADV failure to set multicast Loop detection");
		close(sock);
		return ret;
	}
	ret = setsockopt_ipv6_unicast_hops(sock, 255);
	if (ret < 0) {
		zlog_warn("RTADV failure to set maximum unicast hops");
		close(sock);
		return ret;
	}
	ret = setsockopt_ipv6_multicast_hops(sock, 255);
	if (ret < 0) {
		zlog_warn("RTADV failure to set maximum multicast hops");
		close(sock);
		return ret;
	}
	ret = setsockopt_ipv6_hoplimit(sock, 1);
	if (ret < 0) {
		zlog_warn("RTADV failure to set maximum incoming hop limit");
		close(sock);
		return ret;
	}

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

	ret = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
			 sizeof(struct icmp6_filter));
	if (ret < 0) {
		zlog_info("ICMP6_FILTER set fail: %s", safe_strerror(errno));
		close(sock);
		return ret;
	}

	return sock;
}

static struct adv_if *adv_if_new(const char *name)
{
	struct adv_if *new;

	new = XCALLOC(MTYPE_ADV_IF, sizeof(struct adv_if));

	strlcpy(new->name, name, sizeof(new->name));

	return new;
}

static void adv_if_free(struct adv_if *adv_if)
{
	XFREE(MTYPE_ADV_IF, adv_if);
}

static bool adv_if_is_empty_internal(const struct adv_if_list_head *adv_if_head)
{
	return adv_if_list_count(adv_if_head) ? false : true;
}

static struct adv_if *adv_if_add_internal(struct adv_if_list_head *adv_if_head,
					  const char *name)
{
	struct adv_if adv_if_lookup = {};
	struct adv_if *adv_if = NULL;

	strlcpy(adv_if_lookup.name, name, sizeof(adv_if_lookup.name));
	adv_if = adv_if_list_find(adv_if_head, &adv_if_lookup);

	if (adv_if != NULL)
		return adv_if;

	adv_if = adv_if_new(adv_if_lookup.name);
	adv_if_list_add(adv_if_head, adv_if);

	return NULL;
}

static struct adv_if *adv_if_del_internal(struct adv_if_list_head *adv_if_head,
					  const char *name)
{
	struct adv_if adv_if_lookup = {};
	struct adv_if *adv_if = NULL;

	strlcpy(adv_if_lookup.name, name, sizeof(adv_if_lookup.name));
	adv_if = adv_if_list_find(adv_if_head, &adv_if_lookup);

	if (adv_if == NULL)
		return NULL;

	adv_if_list_del(adv_if_head, adv_if);

	return adv_if;
}

static void adv_if_clean_internal(struct adv_if_list_head *adv_if_head)
{
	struct adv_if *node = NULL;

	if (!adv_if_is_empty_internal(adv_if_head)) {
		frr_each_safe (adv_if_list, adv_if_head, node) {
			adv_if_list_del(adv_if_head, node);
			adv_if_free(node);
		}
	}

	adv_if_list_fini(adv_if_head);
}


/*
 * Add to list. On Success, return NULL, otherwise return already existing
 * adv_if.
 */
static struct adv_if *adv_if_add(struct zebra_vrf *zvrf, const char *name)
{
	struct adv_if *adv_if = NULL;

	adv_if = adv_if_add_internal(&zvrf->rtadv.adv_if, name);

	if (adv_if != NULL)
		return adv_if;

	if (IS_ZEBRA_DEBUG_EVENT) {
		struct vrf *vrf = zvrf->vrf;

		zlog_debug("%s: %s:%u IF %s count: %zu", __func__,
			   VRF_LOGNAME(vrf), zvrf_id(zvrf), name,
			   adv_if_list_count(&zvrf->rtadv.adv_if));
	}

	return NULL;
}

/*
 * Del from list. On Success, return the adv_if, otherwise return NULL. Caller
 * frees.
 */
static struct adv_if *adv_if_del(struct zebra_vrf *zvrf, const char *name)
{
	struct adv_if *adv_if = NULL;

	adv_if = adv_if_del_internal(&zvrf->rtadv.adv_if, name);

	if (adv_if == NULL)
		return NULL;

	if (IS_ZEBRA_DEBUG_EVENT) {
		struct vrf *vrf = zvrf->vrf;

		zlog_debug("%s: %s:%u IF %s count: %zu", __func__,
			   VRF_LOGNAME(vrf), zvrf_id(zvrf), name,
			   adv_if_list_count(&zvrf->rtadv.adv_if));
	}

	return adv_if;
}

/*
 * Add to list. On Success, return NULL, otherwise return already existing
 * adv_if.
 */
static struct adv_if *adv_msec_if_add(struct zebra_vrf *zvrf, const char *name)
{
	struct adv_if *adv_if = NULL;

	adv_if = adv_if_add_internal(&zvrf->rtadv.adv_msec_if, name);

	if (adv_if != NULL)
		return adv_if;

	if (IS_ZEBRA_DEBUG_EVENT) {
		struct vrf *vrf = zvrf->vrf;

		zlog_debug("%s: %s:%u IF %s count: %zu", __func__,
			   VRF_LOGNAME(vrf), zvrf_id(zvrf), name,
			   adv_if_list_count(&zvrf->rtadv.adv_msec_if));
	}

	return NULL;
}

/*
 * Del from list. On Success, return the adv_if, otherwise return NULL. Caller
 * frees.
 */
static struct adv_if *adv_msec_if_del(struct zebra_vrf *zvrf, const char *name)
{
	struct adv_if *adv_if = NULL;

	adv_if = adv_if_del_internal(&zvrf->rtadv.adv_msec_if, name);

	if (adv_if == NULL)
		return NULL;

	if (IS_ZEBRA_DEBUG_EVENT) {
		struct vrf *vrf = zvrf->vrf;

		zlog_debug("%s: %s:%u IF %s count: %zu", __func__,
			   VRF_LOGNAME(vrf), zvrf_id(zvrf), name,
			   adv_if_list_count(&zvrf->rtadv.adv_msec_if));
	}

	return adv_if;
}

/* Clean adv_if list, called on vrf terminate */
static void adv_if_clean(struct zebra_vrf *zvrf)
{
	if (IS_ZEBRA_DEBUG_EVENT) {
		struct vrf *vrf = zvrf->vrf;

		zlog_debug("%s: %s:%u count: %zu -> 0", __func__,
			   VRF_LOGNAME(vrf), zvrf_id(zvrf),
			   adv_if_list_count(&zvrf->rtadv.adv_if));
	}

	adv_if_clean_internal(&zvrf->rtadv.adv_if);
}

/* Clean adv_msec_if list, called on vrf terminate */
static void adv_msec_if_clean(struct zebra_vrf *zvrf)
{
	if (IS_ZEBRA_DEBUG_EVENT) {
		struct vrf *vrf = zvrf->vrf;

		zlog_debug("%s: %s:%u count: %zu -> 0", __func__,
			   VRF_LOGNAME(vrf), zvrf_id(zvrf),
			   adv_if_list_count(&zvrf->rtadv.adv_msec_if));
	}

	adv_if_clean_internal(&zvrf->rtadv.adv_msec_if);
}

static struct rtadv_prefix *rtadv_prefix_new(void)
{
	return XCALLOC(MTYPE_RTADV_PREFIX, sizeof(struct rtadv_prefix));
}

static void rtadv_prefix_free(struct rtadv_prefix *rtadv_prefix)
{
	XFREE(MTYPE_RTADV_PREFIX, rtadv_prefix);
}

static struct rtadv_prefix *rtadv_prefix_get(struct rtadv_prefixes_head *list,
					     struct prefix_ipv6 *p)
{
	struct rtadv_prefix *rprefix, ref;

	ref.prefix = *p;

	rprefix = rtadv_prefixes_find(list, &ref);
	if (rprefix)
		return rprefix;

	rprefix = rtadv_prefix_new();
	memcpy(&rprefix->prefix, p, sizeof(struct prefix_ipv6));
	rtadv_prefixes_add(list, rprefix);

	return rprefix;
}

static void rtadv_prefix_set_defaults(struct rtadv_prefix *rp)
{
	rp->AdvAutonomousFlag = 1;
	rp->AdvOnLinkFlag = 1;
	rp->AdvRouterAddressFlag = 0;
	rp->AdvPreferredLifetime = RTADV_PREFERRED_LIFETIME;
	rp->AdvValidLifetime = RTADV_VALID_LIFETIME;
}

static struct rtadv_prefix *rtadv_prefix_set(struct zebra_if *zif,
					     struct rtadv_prefix *rp)
{
	struct rtadv_prefix *rprefix;

	rprefix = rtadv_prefix_get(zif->rtadv.prefixes, &rp->prefix);

	/*
	 * Set parameters based on where the prefix is created.
	 * If auto-created based on kernel address addition, set the
	 * default values.  If created from a manual "ipv6 nd prefix"
	 * command, take the parameters from the manual command. Note
	 * that if the manual command exists, the default values will
	 * not overwrite the manual values.
	 */
	if (rp->AdvPrefixCreate == PREFIX_SRC_MANUAL) {
		if (rprefix->AdvPrefixCreate == PREFIX_SRC_AUTO)
			rprefix->AdvPrefixCreate = PREFIX_SRC_BOTH;
		else
			rprefix->AdvPrefixCreate = PREFIX_SRC_MANUAL;

		rprefix->AdvAutonomousFlag = rp->AdvAutonomousFlag;
		rprefix->AdvOnLinkFlag = rp->AdvOnLinkFlag;
		rprefix->AdvRouterAddressFlag = rp->AdvRouterAddressFlag;
		rprefix->AdvPreferredLifetime = rp->AdvPreferredLifetime;
		rprefix->AdvValidLifetime = rp->AdvValidLifetime;
	} else if (rp->AdvPrefixCreate == PREFIX_SRC_AUTO) {
		if (rprefix->AdvPrefixCreate == PREFIX_SRC_MANUAL)
			rprefix->AdvPrefixCreate = PREFIX_SRC_BOTH;
		else {
			rprefix->AdvPrefixCreate = PREFIX_SRC_AUTO;
			rtadv_prefix_set_defaults(rprefix);
		}
	}

	return rprefix;
}

static void rtadv_prefix_reset(struct zebra_if *zif, struct rtadv_prefix *rp,
			       struct rtadv_prefix *rprefix)
{
	if (!rprefix)
		rprefix = rtadv_prefixes_find(zif->rtadv.prefixes, rp);

	if (rprefix != NULL) {

		/*
		 * When deleting an address from the list, need to take care
		 * it wasn't defined both automatically via kernel
		 * address addition as well as manually by vtysh cli. If both,
		 * we don't actually delete but may change the parameters
		 * back to default if a manually defined entry is deleted.
		 */
		if (rp->AdvPrefixCreate == PREFIX_SRC_MANUAL) {
			if (rprefix->AdvPrefixCreate == PREFIX_SRC_BOTH) {
				rprefix->AdvPrefixCreate = PREFIX_SRC_AUTO;
				rtadv_prefix_set_defaults(rprefix);
				return;
			}
		} else if (rp->AdvPrefixCreate == PREFIX_SRC_AUTO) {
			if (rprefix->AdvPrefixCreate == PREFIX_SRC_BOTH) {
				rprefix->AdvPrefixCreate = PREFIX_SRC_MANUAL;
				return;
			}
		}

		rtadv_prefixes_del(zif->rtadv.prefixes, rprefix);
		rtadv_prefix_free(rprefix);
	}
}

struct rtadv_prefix *rtadv_add_prefix_manual(struct zebra_if *zif,
					     struct rtadv_prefix *rp)
{
	rp->AdvPrefixCreate = PREFIX_SRC_MANUAL;
	return rtadv_prefix_set(zif, rp);
}

void rtadv_delete_prefix_manual(struct zebra_if *zif,
				struct rtadv_prefix *rprefix)
{
	struct rtadv_prefix rp;

	rp.AdvPrefixCreate = PREFIX_SRC_MANUAL;

	rtadv_prefix_reset(zif, &rp, rprefix);
}

/* Add IPv6 prefixes learned from the kernel to the RA prefix list */
void rtadv_add_prefix(struct zebra_if *zif, const struct prefix_ipv6 *p)
{
	struct rtadv_prefix rp;

	rp.prefix = *p;
	apply_mask_ipv6(&rp.prefix);
	rp.AdvPrefixCreate = PREFIX_SRC_AUTO;
	rtadv_prefix_set(zif, &rp);
}

/* Delete IPv6 prefixes removed by the kernel from the RA prefix list */
void rtadv_delete_prefix(struct zebra_if *zif, const struct prefix *p)
{
	struct rtadv_prefix rp;

	rp.prefix = *((struct prefix_ipv6 *)p);
	apply_mask_ipv6(&rp.prefix);
	rp.AdvPrefixCreate = PREFIX_SRC_AUTO;
	rtadv_prefix_reset(zif, &rp, NULL);
}

static void rtadv_start_interface_events(struct zebra_vrf *zvrf,
					 struct zebra_if *zif)
{
	struct adv_if *adv_if = NULL;

	if (zif->ifp->ifindex == IFINDEX_INTERNAL) {
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug(
				"%s(%s) has not configured an ifindex yet, delaying until we have one",
				zif->ifp->name, zvrf->vrf->name);
		return;
	}

	adv_if = adv_if_add(zvrf, zif->ifp->name);
	if (adv_if != NULL)
		return; /* Already added */

	if_join_all_router(zvrf->rtadv.sock, zif->ifp);

	if (adv_if_list_count(&zvrf->rtadv.adv_if) == 1)
		rtadv_event(zvrf, RTADV_START, 0);
}

void ipv6_nd_suppress_ra_set(struct interface *ifp,
			     enum ipv6_nd_suppress_ra_status status)
{
	struct zebra_if *zif;
	struct zebra_vrf *zvrf;
	struct adv_if *adv_if = NULL;

	zif = ifp->info;

	zvrf = rtadv_interface_get_zvrf(ifp);

	if (status == RA_SUPPRESS) {
		/* RA is currently enabled */
		if (zif->rtadv.AdvSendAdvertisements) {
			rtadv_send_packet(zvrf->rtadv.sock, ifp, RA_SUPPRESS);
			zif->rtadv.AdvSendAdvertisements = 0;
			zif->rtadv.AdvIntervalTimer = 0;

			adv_if = adv_if_del(zvrf, ifp->name);
			if (adv_if == NULL)
				return; /* Nothing to delete */

			adv_if_free(adv_if);

			if_leave_all_router(zvrf->rtadv.sock, ifp);

			if (adv_if_list_count(&zvrf->rtadv.adv_if) == 0)
				rtadv_event(zvrf, RTADV_STOP, 0);
		}
	} else {
		if (!zif->rtadv.AdvSendAdvertisements) {
			zif->rtadv.AdvSendAdvertisements = 1;
			zif->rtadv.AdvIntervalTimer = 0;
			if ((zif->rtadv.MaxRtrAdvInterval >= 1000)
			    && zif->rtadv.UseFastRexmit) {
				/*
				 * Enable Fast RA only when RA interval is in
				 * secs and Fast RA retransmit is enabled
				 */
				zif->rtadv.inFastRexmit = 1;
				zif->rtadv.NumFastReXmitsRemain =
					RTADV_NUM_FAST_REXMITS;
			}

			rtadv_start_interface_events(zvrf, zif);
		}
	}
}

void ipv6_nd_interval_set(struct interface *ifp, uint32_t interval)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_vrf *zvrf = rtadv_interface_get_zvrf(ifp);
	struct adv_if *adv_if;

	if (zif->rtadv.MaxRtrAdvInterval % 1000) {
		adv_if = adv_msec_if_del(zvrf, ifp->name);
		if (adv_if != NULL)
			adv_if_free(adv_if);
	}

	if (interval % 1000)
		(void)adv_msec_if_add(zvrf, ifp->name);

	zif->rtadv.MaxRtrAdvInterval = interval;
	zif->rtadv.MinRtrAdvInterval = 0.33 * interval;

	if (interval != RTADV_MAX_RTR_ADV_INTERVAL) {
		SET_FLAG(zif->rtadv.ra_configured, VTY_RA_INTERVAL_CONFIGURED);
		zif->rtadv.AdvIntervalTimer = 0;
	} else {
		if (CHECK_FLAG(zif->rtadv.ra_configured, BGP_RA_CONFIGURED))
			zif->rtadv.MaxRtrAdvInterval = 10000;

		UNSET_FLAG(zif->rtadv.ra_configured, VTY_RA_INTERVAL_CONFIGURED);
		zif->rtadv.AdvIntervalTimer = zif->rtadv.MaxRtrAdvInterval;
	}
}

/*
 * Handle client (BGP) message to enable or disable IPv6 RA on an interface.
 * Note that while the client could request RA on an interface on which the
 * operator has not enabled RA, RA won't be disabled upon client request
 * if the operator has explicitly enabled RA. The enable request can also
 * specify a RA interval (in seconds).
 */
static void zebra_interface_radv_set(ZAPI_HANDLER_ARGS, int enable)
{
	struct stream *s;
	ifindex_t ifindex;
	struct interface *ifp;
	struct zebra_if *zif;
	uint32_t ra_interval;

	s = msg;

	/* Get interface index and RA interval. */
	STREAM_GETL(s, ifindex);
	STREAM_GETL(s, ra_interval);

	if (IS_ZEBRA_DEBUG_EVENT) {
		struct vrf *vrf = zvrf->vrf;

		zlog_debug("%s:%u: IF %u RA %s from client %s, interval %ums",
			   VRF_LOGNAME(vrf), zvrf_id(zvrf), ifindex,
			   enable ? "enable" : "disable",
			   zebra_route_string(client->proto), ra_interval);
	}

	/* Locate interface and check VRF match. */
	ifp = if_lookup_by_index(ifindex, zvrf->vrf->vrf_id);
	if (!ifp) {
		struct vrf *vrf = zvrf->vrf;

		flog_warn(EC_ZEBRA_UNKNOWN_INTERFACE,
			  "%s:%u: IF %u RA %s client %s - interface unknown",
			  VRF_LOGNAME(vrf), zvrf_id(zvrf), ifindex,
			  enable ? "enable" : "disable",
			  zebra_route_string(client->proto));
		return;
	}
	if (vrf_is_backend_netns() && ifp->vrf->vrf_id != zvrf_id(zvrf)) {
		zlog_debug(
			"%s:%u: IF %u RA %s client %s - VRF mismatch, IF VRF %u",
			ifp->vrf->name, zvrf_id(zvrf), ifindex,
			enable ? "enable" : "disable",
			zebra_route_string(client->proto), ifp->vrf->vrf_id);
		return;
	}

	zif = ifp->info;
	if (enable) {
		if (!CHECK_FLAG(zif->rtadv.ra_configured, BGP_RA_CONFIGURED))
			interfaces_configured_for_ra_from_bgp++;

		SET_FLAG(zif->rtadv.ra_configured, BGP_RA_CONFIGURED);
		ipv6_nd_suppress_ra_set(ifp, RA_ENABLE);
		if (ra_interval
		    && (ra_interval * 1000) < (unsigned int) zif->rtadv.MaxRtrAdvInterval
		    && !CHECK_FLAG(zif->rtadv.ra_configured,
				   VTY_RA_INTERVAL_CONFIGURED))
			zif->rtadv.MaxRtrAdvInterval = ra_interval * 1000;
	} else {
		if (CHECK_FLAG(zif->rtadv.ra_configured, BGP_RA_CONFIGURED))
			interfaces_configured_for_ra_from_bgp--;

		UNSET_FLAG(zif->rtadv.ra_configured, BGP_RA_CONFIGURED);
		if (!CHECK_FLAG(zif->rtadv.ra_configured,
				VTY_RA_INTERVAL_CONFIGURED))
			zif->rtadv.MaxRtrAdvInterval =
				RTADV_MAX_RTR_ADV_INTERVAL;
		if (!CHECK_FLAG(zif->rtadv.ra_configured, VTY_RA_CONFIGURED))
			ipv6_nd_suppress_ra_set(ifp, RA_SUPPRESS);
	}
stream_failure:
	return;
}

/*
 * send router lifetime value of zero in RAs on this interface since we're
 * ceasing to advertise and want to let our neighbors know.
 * RFC 4861 secion 6.2.5
 */
void rtadv_stop_ra(struct interface *ifp)
{
	struct zebra_if *zif;
	struct zebra_vrf *zvrf;

	zif = ifp->info;
	zvrf = rtadv_interface_get_zvrf(ifp);

	if (zif->rtadv.AdvSendAdvertisements)
		rtadv_send_packet(zvrf->rtadv.sock, ifp, RA_SUPPRESS);
}

/*
 * Send router lifetime value of zero in RAs on all interfaces since we're
 * ceasing to advertise globally and want to let all of our neighbors know
 * RFC 4861 secion 6.2.5
 *
 * Delete all ipv6 global prefixes added to the router advertisement prefix
 * lists prior to ceasing.
 */
void rtadv_stop_ra_all(void)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct zebra_if *zif;
	struct rtadv_prefix *rprefix;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		FOR_ALL_INTERFACES (vrf, ifp) {
			zif = ifp->info;

			frr_each_safe (rtadv_prefixes, zif->rtadv.prefixes,
				       rprefix)
				rtadv_prefix_reset(zif, rprefix, rprefix);

			rtadv_stop_ra(ifp);
		}
}

void zebra_interface_radv_disable(ZAPI_HANDLER_ARGS)
{
	zebra_interface_radv_set(client, hdr, msg, zvrf, 0);
}
void zebra_interface_radv_enable(ZAPI_HANDLER_ARGS)
{
	zebra_interface_radv_set(client, hdr, msg, zvrf, 1);
}

static void show_zvrf_rtadv_adv_if_helper(struct vty *vty,
					  struct adv_if_list_head *adv_if_head)
{
	struct adv_if *node = NULL;

	if (!adv_if_is_empty_internal(adv_if_head)) {
		frr_each (adv_if_list, adv_if_head, node) {
			vty_out(vty, "    %s\n", node->name);
		}
	}

	vty_out(vty, "\n");
}

static void show_zvrf_rtadv_helper(struct vty *vty, struct zebra_vrf *zvrf)
{
	vty_out(vty, "VRF: %s\n", zvrf_name(zvrf));
	vty_out(vty, "  Interfaces:\n");
	show_zvrf_rtadv_adv_if_helper(vty, &zvrf->rtadv.adv_if);

	vty_out(vty, "  Interfaces(msec):\n");
	show_zvrf_rtadv_adv_if_helper(vty, &zvrf->rtadv.adv_msec_if);
}

DEFPY(show_ipv6_nd_ra_if, show_ipv6_nd_ra_if_cmd,
      "show ipv6 nd ra-interfaces [vrf<NAME$vrf_name|all$vrf_all>]",
      SHOW_STR IP6_STR
      "Neighbor discovery\n"
      "Route Advertisement Interfaces\n" VRF_FULL_CMD_HELP_STR)
{
	struct zebra_vrf *zvrf = NULL;

	if (!vrf_is_backend_netns() && (vrf_name || vrf_all)) {
		vty_out(vty,
			"%% VRF subcommand only applicable for netns-based vrfs.\n");
		return CMD_WARNING;
	}

	if (vrf_all) {
		struct vrf *vrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			struct zebra_vrf *zvrf;

			zvrf = vrf->info;
			if (!zvrf)
				continue;

			show_zvrf_rtadv_helper(vty, zvrf);
		}

		return CMD_SUCCESS;
	}

	if (vrf_name)
		zvrf = zebra_vrf_lookup_by_name(vrf_name);
	else
		zvrf = zebra_vrf_lookup_by_name(VRF_DEFAULT_NAME);

	if (!zvrf) {
		vty_out(vty, "%% VRF '%s' specified does not exist\n",
			vrf_name);
		return CMD_WARNING;
	}

	show_zvrf_rtadv_helper(vty, zvrf);

	return CMD_SUCCESS;
}

static struct rtadv_rdnss *rtadv_rdnss_new(void)
{
	return XCALLOC(MTYPE_RTADV_RDNSS, sizeof(struct rtadv_rdnss));
}

static void rtadv_rdnss_free(struct rtadv_rdnss *rdnss)
{
	XFREE(MTYPE_RTADV_RDNSS, rdnss);
}

struct rtadv_rdnss *rtadv_rdnss_set(struct zebra_if *zif,
				    struct rtadv_rdnss *rdnss)
{
	struct rtadv_rdnss *p;

	p = rtadv_rdnss_new();
	memcpy(p, rdnss, sizeof(struct rtadv_rdnss));
	listnode_add(zif->rtadv.AdvRDNSSList, p);

	return p;
}

void rtadv_rdnss_reset(struct zebra_if *zif, struct rtadv_rdnss *p)
{
	listnode_delete(zif->rtadv.AdvRDNSSList, p);
	rtadv_rdnss_free(p);
}

static struct rtadv_dnssl *rtadv_dnssl_new(void)
{
	return XCALLOC(MTYPE_RTADV_DNSSL, sizeof(struct rtadv_dnssl));
}

static void rtadv_dnssl_free(struct rtadv_dnssl *dnssl)
{
	XFREE(MTYPE_RTADV_DNSSL, dnssl);
}

struct rtadv_dnssl *rtadv_dnssl_set(struct zebra_if *zif,
				    struct rtadv_dnssl *dnssl)
{
	struct rtadv_dnssl *p;

	p = rtadv_dnssl_new();
	memcpy(p, dnssl, sizeof(struct rtadv_dnssl));
	listnode_add(zif->rtadv.AdvDNSSLList, p);

	return p;
}

void rtadv_dnssl_reset(struct zebra_if *zif, struct rtadv_dnssl *p)
{
	listnode_delete(zif->rtadv.AdvDNSSLList, p);
	rtadv_dnssl_free(p);
}

/*
 * Convert dotted domain name (with or without trailing root zone dot) to
 * sequence of length-prefixed labels, as described in [RFC1035 3.1]. Write up
 * to strlen(in) + 2 octets to out.
 *
 * Returns the number of octets written to out or -1 if in does not constitute
 * a valid domain name.
 */
int rtadv_dnssl_encode(uint8_t *out, const char *in)
{
	const char *label_start, *label_end;
	size_t outp;

	outp = 0;
	label_start = in;

	while (*label_start) {
		size_t label_len;

		label_end = strchr(label_start, '.');
		if (label_end == NULL)
			label_end = label_start + strlen(label_start);

		label_len = label_end - label_start;
		if (label_len >= 64)
			return -1; /* labels must be 63 octets or less */

		out[outp++] = (uint8_t)label_len;
		memcpy(out + outp, label_start, label_len);
		outp += label_len;
		label_start += label_len;
		if (*label_start == '.')
			label_start++;
	}

	out[outp++] = '\0';
	return outp;
}

/* Dump interface ND information to vty. */
static int nd_dump_vty(struct vty *vty, struct interface *ifp)
{
	struct zebra_if *zif;
	struct rtadvconf *rtadv;
	int interval;

	zif = (struct zebra_if *)ifp->info;
	rtadv = &zif->rtadv;

	if (rtadv->AdvSendAdvertisements) {
		vty_out(vty,
			"  ND advertised reachable time is %d milliseconds\n",
			rtadv->AdvReachableTime);
		vty_out(vty,
			"  ND advertised retransmit interval is %u milliseconds\n",
			rtadv->AdvRetransTimer);
		vty_out(vty, "  ND advertised hop-count limit is %d hops\n",
			rtadv->AdvCurHopLimit);
		vty_out(vty, "  ND router advertisements sent: %d rcvd: %d\n",
			zif->ra_sent, zif->ra_rcvd);
		interval = rtadv->MaxRtrAdvInterval;
		if (interval % 1000)
			vty_out(vty,
				"  ND router advertisements are sent every %d milliseconds\n",
				interval);
		else
			vty_out(vty,
				"  ND router advertisements are sent every %d seconds\n",
				interval / 1000);
		if (!rtadv->UseFastRexmit)
			vty_out(vty,
				"  ND router advertisements do not use fast retransmit\n");

		if (rtadv->AdvDefaultLifetime != -1)
			vty_out(vty,
				"  ND router advertisements live for %d seconds\n",
				rtadv->AdvDefaultLifetime);
		else
			vty_out(vty,
				"  ND router advertisements lifetime tracks ra-interval\n");
		vty_out(vty,
			"  ND router advertisement default router preference is %s\n",
			rtadv_pref_strs[rtadv->DefaultPreference]);
		if (rtadv->AdvManagedFlag)
			vty_out(vty,
				"  Hosts use DHCP to obtain routable addresses.\n");
		else
			vty_out(vty,
				"  Hosts use stateless autoconfig for addresses.\n");
		if (rtadv->AdvHomeAgentFlag) {
			vty_out(vty,
				"  ND router advertisements with Home Agent flag bit set.\n");
			if (rtadv->HomeAgentLifetime != -1)
				vty_out(vty,
					"  Home Agent lifetime is %u seconds\n",
					rtadv->HomeAgentLifetime);
			else
				vty_out(vty,
					"  Home Agent lifetime tracks ra-lifetime\n");
			vty_out(vty, "  Home Agent preference is %u\n",
				rtadv->HomeAgentPreference);
		}
		if (rtadv->AdvIntervalOption)
			vty_out(vty,
				"  ND router advertisements with Adv. Interval option.\n");
	}
	return 0;
}

static void rtadv_event(struct zebra_vrf *zvrf, enum rtadv_event event, int val)
{
	struct rtadv *rtadv;

	if (IS_ZEBRA_DEBUG_EVENT) {
		struct vrf *vrf = zvrf->vrf;

		zlog_debug("%s(%s) with event: %d and val: %d", __func__,
			   VRF_LOGNAME(vrf), event, val);
	}

	rtadv = &zvrf->rtadv;

	switch (event) {
	case RTADV_START:
		event_add_read(zrouter.master, rtadv_read, zvrf, rtadv->sock,
			       &rtadv->ra_read);
		event_add_event(zrouter.master, rtadv_timer, zvrf, 0,
				&rtadv->ra_timer);
		break;
	case RTADV_STOP:
		EVENT_OFF(rtadv->ra_timer);
		EVENT_OFF(rtadv->ra_read);
		break;
	case RTADV_TIMER:
		event_add_timer(zrouter.master, rtadv_timer, zvrf, val,
				&rtadv->ra_timer);
		break;
	case RTADV_TIMER_MSEC:
		event_add_timer_msec(zrouter.master, rtadv_timer, zvrf, val,
				     &rtadv->ra_timer);
		break;
	case RTADV_READ:
		event_add_read(zrouter.master, rtadv_read, zvrf, rtadv->sock,
			       &rtadv->ra_read);
		break;
	default:
		break;
	}
	return;
}

void rtadv_if_up(struct zebra_if *zif)
{
	struct zebra_vrf *zvrf = rtadv_interface_get_zvrf(zif->ifp);

	/* Enable fast tx of RA if enabled && RA interval is not in msecs */
	if (zif->rtadv.AdvSendAdvertisements &&
	    (zif->rtadv.MaxRtrAdvInterval >= 1000) &&
	    zif->rtadv.UseFastRexmit) {
		zif->rtadv.inFastRexmit = 1;
		zif->rtadv.NumFastReXmitsRemain = RTADV_NUM_FAST_REXMITS;
	}

	/*
	 * startup the state machine, if it hasn't been already
	 * due to a delayed ifindex on startup ordering
	 */
	if (zif->rtadv.AdvSendAdvertisements)
		rtadv_start_interface_events(zvrf, zif);
}

void rtadv_if_init(struct zebra_if *zif)
{
	/* Set default router advertise values. */
	struct rtadvconf *rtadv;

	rtadv = &zif->rtadv;

	rtadv->AdvSendAdvertisements = 0;
	rtadv->MaxRtrAdvInterval = RTADV_MAX_RTR_ADV_INTERVAL;
	rtadv->MinRtrAdvInterval = RTADV_MIN_RTR_ADV_INTERVAL;
	rtadv->AdvIntervalTimer = 0;
	rtadv->AdvManagedFlag = 0;
	rtadv->AdvOtherConfigFlag = 0;
	rtadv->AdvHomeAgentFlag = 0;
	rtadv->AdvLinkMTU = 0;
	rtadv->AdvReachableTime = 0;
	rtadv->AdvRetransTimer = 0;
	rtadv->AdvCurHopLimit = RTADV_DEFAULT_HOPLIMIT;
	memset(&rtadv->lastadvcurhoplimit, 0,
	       sizeof(rtadv->lastadvcurhoplimit));
	memset(&rtadv->lastadvmanagedflag, 0,
	       sizeof(rtadv->lastadvmanagedflag));
	memset(&rtadv->lastadvotherconfigflag, 0,
	       sizeof(rtadv->lastadvotherconfigflag));
	memset(&rtadv->lastadvreachabletime, 0,
	       sizeof(rtadv->lastadvreachabletime));
	memset(&rtadv->lastadvretranstimer, 0,
	       sizeof(rtadv->lastadvretranstimer));
	rtadv->AdvDefaultLifetime = -1; /* derive from MaxRtrAdvInterval */
	rtadv->HomeAgentPreference = 0;
	rtadv->HomeAgentLifetime = -1; /* derive from AdvDefaultLifetime */
	rtadv->AdvIntervalOption = 0;
	rtadv->UseFastRexmit = true;
	rtadv->DefaultPreference = RTADV_PREF_MEDIUM;

	rtadv_prefixes_init(rtadv->prefixes);

	rtadv->AdvRDNSSList = list_new();
	rtadv->AdvDNSSLList = list_new();
}

void rtadv_if_fini(struct zebra_if *zif)
{
	struct rtadvconf *rtadv;
	struct rtadv_prefix *rp;

	rtadv = &zif->rtadv;

	while ((rp = rtadv_prefixes_pop(rtadv->prefixes)))
		rtadv_prefix_free(rp);

	list_delete(&rtadv->AdvRDNSSList);
	list_delete(&rtadv->AdvDNSSLList);
}

void rtadv_vrf_init(struct zebra_vrf *zvrf)
{
	if (!vrf_is_backend_netns() && (zvrf_id(zvrf) != VRF_DEFAULT))
		return;

	zvrf->rtadv.sock = rtadv_make_socket(zvrf->zns->ns_id);
}

void rtadv_vrf_terminate(struct zebra_vrf *zvrf)
{
	if (!vrf_is_backend_netns() && (zvrf_id(zvrf) != VRF_DEFAULT))
		return;

	rtadv_event(zvrf, RTADV_STOP, 0);
	if (zvrf->rtadv.sock >= 0) {
		close(zvrf->rtadv.sock);
		zvrf->rtadv.sock = -1;
	}

	adv_if_clean(zvrf);
	adv_msec_if_clean(zvrf);
}

void rtadv_cmd_init(void)
{
	interfaces_configured_for_ra_from_bgp = 0;

	hook_register(zebra_if_extra_info, nd_dump_vty);

	install_element(VIEW_NODE, &show_ipv6_nd_ra_if_cmd);
}

static int if_join_all_router(int sock, struct interface *ifp)
{
	int ret;

	struct ipv6_mreq mreq;

	memset(&mreq, 0, sizeof(mreq));
	inet_pton(AF_INET6, ALLROUTER, &mreq.ipv6mr_multiaddr);
	mreq.ipv6mr_interface = ifp->ifindex;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&mreq,
			 sizeof(mreq));
	if (ret < 0)
		flog_err_sys(EC_LIB_SOCKET,
			     "%s(%u): Failed to join group, socket %u error %s",
			     ifp->name, ifp->ifindex, sock,
			     safe_strerror(errno));

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug(
			"%s(%s:%u): Join All-Routers multicast group, socket %u",
			ifp->name, ifp->vrf->name, ifp->ifindex, sock);

	return 0;
}

static int if_leave_all_router(int sock, struct interface *ifp)
{
	int ret;

	struct ipv6_mreq mreq;

	memset(&mreq, 0, sizeof(mreq));
	inet_pton(AF_INET6, ALLROUTER, &mreq.ipv6mr_multiaddr);
	mreq.ipv6mr_interface = ifp->ifindex;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, (char *)&mreq,
			 sizeof(mreq));
	if (ret < 0)
		flog_err_sys(
			EC_LIB_SOCKET,
			"%s(%s:%u): Failed to leave group, socket %u error %s",
			ifp->name, ifp->vrf->name, ifp->ifindex, sock,
			safe_strerror(errno));

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug(
			"%s(%s:%u): Leave All-Routers multicast group, socket %u",
			ifp->name, ifp->vrf->name, ifp->ifindex, sock);

	return 0;
}

bool rtadv_compiled_in(void)
{
	return true;
}

#else /* !HAVE_RTADV */
/*
 * If the end user does not have RADV enabled we should
 * handle this better
 */
void zebra_interface_radv_disable(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug(
			"Received %s command, but ZEBRA is not compiled with Router Advertisements on",
			zserv_command_string(hdr->command));

	return;
}

void zebra_interface_radv_enable(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug(
			"Received %s command, but ZEBRA is not compiled with Router Advertisements on",
			zserv_command_string(hdr->command));

	return;
}

bool rtadv_compiled_in(void)
{
	return false;
}

#endif /* HAVE_RTADV */

uint32_t rtadv_get_interfaces_configured_from_bgp(void)
{
	return interfaces_configured_for_ra_from_bgp;
}

void rtadv_init(void)
{
	if (CMSG_SPACE(sizeof(struct in6_pktinfo)) > RTADV_ADATA_SIZE) {
		zlog_debug("%s: RTADV_ADATA_SIZE choosen will not work on this platform, please use a larger size",
			   __func__);

		exit(-1);
	}
}
