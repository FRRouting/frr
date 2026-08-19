// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Kernel capabilities
 * Copyright 2026 6WIND S.A.
 */

#include <zebra.h>
#include <sys/stat.h>

#include <linux/rtnetlink.h>

#include <zebra/zebra_kernel_capabilities.h>

#ifdef HAVE_NETLINK

#define _LINUX_IN6_H
#include <linux/lwtunnel.h>
#include <linux/seg6_iptunnel.h>
#include <linux/seg6_local.h>
#include <linux/if_addr.h>

#include <lib/ns.h>
#include <lib/kernel_capabilities.h>

#include <zebra/table_manager.h>
#include <zebra/rt.h>
#include <zebra/zebra_dplane.h>
#include <zebra/rt_netlink.h>
#include <zebra/kernel_netlink.h>
#include <zebra/zebra_router.h>

static bool kernel_capabilities_logging_enabled;

#define LOG_UNSUPPORTED_SEG6_ENCAP_SOURCE()                                                   \
	do {                                                                                  \
		if (kernel_capabilities_logging_enabled)                                      \
			zlog_err("%s: SRv6 encap source (SEG6_IPTUNNEL_SRC) is NOT supported", __func__);         \
	} while (0)
#define LOG_UNSUPPORTED_SEG6_ENCAP_LOOKUP()                                                   \
	do {                                                                                  \
		if (kernel_capabilities_logging_enabled)                                      \
			zlog_err("%s: SRv6 encap lookup (SEG6_IPTUNNEL_TABLE) is NOT supported", __func__);         \
	} while (0)

#define LOG_SUPPORTED_SEG6_ENCAP_SOURCE()                                                     \
	do {                                                                                  \
		if (kernel_capabilities_logging_enabled)                                      \
			zlog_info("%s: SRv6 encap source (SEG6_IPTUNNEL_SRC) is supported", __func__);            \
	} while (0)
#define LOG_SUPPORTED_SEG6_ENCAP_LOOKUP()                                                     \
	do {                                                                                  \
		if (kernel_capabilities_logging_enabled)                                      \
			zlog_info("%s: SRv6 encap lookup (SEG6_IPTUNNEL_TABLE) is supported", __func__);            \
	} while (0)

#define CHECK_SRV6_ATTR_PREFIX_STR	"2001:db8:efff::"
#define CHECK_SRV6_DUMMY_INTERFACE	"6wsrv6dummy"
#define CHECK_SRV6_ATTR_SOURCE_ADDRESS	"2001:db8:dfff::"
#define CHECK_SRV6_ATTR_LOOKUP_TABLE 254
#define CHECK_SRV6_ATTR_SUPPORTED_FUNC_DELAY_NOTIFY 30

static bool check_seg6_encap_attrs_in_progress;
struct event *check_srv6_attr_supported_func_thread;

static int check_srv6_attr_netlink_talk_func(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	struct rtmsg *rtm;
	struct rtattr *rta, *rta_encap = NULL;
	size_t plen;
	size_t msglen;
	size_t rta_encap_len = 0;
	struct in6_addr *p, in6_p;
	uint16_t tunnel_type = LWTUNNEL_ENCAP_NONE;

	if (h->nlmsg_type != RTM_NEWROUTE)
		return 0;
	rtm = NLMSG_DATA(h);
	msglen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
	rta = RTM_RTA(rtm);
next_rta_for_rta_encap:
	if (RTA_OK(rta, msglen) == 0)
		return 0;

	plen = RTA_PAYLOAD(rta);
	if (((rta->rta_type & NLA_TYPE_MASK) != RTA_ENCAP) &&
	    ((rta->rta_type & NLA_TYPE_MASK) != RTA_ENCAP_TYPE) &&
	    ((rta->rta_type & NLA_TYPE_MASK) != RTA_DST)) {
		rta = RTA_NEXT(rta, msglen);
		goto next_rta_for_rta_encap;
	}
	if ((rta->rta_type & NLA_TYPE_MASK) == RTA_DST) {
		p = RTA_DATA(rta);
		inet_pton(AF_INET6, CHECK_SRV6_ATTR_PREFIX_STR, &in6_p);
		if (!IPV6_ADDR_SAME(p, &in6_p))
			return 0;
	}
	if ((rta->rta_type & NLA_TYPE_MASK) == RTA_ENCAP_TYPE) {
		tunnel_type = *(uint16_t *)RTA_DATA(rta);
		if (tunnel_type != LWTUNNEL_ENCAP_SEG6)
			return 0;
	}
	if ((rta->rta_type & NLA_TYPE_MASK) == RTA_ENCAP) {
		rta_encap_len = plen;
		rta_encap = RTA_DATA(rta);
	}
	if (rta_encap == NULL || tunnel_type == LWTUNNEL_ENCAP_NONE) {
		rta = RTA_NEXT(rta, msglen);
		goto next_rta_for_rta_encap;
	}

next_rta_encap_inspection:
	if (RTA_OK(rta_encap, rta_encap_len) == 0)
		return 0;
	if ((rta_encap->rta_type & NLA_TYPE_MASK) == SEG6_IPTUNNEL_SRC)
		kernel_capabilities_set_seg6_encap_source(true);
	else if ((rta_encap->rta_type & NLA_TYPE_MASK) == SEG6_IPTUNNEL_TABLE)
		kernel_capabilities_set_seg6_encap_lookup(true);
	rta_encap = RTA_NEXT(rta_encap, rta_encap_len);
	goto next_rta_encap_inspection;

	return 0;
}

static bool handle_fake_seg6_route(struct zebra_ns *zns, int type, struct interface *ifp)
{
	int datalen = NL_PKT_BUF_SIZE;
	struct rtattr *rta_encap;
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[NL_PKT_BUF_SIZE];
	} req = {};
	struct prefix p = {}, p_seg = {};
	char ipv6_segment_str[] = "fefe:dcba:fffe::";
	struct seg6_iptunnel_encap *ipt;
	struct ipv6_sr_hdr *srh;
	char tun_buf[4096] = {};
	size_t srhlen;
	struct in6_addr in6_p = {};

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	inet_pton(p.family, CHECK_SRV6_ATTR_PREFIX_STR, &p.u.prefix6);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = type;
	if (type == RTM_NEWROUTE)
		req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.r.rtm_family = p.family;
	req.r.rtm_dst_len = p.prefixlen;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_table = RT_TABLE_UNSPEC;
	req.r.rtm_protocol = RTPROT_ZEBRA;

	if (!nl_attr_put(&req.n, datalen, RTA_DST, &p.u.prefix, sizeof(struct in6_addr)))
		goto error_fake_seg6_route;

	if (type == RTM_DELROUTE) {
		if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
			goto error_fake_seg6_route;
		return true;
	}

	req.r.rtm_type = RTN_UNICAST;

	if (!nl_attr_put32(&req.n, datalen, RTA_OIF, ifp->ifindex))
		goto error_fake_seg6_route;

	if (type == RTM_GETROUTE) {
		if (netlink_talk(check_srv6_attr_netlink_talk_func, &req.n, &zns->netlink_cmd, zns,
				 0))
			goto error_fake_seg6_route;
		return true;
	}

	if (!nl_attr_put16(&req.n, datalen, RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6))
		goto error_fake_seg6_route;

	rta_encap = nl_attr_nest(&req.n, datalen, RTA_ENCAP);
	if (!rta_encap)
		goto error_fake_seg6_route;

	p_seg.family = AF_INET6;
	p_seg.prefixlen = IPV6_MAX_BITLEN;
	inet_pton(p_seg.family, ipv6_segment_str, &p_seg.u.prefix6);

	srhlen = SRH_BASE_HEADER_LENGTH + SRH_SEGMENT_LENGTH;
	ipt = (struct seg6_iptunnel_encap *)tun_buf;
	ipt->mode = SEG6_IPTUN_MODE_ENCAP;
	srh = (struct ipv6_sr_hdr *)&ipt->srh;
	srh->hdrlen = (srhlen >> 3) - 1;
	srh->type = 4;
	memcpy(&srh->segments[0], &p_seg.u.prefix6, sizeof(struct in6_addr));

	if (!nl_attr_put(&req.n, datalen, SEG6_IPTUNNEL_SRH, tun_buf,
			 sizeof(struct seg6_iptunnel_encap) + srhlen))
		goto error_fake_seg6_route;

	inet_pton(AF_INET6, CHECK_SRV6_ATTR_SOURCE_ADDRESS, &in6_p);
	if (!nl_attr_put(&req.n, datalen, SEG6_IPTUNNEL_SRC, &in6_p,
			 sizeof(struct in6_addr)))
		goto error_fake_seg6_route;

	if (!nl_attr_put32(&req.n, datalen, SEG6_IPTUNNEL_TABLE, CHECK_SRV6_ATTR_LOOKUP_TABLE))
		goto error_fake_seg6_route;

	nl_attr_nest_end(&req.n, rta_encap);

	if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
		goto error_fake_seg6_route;

	return true;

error_fake_seg6_route:
	return false;
}

static bool check_srv6_interfaces_configured(enum kernel_capabilities_interface_action_type action)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	if (!zns || zns->netlink_cmd.sock == -1)
		return false;

	if (action == KERNEL_CAPABILITIES_INTERFACE_DEL) {
		if (!zebra_kernel_capabilities_configure_interface(zns, CHECK_SRV6_DUMMY_INTERFACE,
								   KERNEL_CAPABILITIES_INTERFACE_SHUTDOWN))
			return false;
	}

	if (!zebra_kernel_capabilities_configure_interface(zns, CHECK_SRV6_DUMMY_INTERFACE, action))
		return false;

	check_seg6_encap_attrs_in_progress = true;
	return true;
}

bool zebra_kernel_capabilities_configure_interface(
	struct zebra_ns *zns, const char *ifname,
	enum kernel_capabilities_interface_action_type action)
{
	int buflen = NL_PKT_BUF_SIZE;
	struct rtattr *rta_info;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[NL_PKT_BUF_SIZE];
	} req = {};
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;
	if (action == KERNEL_CAPABILITIES_INTERFACE_ADD ||
	    action == KERNEL_CAPABILITIES_INTERFACE_SHUTDOWN) {
		req.n.nlmsg_type = RTM_NEWLINK;
		if (action == KERNEL_CAPABILITIES_INTERFACE_ADD) {
			req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
			req.ifi.ifi_change = IFF_UP;
			req.ifi.ifi_flags = IFF_UP;
		} else {
			req.ifi.ifi_change |= IFF_UP;
			req.ifi.ifi_flags &= ~IFF_UP;
		}
	} else
		req.n.nlmsg_type = RTM_DELLINK;

	if (!nl_attr_put(&req.n, buflen, IFLA_IFNAME, ifname, strlen(ifname) + 1))
		return false;

	if (action == KERNEL_CAPABILITIES_INTERFACE_DEL) {
		if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
			return false;
		return true;
	}

	rta_info = nl_attr_nest(&req.n, buflen, IFLA_LINKINFO);
	if (!rta_info)
		return false;

	if (!nl_attr_put(&req.n, buflen, IFLA_INFO_KIND, "dummy", 6))
		return false;

	nl_attr_nest_end(&req.n, rta_info);

	if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
		return false;

	return true;
}

static int check_seg6_encap_attrs_supported_func(struct zebra_ns *zns,
						 struct interface *ifp,
						 struct interface *ifp_dummy)
{
	if (!check_seg6_encap_attrs_in_progress)
		return 0;

	if (kernel_capabilities_has_seg6_encap_source() ||
	    kernel_capabilities_has_seg6_encap_lookup())
		return 0;

	check_seg6_encap_attrs_in_progress = false;

	if (!handle_fake_seg6_route(zns, RTM_NEWROUTE, ifp_dummy))
		goto netlink_error;

	if (!handle_fake_seg6_route(zns, RTM_GETROUTE, ifp))
		goto netlink_error;

	if (kernel_capabilities_has_seg6_encap_source())
		LOG_SUPPORTED_SEG6_ENCAP_SOURCE();
	else
		LOG_UNSUPPORTED_SEG6_ENCAP_SOURCE();

	if (kernel_capabilities_has_seg6_encap_lookup())
		LOG_SUPPORTED_SEG6_ENCAP_LOOKUP();
	else
		LOG_UNSUPPORTED_SEG6_ENCAP_LOOKUP();

	handle_fake_seg6_route(zns, RTM_DELROUTE, NULL);

	return 1;

netlink_error:
	LOG_UNSUPPORTED_SEG6_ENCAP_SOURCE();
	LOG_UNSUPPORTED_SEG6_ENCAP_LOOKUP();
	return -1;
}

static void check_srv6_attr_supported_func_notify(struct event *thread)
{
	if (kernel_capabilities_has_seg6_encap_source())
		LOG_SUPPORTED_SEG6_ENCAP_SOURCE();
	else
		LOG_UNSUPPORTED_SEG6_ENCAP_SOURCE();

	if (kernel_capabilities_has_seg6_encap_lookup())
		LOG_SUPPORTED_SEG6_ENCAP_LOOKUP();
	else
		LOG_UNSUPPORTED_SEG6_ENCAP_LOOKUP();
}

static bool check_process_is_in_root_netns(void)
{
	struct stat self_netns, root_netns;

	if (stat("/proc/self/ns/net", &self_netns) == -1) {
		zlog_debug("Erreur stat self");
		return false;
	}

	if (stat("/proc/1/ns/net", &root_netns) == -1) {
		zlog_debug("Erreur stat PID 1");
		return false;
	}

	return self_netns.st_ino == root_netns.st_ino;
}

void zebra_kernel_capabilities_init(void)
{
	check_seg6_encap_attrs_in_progress = false;
	kernel_capabilities_set_seg6_encap_source(false);
	kernel_capabilities_set_seg6_encap_lookup(false);

	kernel_capabilities_logging_enabled = check_process_is_in_root_netns();

	/* create the necessary interfaces to start the probing
	 * for srv6 capabilities check
	 */
	if (!check_srv6_interfaces_configured(KERNEL_CAPABILITIES_INTERFACE_ADD))
		LOG_UNSUPPORTED_SEG6_ENCAP_SOURCE();
}

/*
 * called upon interface creation
 * check that probe interface CHECK_SRV6_DUMMY_INTERFACE is created
 */
void zebra_kernel_capabilities_interface_created_cb(struct interface *ifp)
{
	struct zebra_ns *zns;
	struct interface *ifp_dummy;
	static bool supported_func_done = false;

	/* no need to check for dummy interface creation; only the last interface created is enough */
	if (strncmp(ifp->name, CHECK_SRV6_DUMMY_INTERFACE, strlen(CHECK_SRV6_DUMMY_INTERFACE) + 1))
		return;

	if (supported_func_done)
		/* avoid multiple events from the same interface if probing is over */
		return;

	zns = zebra_ns_lookup(NS_DEFAULT);
	if (!zns || zns->netlink_cmd.sock == -1)
		goto netlink_error;

	ifp_dummy = if_lookup_by_name(CHECK_SRV6_DUMMY_INTERFACE, VRF_DEFAULT);
	if (!ifp_dummy)
		goto netlink_error;

	if (check_seg6_encap_attrs_supported_func(zns, ifp, ifp_dummy) < 0)
		goto netlink_error;

	event_add_timer(zrouter.master, check_srv6_attr_supported_func_notify, NULL,
			CHECK_SRV6_ATTR_SUPPORTED_FUNC_DELAY_NOTIFY,
			&check_srv6_attr_supported_func_thread);

netlink_error:
	supported_func_done = true;
	check_srv6_interfaces_configured(KERNEL_CAPABILITIES_INTERFACE_DEL);
}

#else

bool zebra_kernel_capabilities_configure_interface(struct zebra_ns *zns, const char *ifname,
						   bool add_iface)
{
	return false;
}

void zebra_kernel_capabilities_init(void)
{
}

void zebra_kernel_capabilities_interface_created_cb(struct interface *ifp)
{
}

#endif /* HAVE_NETLINK */
