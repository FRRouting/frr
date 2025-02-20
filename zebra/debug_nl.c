// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2018 Rafael Zalamena
 */

#include <zebra.h>

#if defined(HAVE_NETLINK) && defined(NETLINK_DEBUG)

#include <sys/socket.h>

#include <linux/netconf.h>
#include <linux/netlink.h>
#include <linux/nexthop.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <linux/fib_rules.h>
#include <linux/lwtunnel.h>

#include <stdio.h>
#include <stdint.h>

#include "zebra/rt_netlink.h"
#include "zebra/kernel_netlink.h"
#include "lib/vxlan.h"

const char *nlmsg_type2str(uint16_t type)
{
	switch (type) {
	/* Generic */
	case NLMSG_NOOP:
		return "NOOP";
	case NLMSG_ERROR:
		return "ERROR";
	case NLMSG_DONE:
		return "DONE";
	case NLMSG_OVERRUN:
		return "OVERRUN";

	/* RTM */
	case RTM_NEWLINK:
		return "NEWLINK";
	case RTM_DELLINK:
		return "DELLINK";
	case RTM_GETLINK:
		return "GETLINK";
	case RTM_SETLINK:
		return "SETLINK";

	case RTM_NEWADDR:
		return "NEWADDR";
	case RTM_DELADDR:
		return "DELADDR";
	case RTM_GETADDR:
		return "GETADDR";

	case RTM_NEWROUTE:
		return "NEWROUTE";
	case RTM_DELROUTE:
		return "DELROUTE";
	case RTM_GETROUTE:
		return "GETROUTE";

	case RTM_NEWNEIGH:
		return "NEWNEIGH";
	case RTM_DELNEIGH:
		return "DELNEIGH";
	case RTM_GETNEIGH:
		return "GETNEIGH";

	case RTM_NEWRULE:
		return "NEWRULE";
	case RTM_DELRULE:
		return "DELRULE";
	case RTM_GETRULE:
		return "GETRULE";

	case RTM_NEWNEXTHOP:
		return "NEWNEXTHOP";
	case RTM_DELNEXTHOP:
		return "DELNEXTHOP";
	case RTM_GETNEXTHOP:
		return "GETNEXTHOP";

	case RTM_NEWTUNNEL:
		return "NEWTUNNEL";
	case RTM_DELTUNNEL:
		return "DELTUNNEL";
	case RTM_GETTUNNEL:
		return "GETTUNNEL";

	case RTM_NEWNETCONF:
		return "RTM_NEWNETCONF";
	case RTM_DELNETCONF:
		return "RTM_DELNETCONF";

	default:
		return "UNKNOWN";
	}
}

const char *af_type2str(int type)
{
	switch (type) {
	case AF_UNSPEC:
		return "AF_UNSPEC";
	case AF_UNIX:
		return "AF_UNIX";
	case AF_INET:
		return "AF_INET";
	case AF_INET6:
		return "AF_INET6";
	case AF_BRIDGE:
		return "AF_BRIDGE";
	case AF_NETLINK:
		return "AF_NETLINK";
#ifdef AF_MPLS
	case AF_MPLS:
		return "AF_MPLS";
#endif /* AF_MPLS */
	case AF_BLUETOOTH:
		return "AF_BLUETOOTH";
	case AF_VSOCK:
		return "AF_VSOCK";
	case AF_KEY:
		return "AF_KEY";
	case AF_PACKET:
		return "AF_PACKET";
	default:
		return "UNKNOWN";
	}
}

const char *ifi_type2str(int type)
{
	switch (type) {
	case ARPHRD_ETHER:
		return "ETHER";
	case ARPHRD_EETHER:
		return "EETHER";
	case ARPHRD_NETROM:
		return "NETROM";
	case ARPHRD_AX25:
		return "AX25";
	case ARPHRD_PRONET:
		return "PRONET";
	case ARPHRD_CHAOS:
		return "CHAOS";
	case ARPHRD_IEEE802:
		return "IEEE802";
	case ARPHRD_ARCNET:
		return "ARCNET";
	case ARPHRD_APPLETLK:
		return "APPLETLK";
	case ARPHRD_DLCI:
		return "DLCI";
	case ARPHRD_ATM:
		return "ATM";
	case ARPHRD_METRICOM:
		return "METRICOM";
	case ARPHRD_IEEE1394:
		return "IEEE1394";
	case ARPHRD_EUI64:
		return "EUI64";
	case ARPHRD_INFINIBAND:
		return "INFINIBAND";
	case ARPHRD_SLIP:
		return "SLIP";
	case ARPHRD_CSLIP:
		return "CSLIP";
	case ARPHRD_SLIP6:
		return "SLIP6";
	case ARPHRD_CSLIP6:
		return "CSLIP6";
	case ARPHRD_RSRVD:
		return "RSRVD";
	case ARPHRD_ADAPT:
		return "ADAPT";
	case ARPHRD_ROSE:
		return "ROSE";
	case ARPHRD_X25:
		return "X25";
	case ARPHRD_PPP:
		return "PPP";
	case ARPHRD_HDLC:
		return "HDLC";
	case ARPHRD_LAPB:
		return "LAPB";
	case ARPHRD_DDCMP:
		return "DDCMP";
	case ARPHRD_RAWHDLC:
		return "RAWHDLC";
	case ARPHRD_TUNNEL:
		return "TUNNEL";
	case ARPHRD_TUNNEL6:
		return "TUNNEL6";
	case ARPHRD_FRAD:
		return "FRAD";
	case ARPHRD_SKIP:
		return "SKIP";
	case ARPHRD_LOOPBACK:
		return "LOOPBACK";
	case ARPHRD_LOCALTLK:
		return "LOCALTLK";
	case ARPHRD_FDDI:
		return "FDDI";
	case ARPHRD_BIF:
		return "BIF";
	case ARPHRD_SIT:
		return "SIT";
	case ARPHRD_IPDDP:
		return "IPDDP";
	case ARPHRD_IPGRE:
		return "IPGRE";
	case ARPHRD_PIMREG:
		return "PIMREG";
	case ARPHRD_HIPPI:
		return "HIPPI";
	case ARPHRD_ASH:
		return "ASH";
	case ARPHRD_ECONET:
		return "ECONET";
	case ARPHRD_IRDA:
		return "IRDA";
	case ARPHRD_FCPP:
		return "FCPP";
	case ARPHRD_FCAL:
		return "FCAL";
	case ARPHRD_FCPL:
		return "FCPL";
	case ARPHRD_FCFABRIC:
		return "FCFABRIC";
	case ARPHRD_IEEE802_TR:
		return "IEEE802_TR";
	case ARPHRD_IEEE80211:
		return "IEEE80211";
	case ARPHRD_IEEE80211_PRISM:
		return "IEEE80211_PRISM";
	case ARPHRD_IEEE80211_RADIOTAP:
		return "IEEE80211_RADIOTAP";
	case ARPHRD_IEEE802154:
		return "IEEE802154";
#ifdef ARPHRD_VSOCKMON
	case ARPHRD_VSOCKMON:
		return "VSOCKMON";
#endif /* ARPHRD_VSOCKMON */
	case ARPHRD_VOID:
		return "VOID";
	case ARPHRD_NONE:
		return "NONE";
	default:
		return "UNKNOWN";
	}
}

const char *ifla_pdr_type2str(int type)
{
	switch (type) {
	case IFLA_PROTO_DOWN_REASON_UNSPEC:
		return "UNSPEC";
	case IFLA_PROTO_DOWN_REASON_MASK:
		return "MASK";
	case IFLA_PROTO_DOWN_REASON_VALUE:
		return "VALUE";
	default:
		return "UNKNOWN";
	}
}

const char *ifla_info_type2str(int type)
{
	switch (type) {
	case IFLA_INFO_UNSPEC:
		return "UNSPEC";
	case IFLA_INFO_KIND:
		return "KIND";
	case IFLA_INFO_DATA:
		return "DATA";
	case IFLA_INFO_XSTATS:
		return "XSTATS";
	case IFLA_INFO_SLAVE_KIND:
		return "SLAVE_KIND";
	case IFLA_INFO_SLAVE_DATA:
		return "SLAVE_DATA";
	default:
		return "UNKNOWN";
	}
}

const char *rta_type2str(int type)
{
	switch (type) {
	case IFLA_UNSPEC:
		return "UNSPEC";
	case IFLA_ADDRESS:
		return "ADDRESS";
	case IFLA_BROADCAST:
		return "BROADCAST";
	case IFLA_IFNAME:
		return "IFNAME";
	case IFLA_MTU:
		return "MTU";
	case IFLA_LINK:
		return "LINK";
	case IFLA_QDISC:
		return "QDISC";
	case IFLA_STATS:
		return "STATS";
	case IFLA_COST:
		return "COST";
	case IFLA_PRIORITY:
		return "PRIORITY";
	case IFLA_MASTER:
		return "MASTER";
	case IFLA_WIRELESS:
		return "WIRELESS";
	case IFLA_PROTINFO:
		return "PROTINFO";
	case IFLA_TXQLEN:
		return "TXQLEN";
	case IFLA_MAP:
		return "MAP";
	case IFLA_WEIGHT:
		return "WEIGHT";
	case IFLA_OPERSTATE:
		return "OPERSTATE";
	case IFLA_LINKMODE:
		return "LINKMODE";
	case IFLA_LINKINFO:
		return "LINKINFO";
	case IFLA_NET_NS_PID:
		return "NET_NS_PID";
	case IFLA_IFALIAS:
		return "IFALIAS";
	case IFLA_NUM_VF:
		return "NUM_VF";
	case IFLA_VFINFO_LIST:
		return "VFINFO_LIST";
	case IFLA_STATS64:
		return "STATS64";
	case IFLA_VF_PORTS:
		return "VF_PORTS";
	case IFLA_PORT_SELF:
		return "PORT_SELF";
	case IFLA_AF_SPEC:
		return "AF_SPEC";
	case IFLA_GROUP:
		return "GROUP";
	case IFLA_NET_NS_FD:
		return "NET_NS_FD";
	case IFLA_EXT_MASK:
		return "EXT_MASK";
	case IFLA_PROMISCUITY:
		return "PROMISCUITY";
	case IFLA_NUM_TX_QUEUES:
		return "NUM_TX_QUEUES";
	case IFLA_NUM_RX_QUEUES:
		return "NUM_RX_QUEUES";
	case IFLA_CARRIER:
		return "CARRIER";
	case IFLA_PHYS_PORT_ID:
		return "PHYS_PORT_ID";
	case IFLA_CARRIER_CHANGES:
		return "CARRIER_CHANGES";
	case IFLA_PHYS_SWITCH_ID:
		return "PHYS_SWITCH_ID";
	case IFLA_LINK_NETNSID:
		return "LINK_NETNSID";
	case IFLA_PHYS_PORT_NAME:
		return "PHYS_PORT_NAME";
	case IFLA_PROTO_DOWN:
		return "PROTO_DOWN";
#ifdef IFLA_GSO_MAX_SEGS
	case IFLA_GSO_MAX_SEGS:
		return "GSO_MAX_SEGS";
#endif /* IFLA_GSO_MAX_SEGS */
#ifdef IFLA_GSO_MAX_SIZE
	case IFLA_GSO_MAX_SIZE:
		return "GSO_MAX_SIZE";
#endif /* IFLA_GSO_MAX_SIZE */
#ifdef IFLA_PAD
	case IFLA_PAD:
		return "PAD";
#endif /* IFLA_PAD */
#ifdef IFLA_XDP
	case IFLA_XDP:
		return "XDP";
#endif /* IFLA_XDP */
#ifdef IFLA_EVENT
	case IFLA_EVENT:
		return "EVENT";
#endif /* IFLA_EVENT */
	case IFLA_PROTO_DOWN_REASON:
		return "PROTO_DOWN_REASON";
	default:
		return "UNKNOWN";
	}
}

const char *rtm_type2str(int type)
{
	switch (type) {
	case RTN_UNSPEC:
		return "UNSPEC";
	case RTN_UNICAST:
		return "UNICAST";
	case RTN_LOCAL:
		return "LOCAL";
	case RTN_BROADCAST:
		return "BROADCAST";
	case RTN_ANYCAST:
		return "ANYCAST";
	case RTN_MULTICAST:
		return "MULTICAST";
	case RTN_BLACKHOLE:
		return "BLACKHOLE";
	case RTN_UNREACHABLE:
		return "UNREACHABLE";
	case RTN_PROHIBIT:
		return "PROHIBIT";
	case RTN_THROW:
		return "THROW";
	case RTN_NAT:
		return "NAT";
	case RTN_XRESOLVE:
		return "XRESOLVE";
	default:
		return "UNKNOWN";
	}
}

const char *rtm_protocol2str(int type)
{
	switch (type) {
	case RTPROT_UNSPEC:
		return "UNSPEC";
	case RTPROT_REDIRECT:
		return "REDIRECT";
	case RTPROT_KERNEL:
		return "KERNEL";
	case RTPROT_BOOT:
		return "BOOT";
	case RTPROT_STATIC:
		return "STATIC";
	case RTPROT_GATED:
		return "GATED";
	case RTPROT_RA:
		return "RA";
	case RTPROT_MRT:
		return "MRT";
	case RTPROT_ZEBRA:
		return "ZEBRA";
	case RTPROT_BGP:
		return "BGP";
	case RTPROT_ISIS:
		return "ISIS";
	case RTPROT_OSPF:
		return "OSPF";
	case RTPROT_BIRD:
		return "BIRD";
	case RTPROT_DNROUTED:
		return "DNROUTED";
	case RTPROT_XORP:
		return "XORP";
	case RTPROT_NTK:
		return "NTK";
	case RTPROT_DHCP:
		return "DHCP";
	case RTPROT_MROUTED:
		return "MROUTED";
	case RTPROT_BABEL:
		return "BABEL";
	default:
		return "UNKNOWN";
	}
}

const char *rtm_scope2str(int type)
{
	switch (type) {
	case RT_SCOPE_UNIVERSE:
		return "UNIVERSE";
	case RT_SCOPE_SITE:
		return "SITE";
	case RT_SCOPE_LINK:
		return "LINK";
	case RT_SCOPE_HOST:
		return "HOST";
	case RT_SCOPE_NOWHERE:
		return "NOWHERE";
	default:
		return "UNKNOWN";
	}
}

const char *rtm_rta2str(int type)
{
	switch (type) {
	case RTA_UNSPEC:
		return "UNSPEC";
	case RTA_DST:
		return "DST";
	case RTA_SRC:
		return "SRC";
	case RTA_IIF:
		return "IIF";
	case RTA_OIF:
		return "OIF";
	case RTA_GATEWAY:
		return "GATEWAY";
	case RTA_PRIORITY:
		return "PRIORITY";
	case RTA_PREF:
		return "PREF";
	case RTA_PREFSRC:
		return "PREFSRC";
	case RTA_MARK:
		return "MARK";
	case RTA_METRICS:
		return "METRICS";
	case RTA_MULTIPATH:
		return "MULTIPATH";
	case RTA_PROTOINFO:
		return "PROTOINFO";
	case RTA_FLOW:
		return "FLOW";
	case RTA_CACHEINFO:
		return "CACHEINFO";
	case RTA_TABLE:
		return "TABLE";
	case RTA_MFC_STATS:
		return "MFC_STATS";
	case RTA_NH_ID:
		return "NH_ID";
	case RTA_EXPIRES:
		return "EXPIRES";
	case RTA_VIA:
		return "VIA";
	case RTA_ENCAP_TYPE:
		return "RTA_ENCAP_TYPE";
	case RTA_ENCAP:
		return "RTA_ENCAP";
	default:
		return "UNKNOWN";
	}
}

const char *neigh_rta2str(int type)
{
	switch (type) {
	case NDA_UNSPEC:
		return "UNSPEC";
	case NDA_DST:
		return "DST";
	case NDA_LLADDR:
		return "LLADDR";
	case NDA_CACHEINFO:
		return "CACHEINFO";
	case NDA_PROBES:
		return "PROBES";
	case NDA_VLAN:
		return "VLAN";
	case NDA_PORT:
		return "PORT";
	case NDA_VNI:
		return "VNI";
	case NDA_IFINDEX:
		return "IFINDEX";
	case NDA_MASTER:
		return "MASTER";
	case NDA_LINK_NETNSID:
		return "LINK_NETNSID";
	default:
		return "UNKNOWN";
	}
}

const char *ifa_rta2str(int type)
{
	switch (type) {
	case IFA_UNSPEC:
		return "UNSPEC";
	case IFA_ADDRESS:
		return "ADDRESS";
	case IFA_LOCAL:
		return "LOCAL";
	case IFA_LABEL:
		return "LABEL";
	case IFA_BROADCAST:
		return "BROADCAST";
	case IFA_ANYCAST:
		return "ANYCAST";
	case IFA_CACHEINFO:
		return "CACHEINFO";
	case IFA_MULTICAST:
		return "MULTICAST";
	case IFA_FLAGS:
		return "FLAGS";
	default:
		return "UNKNOWN";
	}
}

const char *nhm_rta2str(int type)
{
	switch (type) {
	case NHA_UNSPEC:
		return "UNSPEC";
	case NHA_ID:
		return "ID";
	case NHA_GROUP:
		return "GROUP";
	case NHA_GROUP_TYPE:
		return "GROUP_TYPE";
	case NHA_BLACKHOLE:
		return "BLACKHOLE";
	case NHA_OIF:
		return "OIF";
	case NHA_GATEWAY:
		return "GATEWAY";
	case NHA_ENCAP_TYPE:
		return "ENCAP_TYPE";
	case NHA_ENCAP:
		return "ENCAP";
	case NHA_GROUPS:
		return "GROUPS";
	case NHA_MASTER:
		return "MASTER";
	default:
		return "UNKNOWN";
	}
}

const char *frh_rta2str(int type)
{
	switch (type) {
	case FRA_DST:
		return "DST";
	case FRA_SRC:
		return "SRC";
	case FRA_IIFNAME:
		return "IIFNAME";
	case FRA_GOTO:
		return "GOTO";
	case FRA_UNUSED2:
		return "UNUSED2";
	case FRA_PRIORITY:
		return "PRIORITY";
	case FRA_UNUSED3:
		return "UNUSED3";
	case FRA_UNUSED4:
		return "UNUSED4";
	case FRA_UNUSED5:
		return "UNUSED5";
	case FRA_FWMARK:
		return "FWMARK";
	case FRA_FLOW:
		return "FLOW";
	case FRA_TUN_ID:
		return "TUN_ID";
	case FRA_SUPPRESS_IFGROUP:
		return "SUPPRESS_IFGROUP";
	case FRA_SUPPRESS_PREFIXLEN:
		return "SUPPRESS_PREFIXLEN";
	case FRA_TABLE:
		return "TABLE";
	case FRA_FWMASK:
		return "FWMASK";
	case FRA_OIFNAME:
		return "OIFNAME";
	case FRA_PAD:
		return "PAD";
	case FRA_L3MDEV:
		return "L3MDEV";
	case FRA_UID_RANGE:
		return "UID_RANGE";
	case FRA_PROTOCOL:
		return "PROTOCOL";
	case FRA_IP_PROTO:
		return "IP_PROTO";
	case FRA_SPORT_RANGE:
		return "SPORT_RANGE";
	case FRA_DPORT_RANGE:
		return "DPORT_RANGE";
	default:
		return "UNKNOWN";
	}
}

const char *frh_action2str(uint8_t action)
{
	switch (action) {
	case FR_ACT_TO_TBL:
		return "TO_TBL";
	case FR_ACT_GOTO:
		return "GOTO";
	case FR_ACT_NOP:
		return "NOP";
	case FR_ACT_RES3:
		return "RES3";
	case FR_ACT_RES4:
		return "RES4";
	case FR_ACT_BLACKHOLE:
		return "BLACKHOLE";
	case FR_ACT_UNREACHABLE:
		return "UNREACHABLE";
	case FR_ACT_PROHIBIT:
		return "PROHIBIT";
	default:
		return "UNKNOWN";
	}
}

static const char *ncm_rta2str(int type)
{
	switch (type) {
	case NETCONFA_UNSPEC:
		return "UNSPEC";
	case NETCONFA_IFINDEX:
		return "IFINDEX";
	case NETCONFA_FORWARDING:
		return "FORWARDING";
	case NETCONFA_RP_FILTER:
		return "RP_FILTER";
	case NETCONFA_MC_FORWARDING:
		return "MCAST";
	case NETCONFA_PROXY_NEIGH:
		return "PROXY_NEIGH";
	case NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN:
		return "IGNORE_LINKDOWN";
	case NETCONFA_INPUT:
		return "MPLS";
	case NETCONFA_BC_FORWARDING:
		return "BCAST";
	default:
		return "UNKNOWN";
	}
}

static void dump_on_off(uint32_t ival, const char *prefix)
{
	zlog_debug("%s%s", prefix, (ival != 0) ? "on" : "off");
}

static inline void flag_write(int flags, int flag, const char *flagstr,
			      char *buf, size_t buflen)
{
	if (CHECK_FLAG(flags, flag) == 0)
		return;

	if (buf[0])
		strlcat(buf, ",", buflen);

	strlcat(buf, flagstr, buflen);
}

const char *nlmsg_flags2str(uint16_t flags, char *buf, size_t buflen)
{
	const char *bufp = buf;

	*buf = 0;
	/* Specific flags. */
	flag_write(flags, NLM_F_REQUEST, "REQUEST", buf, buflen);
	flag_write(flags, NLM_F_MULTI, "MULTI", buf, buflen);
	flag_write(flags, NLM_F_ACK, "ACK", buf, buflen);
	flag_write(flags, NLM_F_ECHO, "ECHO", buf, buflen);
	flag_write(flags, NLM_F_DUMP, "DUMP", buf, buflen);

	/* Netlink family type dependent. */
	flag_write(flags, 0x0100, "(ROOT|REPLACE|CAPPED)", buf, buflen);
	flag_write(flags, 0x0200, "(MATCH|EXCLUDE|ACK_TLVS)", buf, buflen);
	flag_write(flags, 0x0400, "(ATOMIC|CREATE)", buf, buflen);
	flag_write(flags, 0x0800, "(DUMP|APPEND)", buf, buflen);

	return (bufp);
}

const char *if_flags2str(uint32_t flags, char *buf, size_t buflen)
{
	const char *bufp = buf;

	*buf = 0;
	flag_write(flags, IFF_UP, "UP", buf, buflen);
	flag_write(flags, IFF_BROADCAST, "BROADCAST", buf, buflen);
	flag_write(flags, IFF_DEBUG, "DEBUG", buf, buflen);
	flag_write(flags, IFF_LOOPBACK, "LOOPBACK", buf, buflen);
	flag_write(flags, IFF_POINTOPOINT, "POINTOPOINT", buf, buflen);
	flag_write(flags, IFF_NOTRAILERS, "NOTRAILERS", buf, buflen);
	flag_write(flags, IFF_RUNNING, "RUNNING", buf, buflen);
	flag_write(flags, IFF_NOARP, "NOARP", buf, buflen);
	flag_write(flags, IFF_PROMISC, "PROMISC", buf, buflen);
	flag_write(flags, IFF_ALLMULTI, "ALLMULTI", buf, buflen);
	flag_write(flags, IFF_MASTER, "MASTER", buf, buflen);
	flag_write(flags, IFF_SLAVE, "SLAVE", buf, buflen);
	flag_write(flags, IFF_MULTICAST, "MULTICAST", buf, buflen);
	flag_write(flags, IFF_PORTSEL, "PORTSEL", buf, buflen);
	flag_write(flags, IFF_AUTOMEDIA, "AUTOMEDIA", buf, buflen);
	flag_write(flags, IFF_DYNAMIC, "DYNAMIC", buf, buflen);

	return (bufp);
}

const char *rtm_flags2str(uint32_t flags, char *buf, size_t buflen)
{
	const char *bufp = buf;

	*buf = 0;
	flag_write(flags, RTM_F_NOTIFY, "NOTIFY", buf, buflen);
	flag_write(flags, RTM_F_CLONED, "CLONED", buf, buflen);
	flag_write(flags, RTM_F_EQUALIZE, "EQUALIZE", buf, buflen);

	return (bufp);
}

const char *neigh_state2str(uint32_t flags, char *buf, size_t buflen)
{
	const char *bufp = buf;

	*buf = 0;
	flag_write(flags, NUD_INCOMPLETE, "INCOMPLETE", buf, buflen);
	flag_write(flags, NUD_REACHABLE, "REACHABLE", buf, buflen);
	flag_write(flags, NUD_STALE, "STALE", buf, buflen);
	flag_write(flags, NUD_DELAY, "DELAY", buf, buflen);
	flag_write(flags, NUD_PROBE, "PROBE", buf, buflen);
	flag_write(flags, NUD_FAILED, "FAILED", buf, buflen);
	flag_write(flags, NUD_NOARP, "NOARP", buf, buflen);
	flag_write(flags, NUD_PERMANENT, "PERMANENT", buf, buflen);

	return (bufp);
}

const char *neigh_flags2str(uint32_t flags, char *buf, size_t buflen)
{
	const char *bufp = buf;

	*buf = 0;
	flag_write(flags, NTF_USE, "USE", buf, buflen);
	flag_write(flags, NTF_SELF, "SELF", buf, buflen);
	flag_write(flags, NTF_MASTER, "MASTER", buf, buflen);
	flag_write(flags, NTF_PROXY, "PROXY", buf, buflen);
	flag_write(flags, NTF_EXT_LEARNED, "EXT_LEARNED", buf, buflen);
#ifdef NTF_OFFLOADED
	flag_write(flags, NTF_OFFLOADED, "OFFLOADED", buf, buflen);
#endif /* NTF_OFFLOADED */
	flag_write(flags, NTF_ROUTER, "ROUTER", buf, buflen);

	return (bufp);
}

const char *ifa_flags2str(uint32_t flags, char *buf, size_t buflen)
{
	const char *bufp = buf;

	*buf = 0;
	flag_write(flags, IFA_F_SECONDARY, "SECONDARY", buf, buflen);
	flag_write(flags, IFA_F_NODAD, "NODAD", buf, buflen);
	flag_write(flags, IFA_F_OPTIMISTIC, "OPTIMISTIC", buf, buflen);
	flag_write(flags, IFA_F_DADFAILED, "DADFAILED", buf, buflen);
	flag_write(flags, IFA_F_HOMEADDRESS, "HOMEADDRESS", buf, buflen);
	flag_write(flags, IFA_F_DEPRECATED, "DEPRECATED", buf, buflen);
	flag_write(flags, IFA_F_TENTATIVE, "TENTATIVE", buf, buflen);
	flag_write(flags, IFA_F_PERMANENT, "PERMANENT", buf, buflen);
	flag_write(flags, IFA_F_MANAGETEMPADDR, "MANAGETEMPADDR", buf, buflen);
	flag_write(flags, IFA_F_NOPREFIXROUTE, "NOPREFIXROUTE", buf, buflen);
	flag_write(flags, IFA_F_MCAUTOJOIN, "MCAUTOJOIN", buf, buflen);
	flag_write(flags, IFA_F_STABLE_PRIVACY, "STABLE_PRIVACY", buf, buflen);

	return (bufp);
}

const char *nh_flags2str(uint32_t flags, char *buf, size_t buflen)
{
	const char *bufp = buf;

	*buf = 0;
	flag_write(flags, RTNH_F_DEAD, "DEAD", buf, buflen);
	flag_write(flags, RTNH_F_PERVASIVE, "PERVASIVE", buf, buflen);
	flag_write(flags, RTNH_F_ONLINK, "ONLINK", buf, buflen);
	flag_write(flags, RTNH_F_OFFLOAD, "OFFLOAD", buf, buflen);
	flag_write(flags, RTNH_F_LINKDOWN, "LINKDOWN", buf, buflen);
	flag_write(flags, RTNH_F_UNRESOLVED, "UNRESOLVED", buf, buflen);

	return (bufp);
}

/*
 * Netlink abstractions.
 */
static void nllink_pdr_dump(struct rtattr *rta, size_t msglen)
{
	size_t plen;
	uint32_t u32v;

next_rta:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);
	zlog_debug("      linkinfo [len=%d (payload=%zu) type=(%d) %s]",
		   rta->rta_len, plen, rta->rta_type,
		   ifla_pdr_type2str(rta->rta_type));
	switch (rta->rta_type) {
	case IFLA_PROTO_DOWN_REASON_MASK:
	case IFLA_PROTO_DOWN_REASON_VALUE:
		if (plen < sizeof(uint32_t)) {
			zlog_debug("        invalid length");
			break;
		}

		u32v = *(uint32_t *)RTA_DATA(rta);
		zlog_debug("        %u", u32v);
		break;

	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

static void nllink_linkinfo_dump(struct rtattr *rta, size_t msglen)
{
	size_t plen;
	char dbuf[128];

next_rta:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);
	zlog_debug("      linkinfo [len=%d (payload=%zu) type=(%d) %s]",
		   rta->rta_len, plen, rta->rta_type,
		   ifla_info_type2str(rta->rta_type));
	switch (rta->rta_type) {
	case IFLA_INFO_KIND:
		if (plen == 0) {
			zlog_debug("        invalid length");
			break;
		}

		snprintf(dbuf, sizeof(dbuf), "%s", (char *)RTA_DATA(rta));
		zlog_debug("        %s", dbuf);
		break;
	case IFLA_INFO_SLAVE_KIND:
		if (plen == 0) {
			zlog_debug("        invalid length");
			break;
		}

		snprintf(dbuf, sizeof(dbuf), "%s", (char *)RTA_DATA(rta));
		zlog_debug("        %s", dbuf);
		break;

	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

static void nllink_dump(struct ifinfomsg *ifi, size_t msglen)
{
	uint8_t *datap;
	struct rtattr *rta;
	size_t plen, it;
	uint32_t u32v;
	uint8_t u8v;
	char bytestr[16];
	char dbuf[128];
	unsigned short rta_type;

	/* Get the first attribute and go from there. */
	rta = IFLA_RTA(ifi);
next_rta:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);
	rta_type = rta->rta_type & ~NLA_F_NESTED;
	zlog_debug("    rta [len=%d (payload=%zu) type=(%d) %s]", rta->rta_len,
		   plen, rta_type, rta_type2str(rta_type));
	switch (rta_type) {
	case IFLA_IFNAME:
	case IFLA_IFALIAS:
		if (plen == 0) {
			zlog_debug("      invalid length");
			break;
		}

		snprintf(dbuf, sizeof(dbuf), "%s", (char *)RTA_DATA(rta));
		zlog_debug("      %s", dbuf);
		break;

	case IFLA_MTU:
	case IFLA_TXQLEN:
	case IFLA_NUM_TX_QUEUES:
	case IFLA_NUM_RX_QUEUES:
	case IFLA_GROUP:
	case IFLA_PROMISCUITY:
#ifdef IFLA_GSO_MAX_SEGS
	case IFLA_GSO_MAX_SEGS:
#endif /* IFLA_GSO_MAX_SEGS */
#ifdef IFLA_GSO_MAX_SIZE
	case IFLA_GSO_MAX_SIZE:
#endif /* IFLA_GSO_MAX_SIZE */
	case IFLA_CARRIER_CHANGES:
	case IFLA_MASTER:
	case IFLA_LINK:
		if (plen < sizeof(uint32_t)) {
			zlog_debug("      invalid length");
			break;
		}

		u32v = *(uint32_t *)RTA_DATA(rta);
		zlog_debug("      %u", u32v);
		break;

	case IFLA_PROTO_DOWN:
		if (plen < sizeof(uint8_t)) {
			zlog_debug("      invalid length");
			break;
		}

		u8v = *(uint8_t *)RTA_DATA(rta);
		zlog_debug("      %u", u8v);
		break;
	case IFLA_ADDRESS:
		datap = RTA_DATA(rta);
		dbuf[0] = 0;
		for (it = 0; it < plen; it++) {
			snprintf(bytestr, sizeof(bytestr), "%02X:", *datap);
			strlcat(dbuf, bytestr, sizeof(dbuf));
			datap++;
		}
		/* Remove trailing ':'. */
		if (dbuf[0])
			dbuf[strlen(dbuf) - 1] = 0;

		zlog_debug("      %s", dbuf[0] ? dbuf : "<empty>");
		break;

	case IFLA_LINKINFO:
		nllink_linkinfo_dump(RTA_DATA(rta), plen);
		break;

	case IFLA_PROTO_DOWN_REASON:
		nllink_pdr_dump(RTA_DATA(rta), plen);
		break;

	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

static void nlroute_dump(struct rtmsg *rtm, size_t msglen)
{
	struct rta_mfc_stats *mfc_stats;
	struct rtattr *rta;
	size_t plen;
	uint32_t u32v;
	uint64_t u64v;

	/* Get the first attribute and go from there. */
	rta = RTM_RTA(rtm);
next_rta:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);
	zlog_debug("    rta [len=%d (payload=%zu) type=(%d) %s]", rta->rta_len,
		   plen, rta->rta_type & NLA_TYPE_MASK,
		   rtm_rta2str(rta->rta_type & NLA_TYPE_MASK));
	switch (rta->rta_type & NLA_TYPE_MASK) {
	case RTA_IIF:
	case RTA_OIF:
	case RTA_PRIORITY:
	case RTA_TABLE:
	case RTA_NH_ID:
		u32v = *(uint32_t *)RTA_DATA(rta);
		zlog_debug("      %u", u32v);
		break;

	case RTA_EXPIRES:
		u64v = *(uint64_t *)RTA_DATA(rta);
		zlog_debug("      %" PRIu64, u64v);
		break;

	case RTA_GATEWAY:
	case RTA_DST:
	case RTA_SRC:
	case RTA_PREFSRC:
		switch (plen) {
		case sizeof(struct in_addr):
			zlog_debug("      %pI4",
				   (struct in_addr *)RTA_DATA(rta));
			break;
		case sizeof(struct in6_addr):
			zlog_debug("      %pI6",
				   (struct in6_addr *)RTA_DATA(rta));
			break;
		default:
			break;
		}
		break;

	case RTA_MFC_STATS:
		mfc_stats = (struct rta_mfc_stats *)RTA_DATA(rta);
		zlog_debug("      pkts=%ju bytes=%ju wrong_if=%ju",
			   (uintmax_t)mfc_stats->mfcs_packets,
			   (uintmax_t)mfc_stats->mfcs_bytes,
			   (uintmax_t)mfc_stats->mfcs_wrong_if);
		break;

	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

static void nlneigh_dump(struct ndmsg *ndm, size_t msglen)
{
	struct rtattr *rta;
	uint8_t *datap;
	size_t plen, it;
	uint16_t vid;
	char bytestr[16];
	char dbuf[128];
	unsigned short rta_type;

#ifndef NDA_RTA
#define NDA_RTA(ndm)                                                           \
	/* struct ndmsg *ndm; */                                               \
	((struct rtattr *)(((uint8_t *)(ndm))                                  \
			   + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif /* NDA_RTA */

	/* Get the first attribute and go from there. */
	rta = NDA_RTA(ndm);
next_rta:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);
	rta_type = rta->rta_type & ~NLA_F_NESTED;
	zlog_debug("    rta [len=%d (payload=%zu) type=(%d) %s]", rta->rta_len,
		   plen, rta->rta_type, neigh_rta2str(rta_type));
	switch (rta_type) {
	case NDA_LLADDR:
		datap = RTA_DATA(rta);
		dbuf[0] = 0;
		for (it = 0; it < plen; it++) {
			snprintf(bytestr, sizeof(bytestr), "%02X:", *datap);
			strlcat(dbuf, bytestr, sizeof(dbuf));
			datap++;
		}
		/* Remove trailing ':'. */
		if (dbuf[0])
			dbuf[strlen(dbuf) - 1] = 0;

		zlog_debug("      %s", dbuf[0] ? dbuf : "<empty>");
		break;

	case NDA_DST:
		switch (plen) {
		case sizeof(struct in_addr):
			zlog_debug("      %pI4",
				   (struct in_addr *)RTA_DATA(rta));
			break;
		case sizeof(struct in6_addr):
			zlog_debug("      %pI6",
				   (struct in6_addr *)RTA_DATA(rta));
			break;
		default:
			break;
		}
		break;

	case NDA_VLAN:
		vid = *(uint16_t *)RTA_DATA(rta);
		zlog_debug("      %d", vid);
		break;

	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

static void nlifa_dump(struct ifaddrmsg *ifa, size_t msglen)
{
	struct rtattr *rta;
	size_t plen;
	uint32_t u32v;

	/* Get the first attribute and go from there. */
	rta = IFA_RTA(ifa);
next_rta:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);
	zlog_debug("    rta [len=%d (payload=%zu) type=(%d) %s]", rta->rta_len,
		   plen, rta->rta_type, ifa_rta2str(rta->rta_type));
	switch (rta->rta_type) {
	case IFA_UNSPEC:
		u32v = *(uint32_t *)RTA_DATA(rta);
		zlog_debug("      %u", u32v);
		break;

	case IFA_LABEL:
		zlog_debug("      %s", (const char *)RTA_DATA(rta));
		break;

	case IFA_ADDRESS:
	case IFA_LOCAL:
	case IFA_BROADCAST:
		switch (plen) {
		case 4:
			zlog_debug("      %pI4",
				   (struct in_addr *)RTA_DATA(rta));
			break;
		case 16:
			zlog_debug("      %pI6",
				   (struct in6_addr *)RTA_DATA(rta));
			break;
		default:
			break;
		}
		break;

	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

static void nltnl_dump(struct tunnel_msg *tnlm, size_t msglen)
{
	struct rtattr *attr;
	vni_t vni_start = 0, vni_end = 0;
	struct rtattr *ttb[VXLAN_VNIFILTER_ENTRY_MAX + 1];
	uint8_t rta_type;

	attr = TUNNEL_RTA(tnlm);
next_attr:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(attr, msglen) == 0)
		return;

	rta_type = attr->rta_type & NLA_TYPE_MASK;

	if (rta_type != VXLAN_VNIFILTER_ENTRY) {
		attr = RTA_NEXT(attr, msglen);
		goto next_attr;
	}

	memset(ttb, 0, sizeof(ttb));

	netlink_parse_rtattr_flags(ttb, VXLAN_VNIFILTER_ENTRY_MAX,
				   RTA_DATA(attr), RTA_PAYLOAD(attr),
				   NLA_F_NESTED);

	if (ttb[VXLAN_VNIFILTER_ENTRY_START])
		vni_start =
			*(uint32_t *)RTA_DATA(ttb[VXLAN_VNIFILTER_ENTRY_START]);

	if (ttb[VXLAN_VNIFILTER_ENTRY_END])
		vni_end = *(uint32_t *)RTA_DATA(ttb[VXLAN_VNIFILTER_ENTRY_END]);
	zlog_debug("  vni_start %u, vni_end %u", vni_start, vni_end);

	attr = RTA_NEXT(attr, msglen);
	goto next_attr;
}

static const char *lwt_type2str(uint16_t type)
{
	switch (type) {
	case LWTUNNEL_ENCAP_NONE:
		return "NONE";
	case LWTUNNEL_ENCAP_MPLS:
		return "MPLS";
	case LWTUNNEL_ENCAP_IP:
		return "IPv4";
	case LWTUNNEL_ENCAP_ILA:
		return "ILA";
	case LWTUNNEL_ENCAP_IP6:
		return "IPv6";
	case LWTUNNEL_ENCAP_SEG6:
		return "SEG6";
	case LWTUNNEL_ENCAP_BPF:
		return "BPF";
	case LWTUNNEL_ENCAP_SEG6_LOCAL:
		return "SEG6_LOCAL";
	default:
		return "UNKNOWN";
	}
}

static const char *nhg_type2str(uint16_t type)
{
	switch (type) {
	case NEXTHOP_GRP_TYPE_MPATH:
		return "MULTIPATH";
	case NEXTHOP_GRP_TYPE_RES:
		return "RESILIENT MULTIPATH";
	default:
		return "UNKNOWN";
	}
}

static void nlnh_dump(struct nhmsg *nhm, size_t msglen)
{
	struct rtattr *rta;
	int ifindex;
	size_t plen;
	uint16_t u16v;
	uint32_t u32v;
	unsigned long count, i;
	struct nexthop_grp *nhgrp;
	unsigned short rta_type;

	rta = RTM_NHA(nhm);

next_rta:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);
	rta_type = rta->rta_type & ~NLA_F_NESTED;
	zlog_debug("    rta [len=%d (payload=%zu) type=(%d) %s]", rta->rta_len,
		   plen, rta->rta_type, nhm_rta2str(rta_type));
	switch (rta_type) {
	case NHA_ID:
		u32v = *(uint32_t *)RTA_DATA(rta);
		zlog_debug("      %u", u32v);
		break;
	case NHA_GROUP:
		nhgrp = (struct nexthop_grp *)RTA_DATA(rta);
		count = (RTA_PAYLOAD(rta) / sizeof(*nhgrp));
		if (count == 0
		    || (count * sizeof(*nhgrp)) != RTA_PAYLOAD(rta)) {
			zlog_debug("      invalid nexthop group received");
			return;
		}

		for (i = 0; i < count; i++)
			zlog_debug("      id %d weight %d", nhgrp[i].id,
				   nhgrp[i].weight);
		break;
	case NHA_ENCAP_TYPE:
		u16v = *(uint16_t *)RTA_DATA(rta);
		zlog_debug("      %s", lwt_type2str(u16v));
		break;
	case NHA_GROUP_TYPE:
		u16v = *(uint16_t *)RTA_DATA(rta);
		zlog_debug("      %s", nhg_type2str(u16v));
		break;
	case NHA_BLACKHOLE:
		/* NOTHING */
		break;
	case NHA_OIF:
		ifindex = *(int *)RTA_DATA(rta);
		zlog_debug("      %d", ifindex);
		break;
	case NHA_GATEWAY:
		switch (nhm->nh_family) {
		case AF_INET:
			zlog_debug("      %pI4",
				   (struct in_addr *)RTA_DATA(rta));
			break;
		case AF_INET6:
			zlog_debug("      %pI6",
				   (struct in6_addr *)RTA_DATA(rta));
			break;

		default:
			zlog_debug("      invalid family %d", nhm->nh_family);
			break;
		}
		break;
	case NHA_ENCAP:
		/* TODO: handle MPLS labels. */
		zlog_debug("      unparsed MPLS labels");
		break;
	case NHA_GROUPS:
		/* TODO: handle this message. */
		zlog_debug("      unparsed GROUPS message");
		break;

	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

static void nlrule_dump(struct fib_rule_hdr *frh, size_t msglen)
{
	struct rtattr *rta;
	size_t plen;
	uint8_t u8v;
	uint32_t u32v;
	int32_t s32v;
	uint64_t u64v;
	char dbuf[128];
	struct fib_rule_uid_range *u_range;
	struct fib_rule_port_range *p_range;

	/* Get the first attribute and go from there. */
	rta = RTM_RTA(frh);
next_rta:
	/* Check the header for valid length and for outbound access. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);
	zlog_debug("    rta [len=%d (payload=%zu) type=(%d) %s]", rta->rta_len,
		   plen, rta->rta_type, frh_rta2str(rta->rta_type));
	switch (rta->rta_type) {
	case FRA_DST:
	case FRA_SRC:
		switch (plen) {
		case sizeof(struct in_addr):
			zlog_debug("      %pI4",
				   (struct in_addr *)RTA_DATA(rta));
			break;
		case sizeof(struct in6_addr):
			zlog_debug("      %pI6",
				   (struct in6_addr *)RTA_DATA(rta));
			break;
		default:
			break;
		}
		break;

	case FRA_IIFNAME:
	case FRA_OIFNAME:
		snprintf(dbuf, sizeof(dbuf), "%s", (char *)RTA_DATA(rta));
		zlog_debug("        %s", dbuf);
		break;

	case FRA_GOTO:
	case FRA_UNUSED2:
	case FRA_PRIORITY:
	case FRA_UNUSED3:
	case FRA_UNUSED4:
	case FRA_UNUSED5:
	case FRA_FWMARK:
	case FRA_FLOW:
	case FRA_TABLE:
	case FRA_FWMASK:
		u32v = *(uint32_t *)RTA_DATA(rta);
		zlog_debug("      %u", u32v);
		break;

	case FRA_SUPPRESS_IFGROUP:
	case FRA_SUPPRESS_PREFIXLEN:
		s32v = *(int32_t *)RTA_DATA(rta);
		zlog_debug("      %d", s32v);
		break;

	case FRA_TUN_ID:
		u64v = *(uint64_t *)RTA_DATA(rta);
		zlog_debug("      %" PRIu64, u64v);
		break;

	case FRA_L3MDEV:
	case FRA_PROTOCOL:
	case FRA_IP_PROTO:
		u8v = *(uint8_t *)RTA_DATA(rta);
		zlog_debug("      %u", u8v);
		break;

	case FRA_UID_RANGE:
		u_range = (struct fib_rule_uid_range *)RTA_DATA(rta);
		if (u_range->start == u_range->end)
			zlog_debug("      %u", u_range->start);
		else
			zlog_debug("      %u-%u", u_range->start, u_range->end);
		break;

	case FRA_SPORT_RANGE:
	case FRA_DPORT_RANGE:
		p_range = (struct fib_rule_port_range *)RTA_DATA(rta);
		if (p_range->start == p_range->end)
			zlog_debug("      %u", p_range->start);
		else
			zlog_debug("      %u-%u", p_range->start, p_range->end);
		break;

	case FRA_PAD: /* fallthrough */
	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

static const char *tcm_nltype2str(int nltype)
{
	switch (nltype) {
	case RTM_NEWQDISC:
	case RTM_DELQDISC:
		return "qdisc";
	case RTM_NEWTCLASS:
	case RTM_DELTCLASS:
		return "tclass";
	case RTM_NEWTFILTER:
	case RTM_DELTFILTER:
		return "tfilter";
	default:
		/* should never hit */
		return "unknown";
	}
}

static void nlncm_dump(const struct netconfmsg *ncm, size_t msglen)
{
	const struct rtattr *rta;
	size_t plen;
	uint32_t ival;

	rta = (void *)((const char *)ncm +
		       NLMSG_ALIGN(sizeof(struct netconfmsg)));

next_rta:
	/* Check the attr header for valid length. */
	if (RTA_OK(rta, msglen) == 0)
		return;

	plen = RTA_PAYLOAD(rta);

	zlog_debug("    rta [len=%d (payload=%zu) type=(%d) %s]", rta->rta_len,
		   plen, rta->rta_type, ncm_rta2str(rta->rta_type));

	switch (rta->rta_type) {
	case NETCONFA_IFINDEX:
		ival = *(uint32_t *)RTA_DATA(rta);
		zlog_debug("      %d", (int32_t)ival);
		break;

	/* Most attrs are just on/off. */
	case NETCONFA_FORWARDING:
	case NETCONFA_RP_FILTER:
	case NETCONFA_MC_FORWARDING:
	case NETCONFA_PROXY_NEIGH:
	case NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN:
	case NETCONFA_INPUT:
	case NETCONFA_BC_FORWARDING:
		ival = *(uint32_t *)RTA_DATA(rta);
		dump_on_off(ival, "      ");
		break;
	default:
		/* NOTHING: unhandled. */
		break;
	}

	/* Get next pointer and start iteration again. */
	rta = RTA_NEXT(rta, msglen);
	goto next_rta;
}

void nl_dump(void *msg, size_t msglen)
{
	struct nlmsghdr *nlmsg = msg;
	struct nlmsgerr *nlmsgerr;
	struct rtgenmsg *rtgen;
	struct ifaddrmsg *ifa;
	struct ndmsg *ndm;
	struct rtmsg *rtm;
	struct nhmsg *nhm;
	struct netconfmsg *ncm;
	struct ifinfomsg *ifi;
	struct tunnel_msg *tnlm;
	struct fib_rule_hdr *frh;
	struct tcmsg *tcm;

	char fbuf[128];
	char ibuf[128];

next_header:
	zlog_debug(
		"nlmsghdr [len=%u type=(%d) %s flags=(0x%04x) {%s} seq=%u pid=%u]",
		nlmsg->nlmsg_len, nlmsg->nlmsg_type,
		nlmsg_type2str(nlmsg->nlmsg_type), nlmsg->nlmsg_flags,
		nlmsg_flags2str(nlmsg->nlmsg_flags, fbuf, sizeof(fbuf)),
		nlmsg->nlmsg_seq, nlmsg->nlmsg_pid);

	switch (nlmsg->nlmsg_type) {
	/* Generic. */
	case NLMSG_NOOP:
		break;
	case NLMSG_ERROR:
		nlmsgerr = NLMSG_DATA(nlmsg);
		zlog_debug("  nlmsgerr [error=(%d) %s]", nlmsgerr->error,
			   strerror(-nlmsgerr->error));
		break;
	case NLMSG_DONE:
		return;
	case NLMSG_OVERRUN:
		break;

	/* RTM. */
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_SETLINK:
		ifi = NLMSG_DATA(nlmsg);
		zlog_debug(
			"  ifinfomsg [family=%d type=(%d) %s index=%d flags=0x%04x {%s}]",
			ifi->ifi_family, ifi->ifi_type,
			ifi_type2str(ifi->ifi_type), ifi->ifi_index,
			ifi->ifi_flags,
			if_flags2str(ifi->ifi_flags, ibuf, sizeof(ibuf)));
		nllink_dump(ifi, nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
		break;
	case RTM_GETLINK:
		rtgen = NLMSG_DATA(nlmsg);
		zlog_debug("  rtgen [family=(%d) %s]", rtgen->rtgen_family,
			   af_type2str(rtgen->rtgen_family));
		break;

	case RTM_NEWROUTE:
	case RTM_DELROUTE:
	case RTM_GETROUTE:
		rtm = NLMSG_DATA(nlmsg);
		zlog_debug(
			"  rtmsg [family=(%d) %s dstlen=%d srclen=%d tos=%d table=%d protocol=(%d) %s scope=(%d) %s type=(%d) %s flags=0x%04x {%s}]",
			rtm->rtm_family, af_type2str(rtm->rtm_family),
			rtm->rtm_dst_len, rtm->rtm_src_len, rtm->rtm_tos,
			rtm->rtm_table, rtm->rtm_protocol,
			rtm_protocol2str(rtm->rtm_protocol), rtm->rtm_scope,
			rtm_scope2str(rtm->rtm_scope), rtm->rtm_type,
			rtm_type2str(rtm->rtm_type), rtm->rtm_flags,
			rtm_flags2str(rtm->rtm_flags, fbuf, sizeof(fbuf)));
		nlroute_dump(rtm,
			     nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm)));
		break;

	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		ndm = NLMSG_DATA(nlmsg);
		zlog_debug(
			"  ndm [family=%d (%s) ifindex=%d state=0x%04x {%s} flags=0x%04x {%s} type=%d (%s)]",
			ndm->ndm_family, af_type2str(ndm->ndm_family),
			ndm->ndm_ifindex, ndm->ndm_state,
			neigh_state2str(ndm->ndm_state, ibuf, sizeof(ibuf)),
			ndm->ndm_flags,
			neigh_flags2str(ndm->ndm_flags, fbuf, sizeof(fbuf)),
			ndm->ndm_type, rtm_type2str(ndm->ndm_type));
		nlneigh_dump(ndm,
			     nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*ndm)));
		break;

	case RTM_NEWRULE:
	case RTM_DELRULE:
		frh = NLMSG_DATA(nlmsg);
		zlog_debug(
			"  frh [family=%d (%s) dst_len=%d src_len=%d tos=%d table=%d res1=%d res2=%d action=%d (%s) flags=0x%x]",
			frh->family, af_type2str(frh->family), frh->dst_len,
			frh->src_len, frh->tos, frh->table, frh->res1,
			frh->res2, frh->action, frh_action2str(frh->action),
			frh->flags);
		nlrule_dump(frh, nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*frh)));
		break;


	case RTM_NEWADDR:
	case RTM_DELADDR:
		ifa = NLMSG_DATA(nlmsg);
		zlog_debug(
			"  ifa [family=(%d) %s prefixlen=%d flags=0x%04x {%s} scope=%d index=%u]",
			ifa->ifa_family, af_type2str(ifa->ifa_family),
			ifa->ifa_prefixlen, ifa->ifa_flags,
			if_flags2str(ifa->ifa_flags, fbuf, sizeof(fbuf)),
			ifa->ifa_scope, ifa->ifa_index);
		nlifa_dump(ifa, nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
		break;

	case RTM_NEWNEXTHOP:
	case RTM_DELNEXTHOP:
	case RTM_GETNEXTHOP:
		nhm = NLMSG_DATA(nlmsg);
		zlog_debug(
			"  nhm [family=(%d) %s scope=(%d) %s protocol=(%d) %s flags=0x%08x {%s}]",
			nhm->nh_family, af_type2str(nhm->nh_family),
			nhm->nh_scope, rtm_scope2str(nhm->nh_scope),
			nhm->nh_protocol, rtm_protocol2str(nhm->nh_protocol),
			nhm->nh_flags,
			nh_flags2str(nhm->nh_flags, fbuf, sizeof(fbuf)));
		nlnh_dump(nhm, nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*nhm)));
		break;

	case RTM_NEWTUNNEL:
	case RTM_DELTUNNEL:
	case RTM_GETTUNNEL:
		tnlm = NLMSG_DATA(nlmsg);
		zlog_debug("  tnlm [family=(%d) %s ifindex=%d ", tnlm->family,
			   af_type2str(tnlm->family), tnlm->ifindex);
		nltnl_dump(tnlm,
			   nlmsg->nlmsg_len -
				   NLMSG_LENGTH(sizeof(struct tunnel_msg)));
		break;


	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
		ncm = NLMSG_DATA(nlmsg);
		zlog_debug(" ncm [family=%s (%d)]",
			   af_type2str(ncm->ncm_family), ncm->ncm_family);
		nlncm_dump(ncm, nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(*ncm)));
		break;

	case RTM_NEWQDISC:
	case RTM_DELQDISC:
	case RTM_NEWTCLASS:
	case RTM_DELTCLASS:
	case RTM_NEWTFILTER:
	case RTM_DELTFILTER:
		tcm = NLMSG_DATA(nlmsg);
		zlog_debug(
			" tcm [type=%s family=%s (%d) ifindex=%d handle=%04x:%04x]",
			tcm_nltype2str(nlmsg->nlmsg_type),
			af_type2str(tcm->tcm_family), tcm->tcm_family,
			tcm->tcm_ifindex, tcm->tcm_handle >> 16,
			tcm->tcm_handle & 0xffff);
		break;

	default:
		break;
	}

	/*
	 * Try to get the next header. There should only be more
	 * messages if this header was flagged as MULTI, otherwise just
	 * end it here.
	 */
	nlmsg = NLMSG_NEXT(nlmsg, msglen);
	if (NLMSG_OK(nlmsg, msglen) == 0)
		return;

	goto next_header;
}

#endif /* NETLINK_DEBUG */
