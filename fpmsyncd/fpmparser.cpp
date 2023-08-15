#include <fstream>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>
#include "fpmjson.h"
#include "linux/netlink.h"
#include "netlink/msg.h"
#include "fpmparser.h"
#include <string.h>
#include <arpa/inet.h>

#include "log.h"
#include "zlog.h"
using namespace std;


#define VXLAN_IF_NAME_PREFIX "Brvxlan"
#define VNET_PREFIX	     "Vnet"
#define VRF_PREFIX	     "Vrf"
#define MGMT_VRF_PREFIX	     "mgmt"

#define NHG_DELIMITER ','

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef NDA_RTA
#define NDA_RTA(r)                                                             \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#define VXLAN_VNI      0
#define VXLAN_RMAC     1
#define NH_ENCAP_VXLAN 100


#define IPV4_MAX_BYTE	4
#define IPV6_MAX_BYTE	16
#define IPV4_MAX_BITLEN 32
#define IPV6_MAX_BITLEN 128

#define ETHER_ADDR_STRLEN (3 * ETH_ALEN)


string getTimestamp()
{
	char buffer[64];
	struct timeval tv;
	gettimeofday(&tv, NULL);

	size_t size = strftime(buffer, 32, "%Y-%m-%d.%T.",
			       localtime(&tv.tv_sec));
	snprintf(&buffer[size], 32, "%06ld", tv.tv_usec);

	return string(buffer);
}


Fpmparser::Fpmparser(char *file_path)
{
	m_nl_sock = nl_socket_alloc();
	nl_connect(m_nl_sock, NETLINK_ROUTE);
	rtnl_link_alloc_cache(m_nl_sock, AF_UNSPEC, &m_link_cache);
	m_output_file_path = file_path;
	m_output_file.open(m_output_file_path,
			   std::ofstream::in | std::ofstream::out);

	thread_exit = false;
	flushtimer_t = std::thread(&Fpmparser::timer_flush_pipe, this);
}

Fpmparser::~Fpmparser()
{
	thread_exit = true;
	flushtimer_t.detach();
	Fpmparser::fflush();
	m_output_file.close();
}

void Fpmparser::push_to_ringbuffer(fpmjson::header &header,
				   fpmjson::payload &payload)
{
	fpmjson::msg msg(header, payload, getTimestamp());
	while (!m_task_ringbuffer.push(msg.to_json())) {
		usleep(10);
	}
	return;
}

bool Fpmparser::is_output_file_empty()
{
	m_output_file.seekp(0, std::ios::end);
	return m_output_file.tellp() == 0;
}

std::string nlmsg_type2str(int nlmsg_type)
{
	if (nlmsg_type == RTM_NEWROUTE)
		return "RTM_NEWROUTE";
	else if (nlmsg_type == RTM_DELROUTE)
		return "RTM_DELROUTE";
	else if (nlmsg_type == RTM_NEWLINK)
		return "RTM_NEWLINK";
	else if (nlmsg_type == RTM_DELLINK)
		return "RTM_DELLINK";
	else
		return "unknown";
}

bool Fpmparser::getIfName(int if_index, char *if_name, size_t name_len)
{
	if (!if_name || name_len == 0) {
		return false;
	}
	memset(if_name, 0, name_len);

	/* Cannot get interface name. Possibly the interface gets re-created. */
	if (!rtnl_link_i2name(m_link_cache, if_index, if_name, name_len)) {
		/* Trying to refill cache */
		nl_cache_refill(m_nl_sock, m_link_cache);
		if (!rtnl_link_i2name(m_link_cache, if_index, if_name,
				      name_len)) {
			return false;
		}
	}
	return true;
}


void Fpmparser::fflush()
{
	if (m_task_ringbuffer.is_empty())
		return;
	nlohmann::json j;
	/* Handle json format */
	if (is_output_file_empty()) {
		m_task_ringbuffer.pop(j);
		m_output_file << "[" << j.dump(4) << "]" << std::endl;
	}
	while (!m_task_ringbuffer.is_empty()) {
		m_output_file.seekp(-2, std::ios::end);
		m_task_ringbuffer.pop(j);
		m_output_file << ",\n" << j.dump(4) << "]" << std::endl;
	}
}

void Fpmparser::timer_flush_pipe()
{
	while (!thread_exit) {
		usleep(100);
		this->fflush();
	}
}

fpmjson::header nlmsg_header_to_json_header(struct nlmsghdr *nlh)
{
	char buf[128];
	return fpmjson::header(nl_nlmsg_flags2str(nlh->nlmsg_flags, buf,
						  sizeof(buf)),
			       nlh->nlmsg_len, nlh->nlmsg_pid, nlh->nlmsg_seq,
			       nlmsg_type2str(nlh->nlmsg_type));
}

/**
 * @parseEncap() - Parses encapsulated attributes
 * @tb:         Pointer to rtattr to look for nested items in.
 * @labels:     Pointer to store vni in.
 *
 * Return:      void.
 */
void Fpmparser::parseEncap(struct rtattr *tb, uint32_t &encap_value,
			   string &rmac)
{
	struct rtattr *tb_encap[3] = { 0 };
	char mac_buf[MAX_ADDR_SIZE + 1];
	char mac_val[MAX_ADDR_SIZE + 1];

	netlink_parse_rtattr(tb_encap, 3, (struct rtattr *)RTA_DATA(tb),
			     (int)RTA_PAYLOAD(tb));
	encap_value = *(uint32_t *)RTA_DATA(tb_encap[VXLAN_VNI]);
	if (!tb_encap[VXLAN_RMAC]) {
		rmac = "";
		zlog_err("Broken encap, tb_encap[VXLAN_RMAC] is NULL");
		return;
	}
	memcpy(&mac_buf, RTA_DATA(tb_encap[VXLAN_RMAC]), MAX_ADDR_SIZE);
	snprintf(mac_val, (ETHER_ADDR_STRLEN), "%02x:%02x:%02x:%02x:%02x:%02x",
		 (uint8_t)mac_buf[0], (uint8_t)mac_buf[1], (uint8_t)mac_buf[2],
		 (uint8_t)mac_buf[3], (uint8_t)mac_buf[4], (uint8_t)mac_buf[5]);

	rmac = mac_val;

	return;
}

bool Fpmparser::parse_evpn_nexthop(struct rtattr **tb, struct rtattr **subtb,
				   fpmjson::evpn_nexthop *nexthop)
{
	char gateaddr[IPV4_MAX_BYTE] = { 0 };
	struct in6_addr ipv6_address;
	char if_name[IFNAMSIZ + 1] = { 0 };
	char nexthopaddr[MAX_ADDR_SIZE + 1] = { 0 };
	int vrf_index;
	string vlan;
	uint16_t encap = 0;
	uint32_t encap_value = 0;
	string rmac;

	if (tb[RTA_GATEWAY]) {
		if (RTA_PAYLOAD(tb[RTA_GATEWAY]) <= IPV4_MAX_BYTE) {
			memcpy(gateaddr, tb[RTA_GATEWAY], IPV4_MAX_BYTE);
		} else {
			memcpy(ipv6_address.s6_addr, tb[RTA_GATEWAY],
			       IPV6_MAX_BYTE);
			if (IN6_IS_ADDR_V4MAPPED(&ipv6_address)) {
				memcpy(gateaddr, (ipv6_address.s6_addr + 12),
				       IPV4_MAX_BYTE);
			} else
				return false;
		}
	}

	inet_ntop(AF_INET, gateaddr, nexthopaddr, MAX_ADDR_SIZE);

	if (subtb[RTA_OIF]) {
		vrf_index = *(int *)RTA_DATA(subtb[RTA_OIF]);

		if (!getIfName(vrf_index, if_name, IFNAMSIZ)) {
			strcpy(if_name, "unknown");
		}
		vlan = if_name;
	}

	if (subtb[RTA_ENCAP_TYPE]) {
		encap = *(uint16_t *)RTA_DATA(subtb[RTA_ENCAP_TYPE]);
	}
	if (subtb[RTA_ENCAP] && subtb[RTA_ENCAP_TYPE] &&
	    (*(uint16_t *)RTA_DATA(subtb[RTA_ENCAP_TYPE]) == NH_ENCAP_VXLAN)) {
		parseEncap(subtb[RTA_ENCAP], encap_value, rmac);
	}
	if (encap_value == 0 || !(vlan.compare("unknown"))) {
		return false;
	}
	nexthop->gate = string(nexthopaddr);
	nexthop->interface = string(vlan);
	nexthop->vni = to_string(encap_value);
	nexthop->rmac = rmac;
}

bool Fpmparser::getEvpnNextHopList(struct nlmsghdr *h, struct rtattr *tb[],
				   std::vector<fpmjson::nexthop *> &nexthop_list)
{
	if (h->nlmsg_type == RTM_NEWROUTE) {
		if (!tb[RTA_MULTIPATH]) {
			fpmjson::evpn_nexthop *nh;
			parse_evpn_nexthop(tb, tb, nh);
			nexthop_list.push_back((fpmjson::nexthop *)nh);
		} else {
			/* This is a multipath route */
			struct rtattr *subtb[RTA_MAX + 1];
			int len = (int)RTA_PAYLOAD(tb[RTA_MULTIPATH]);
			struct rtnexthop *rtnh =
				(struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);
			for (; len >= rtnh->rtnh_len;
			     len -= NLMSG_ALIGN(rtnh->rtnh_len),
			     rtnh = RTNH_NEXT(rtnh)) {
				// zlog_debug("rtnh->rtnh_len %d,sizeof(*rtnh) %d",
				// 	   rtnh->rtnh_len, sizeof(*rtnh));

				if (rtnh->rtnh_len > sizeof(*rtnh)) {
					memset(subtb, 0, sizeof(subtb));
					netlink_parse_rtattr(subtb, RTA_MAX,
							     RTNH_DATA(rtnh),
							     (int)(rtnh->rtnh_len -
								   sizeof(*rtnh)));

					fpmjson::evpn_nexthop *nh;
					parse_evpn_nexthop(tb, subtb, nh);
					nexthop_list.push_back(
						(fpmjson::nexthop *)nh);
				}
			}
		}
	}
	return false;
}

void Fpmparser::onEvpnRouteMsg(struct nlmsghdr *h, int len,
			       fpmjson::payload &payload)
{
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1] = { 0 };

	char dstaddr[IPV6_MAX_BYTE] = { 0 };
	char buf[MAX_ADDR_SIZE + 1] = { 0 };
	char prefix[MAX_ADDR_SIZE + 1] = { 0 };
	char if_buf[IFNAMSIZ + 1] = { 0 };
	int dst_len = 0;
	int nlmsg_type = h->nlmsg_type;
	unsigned int vrf_index;

	rtm = (struct rtmsg *)NLMSG_DATA(h);

	/* Parse attributes and extract fields of interest. */
	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (tb[RTA_DST]) {
		if (rtm->rtm_family == AF_INET) {
			if (rtm->rtm_dst_len > IPV4_MAX_BITLEN)
				return;
			memcpy(dstaddr, RTA_DATA(tb[RTA_DST]), IPV4_MAX_BYTE);
		} else if (rtm->rtm_family == AF_INET6) {
			if (rtm->rtm_dst_len > IPV6_MAX_BITLEN)
				return;
			memcpy(dstaddr, RTA_DATA(tb[RTA_DST]), IPV6_MAX_BYTE);
		}
	}

	dst_len = rtm->rtm_dst_len;
	if ((rtm->rtm_family == AF_INET && dst_len == IPV4_MAX_BITLEN) ||
	    (rtm->rtm_family == AF_INET6 && dst_len == IPV6_MAX_BITLEN)) {
		snprintf(prefix, MAX_ADDR_SIZE, "%s",
			 inet_ntop(rtm->rtm_family, dstaddr, buf,
				   MAX_ADDR_SIZE));
	} else {
		snprintf(prefix, MAX_ADDR_SIZE, "%s/%u",
			 inet_ntop(rtm->rtm_family, dstaddr, buf, MAX_ADDR_SIZE),
			 dst_len);
	}

	payload.prefix = prefix;

	/* Table corresponding to route. */
	if (tb[RTA_TABLE]) {
		vrf_index = *(int *)RTA_DATA(tb[RTA_TABLE]);
	} else {
		vrf_index = rtm->rtm_table;
	}
	payload.vrf_index = vrf_index;

	if (vrf_index) {
		if (!getIfName(vrf_index, prefix, IFNAMSIZ)) {
			zlog_err("Fail to get the VRF name (ifindex %u)",
				 vrf_index);
			return;
		}
	}


	bool ret = getEvpnNextHopList(h, tb, payload.nexthops);
	if (ret == false) {
		return;
	}

	return;
}

void Fpmparser::process_raw_msg(struct nlmsghdr *h)
{
	int len;

	if ((h->nlmsg_type != RTM_NEWROUTE) && (h->nlmsg_type != RTM_DELROUTE))
		return;
	/* Length validity. */
	len = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg)));
	if (len < 0) {
		zlog_err("%s: Message received from netlink is of a broken size %d %zu",
			 __PRETTY_FUNCTION__, h->nlmsg_len,
			 (size_t)NLMSG_LENGTH(sizeof(struct ndmsg)));
		return;
	}
	fpmjson::payload payload;
	fpmjson::header header = nlmsg_header_to_json_header(h);
	payload.type = "evpn";
	onEvpnRouteMsg(h, len, payload);
	push_to_ringbuffer(header, payload);
	return;
}


void Fpmparser::process_normal_msg(struct nl_object *obj, void *arg)
{
	struct nlmsghdr *h = (struct nlmsghdr *)arg;
	fpmjson::header header = nlmsg_header_to_json_header(h);
	struct rtnl_route *route_obj = (struct rtnl_route *)obj;
	auto family = rtnl_route_get_family(route_obj);
	char buffer[256] = { 0 };
	if (family != AF_INET && family != AF_INET6 && family != AF_MPLS)
		return;

	unsigned int master_index = rtnl_route_get_table(route_obj);
	char prefix[MAX_ADDR_SIZE + 1] = { 0 };
	fpmjson::payload payload;

	struct nl_addr *dip = rtnl_route_get_dst(route_obj);
	nl_addr2str(dip, prefix, MAX_ADDR_SIZE);
	getNextHopList(route_obj, payload.nexthops);
	payload.family = family;
	payload.vrf_index = master_index;
	payload.protocol =
		rtnl_route_proto2str(rtnl_route_get_protocol(route_obj), buffer,
				     sizeof(buffer));
	payload.prefix = prefix;
	payload.type = "normal";
	push_to_ringbuffer(header, payload);
}

void Fpmparser::getNextHopList(struct rtnl_route *route_obj,
			       std::vector<fpmjson::nexthop *> &nexthop_list)
{
	for (int i = 0; i < rtnl_route_get_nnexthops(route_obj); i++) {
		struct rtnl_nexthop *nexthop = rtnl_route_nexthop_n(route_obj,
								    i);
		struct nl_addr *addr = NULL;
		char gw_buf[MAX_ADDR_SIZE + 1] = { 0 };
		char mp_buf[MAX_ADDR_SIZE + 1] = { 0 };
		char if_buf[IFNAMSIZ + 1] = { 0 };
		uint8_t weight;

		if ((addr = rtnl_route_nh_get_gateway(nexthop)) ||
		    (addr = rtnl_route_nh_get_via(nexthop))) {
			nl_addr2str(addr, gw_buf, MAX_ADDR_SIZE);

			if (addr = rtnl_route_nh_get_encap_mpls_dst(nexthop))
				nl_addr2str(addr, mp_buf, MAX_ADDR_SIZE);
		} else {
			if (rtnl_route_get_family(route_obj) == AF_INET6)
				strncpy(gw_buf, "::", MAX_ADDR_SIZE);
			else
				strncpy(gw_buf, "0.0.0.0", MAX_ADDR_SIZE);
			strncpy(mp_buf, "na", MAX_ADDR_SIZE);
		}

		if (!(weight = rtnl_route_nh_get_weight(nexthop)))
			weight = 0;

		unsigned if_index = rtnl_route_nh_get_ifindex(nexthop);
		getIfName(if_index, if_buf, IFNAMSIZ);

		fpmjson::normal_nexthop *nh =
			new fpmjson::normal_nexthop(if_buf, gw_buf, mp_buf,
						    weight);
		nexthop_list.push_back((fpmjson::nexthop *)nh);
	}
}
