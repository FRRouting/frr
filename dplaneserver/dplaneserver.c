// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Server socket program to simulate fpm using protobuf
 * Copyright (C) 2023 Alibaba, Inc.
 *                    Hongyu Li
 */
#include "dplaneserver.h"

#define FPM_HEADER_SIZE 4
DEFINE_MGROUP(DPLANESERVER, "dplaneserver");
DEFINE_MTYPE(DPLANESERVER, DPLANE_BUFFER, "dplaneserver communication");
struct Dplaneserver_data dplaneserver_data = { .bufSize = 2048,
					       .messageBuffer = NULL,
					       .pos = 0,
					       .server_socket = 0,
					       .connection_socket = 0,
					       .connected = false,
					       .server_up = false };
enum fpm_msg_op fm_op;

void process_fpm_msg(fpm_msg_hdr_t *fpm_hdr)
{
	size_t msg_len = fpm_msg_len(fpm_hdr);
#ifdef HAVE_NETLINK
	if (fpm_hdr->msg_type == FPM_MSG_TYPE_NETLINK) {
		struct nlmsghdr *nl_hdr =
			(struct nlmsghdr *)fpm_msg_data(fpm_hdr);
		for (; NLMSG_OK(nl_hdr, msg_len);
		     nl_hdr = NLMSG_NEXT(nl_hdr, msg_len)) {
			process_netlink_msg(nl_hdr);
		}
	}
#endif /* HAVE_NETLINK */
#ifdef HAVE_PROTOBUF
	if (fpm_hdr->msg_type == FPM_MSG_TYPE_PROTOBUF) {
		Fpm__Message *msg;
		msg = fpm__message__unpack(NULL, msg_len - FPM_HEADER_SIZE,
					   (uint8_t *)fpm_msg_data(fpm_hdr));
		if (msg) {
			fm_op = msg->type;
			switch (fm_op) {
			case FPM_OP_ROUTE_INSTALL:
				if (!msg->add_route) {
					zlog_err("%s: ROUTE_INSTALL info doesn't exist",
						 __func__);
					break;
				}
				process_route_install_msg(msg->add_route);
				break;
			/* Un-handled at this time */
			case FPM_OP_ROUTE_DELETE:
				break;
			}
			fpm__message__free_unpacked(msg, NULL);
		} else {
			zlog_err("%s: unpack fpm message failed", __func__);
			return;
		}
	}
#endif /* HAVE_PROTOBUF */
}

int dplaneserver_init(void)
{
	struct sockaddr_in server_addr;

	dplaneserver_data.server_socket = socket(PF_INET, SOCK_STREAM,
						 IPPROTO_TCP);
	if (dplaneserver_data.server_socket < 0) {
		zlog_err("%s: Can not open socket", __func__);
		return -1;
	}

	if (sockopt_reuseaddr(dplaneserver_data.server_socket) == -1) {
		zlog_err("%s: Can not set socket opt", __func__);
		return -1;
	}

	// bind port
	memset(&server_addr, 0, sizeof(server_addr));
	if (is_ipv6)
		server_addr.sin_family = AF_INET6;
	else
		server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(FPM_DEFAULT_PORT);
	server_addr.sin_addr.s_addr = FPM_DEFAULT_IP;

	if (bind(dplaneserver_data.server_socket,
		 (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
		zlog_err("%s: bing socket to address failed", __func__);
		return -1;
	}

	if (listen(dplaneserver_data.server_socket, 10) == -1) {
		zlog_err("%s: listen socket failed", __func__);
		return -1;
	}

	dplaneserver_data.server_up = true;
	dplaneserver_data.messageBuffer = XMALLOC(MTYPE_DPLANE_BUFFER,
						  dplaneserver_data.bufSize);

	if (IS_DPLANE_SERVER_DEBUG)
		zlog_debug("%s: connect socket successfully", __func__);
	return 0;
}

void dplaneserver_exit(void)
{
	XFREE(MTYPE_DPLANE_BUFFER, dplaneserver_data.messageBuffer);
	if (dplaneserver_data.connected)
		close(dplaneserver_data.connection_socket);
	if (dplaneserver_data.server_up)
		close(dplaneserver_data.server_socket);
}

int dplaneserver_read_data(void)
{
	fpm_msg_hdr_t *fpm_hdr;
	size_t msg_len;
	size_t start = 0, left;
	ssize_t read_len;

	read_len = read(dplaneserver_data.connection_socket,
			dplaneserver_data.messageBuffer + dplaneserver_data.pos,
			dplaneserver_data.bufSize - dplaneserver_data.pos);

	if (read_len == 0) {
		if (IS_DPLANE_SERVER_DEBUG)
			zlog_debug("%s: socket connection closed", __func__);
		return -2;
	}
	if (read_len < 0) {
		zlog_err("%s: socket connection read error", __func__);
		return -1;
	}
	dplaneserver_data.pos += (uint32_t)read_len;
	while (true) {
		fpm_hdr = (fpm_msg_hdr_t *)(dplaneserver_data.messageBuffer +
					    start);
		left = dplaneserver_data.pos - start;
		if (left < FPM_MSG_HDR_LEN)
			break;
		/* fpm_msg_len includes header size */
		msg_len = fpm_msg_len(fpm_hdr);
		if (left < msg_len)
			break;
		if (!fpm_msg_ok(fpm_hdr, left)) {
			zlog_err("%s: fpm message header check failed",
				 __func__);
			return -1;
		}
		process_fpm_msg(fpm_hdr);
		start += msg_len;
	}
	/* update msg buffer*/
	memmove(dplaneserver_data.messageBuffer,
		dplaneserver_data.messageBuffer + start,
		dplaneserver_data.pos - start);
	dplaneserver_data.pos = dplaneserver_data.pos - (uint32_t)start;
	return 0;
}

int dplaneserver_poll(void)
{
	struct pollfd poll_fd_set[MAX_CLIENTS + 1];

	memset(poll_fd_set, 0, sizeof(poll_fd_set));
	poll_fd_set[0].fd = dplaneserver_data.server_socket;
	poll_fd_set[0].events = POLLIN;
	while (true) {
		// poll for events
		int nready = poll(poll_fd_set, MAX_CLIENTS + 1, -1);

		if (nready == -1) {
			zlog_err("%s: failed to poll socket", __func__);
			return -1;
		}
		if (poll_fd_set[0].revents & POLLIN) {
			struct sockaddr_in client_addr;
			int i;
			socklen_t addr_len = sizeof(client_addr);
			int client_fd = accept(dplaneserver_data.server_socket,
					       (struct sockaddr *)&client_addr,
					       &addr_len);

			if (client_fd == -1) {
				zlog_err("%s: failed to accept client connection",
					 __func__);
				continue;
			}
			// add new connection to poll fd set
			for (i = 1; i <= MAX_CLIENTS; i++) {
				if (poll_fd_set[i].fd == 0) {
					if (IS_DPLANE_SERVER_DEBUG)
						zlog_debug("%s: a new client has connected",
							   __func__);
					poll_fd_set[i].fd = client_fd;
					poll_fd_set[i].events = POLLIN;
					dplaneserver_data.connection_socket =
						client_fd;
					dplaneserver_data.connected = true;
					break;
				}
			}
			if (i > MAX_CLIENTS) {
				close(client_fd);
				continue;
			}
		}
		// check for events on client sockets
		for (int i = 1; i <= MAX_CLIENTS; i++) {
			if (poll_fd_set[i].fd == 0)
				continue;
			if (poll_fd_set[i].revents & POLLIN) {
				int res = dplaneserver_read_data();
				/* if func return -1 or -2 it means errors occur*/
				if (res)
					return res;
			}
			if (poll_fd_set[i].revents &
			    (POLLERR | POLLHUP | POLLNVAL)) {
				if (IS_DPLANE_SERVER_DEBUG)
					zlog_debug("%s: socket POLLERR | POLLHUP | POLLNVAL event happened",
						   __func__);
				close(poll_fd_set[i].fd);
				poll_fd_set[i].fd = 0;
			}
		}
	}
}

#ifdef HAVE_PROTOBUF
void process_route_install_msg(Fpm__AddRoute *msg)
{
	char buf[4096] = { 0 };

	if (!msg->key) {
		zlog_err("%s: ROUTE_INSTALL route key doesn't exist", __func__);
		return;
	}
	if (!msg->key->prefix) {
		zlog_err("%s: ROUTE_INSTALL prefix doesn't exist", __func__);
		return;
	}
	if (IS_DPLANE_SERVER_DEBUG)
		zlog_debug("%s: msg address family:%d", __func__,
			   msg->address_family);
	if (msg->address_family == AF_INET) {
		inet_ntop(AF_INET, msg->key->prefix->bytes.data, buf,
			  sizeof(buf));
		if (IS_DPLANE_SERVER_DEBUG)
			zlog_debug("%s: key ipv4 prefix:%pI4", __func__, buf);
	} else if (msg->address_family == AF_INET6) {
		inet_ntop(AF_INET6, msg->key->prefix->bytes.data, buf,
			  sizeof(buf));
		if (IS_DPLANE_SERVER_DEBUG)
			zlog_debug("%s: key ipv6 prefix:%pI6", __func__, buf);
	} else {
		zlog_err("%s: not ipv4 or ipv6 address family", __func__);
		return;
	}
	if (IS_DPLANE_SERVER_DEBUG)
		zlog_debug("%s: key length:%d", __func__,
			   msg->key->prefix->length);

	json_object *json = json_object_new_object();

	json_object_int_add(json, "vrfId", (int64_t)(msg->vrf_id));
	json_object_int_add(json, "addressFamily",
			    (int64_t)(msg->address_family));
	json_object_int_add(json, "metric", (int64_t)(msg->metric));
	json_object_int_add(json, "subAddressFamily",
			    (int64_t)(msg->sub_address_family));
	json_object_int_add(json, "hasRouteType",
			    (int64_t)(msg->has_route_type));
	json_object_int_add(json, "routeType", (int64_t)(msg->route_type));
	if (msg->key) {
		json_object_string_add(json, "prefix", buf);
		json_object_int_add(json, "prefixLength",
				    (int64_t)(msg->key->prefix->length));
	}
	if (output_file_path) {
		FILE *fp = fopen(output_file_path, "a+");

		if (!fp) {
			zlog_err("%s open output json file failed:%s", __func__,
				 output_file_path);
		} else {
			fprintf(fp, "%s\n",
				json_object_to_json_string_ext(json,
							       JSON_C_TO_STRING_PRETTY));
			fclose(fp);
		}
	} else {
		zlog_err("%s output json file doesn't exist", __func__);
	}
	json_object_free(json);
}

#endif /* HAVE_PROTOBUF */
#ifdef HAVE_NETLINK
const char *rtm_protocol2str(int type)
{
	switch (type) {
	case RTPROT_UNSPEC:
		return "unspec";
	case RTPROT_KERNEL:
		return "connected";
	case RTPROT_STATIC:
		return "static";
	case RTPROT_ZEBRA:
		return "zebra";
	case RTPROT_BGP:
		return "bgp";
	default:
		return "unkown";
	}
}
void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta,
			  int len)
{
	int rta_type;

	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max) {
			tb[rta->rta_type] = rta;
		} else {
			/* FRR 7.5 is sending RTA_ENCAP with NLA_F_NESTED bit set*/
			if (rta->rta_type & NLA_F_NESTED) {
				rta_type = rta->rta_type & ~NLA_F_NESTED;
				if (rta_type <= max)
					tb[rta_type] = rta;
			}
		}
		rta = RTA_NEXT(rta, len);
	}
}

bool parse_nexthop(struct rtattr **rtnh_tb, int family, int ifindex,
		   uint16_t encap, struct json_object *nexthop_json)
{
	char ip_buf[ADDR_MAX_LEN + 1] = { 0 };
	char ifname[IF_NAMESIZE + 1] = { 0 };
	char rmac[ETHER_ADDR_STRLEN + 1] = { 0 };

	if (rtnh_tb[RTA_GATEWAY]) {
		if (family == AF_INET) {
			snprintfrr(ip_buf, ADDR_MAX_LEN, "%pI4",
				   (struct in_addr *)RTA_DATA(
					   rtnh_tb[RTA_GATEWAY]));

		} else if (family == AF_INET6) {
			snprintfrr(ip_buf, ADDR_MAX_LEN, "%pI4",
				   (struct in_addr *)RTA_DATA(
					   rtnh_tb[RTA_GATEWAY]));
		} else {
			zlog_err("%s: unknown address family:%d", __func__,
				 family);
			return false;
		}
		json_object_string_add(nexthop_json, "ip", ip_buf);
	}
	/* evpn nexthop process */
	if (encap > 0) {
		if (rtnh_tb[RTA_OIF] > 0) {
			ifindex = *(int *)RTA_DATA(rtnh_tb[RTA_OIF]);
			json_object_int_add(nexthop_json, "interfaceIndex",
					    ifindex);
			if (if_indextoname(ifindex, ifname)) {
				json_object_string_add(nexthop_json,
						       "interfaceName", ifname);
			}
		}
		if (rtnh_tb[RTA_ENCAP] && rtnh_tb[RTA_ENCAP_TYPE] &&
		    (*(uint16_t *)RTA_DATA(rtnh_tb[RTA_ENCAP_TYPE]) ==
		     FPM_NH_ENCAP_VXLAN)) {
			struct rtattr *encap_tb[RTA_MAX] = { 0 };
			/* parse evpn nested info */
			netlink_parse_rtattr(encap_tb, RTA_MAX,
					     (struct rtattr *)RTA_DATA(
						     rtnh_tb[RTA_ENCAP]),
					     (int)RTA_PAYLOAD(
						     rtnh_tb[RTA_ENCAP]));
			if (encap_tb[0]) {
				json_object_int_add(nexthop_json, "vni",
						    *(uint32_t *)RTA_DATA(
							    encap_tb[0]));
			}

			if (encap_tb[1]) {
				snprintfrr(rmac, ETHER_ADDR_STRLEN, "%pEA",
					   (struct ether_addr *)RTA_DATA(
						   encap_tb[1]));
				json_object_string_add(nexthop_json, "rmac",
						       rmac);
			}
		}

	}
	/* normal nexthop process */
	else {
		if (ifindex > 0) {
			json_object_int_add(nexthop_json, "interfaceIndex",
					    ifindex);
			if (if_indextoname(ifindex, ifname)) {
				json_object_string_add(nexthop_json,
						       "interfaceName", ifname);
			}
		}
	}

	return true;
}

void process_netlink_msg(struct nlmsghdr *nl_hdr)
{
	int len;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1] = {};
	struct ipaddr prefix;
	char prefix_buf[ADDR_MAX_LEN + 1] = { 0 };
	int ifindex = 0;
	uint16_t encap = 0;
	struct rtnexthop *rtnh;
	int vrf_id = VRF_DEFAULT;
	char vrf_buf[VRF_NAMSIZ + 1] = { 0 };

	len = nl_hdr->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	rtm = NLMSG_DATA(nl_hdr);
	if (len < 0) {
		zlog_err("%s: Message received from netlink is of a broken size %d %zu",
			 __func__, nl_hdr->nlmsg_len,
			 (size_t)NLMSG_LENGTH(sizeof(struct rtmsg)));
		return;
	}

	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (tb[RTA_DST]) {
		if (rtm->rtm_family == AF_INET) {
			prefix.ip._v4_addr =
				*(struct in_addr *)RTA_DATA(tb[RTA_DST]);
			snprintfrr(prefix_buf, ADDR_MAX_LEN, "%pI4/%d",
				   &prefix.ip._v4_addr, (int)rtm->rtm_dst_len);
		} else {
			prefix.ip._v6_addr =
				*(struct in6_addr *)RTA_DATA(tb[RTA_DST]);
			snprintfrr(prefix_buf, ADDR_MAX_LEN, "%pI6/%d",
				   &prefix.ip._v6_addr, (int)rtm->rtm_dst_len);
		}
	} else {
		zlog_err("broken route message without prefix");
		return;
	}

	if (tb[RTA_TABLE])
		vrf_id = *(vrf_id_t *)RTA_DATA(tb[RTA_TABLE]);

	if (vrf_id != VRF_DEFAULT)
		snprintfrr(vrf_buf, ADDR_MAX_LEN, "%s", vrf_id_to_name(vrf_id));
	else
		snprintfrr(vrf_buf, ADDR_MAX_LEN, "default");


	if (nl_hdr->nlmsg_type == RTM_NEWROUTE) {
		json_object *json = json_object_new_object();
		json_object *nexthops_json = json_object_new_array();

		/* make format consistent with cmd "show ip route json" */
		json_object_string_add(json, "prefix", prefix_buf);
		json_object_string_add(json, "vrfName", vrf_buf);
		json_object_int_add(json, "vrfId", vrf_id);
		json_object_string_add(json, "protocol", (rtm_protocol2str(rtm->rtm_protocol)));


		if (!tb[RTA_MULTIPATH]) {
			json_object *nexthop_json = json_object_new_object();

			if (tb[RTA_OIF])
				ifindex = *(int *)RTA_DATA(tb[RTA_OIF]);
			if (tb[RTA_ENCAP_TYPE])
				encap = *(uint16_t *)RTA_DATA(
					tb[RTA_ENCAP_TYPE]);
			if (parse_nexthop(tb, rtm->rtm_family, ifindex, encap,
					  nexthop_json))
				json_object_array_add(nexthops_json,
						      nexthop_json);
			else
				json_object_free(nexthop_json);

		} else {
			len = (int)RTA_PAYLOAD(tb[RTA_MULTIPATH]);
			rtnh = (struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);
			for (;;) {
				if (len < (int)sizeof(*rtnh) ||
				    rtnh->rtnh_len > len)
					break;
				if (rtnh->rtnh_len > sizeof(*rtnh)) {
					json_object *nexthop_json =
						json_object_new_object();
					struct rtattr *rtnh_tb[RTA_MAX + 1] = {};
					int ifindex = rtnh->rtnh_ifindex;

					netlink_parse_rtattr(rtnh_tb, RTA_MAX,
							     RTNH_DATA(rtnh),
							     (int)(rtnh->rtnh_len -
								   sizeof(*rtnh)));
					if (rtnh_tb[RTA_ENCAP_TYPE]) {
						encap = *(uint16_t *)RTA_DATA(
							rtnh_tb[RTA_ENCAP_TYPE]);
					}

					if (parse_nexthop(rtnh_tb,
							  rtm->rtm_family,
							  ifindex, encap,
							  nexthop_json))
						json_object_array_add(nexthops_json,
								      nexthop_json);
					else
						json_object_free(nexthop_json);

					if (rtnh->rtnh_len == 0)
						break;
					len -= NLMSG_ALIGN(rtnh->rtnh_len);
					rtnh = RTNH_NEXT(rtnh);
				}
			}
		}
		json_object_object_add(json, "nexthops", nexthops_json);

		if (output_file_path) {
			FILE *fp = fopen(output_file_path, "a+");
			if (!fp) {
				zlog_err("%s open output json file failed:%s",
					 __func__, output_file_path);
			} else {
					fseek(fp, 0, SEEK_END);
					if (ftell(fp) == 0) {
						fprintf(fp, "[%s]",
							json_object_to_json_string_ext(json,
											JSON_C_TO_STRING_PRETTY));
					} else {
						fseek(fp, -1, SEEK_END);
						if (ftruncate(fileno(fp), ftell(fp)) == 0) {
							fprintf(fp, ",\n%s]", json_object_get_string(json));
						}
					}
				fclose(fp);
			}
		} else {
			zlog_err("%s: output json file doesn't exist", __func__);
		}
		json_object_free(json);
	} else
		return;
}
#endif /* HAVE_NETLINK */
