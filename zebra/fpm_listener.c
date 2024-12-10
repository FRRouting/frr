// SPDX-License-Identifier: ISC
/*
 * Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef GNU_LINUX
#include <stdint.h>
#include <memory.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <err.h>
#include <sys/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>

#include "rt_netlink.h"
#include "fpm/fpm.h"
#include "lib/libfrr.h"

XREF_SETUP();

struct glob {
	int server_sock;
	int sock;
	bool reflect;
	bool dump_hex;
};

struct glob glob_space;
struct glob *glob = &glob_space;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/*
 * get_print_buf
 */
static char *
get_print_buf(size_t *buf_len)
{
	static char print_bufs[16][128];
	static int counter;

	counter++;
	if (counter >= 16)
		counter = 0;

	*buf_len = 128;
	return &print_bufs[counter][0];
}

/*
 * create_listen_sock
 */
static int create_listen_sock(int port, int *sock_p)
{
	int sock;
	struct sockaddr_in addr;
	int reuse;

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
		return 0;
	}

	reuse = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
	    0) {
		fprintf(stderr, "Failed to set reuse addr option: %s\n",
			 strerror(errno));
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Failed to bind to port %d: %s\n", port, strerror(errno));
		close(sock);
		return 0;
	}

	if (listen(sock, 5)) {
		fprintf(stderr, "Failed to listen on socket: %s\n", strerror(errno));
		close(sock);
		return 0;
	}

	*sock_p = sock;
	return 1;
}

/*
 * accept_conn
 */
static int accept_conn(int listen_sock)
{
	int sock;
	struct sockaddr_in client_addr = { 0 };
	unsigned int client_len;

	while (1) {
		char buf[120];

		fprintf(stdout, "Waiting for client connection...\n");
		client_len = sizeof(client_addr);
		sock = accept(listen_sock, (struct sockaddr *)&client_addr,
			      &client_len);

		if (sock >= 0) {
			fprintf(stdout, "Accepted client %s\n",
				inet_ntop(AF_INET, &client_addr.sin_addr, buf, sizeof(buf)));
			return sock;
		}
		fprintf(stderr, "Failed to accept socket: %s\n", strerror(errno));
	}
}

/*
 * read_fpm_msg
 */
static fpm_msg_hdr_t *
read_fpm_msg(char *buf, size_t buf_len)
{
	char *cur, *end;
	long need_len, bytes_read, have_len;
	fpm_msg_hdr_t *hdr;
	int reading_full_msg;

	end = buf + buf_len;
	cur = buf;
	hdr = (fpm_msg_hdr_t *)buf;

	while (1) {
		reading_full_msg = 0;

		have_len = cur - buf;

		if (have_len < (long)FPM_MSG_HDR_LEN) {
			need_len = FPM_MSG_HDR_LEN - have_len;
		} else {
			need_len = fpm_msg_len(hdr) - have_len;
			assert(need_len >= 0 && need_len <= (end - cur));

			if (!need_len)
				return hdr;

			reading_full_msg = 1;
		}

		bytes_read = read(glob->sock, cur, need_len);

		if (bytes_read == 0) {
			fprintf(stdout,
				"Socket closed as that read returned 0\n");
			return NULL;
		}

		if (bytes_read < 0) {
			fprintf(stderr, "Error reading from socket: %s\n",
				strerror(errno));
			return NULL;
		}

		cur += bytes_read;

		if (bytes_read < need_len) {
			fprintf(stderr,
				"Read %lu bytes but expected to read %lu bytes instead\n",
				bytes_read, need_len);
			return NULL;
		}

		if (reading_full_msg)
			return hdr;

		if (!fpm_msg_ok(hdr, buf_len)) {
			assert(0);
			fprintf(stderr, "Malformed fpm message\n");
			return NULL;
		}
	}
}

/*
 * netlink_msg_type_to_s
 */
static const char *
netlink_msg_type_to_s(uint16_t type)
{
	switch (type) {

	case RTM_NEWROUTE:
		return "New route";

	case RTM_DELROUTE:
		return "Del route";

	case RTM_NEWNEXTHOP:
		return "New Nexthop Group";

	case RTM_DELNEXTHOP:
		return "Del Nexthop Group";

	default:
		return "Unknown";
	}
}

/*
 * netlink_prot_to_s
 */
static const char *
netlink_prot_to_s(unsigned char prot)
{
	switch (prot) {

	case RTPROT_KERNEL:
		return "Kernel";

	case RTPROT_BOOT:
		return "Boot";

	case RTPROT_STATIC:
		return "Static";

	case RTPROT_ZEBRA:
		return "Zebra";

	case RTPROT_DHCP:
		return "Dhcp";

	case RTPROT_BGP:
		return "BGP";

	case RTPROT_ISIS:
		return "ISIS";

	case RTPROT_OSPF:
		return "OSPF";

	case RTPROT_RIP:
		return "RIP";

	case RTPROT_RIPNG:
		return "RIPNG";

	case RTPROT_BABEL:
		return "BABEL";

	case RTPROT_NHRP:
		return "NHRP";

	case RTPROT_EIGRP:
		return "EIGRP";

	case RTPROT_SHARP:
		return "SHARP";

	case RTPROT_PBR:
		return "PBR";

	case RTPROT_ZSTATIC:
		return "Static";

	default:
		return "Unknown";
	}
}

#define MAX_NHS 16

struct netlink_nh {
	struct rtattr *gateway;
	int if_index;
	uint16_t encap_type;
	uint32_t vxlan_vni;
};

struct netlink_msg_ctx {
	struct nlmsghdr *hdr;

	/*
	 * Stuff pertaining to route messages.
	 */
	struct rtmsg *rtmsg;
	struct rtattr *rtattrs[RTA_MAX + 1];

	/*
	 * Nexthops.
	 */
	struct netlink_nh nhs[MAX_NHS];
	unsigned long num_nhs;

	struct rtattr *dest;
	struct rtattr *src;
	int *metric;
	unsigned int *nhgid;

	const char *err_msg;
};

/*
 * netlink_msg_ctx_init
 */
static inline void netlink_msg_ctx_init(struct netlink_msg_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

/*
 * netlink_msg_ctx_set_err
 */
static inline void netlink_msg_ctx_set_err(struct netlink_msg_ctx *ctx,
					   const char *err_msg)
{
	if (ctx->err_msg)
		return;

	ctx->err_msg = err_msg;
}

/*
 * parse_rtattrs_
 */
static int parse_rtattrs_(struct rtattr *rta, size_t len, struct rtattr **rtas,
			  uint16_t num_rtas, const char **err_msg)
{
	memset(rtas, 0, num_rtas * sizeof(rtas[0]));

	for (; len > 0; rta = RTA_NEXT(rta, len)) {
		uint16_t type = rta->rta_type & NLA_TYPE_MASK;

		if (!RTA_OK(rta, len)) {
			*err_msg = "Malformed rta";
			return 0;
		}

		if (type >= num_rtas) {
			warn("Unknown rtattr type %d", rta->rta_type);
			continue;
		}

		rtas[type] = rta;
	}

	return 1;
}

/*
 * parse_rtattrs
 */
static int parse_rtattrs(struct netlink_msg_ctx *ctx, struct rtattr *rta,
			 size_t len)
{
	const char *err_msg;

	err_msg = NULL;

	if (!parse_rtattrs_(rta, len, ctx->rtattrs, ARRAY_SIZE(ctx->rtattrs),
			    &err_msg)) {
		netlink_msg_ctx_set_err(ctx, err_msg);
		return 0;
	}

	return 1;
}

/*
 * netlink_msg_ctx_add_nh
 */
static int netlink_msg_ctx_add_nh(struct netlink_msg_ctx *ctx, int if_index,
				  struct rtattr *gateway, uint16_t encap_type,
				  uint32_t vxlan_vni)
{
	struct netlink_nh *nh;

	if (ctx->num_nhs + 1 >= ARRAY_SIZE(ctx->nhs)) {
		warn("Too many next hops");
		return 0;
	}
	nh = &ctx->nhs[ctx->num_nhs];
	ctx->num_nhs++;

	nh->gateway = gateway;
	nh->if_index = if_index;

	nh->encap_type = encap_type;
	nh->vxlan_vni = vxlan_vni;
	return 1;
}

/*
 * parse_multipath_attr
 */
static int parse_multipath_attr(struct netlink_msg_ctx *ctx,
				struct rtattr *mpath_rtattr)
{
	int len;
	struct rtnexthop *rtnh;
	struct rtattr *rtattrs[RTA_MAX + 1];
	struct rtattr *tb[RTA_MAX + 1];
	struct rtattr *gateway;
	const char *err_msg;

	rtnh = RTA_DATA(mpath_rtattr);
	len = RTA_PAYLOAD(mpath_rtattr);

	for (; len > 0;
	     len -= NLMSG_ALIGN(rtnh->rtnh_len), rtnh = RTNH_NEXT(rtnh)) {
		uint32_t vxlan_vni;
		uint16_t encap_type;

		if (!RTNH_OK(rtnh, len)) {
			netlink_msg_ctx_set_err(ctx, "Malformed nh");
			return 0;
		}

		if (rtnh->rtnh_len <= sizeof(*rtnh)) {
			netlink_msg_ctx_set_err(ctx, "NH len too small");
			return 0;
		}

		/*
		 * Parse attributes included in the nexthop.
		 */
		err_msg = NULL;
		if (!parse_rtattrs_(RTNH_DATA(rtnh),
				    rtnh->rtnh_len - sizeof(*rtnh), rtattrs,
				    ARRAY_SIZE(rtattrs), &err_msg)) {
			netlink_msg_ctx_set_err(ctx, err_msg);
			return 0;
		}

		gateway = rtattrs[RTA_GATEWAY];
		memset(tb, 0, sizeof(tb));
		if (rtattrs[RTA_ENCAP]) {
			parse_rtattrs_(RTA_DATA(rtattrs[RTA_ENCAP]),
				       rtattrs[RTA_ENCAP]->rta_len -
					       sizeof(struct rtattr),
				       tb, ARRAY_SIZE(tb), &err_msg);
		}

		if (rtattrs[RTA_ENCAP_TYPE])
			encap_type =
				*(uint16_t *)RTA_DATA(rtattrs[RTA_ENCAP_TYPE]);
		else
			encap_type = 0;

		if (tb[0])
			vxlan_vni = *(uint32_t *)RTA_DATA(tb[0]);
		else
			vxlan_vni = 0;

		netlink_msg_ctx_add_nh(ctx, rtnh->rtnh_ifindex, gateway,
				       encap_type, vxlan_vni);
	}

	return 1;
}

/*
 * parse_route_msg
 */
static int parse_route_msg(struct netlink_msg_ctx *ctx)
{
	int len;
	struct rtattr **rtattrs, *rtattr, *gateway, *oif;
	int if_index;

	ctx->rtmsg = NLMSG_DATA(ctx->hdr);

	len = ctx->hdr->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	if (len < 0) {
		netlink_msg_ctx_set_err(ctx, "Bad message length");
		return 0;
	}

	if (!parse_rtattrs(ctx, RTM_RTA(ctx->rtmsg), len))
		return 0;

	rtattrs = ctx->rtattrs;

	ctx->dest = rtattrs[RTA_DST];
	ctx->src = rtattrs[RTA_PREFSRC];

	rtattr = rtattrs[RTA_PRIORITY];
	if (rtattr)
		ctx->metric = (int *)RTA_DATA(rtattr);

	rtattr = rtattrs[RTA_NH_ID];
	if (rtattr)
		ctx->nhgid = (unsigned int *)RTA_DATA(rtattr);

	gateway = rtattrs[RTA_GATEWAY];
	oif = rtattrs[RTA_OIF];
	if (gateway || oif) {
		struct rtattr *tb[RTA_MAX + 1] = { 0 };
		uint16_t encap_type = 0;
		uint32_t vxlan_vni = 0;

		if_index = 0;
		if (oif)
			if_index = *((int *)RTA_DATA(oif));


		if (rtattrs[RTA_ENCAP]) {
			const char *err_msg;

			parse_rtattrs_(RTA_DATA(rtattrs[RTA_ENCAP]),
				       rtattrs[RTA_ENCAP]->rta_len -
					       sizeof(struct rtattr),
				       tb, ARRAY_SIZE(tb), &err_msg);
		}

		if (rtattrs[RTA_ENCAP_TYPE])
			encap_type =
				*(uint16_t *)RTA_DATA(rtattrs[RTA_ENCAP_TYPE]);

		if (tb[0])
			vxlan_vni = *(uint32_t *)RTA_DATA(tb[0]);

		netlink_msg_ctx_add_nh(ctx, if_index, gateway, encap_type,
				       vxlan_vni);
	}

	rtattr = rtattrs[RTA_MULTIPATH];
	if (rtattr)
		parse_multipath_attr(ctx, rtattr);

	return 1;
}

/*
 * addr_to_s
 */
static const char *
addr_to_s(unsigned char family, void *addr)
{
	size_t buf_len;
	char *buf;

	buf = get_print_buf(&buf_len);

	return inet_ntop(family, addr, buf, buf_len);
}

/*
 * netlink_msg_ctx_print
 */
static int netlink_msg_ctx_snprint(struct netlink_msg_ctx *ctx, char *buf,
				   size_t buf_len)
{
	struct nlmsghdr *hdr;
	struct rtmsg *rtmsg;
	struct netlink_nh *nh;
	char *cur, *end;
	unsigned long i;

	hdr = ctx->hdr;
	rtmsg = ctx->rtmsg;

	cur = buf;
	end = buf + buf_len;

	cur += snprintf(cur, end - cur, "%s %s/%d, Prot: %s(%u)",
			netlink_msg_type_to_s(hdr->nlmsg_type),
			addr_to_s(rtmsg->rtm_family, RTA_DATA(ctx->dest)),
			rtmsg->rtm_dst_len,
			netlink_prot_to_s(rtmsg->rtm_protocol),
			rtmsg->rtm_protocol);

	if (ctx->metric)
		cur += snprintf(cur, end - cur, ", Metric: %d", *ctx->metric);

	if (ctx->nhgid)
		cur += snprintf(cur, end - cur, ", nhgid: %u", *ctx->nhgid);
	for (i = 0; i < ctx->num_nhs; i++) {
		cur += snprintf(cur, end - cur, "\n ");
		nh = &ctx->nhs[i];

		if (nh->gateway) {
			cur += snprintf(cur, end - cur, " %s",
					addr_to_s(rtmsg->rtm_family,
						  RTA_DATA(nh->gateway)));
		}

		if (nh->if_index) {
			cur += snprintf(cur, end - cur, " via interface %d",
					nh->if_index);
		}

		if (nh->encap_type)
			cur += snprintf(cur, end - cur,
					", Encap Type: %u Vxlan vni %u",
					nh->encap_type, nh->vxlan_vni);
	}

	return cur - buf;
}

/*
 * print_netlink_msg_ctx
 */
static void print_netlink_msg_ctx(struct netlink_msg_ctx *ctx)
{
	char buf[1024];

	netlink_msg_ctx_snprint(ctx, buf, sizeof(buf));
	printf("%s\n", buf);
}

static void fpm_listener_hexdump(const void *mem, size_t len)
{
	char line[64];
	const uint8_t *src = mem;
	const uint8_t *end = src + len;

	if (!glob->dump_hex)
		return;

	if (len == 0) {
		printf("%016lx: (zero length / no data)\n", (long)src);
		return;
	}

	while (src < end) {
		struct fbuf fb = {
			.buf = line,
			.pos = line,
			.len = sizeof(line),
		};
		const uint8_t *lineend = src + 8;
		uint32_t line_bytes = 0;

		printf("%016lx: ", (long)src);

		while (src < lineend && src < end) {
			printf("%02x ", *src++);
			line_bytes++;
		}
		if (line_bytes < 8)
			printf("%*s", (8 - line_bytes) * 3, "");

		src -= line_bytes;
		while (src < lineend && src < end && fb.pos < fb.buf + fb.len) {
			uint8_t byte = *src++;

			if (isprint(byte))
				*fb.pos++ = byte;
			else
				*fb.pos++ = '.';
		}
		printf("\n");
	}
}

/*
 * parse_netlink_msg
 */
static void parse_netlink_msg(char *buf, size_t buf_len, fpm_msg_hdr_t *fpm)
{
	struct netlink_msg_ctx ctx_space, *ctx;
	struct nlmsghdr *hdr;
	unsigned int len;

	fpm_listener_hexdump(buf, buf_len);
	ctx = &ctx_space;

	hdr = (struct nlmsghdr *)buf;
	len = buf_len;
	for (; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {

		netlink_msg_ctx_init(ctx);
		ctx->hdr = hdr;

		switch (hdr->nlmsg_type) {

		case RTM_DELROUTE:
		case RTM_NEWROUTE:

			parse_route_msg(ctx);
			if (ctx->err_msg) {
				fprintf(stderr,
					"Error parsing route message: %s\n",
					ctx->err_msg);
			}

			print_netlink_msg_ctx(ctx);

			if (glob->reflect && hdr->nlmsg_type == RTM_NEWROUTE &&
			    ctx->rtmsg->rtm_protocol > RTPROT_STATIC) {
				printf("  Route %s(%u) reflecting back\n",
				       netlink_prot_to_s(
					       ctx->rtmsg->rtm_protocol),
				       ctx->rtmsg->rtm_protocol);
				ctx->rtmsg->rtm_flags |= RTM_F_OFFLOAD;
				write(glob->sock, fpm, fpm_msg_len(fpm));
			}
			break;

		default:
			fprintf(stdout,
				"Ignoring netlink message - Type: %s(%d)\n",
				netlink_msg_type_to_s(hdr->nlmsg_type),
				hdr->nlmsg_type);
		}
	}
}

/*
 * process_fpm_msg
 */
static void process_fpm_msg(fpm_msg_hdr_t *hdr)
{
	fprintf(stdout, "FPM message - Type: %d, Length %d\n", hdr->msg_type,
	      ntohs(hdr->msg_len));

	if (hdr->msg_type != FPM_MSG_TYPE_NETLINK) {
		fprintf(stderr, "Unknown fpm message type %u\n", hdr->msg_type);
		return;
	}

	parse_netlink_msg(fpm_msg_data(hdr), fpm_msg_data_len(hdr), hdr);
}

/*
 * fpm_serve
 */
static void fpm_serve(void)
{
	char buf[FPM_MAX_MSG_LEN * 4];
	fpm_msg_hdr_t *hdr;

	while (1) {

		hdr = read_fpm_msg(buf, sizeof(buf));
		if (!hdr)
			return;

		process_fpm_msg(hdr);
	}
}

int main(int argc, char **argv)
{
	pid_t daemon;
	int r;
	bool fork_daemon = false;

	memset(glob, 0, sizeof(*glob));

	while ((r = getopt(argc, argv, "rdv")) != -1) {
		switch (r) {
		case 'r':
			glob->reflect = true;
			break;
		case 'd':
			fork_daemon = true;
			break;
		case 'v':
			glob->dump_hex = true;
			break;
		}
	}

	if (fork_daemon) {
		daemon = fork();

		if (daemon)
			exit(0);
	}

	if (!create_listen_sock(FPM_DEFAULT_PORT, &glob->server_sock))
		exit(1);

	/*
	 * Server forever.
	 */
	while (1) {
		glob->sock = accept_conn(glob->server_sock);
		fpm_serve();
		fprintf(stdout, "Done serving client");
	}
}
#else

int main(int argc, char **argv)
{
	fprintf(stderr, "This program only works on linux");
	exit(-1);
}
#endif
