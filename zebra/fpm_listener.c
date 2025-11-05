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
#include <time.h>
#include <signal.h>

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
#include <linux/nexthop.h>

#include "rt_netlink.h"
#include "fpm/fpm.h"
#include "lib/libfrr.h"
#include "zebra/kernel_netlink.h"
#include "lib/netlink_parser.h"

XREF_SETUP();

PREDECL_RBTREE_UNIQ(fpm_route);
PREDECL_HASH(fpm_nhg);

/* Route structure to store in RB tree */
struct fpm_route {
	struct prefix prefix;
	uint32_t table_id;
	uint32_t nhg_id;
	struct fpm_route_item rb_item;
};

/* Comparison function for routes */
static int fpm_route_cmp(const struct fpm_route *a, const struct fpm_route *b)
{
	int ret;

	/* First compare table IDs */
	if (a->table_id < b->table_id)
		return -1;
	if (a->table_id > b->table_id)
		return 1;

	/* Then compare prefixes */
	ret = prefix_cmp(&a->prefix, &b->prefix);
	return ret;
}

/* RB tree for storing routes */
DECLARE_RBTREE_UNIQ(fpm_route, struct fpm_route, rb_item, fpm_route_cmp);

/* Nexthop group structure to store in Hash table */
struct fpm_nhg {
	uint32_t id;	      /* Nexthop group ID */
	uint8_t family;	      /* Address family */
	uint8_t protocol;     /* Routing protocol that installed nhg */
	uint8_t scope;	      /* Scope */
	bool is_blackhole;    /* Is this a blackhole nexthop? */
	uint8_t num_nexthops; /* Number of nexthops in the group */

	/* Individual nexthops in the group */
	struct {
		uint32_t id;	   /* Nexthop ID */
		uint8_t weight;	   /* Weight of this nexthop */
	} nexthops[MULTIPATH_NUM]; /* Support up to MULTIPATH_NUM nexthops in a group */

	struct fpm_nhg_item hash_item;
};

/* Comparison function for nexthop groups */
static int fpm_nhg_cmp(const struct fpm_nhg *a, const struct fpm_nhg *b)
{
	return a->id - b->id;
}

/* Hash function for nexthop groups */
static uint32_t fpm_nhg_hash(const struct fpm_nhg *a)
{
	return jhash_1word(a->id, 0x55aa5a5a);
}

/* Hash table for storing nexthop groups */
DECLARE_HASH(fpm_nhg, struct fpm_nhg, hash_item, fpm_nhg_cmp, fpm_nhg_hash);

struct glob {
	int server_sock;
	int sock;
	bool reflect;
	bool reflect_fail_all;
	bool dump_hex;
	FILE *output_file;
	const char *dump_file;
	struct fpm_route_head route_tree;
	struct fpm_nhg_head nhg_hash;
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
 * get_timestamp
 * Returns a timestamp string.
 */
static const char *get_timestamp(void)
{
	static char timestamp[64];
	struct timespec ts;
	struct tm tm;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tm);
	snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%09ld",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
		 ts.tv_nsec);
	return timestamp;
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

		fprintf(glob->output_file, "Waiting for client connection...\n");
		client_len = sizeof(client_addr);
		sock = accept(listen_sock, (struct sockaddr *)&client_addr,
			      &client_len);

		if (sock >= 0) {
			fprintf(glob->output_file, "[%s] Accepted client %s\n", get_timestamp(),
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
			fprintf(glob->output_file, "Socket closed as that read returned 0\n");
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
			continue;
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
	struct netlink_nh nhs[MULTIPATH_NUM];
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

/* Forward declaration for handle_nexthop_update */
static void handle_nexthop_update(struct nlmsghdr *hdr, struct nhmsg *nhmsg, struct rtattr *tb[],
				  bool is_add);

/*
 * parse_nexthop_msg
 */
static int parse_nexthop_msg(struct nlmsghdr *hdr)
{
	struct nhmsg *nhmsg;
	struct rtattr *tb[NHA_MAX + 1] = {};
	int len;
	uint32_t nhgid = 0;
	uint16_t nhg_count = 0;
	const char *err_msg = NULL;
	char protocol_str[32] = "Unknown";
	char nexthop_buf[16192] = "";
	size_t buf_pos = 0;

	nhmsg = NLMSG_DATA(hdr);
	len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*nhmsg));
	if (len < 0) {
		fprintf(stderr, "Bad nexthop message length\n");
		return 0;
	}

	if (!parse_rtattrs_(RTM_NHA(nhmsg), len, tb, ARRAY_SIZE(tb), &err_msg)) {
		fprintf(stderr, "Error parsing nexthop attributes: %s\n", err_msg);
		return 0;
	}

	/* Get protocol string */
	snprintf(protocol_str, sizeof(protocol_str), "%s(%u)",
		 netlink_prot_to_s(nhmsg->nh_protocol), nhmsg->nh_protocol);

	/* Get Nexthop Group ID */
	if (tb[NHA_ID])
		nhgid = *(uint32_t *)RTA_DATA(tb[NHA_ID]);

	/* Count nexthops in the group and collect NH IDs */
	if (tb[NHA_GROUP]) {
		struct nexthop_grp *nhg = (struct nexthop_grp *)RTA_DATA(tb[NHA_GROUP]);
		size_t count = (RTA_PAYLOAD(tb[NHA_GROUP]) / sizeof(*nhg));

		if (count > 0 && (count * sizeof(*nhg)) == RTA_PAYLOAD(tb[NHA_GROUP])) {
			nhg_count = count > MULTIPATH_NUM ? MULTIPATH_NUM
							  : count; /* Limit to our array size */

			/* Build a string with all nexthop IDs and their weights */
			buf_pos = 0;
			for (size_t i = 0; i < count; i++) {
				int len_written;
				if (i > 0)
					nexthop_buf[buf_pos++] = ',';

				if (nhg[i].weight > 1) {
					uint16_t weight;

					weight = nhg[i].weight_high << 8 | nhg[i].weight;
					len_written = snprintf(nexthop_buf + buf_pos,
							       sizeof(nexthop_buf) - buf_pos,
							       " %u(w:%u)", nhg[i].id, weight + 1);
				} else
					len_written = snprintf(nexthop_buf + buf_pos,
							       sizeof(nexthop_buf) - buf_pos, " %u",
							       nhg[i].id);

				if (len_written > 0)
					buf_pos += len_written;
			}
			nexthop_buf[buf_pos] = '\0';
		}
	} else if (tb[NHA_OIF] || tb[NHA_GATEWAY]) {
		/* Single nexthop case */
		nhg_count = 1;
		snprintf(nexthop_buf, sizeof(nexthop_buf), " Singleton");
	}

	/* Print blackhole status if applicable */
	if (tb[NHA_BLACKHOLE]) {
		fprintf(glob->output_file,
			"[%s] %s Nexthop Group ID: %u, Protocol: %s, Type: BLACKHOLE, Family: %u\n",
			get_timestamp(), hdr->nlmsg_type == RTM_NEWNEXTHOP ? "New" : "Del", nhgid,
			protocol_str, nhmsg->nh_family);
	} else {
		fprintf(glob->output_file,
			"[%s] %s Nexthop Group ID: %u, Protocol: %s, Contains %u nexthops, Family: %u, Scope: %u\n"
			"    Nexthops:%s\n",
			get_timestamp(), hdr->nlmsg_type == RTM_NEWNEXTHOP ? "New" : "Del", nhgid,
			protocol_str, nhg_count, nhmsg->nh_family, nhmsg->nh_scope, nexthop_buf);
	}

	/* Update the nexthop hash table */
	handle_nexthop_update(hdr, nhmsg, tb, hdr->nlmsg_type == RTM_NEWNEXTHOP);

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
 * netlink_msg_ctx_snprint
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

	cur += snprintf(cur, end - cur, "[%s] %s %s/%d, Prot: %s(%u)", get_timestamp(),
			netlink_msg_type_to_s(hdr->nlmsg_type),
			addr_to_s(rtmsg->rtm_family, RTA_DATA(ctx->dest)), rtmsg->rtm_dst_len,
			netlink_prot_to_s(rtmsg->rtm_protocol), rtmsg->rtm_protocol);

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
	fprintf(glob->output_file, "%s\n", buf);
}

static void fpm_listener_hexdump(const void *mem, size_t len)
{
	char line[64];
	const uint8_t *src = mem;
	const uint8_t *end = src + len;

	if (!glob->dump_hex)
		return;

	if (len == 0) {
		fprintf(glob->output_file, "%016lx: (zero length / no data)\n", (long)src);
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

		fprintf(glob->output_file, "%016lx: ", (long)src);

		while (src < lineend && src < end) {
			fprintf(glob->output_file, "%02x ", *src++);
			line_bytes++;
		}
		if (line_bytes < 8)
			fprintf(glob->output_file, "%*s", (8 - line_bytes) * 3, "");

		src -= line_bytes;
		while (src < lineend && src < end && fb.pos < fb.buf + fb.len) {
			uint8_t byte = *src++;

			if (isprint(byte))
				*fb.pos++ = byte;
			else
				*fb.pos++ = '.';
		}
		fprintf(glob->output_file, "\n");
	}
}

/*
 * handle_route_update
 * Handles adding or removing a route from the route tree
 */
static void handle_route_update(struct netlink_msg_ctx *ctx, bool is_add)
{
	struct fpm_route *route;
	struct fpm_route *existing;
	struct fpm_route lookup = { 0 };

	if (!ctx->dest || !ctx->rtmsg)
		return;

	/* Set up lookup key */
	lookup.prefix.family = ctx->rtmsg->rtm_family;
	lookup.prefix.prefixlen = ctx->rtmsg->rtm_dst_len;
	memcpy(&lookup.prefix.u.prefix, RTA_DATA(ctx->dest),
	       (ctx->rtmsg->rtm_family == AF_INET) ? 4 : 16);
	lookup.table_id = ctx->rtmsg->rtm_table;
	lookup.nhg_id = ctx->nhgid ? *ctx->nhgid : 0;
	/* Look up existing route */
	existing = fpm_route_find(&glob->route_tree, &lookup);

	if (is_add) {
		if (existing) {
			/* Route exists, update it */
			existing->prefix = lookup.prefix;
			existing->table_id = lookup.table_id;
			existing->nhg_id = lookup.nhg_id;
		} else {
			/* Create new route structure */
			route = calloc(1, sizeof(struct fpm_route));
			if (!route) {
				fprintf(stderr, "Failed to allocate route structure\n");
				return;
			}

			/* Copy prefix information */
			route->prefix = lookup.prefix;
			route->table_id = lookup.table_id;
			route->nhg_id = lookup.nhg_id;

			/* Add route to tree */
			if (fpm_route_add(&glob->route_tree, route)) {
				fprintf(stderr, "Failed to add route to tree\n");
				free(route);
			}
		}
	} else {
		/* Remove route from tree */
		if (existing) {
			existing = fpm_route_del(&glob->route_tree, existing);
			if (existing)
				free(existing);
		}
	}
}

/*
 * handle_nexthop_update
 * Handles adding or removing a nexthop group from the nexthop hash
 */
static void handle_nexthop_update(struct nlmsghdr *hdr, struct nhmsg *nhmsg, struct rtattr *tb[],
				  bool is_add)
{
	struct fpm_nhg *nhg;
	struct fpm_nhg *existing;
	struct fpm_nhg lookup = { 0 };
	uint32_t nhgid = 0;
	uint16_t nhg_count = 0;

	/* Get Nexthop Group ID */
	if (tb[NHA_ID])
		nhgid = *(uint32_t *)RTA_DATA(tb[NHA_ID]);
	else
		return; /* Can't process without an ID */

	/* Count nexthops in the group */
	if (tb[NHA_GROUP]) {
		size_t count = (RTA_PAYLOAD(tb[NHA_GROUP]) / sizeof(struct nexthop_group));

		if (count > 0 &&
		    (count * sizeof(struct nexthop_group)) == RTA_PAYLOAD(tb[NHA_GROUP]))
			nhg_count = count > MULTIPATH_NUM ? MULTIPATH_NUM
							  : count; /* Limit to our array size */
	} else if (tb[NHA_OIF] || tb[NHA_GATEWAY]) {
		/* Single nexthop case */
		nhg_count = 1;
	}

	/* Set up lookup key */
	lookup.id = nhgid;

	/* Look up existing nexthop group */
	existing = fpm_nhg_find(&glob->nhg_hash, &lookup);

	if (is_add) {
		if (existing) {
			/* Nexthop group exists, update it */
			existing->family = nhmsg->nh_family;
			existing->protocol = nhmsg->nh_protocol;
			existing->scope = nhmsg->nh_scope;
			existing->is_blackhole = tb[NHA_BLACKHOLE] ? true : false;
			existing->num_nexthops = nhg_count;

			/* Update individual nexthop IDs and weights */
			if (tb[NHA_GROUP]) {
				struct nexthop_grp *nhgrp =
					(struct nexthop_grp *)RTA_DATA(tb[NHA_GROUP]);
				for (size_t i = 0; i < nhg_count; i++) {
					uint16_t weight;

					existing->nexthops[i].id = nhgrp[i].id;
					weight = nhgrp[i].weight_high << 8 | nhgrp[i].weight;
					existing->nexthops[i].weight = weight + 1;
				}
			}
		} else {
			/* Create new nexthop group */
			nhg = calloc(1, sizeof(struct fpm_nhg));
			if (!nhg) {
				fprintf(stderr, "Failed to allocate nexthop group structure\n");
				return;
			}

			/* Copy nexthop group information */
			nhg->id = nhgid;
			nhg->family = nhmsg->nh_family;
			nhg->protocol = nhmsg->nh_protocol;
			nhg->scope = nhmsg->nh_scope;
			nhg->is_blackhole = tb[NHA_BLACKHOLE] ? true : false;
			nhg->num_nexthops = nhg_count;

			/* Store individual nexthop IDs and weights */
			if (tb[NHA_GROUP]) {
				struct nexthop_grp *nhgrp =
					(struct nexthop_grp *)RTA_DATA(tb[NHA_GROUP]);
				for (size_t i = 0; i < nhg_count; i++) {
					nhg->nexthops[i].id = nhgrp[i].id;
					nhg->nexthops[i].weight = nhgrp[i].weight;
				}
			}

			/* Add nexthop group to hash */
			if (fpm_nhg_add(&glob->nhg_hash, nhg)) {
				fprintf(stderr, "Failed to add nexthop group to hash\n");
				free(nhg);
			}
		}
	} else {
		/* Remove nexthop group from hash */
		if (existing) {
			existing = fpm_nhg_del(&glob->nhg_hash, existing);
			if (existing)
				free(existing);
		}
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
			handle_route_update(ctx, hdr->nlmsg_type == RTM_NEWROUTE);

			if (glob->reflect && hdr->nlmsg_type == RTM_NEWROUTE &&
			    ctx->rtmsg->rtm_protocol > RTPROT_STATIC) {
				fprintf(glob->output_file,
					"[%s] Route %s(%u) reflecting back as %s\n",
					get_timestamp(), netlink_prot_to_s(ctx->rtmsg->rtm_protocol),
					ctx->rtmsg->rtm_protocol,
					glob->reflect_fail_all ? "Offload Failed" : "Offloaded");
				if (glob->reflect_fail_all)
					ctx->rtmsg->rtm_flags |= RTM_F_OFFLOAD_FAILED;
				else
					ctx->rtmsg->rtm_flags |= RTM_F_OFFLOAD;
				write(glob->sock, fpm, fpm_msg_len(fpm));
			}
			break;

		case RTM_NEWNEXTHOP:
		case RTM_DELNEXTHOP:
			parse_nexthop_msg(hdr);
			break;

		default:
			fprintf(glob->output_file, "[%s] Ignoring netlink message - Type: %s(%d)\n",
				get_timestamp(), netlink_msg_type_to_s(hdr->nlmsg_type),
				hdr->nlmsg_type);
		}
	}
}

/*
 * process_fpm_msg
 */
static void process_fpm_msg(fpm_msg_hdr_t *hdr)
{
	fprintf(glob->output_file, "[%s] FPM message - Type: %d, Length %d\n", get_timestamp(),
		hdr->msg_type, ntohs(hdr->msg_len));

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
		if (!hdr) {
			close(glob->sock);
			return;
		}

		process_fpm_msg(hdr);
	}
}

/* Signal handler for SIGUSR1 */
static void sigusr1_handler(int signum)
{
	struct fpm_route *route;
	struct fpm_nhg *nhg;
	char buf[PREFIX_STRLEN];
	FILE *out = glob->output_file;
	FILE *dump_fp = NULL;

	if (glob->dump_file) {
		dump_fp = fopen(glob->dump_file, "w");
		if (dump_fp) {
			out = dump_fp;
			setbuf(dump_fp, NULL);
		} else
			out = glob->output_file;
	}

	fprintf(out, "\n=== Nexthop Group Hash Dump ===\n");
	fprintf(out, "Timestamp: %s\n", get_timestamp());
	fprintf(out, "Total nexthop groups: %zu\n", fpm_nhg_count(&glob->nhg_hash));
	fprintf(out, "Nexthop Groups:\n");

	frr_each (fpm_nhg, &glob->nhg_hash, nhg) {
		fprintf(out, "  ID: %u, Protocol: %s(%u), Family: %u, Nexthops: %u %s", nhg->id,
			netlink_prot_to_s(nhg->protocol), nhg->protocol, nhg->family,
			nhg->num_nexthops ? nhg->num_nexthops : 1,
			nhg->is_blackhole ? "BLACKHOLE" : "");

		/* Display individual nexthops if any */
		if (nhg->num_nexthops > 0 && !nhg->is_blackhole) {
			if (nhg->nexthops[0].id == 0) {
				fprintf(out, "\n");
				continue;
			}

			fprintf(out, "    Nexthops: ");
			for (uint8_t i = 0; i < nhg->num_nexthops; i++) {
				if (i > 0)
					fprintf(out, ", ");


				if (nhg->nexthops[i].weight > 1)
					fprintf(out, "%u(w:%u)", nhg->nexthops[i].id,
						nhg->nexthops[i].weight);
				else
					fprintf(out, "%u", nhg->nexthops[i].id);
			}
			fprintf(out, "\n");
		}
	}
	fprintf(out, "=====================\n\n");

	fprintf(out, "\n=== Route Tree Dump ===\n");
	fprintf(out, "Timestamp: %s\n", get_timestamp());
	fprintf(out, "Total routes: %zu\n", fpm_route_count(&glob->route_tree));
	fprintf(out, "Routes:\n");

	frr_each (fpm_route, &glob->route_tree, route) {
		prefix2str(&route->prefix, buf, sizeof(buf));
		fprintf(out, "  Table %u, NHG %u: %s\n", route->table_id, route->nhg_id, buf);
	}
	fprintf(out, "=====================\n\n");


	fflush(out);

	if (dump_fp)
		fclose(dump_fp);
}

int main(int argc, char **argv)
{
	pid_t daemon;
	int r;
	bool fork_daemon = false;
	const char *output_file = NULL;
	struct sigaction sa;

	memset(glob, 0, sizeof(*glob));
	glob->output_file = stdout;
	fpm_route_init(&glob->route_tree);
	fpm_nhg_init(&glob->nhg_hash);

	/* Set up signal handler for SIGUSR1 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		fprintf(stderr, "Failed to set up SIGUSR1 handler: %s\n", strerror(errno));
		exit(1);
	}

	while ((r = getopt(argc, argv, "rfdvo:z:")) != -1) {
		switch (r) {
		case 'r':
			glob->reflect = true;
			break;
		case 'f':
			glob->reflect_fail_all = true;
			break;
		case 'd':
			fork_daemon = true;
			break;
		case 'v':
			glob->dump_hex = true;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'z':
			glob->dump_file = optarg;
			break;
		}
	}

	if (output_file) {
		glob->output_file = fopen(output_file, "w");
		if (!glob->output_file) {
			fprintf(stderr, "Failed to open output file %s: %s\n", output_file,
				strerror(errno));
			exit(1);
		}
	}

	setbuf(glob->output_file, NULL);

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
		fprintf(glob->output_file, "Done serving client\n");
	}
}
#else

int main(int argc, char **argv)
{
	fprintf(stderr, "This program only works on linux");
	exit(-1);
}
#endif
