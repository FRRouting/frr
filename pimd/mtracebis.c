/*
 * Multicast Traceroute for FRRouting
 * Copyright (C) 2018  Mladen Sablic
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef __linux__

#include "pim_igmp_mtrace.h"

#include "checksum.h"
#include "prefix.h"
#include "mtracebis_routeget.h"

#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>

#define MTRACEBIS_VERSION "0.1"
#define MTRACE_TIMEOUT (5)

#define IP_HDR_LEN (sizeof(struct ip))
#define IP_RA_LEN (4)
#define MTRACE_BUF_LEN (MTRACE_HDR_SIZE + (MTRACE_MAX_HOPS * MTRACE_RSP_SIZE))
#define IP_AND_MTRACE_BUF_LEN (IP_HDR_LEN + IP_RA_LEN + MTRACE_BUF_LEN)

static const char *progname;
static void usage(void)
{
	fprintf(stderr, "Usage : %s <multicast source> [<multicast group>]\n",
		progname);
}
static void version(void)
{
	fprintf(stderr, "%s %s\n", progname, MTRACEBIS_VERSION);
}

static void print_host(struct in_addr addr)
{
	struct hostent *h;

	h = gethostbyaddr(&addr, sizeof(addr), AF_INET);
	if (h == NULL)
		printf("?");
	else
		printf("%s", h->h_name);
	printf(" (%s) ", inet_ntoa(addr));
}

static void print_line_no(int i)
{
	printf("%3d  ", -i);
}

static const char *rtg_proto_str(enum mtrace_rtg_proto proto)
{
	static char buf[80];

	buf[0] = '\0';

	switch (proto) {
	case MTRACE_RTG_PROTO_DVMRP:
		return "DVMRP";
	case MTRACE_RTG_PROTO_MOSPF:
		return "MOSPF";
	case MTRACE_RTG_PROTO_PIM:
		return "PIM";
	case MTRACE_RTG_PROTO_CBT:
		return "CBT";
	case MTRACE_RTG_PROTO_PIM_SPECIAL:
		return "PIM special";
	case MTRACE_RTG_PROTO_PIM_STATIC:
		return "PIM static";
	case MTRACE_RTG_PROTO_DVMRP_STATIC:
		return "DVMRP static";
	case MTRACE_RTG_PROTO_PIM_MBGP:
		return "PIM MBGP";
	case MTRACE_RTG_PROTO_CBT_SPECIAL:
		return "CBT special";
	case MTRACE_RTG_PROTO_CBT_STATIC:
		return "CBT static";
	case MTRACE_RTG_PROTO_PIM_ASSERT:
		return "PIM assert";
	default:
		sprintf(buf, "unknown protocol (%d)", proto);
		return buf;
	}
}

static void print_rtg_proto(uint32_t rtg_proto)
{
	printf("%s", rtg_proto_str(rtg_proto));
}

static void print_fwd_ttl(uint32_t fwd_ttl)
{
	printf("thresh^ %d", fwd_ttl);
}

static const char *fwd_code_str(enum mtrace_fwd_code code)
{
	static char buf[80];

	buf[0] = '\0';

	switch (code) {
	case MTRACE_FWD_CODE_NO_ERROR:
		return "no error";
	case MTRACE_FWD_CODE_WRONG_IF:
		return "wrong interface";
	case MTRACE_FWD_CODE_PRUNE_SENT:
		return "prune sent";
	case MTRACE_FWD_CODE_PRUNE_RCVD:
		return "prune received";
	case MTRACE_FWD_CODE_SCOPED:
		return "scoped";
	case MTRACE_FWD_CODE_NO_ROUTE:
		return "no route";
	case MTRACE_FWD_CODE_WRONG_LAST_HOP:
		return "wrong last hop";
	case MTRACE_FWD_CODE_NOT_FORWARDING:
		return "not forwarding";
	case MTRACE_FWD_CODE_REACHED_RP:
		return "reached RP";
	case MTRACE_FWD_CODE_RPF_IF:
		return "RPF interface";
	case MTRACE_FWD_CODE_NO_MULTICAST:
		return "no multicast";
	case MTRACE_FWD_CODE_INFO_HIDDEN:
		return "info hidden";
	case MTRACE_FWD_CODE_NO_SPACE:
		return "no space";
	case MTRACE_FWD_CODE_OLD_ROUTER:
		return "old router";
	case MTRACE_FWD_CODE_ADMIN_PROHIB:
		return "admin. prohib.";
	default:
		sprintf(buf, "unknown fwd. code (%d)", code);
		return buf;
	}
}

static void print_fwd_code(uint32_t fwd_code)
{
	printf("%s", fwd_code_str(fwd_code));
}

static void print_rsp(struct igmp_mtrace_rsp *rsp)
{
	print_host(rsp->outgoing);
	if (rsp->fwd_code == 0 || rsp->fwd_code == MTRACE_FWD_CODE_REACHED_RP) {
		print_rtg_proto(rsp->rtg_proto);
		printf(" ");
		if (rsp->fwd_code == MTRACE_FWD_CODE_REACHED_RP)
			printf("(RP) ");
		if (rsp->rtg_proto == MTRACE_RTG_PROTO_PIM) {
			switch (rsp->src_mask) {
			case MTRACE_SRC_MASK_GROUP:
				printf("(*,G) ");
				break;
			case MTRACE_SRC_MASK_SOURCE:
				printf("(S,G) ");
				break;
			}
		}
		print_fwd_ttl(rsp->fwd_ttl);
	} else {
		print_fwd_code(rsp->fwd_code);
	}
	printf("\n");
}

static void print_dest(struct igmp_mtrace *mtrace)
{
	print_line_no(0);
	print_host(mtrace->dst_addr);
	printf("\n");
}

static void print_summary(struct igmp_mtrace *mtrace, int hops, long msec)
{
	int i;
	int t = 0;

	for (i = 0; i < hops; i++)
		t += mtrace->rsp[i].fwd_ttl;

	printf("Round trip time %ld ms; total ttl of %d required.\n", msec, t);
}

static void print_responses(struct igmp_mtrace *mtrace, int hops, long msec)
{
	int i;

	print_dest(mtrace);

	for (i = 0; i < hops; i++) {
		print_line_no(i + 1);
		print_rsp(&mtrace->rsp[i]);
	}
	print_summary(mtrace, hops, msec);
}

static int send_query(int fd, struct in_addr to_addr,
		      struct igmp_mtrace *mtrace)
{
	struct sockaddr_in to;
	socklen_t tolen;
	int sent;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = to_addr;
	tolen = sizeof(to);

	sent = sendto(fd, (char *)mtrace, sizeof(*mtrace), MSG_DONTWAIT,
		      (struct sockaddr *)&to, tolen);

	if (sent < 1)
		return -1;
	return 0;
}

static void print_query(struct igmp_mtrace *mtrace)
{
	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];
	char grp_str[INET_ADDRSTRLEN];

	printf("* Mtrace from %s to %s via group %s\n",
	       inet_ntop(AF_INET, &mtrace->src_addr, src_str, sizeof(src_str)),
	       inet_ntop(AF_INET, &mtrace->dst_addr, dst_str, sizeof(dst_str)),
	       inet_ntop(AF_INET, &mtrace->grp_addr, grp_str, sizeof(grp_str)));
}

static int recv_response(int fd, int *hops, struct igmp_mtrace *mtracer)
{
	int recvd;
	char mtrace_buf[IP_AND_MTRACE_BUF_LEN];
	struct ip *ip;
	struct igmp_mtrace *mtrace;
	int mtrace_len;
	int responses;
	unsigned short sum;
	size_t mtrace_off;
	size_t ip_len;

	recvd = recvfrom(fd, mtrace_buf, IP_AND_MTRACE_BUF_LEN, 0, NULL, 0);

	if (recvd < 1) {
		fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
		return -1;
	}

	if (recvd < (int)sizeof(struct ip)) {
		fprintf(stderr, "no ip header\n");
		return -1;
	}

	ip = (struct ip *)mtrace_buf;

	if (ip->ip_v != 4) {
		fprintf(stderr, "IP not version 4\n");
		return -1;
	}

	sum = ip->ip_sum;
	ip->ip_sum = 0;

	if (sum != in_cksum(ip, ip->ip_hl * 4))
		return -1;

	/* Header overflow check */
	mtrace_off = 4 * ip->ip_hl;
	if (mtrace_off > MTRACE_BUF_LEN)
		return -1;

	/* Underflow/overflow check */
	ip_len = ntohs(ip->ip_len);
	if (ip_len < mtrace_off || ip_len < MTRACE_HDR_SIZE
	    || ip_len > MTRACE_BUF_LEN)
		return -1;

	mtrace_len = ip_len - mtrace_off;
	mtrace = (struct igmp_mtrace *)(mtrace_buf + mtrace_off);

	sum = mtrace->checksum;
	mtrace->checksum = 0;
	if (sum != in_cksum(mtrace, mtrace_len)) {
		fprintf(stderr, "mtrace checksum wrong\n");
		return -1;
	}

	if (mtrace->type != PIM_IGMP_MTRACE_RESPONSE)
		return -1;


	responses = mtrace_len - sizeof(struct igmp_mtrace);
	responses /= sizeof(struct igmp_mtrace_rsp);

	if (responses > MTRACE_MAX_HOPS) {
		fprintf(stderr, "mtrace too large\n");
		return -1;
	}

	if (hops)
		*hops = responses;

	if (mtracer)
		memcpy(mtracer, mtrace, mtrace_len);

	return 0;
}

static int wait_for_response(int fd, int *hops, struct igmp_mtrace *mtrace,
			     long *ret_msec)
{
	fd_set readfds;
	struct timeval timeout;
	int ret;
	long msec, rmsec, tmsec;

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	memset(&timeout, 0, sizeof(timeout));

	timeout.tv_sec = MTRACE_TIMEOUT;

	tmsec = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
	do {
		ret = select(fd + 1, &readfds, NULL, NULL, &timeout);
		if (ret <= 0)
			return ret;
		rmsec = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
		msec = tmsec - rmsec;
	} while (recv_response(fd, hops, mtrace) != 0);

	if (ret_msec)
		*ret_msec = msec;

	return ret;
}

static bool check_end(struct igmp_mtrace *mtrace, int hops)
{
	return mtrace->src_addr.s_addr == mtrace->rsp[hops - 1].prev_hop.s_addr;
}

int main(int argc, char *const argv[])
{
	struct in_addr mc_source;
	struct in_addr mc_group;
	struct in_addr iface_addr;
	struct in_addr gw_addr;
	struct in_addr mtrace_addr;
	struct igmp_mtrace mtrace;
	struct igmp_mtrace *mtracep;
	int hops = 255;
	int rhops;
	int maxhops = 255;
	int perhop = 3;
	int ifindex;
	int unicast = 1;
	int ttl = 64;
	int fd = -1;
	int ret = -1;
	int c;
	long msec;
	int i, j;
	char ifname[IF_NAMESIZE];
	char mbuf[MTRACE_BUF_LEN];
	bool not_group;

	mtrace_addr.s_addr = inet_addr("224.0.1.32");

	uid_t uid = getuid();

	if (uid != 0) {
		printf("must run as root\n");
		exit(EXIT_FAILURE);
	}

	if (argc <= 0)
		progname = "mtracebis";
	else
		progname = argv[0];

	if (argc != 2 && argc != 3) {
		usage();
		exit(EXIT_FAILURE);
	}

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"version", no_argument, 0, 'v'},
			{0, 0, 0, 0}};
		int option_index = 0;

		c = getopt_long(argc, argv, "vh", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			exit(0);
		case 'v':
			version();
			exit(0);
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}
	if (inet_pton(AF_INET, argv[1], &mc_source) != 1) {
		usage();
		fprintf(stderr, "%s: %s is not a valid IPv4 address\n", argv[0],
			argv[1]);
		exit(EXIT_FAILURE);
	}

	mc_group.s_addr = 0;
	not_group = false;

	if (argc == 3) {
		if (inet_pton(AF_INET, argv[2], &mc_group) != 1)
			not_group = true;
		if (!not_group && !IPV4_CLASS_DE(ntohl(mc_group.s_addr)))
			not_group = true;
	}

	if (not_group) {
		usage();
		fprintf(stderr, "%s: %s is not a valid IPv4 group address\n",
			argv[0], argv[2]);
		exit(EXIT_FAILURE);
	}

	ifindex = routeget(mc_source, &iface_addr, &gw_addr);
	if (ifindex < 0) {
		fprintf(stderr, "%s: failed to get route to source %s\n",
			argv[0], argv[1]);
		exit(EXIT_FAILURE);
	}

	if (if_indextoname(ifindex, ifname) == NULL) {
		fprintf(stderr, "%s: if_indextoname error: %s\n", argv[0],
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* zero mtrace struct */
	memset((char *)&mtrace, 0, sizeof(mtrace));

	/* set up query */
	mtrace.type = PIM_IGMP_MTRACE_QUERY_REQUEST;
	mtrace.hops = hops;
	mtrace.checksum = 0;
	mtrace.grp_addr = mc_group;
	mtrace.src_addr = mc_source;
	mtrace.dst_addr = iface_addr;
	mtrace.rsp_addr = unicast ? iface_addr : mtrace_addr;
	mtrace.rsp_ttl = ttl;
	mtrace.qry_id = 0xffffff & time(NULL);

	mtrace.checksum = in_cksum(&mtrace, sizeof(mtrace));

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);

	if (fd < 1) {
		fprintf(stderr, "%s: socket error: %s\n", argv[0],
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
			 strlen(ifname));

	if (ret < 0) {
		fprintf(stderr, "%s: setsockopt error: %s\n", argv[0],
			strerror(errno));
		ret = EXIT_FAILURE;
		goto close_fd;
	}

	print_query(&mtrace);
	if (send_query(fd, gw_addr, &mtrace) < 0) {
		fprintf(stderr, "%s: sendto error: %s\n", argv[0],
			strerror(errno));
		ret = EXIT_FAILURE;
		goto close_fd;
	}
	printf("Querying full reverse path...\n");
	mtracep = (struct igmp_mtrace *)mbuf;
	ret = wait_for_response(fd, &rhops, mtracep, &msec);
	if (ret > 0) {
		print_responses(mtracep, rhops, msec);
		ret = 0;
		goto close_fd;
	}
	if (ret < 0) {
		fprintf(stderr, "%s: select error: %s\n", argv[0],
			strerror(errno));
		ret = EXIT_FAILURE;
		goto close_fd;
	}
	printf(" * ");
	printf("switching to hop-by-hop:\n");
	print_dest(&mtrace);
	for (i = 1; i < maxhops; i++) {
		print_line_no(i);
		mtrace.hops = i;
		for (j = 0; j < perhop; j++) {
			mtrace.qry_id++;
			mtrace.checksum = 0;
			mtrace.checksum = in_cksum(&mtrace, sizeof(mtrace));
			if (send_query(fd, gw_addr, &mtrace) < 0) {
				fprintf(stderr, "%s: sendto error: %s\n",
					argv[0], strerror(errno));
				ret = EXIT_FAILURE;
				goto close_fd;
			}
			ret = wait_for_response(fd, &rhops, mtracep, &msec);
			if (ret > 0) {
				if (check_end(mtracep, rhops)) {
					print_rsp(&mtracep->rsp[rhops - 1]);
					print_summary(mtracep, rhops, msec);
					ret = 0;
					goto close_fd;
				}
				if (i > rhops) {
					printf(" * ...giving up.\n");
					ret = 0;
					goto close_fd;
				}
				print_rsp(&mtracep->rsp[rhops - 1]);
				break;
			}
			printf(" *");
		}
		if (ret <= 0)
			printf("\n");
	}
	ret = 0;
close_fd:
	close(fd);
	exit(ret);
}

#else /* __linux__ */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	printf("%s implemented only for GNU/Linux\n", argv[0]);
	exit(0);
}

#endif /* __linux__ */
