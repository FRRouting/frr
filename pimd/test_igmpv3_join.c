// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "if.h"
#include "pim_igmp_join.h"

const char *prog_name = 0;

static int iface_solve_index(const char *ifname)
{
	struct if_nameindex *ini;
	ifindex_t ifindex = -1;
	int i;

	if (!ifname)
		return -1;

	ini = if_nameindex();
	if (!ini) {
		int err = errno;
		fprintf(stderr,
			"%s: interface=%s: failure solving index: errno=%d: %s\n",
			prog_name, ifname, err, strerror(err));
		errno = err;
		return -1;
	}

	for (i = 0; ini[i].if_index; ++i) {
		if (!strcmp(ini[i].if_name, ifname)) {
			ifindex = ini[i].if_index;
			break;
		}
	}

	if_freenameindex(ini);

	return ifindex;
}

int main(int argc, const char *argv[])
{
	pim_addr group_addr;
	pim_addr source_addr;
	const char *ifname;
	const char *group;
	const char *source;
	ifindex_t ifindex;
	int result;
	int fd;

	prog_name = argv[0];

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		fprintf(stderr,
			"%s: could not create socket: socket(): errno=%d: %s\n",
			prog_name, errno, strerror(errno));
		exit(1);
	}

	if (argc != 4) {
		fprintf(stderr,
			"usage:   %s interface group     source\n"
			"example: %s eth0      232.1.1.1 1.1.1.1\n",
			prog_name, prog_name);
		exit(1);
	}

	ifname = argv[1];
	group = argv[2];
	source = argv[3];

	ifindex = iface_solve_index(ifname);
	if (ifindex < 0) {
		fprintf(stderr, "%s: could not find interface: %s\n", prog_name,
			ifname);
		exit(1);
	}

	result = inet_pton(AF_INET, group, &group_addr);
	if (result <= 0) {
		fprintf(stderr, "%s: bad group address: %s\n", prog_name,
			group);
		exit(1);
	}

	result = inet_pton(AF_INET, source, &source_addr);
	if (result <= 0) {
		fprintf(stderr, "%s: bad source address: %s\n", prog_name,
			source);
		exit(1);
	}

	result = pim_gm_join_source(fd, ifindex, group_addr, source_addr);
	if (result) {
		fprintf(stderr,
			"%s: setsockopt(fd=%d) failure for IGMP group %s source %s ifindex %d on interface %s: errno=%d: %s\n",
			prog_name, fd, group, source, ifindex, ifname, errno,
			strerror(errno));
		exit(1);
	}

	printf("%s: joined channel (S,G)=(%s,%s) on interface %s\n", prog_name,
	       source, group, ifname);

	printf("%s: waiting...\n", prog_name);

	if (getchar() == EOF)
		fprintf(stderr, "getchar failure\n");

	close(fd);

	printf("%s: left channel (S,G)=(%s,%s) on interface %s\n", prog_name,
	       source, group, ifname);

	exit(0);
}
