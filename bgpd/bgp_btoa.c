/* BGP dump to ascii converter
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "zebra.h"
#include "stream.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "memory.h"
#include "privs.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"

/* privileges */
static zebra_capabilities_t _caps_p[] = {
	ZCAP_BIND, ZCAP_NET_RAW, ZCAP_NET_ADMIN,
};

struct zebra_privs_t bgpd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0,
};

enum MRT_MSG_TYPES {
	MSG_NULL,
	MSG_START,		  /* sender is starting up */
	MSG_DIE,		  /* receiver should shut down */
	MSG_I_AM_DEAD,		  /* sender is shutting down */
	MSG_PEER_DOWN,		  /* sender's peer is down */
	MSG_PROTOCOL_BGP,	 /* msg is a BGP packet */
	MSG_PROTOCOL_RIP,	 /* msg is a RIP packet */
	MSG_PROTOCOL_IDRP,	/* msg is an IDRP packet */
	MSG_PROTOCOL_RIPNG,       /* msg is a RIPNG packet */
	MSG_PROTOCOL_BGP4PLUS,    /* msg is a BGP4+ packet */
	MSG_PROTOCOL_BGP4PLUS_01, /* msg is a BGP4+ (draft 01) packet */
	MSG_PROTOCOL_OSPF,	/* msg is an OSPF packet */
	MSG_TABLE_DUMP		  /* routing table dump */
};

static int attr_parse(struct stream *s, uint16_t len)
{
	unsigned int flag;
	unsigned int type;
	uint16_t length;
	uint16_t lim;

	lim = s->getp + len;

	printf("attr_parse s->getp %zd, len %d, lim %d\n", s->getp, len, lim);

	while (s->getp < lim) {
		flag = stream_getc(s);
		type = stream_getc(s);

		if (flag & BGP_ATTR_FLAG_EXTLEN)
			length = stream_getw(s);
		else
			length = stream_getc(s);

		printf("FLAG: %d\n", flag);
		printf("TYPE: %d\n", type);
		printf("Len: %d\n", length);

		switch (type) {
		case BGP_ATTR_ORIGIN: {
			uint8_t origin;
			origin = stream_getc(s);
			printf("ORIGIN: %d\n", origin);
		} break;
		case BGP_ATTR_AS_PATH: {
			struct aspath *aspath;

			aspath = aspath_parse(s, length, 1);
			printf("ASPATH: %s\n", aspath->str);
			aspath_free(aspath);
		} break;
		case BGP_ATTR_NEXT_HOP: {
			struct in_addr nexthop;
			nexthop.s_addr = stream_get_ipv4(s);
			printf("NEXTHOP: %s\n", inet_ntoa(nexthop));
		} break;
		default:
			stream_getw_from(s, length);
			break;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	int fd;
	struct stream *s;
	time_t now;
	int type;
	int subtype;
	size_t len;
	int source_as;
	int dest_as;
	ifindex_t ifindex;
	int family;
	struct in_addr sip;
	struct in_addr dip;
	uint16_t viewno, seq_num;
	struct prefix_ipv4 p;

	s = stream_new(10000);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s FILENAME\n", argv[0]);
		exit(1);
	}
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stdout,
			"%% Can't open configuration file %s due to '%s'.\n",
			argv[1], safe_strerror(errno));
		exit(1);
	}

	while (1) {
		stream_reset(s);

		ret = stream_read(s, fd, 12);
		if (ret != 12) {
			if (!ret)
				printf("END OF FILE\n");
			else if (ret < 0)
				printf("ERROR OF READ\n");
			else
				printf("UNDERFLOW\n");
			break;
		}

		/* Extract header. */
		now = stream_getl(s);
		type = stream_getw(s);
		subtype = stream_getw(s);
		len = stream_getl(s);

		printf("TIME: %s", ctime(&now));

		/* printf ("TYPE: %d/%d\n", type, subtype); */

		if (type == MSG_PROTOCOL_BGP4MP)
			printf("TYPE: BGP4MP");
		else if (type == MSG_PROTOCOL_BGP4MP_ET)
			printf("TYPE: BGP4MP_ET");
		else if (type == MSG_TABLE_DUMP)
			printf("TYPE: MSG_TABLE_DUMP");
		else
			printf("TYPE: Unknown %d", type);

		if (type == MSG_TABLE_DUMP)
			switch (subtype) {
			case AFI_IP:
				printf("/AFI_IP\n");
				break;
			case AFI_IP6:
				printf("/AFI_IP6\n");
				break;
			default:
				printf("/UNKNOWN %d", subtype);
				break;
			}
		else {
			switch (subtype) {
			case BGP4MP_STATE_CHANGE:
				printf("/CHANGE\n");
				break;
			case BGP4MP_MESSAGE:
				printf("/MESSAGE\n");
				break;
			case BGP4MP_ENTRY:
				printf("/ENTRY\n");
				break;
			case BGP4MP_SNAPSHOT:
				printf("/SNAPSHOT\n");
				break;
			default:
				printf("/UNKNOWN %d", subtype);
				break;
			}
		}

		printf("len: %zd\n", len);

		ret = stream_read(s, fd, len);
		if (ret != (int)len) {
			if (!ret)
				printf("END OF FILE 2\n");
			else if (ret < 0)
				printf("ERROR OF READ 2\n");
			else
				printf("UNDERFLOW 2\n");
			break;
		}

		/* printf ("now read %d\n", len); */

		if (type == MSG_TABLE_DUMP) {
			uint8_t status;
			time_t originated;
			struct in_addr peer;
			uint16_t attrlen;

			viewno = stream_getw(s);
			seq_num = stream_getw(s);
			printf("VIEW: %d\n", viewno);
			printf("SEQUENCE: %d\n", seq_num);

			/* start */
			while (s->getp < len - 16) {
				p.prefix.s_addr = stream_get_ipv4(s);
				p.prefixlen = stream_getc(s);
				printf("PREFIX: %s/%d\n", inet_ntoa(p.prefix),
				       p.prefixlen);

				status = stream_getc(s);
				originated = stream_getl(s);
				peer.s_addr = stream_get_ipv4(s);
				source_as = stream_getw(s);

				printf("FROM: %s AS%d\n", inet_ntoa(peer),
				       source_as);
				printf("ORIGINATED: %s", ctime(&originated));

				attrlen = stream_getw(s);
				printf("ATTRLEN: %d\n", attrlen);

				attr_parse(s, attrlen);

				printf("STATUS: 0x%x\n", status);
			}
		} else {
			source_as = stream_getw(s);
			dest_as = stream_getw(s);
			printf("source_as: %d\n", source_as);
			printf("dest_as: %d\n", dest_as);

			ifindex = stream_getw(s);
			family = stream_getw(s);

			printf("ifindex: %d\n", ifindex);
			printf("family: %d\n", family);

			sip.s_addr = stream_get_ipv4(s);
			dip.s_addr = stream_get_ipv4(s);

			printf("saddr: %s\n", inet_ntoa(sip));
			printf("daddr: %s\n", inet_ntoa(dip));

			printf("\n");
		}
	}
	close(fd);
	return 0;
}
