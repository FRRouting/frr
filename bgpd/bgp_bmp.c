/* BMP support.
 * Copyright (C) 2018 Yasuhiro Ohara
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

#include "log.h"
#include "stream.h"
#include "sockunion.h"
#include "command.h"
#include "prefix.h"
#include "thread.h"
#include "linklist.h"
#include "queue.h"
#include "memory.h"
#include "network.h"
#include "filter.h"
#include "lib_errors.h"
#include "stream.h"

#include "bgpd/bgp_table.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_bmp.h"

int accept_sock = -1;
struct thread *bmp_serv_thread = NULL;


/* BMP access-class command */
static char *bmp_acl_name = NULL;

/* BMP access-calss for IPv6. */
static char *bmp_acl6_name = NULL;

struct bmp *bmp_default = NULL;

static struct bmp *bmp_new(int bmp_sock)
{
	struct bmp *new = XCALLOC(MTYPE_BGP_BMP, sizeof(struct bmp));

	new->socket = bmp_sock;
	new->obuf = stream_fifo_new();

	return new;
}

static void bmp_free (struct bmp *bmp)
{
  stream_fifo_free(bmp->obuf);
  XFREE(MTYPE_BGP_BMP, bmp);
}

static int bmp_read(struct thread *thread)
{
	int nbytes;
	unsigned char buf[BMP_READ_BUFSIZ];
	//int bmp_sock = THREAD_FD(thread);
	struct bmp *bmp = THREAD_ARG(thread);
	bmp->t_read = NULL;

	memset (buf, 0, sizeof(buf));

	nbytes = read(bmp->socket, buf, BMP_READ_BUFSIZ);
	if (nbytes == 0) {
	    zlog_info("bmp_read: 0-byte read: close.\n");
		close(bmp->socket);
        if (bmp_default == bmp)
			bmp_default = NULL;
		bmp_free (bmp);
	} else {
	    zlog_info("bmp_read: read %d nbytes: %s", nbytes, buf);
		thread_add_read(bm->master, bmp_read, bmp, bmp->socket,
			&bmp->t_read);
	}
	return 0;
}

#if 0
static int bmp_write(struct thread *thread)
{
	//int bmp_sock = THREAD_FD(thread);
	struct bmp *bmp = THREAD_ARG(thread);
	thread_add_write(bm->master, bmp_write, bmp, bmp->socket,
		&bmp->t_write);
	return 0;
}
#endif

static uint16_t bmp_send_packets(struct bmp *bmp)
{
	struct stream *s;
	int len, num;
	while ((s = stream_fifo_head(bmp->obuf))) {
		do {
			len = stream_get_endp(s) - stream_get_getp(s);
			num = write(bmp->socket, stream_pnt(s), len);
			if (num > 0 && num != len)
				stream_forward_getp(s, num);
		} while (num > 0 && num < len);
		stream_free(stream_fifo_pop(bmp->obuf));
	}
	return 0;
}

static void bmp_common_hdr(struct stream *s, uint8_t ver, uint8_t type)
{
	stream_putc(s, ver);
	stream_putl(s, 0); //dummy message length. will be set later.
	stream_putc(s, type);
}

static void bmp_per_peer_hdr(struct stream *s, struct peer *peer)
{
	uint8_t peer_flag;
	char peer_distinguisher[8];

#define BMP_PEER_TYPE_GLOBAL_INSTANCE 0
#define BMP_PEER_TYPE_RD_INSTANCE     1
#define BMP_PEER_TYPE_LOCAL_INSTANCE  2

#define BMP_PEER_FLAG_V (1 << 7)
#define BMP_PEER_FLAG_L (1 << 6)
#define BMP_PEER_FLAG_A (1 << 5)

	/* Peer Type */
	stream_putc(s, BMP_PEER_TYPE_GLOBAL_INSTANCE);

	/* Peer Flags */
	peer_flag = 0;
	if (peer->su_remote->sa.sa_family == AF_INET6)
		SET_FLAG(peer_flag, BMP_PEER_FLAG_V);
	UNSET_FLAG(peer_flag, BMP_PEER_FLAG_L); /* pre-policy Adj-RIB-In */
	UNSET_FLAG(peer_flag, BMP_PEER_FLAG_A); /* 4-byte AS_PATH format */
	stream_putc(s, peer_flag);

	/* Peer Distinguisher */
	memset (&peer_distinguisher[0], 0, 8);
	stream_put(s, &peer_distinguisher[0], 8);

	/* Peer Address */
	if (peer->su_remote->sa.sa_family == AF_INET6)
		stream_put(s, &peer->su_remote->sin6.sin6_addr, 16);
	else if (peer->su_remote->sa.sa_family == AF_INET) {
		stream_putl(s, 0);
		stream_putl(s, 0);
		stream_putl(s, 0);
		stream_put_in_addr(s, &peer->su_remote->sin.sin_addr);
	}

	/* Peer AS */
	stream_putl(s, peer->as);

	/* Peer BGP ID */
	stream_put_in_addr(s, &peer->remote_id);

	/* Timestamp */
	stream_putl(s, 0); /* seconds */
	stream_putl(s, 0); /* microseconds */
}

static void bmp_put_info_tlv(struct stream *s, uint16_t type, char *string)
{
	int len = strlen (string);
	stream_putw(s, type);
	stream_putw(s, len);
	stream_put(s, string, len);
}

static int bmp_send_initiation(struct bmp *bmp)
{
	int len;
	struct stream *s;
	s = stream_new(BGP_MAX_PACKET_SIZE);
	bmp_common_hdr(s, BMP_VERSION_3, BMP_TYPE_INITIATION);

#define BMP_INFO_TYPE_SYSDESCR	1
#define BMP_INFO_TYPE_SYSNAME	2
	bmp_put_info_tlv(s, BMP_INFO_TYPE_SYSDESCR, (char *)"sysDescr");
	bmp_put_info_tlv(s, BMP_INFO_TYPE_SYSNAME, (char *)"sysName");

	len = stream_get_endp(s);
	stream_putl_at(s, BMP_LENGTH_POS, len); //message length is set.

	stream_fifo_push(bmp->obuf, s);
	bmp_send_packets(bmp);

	return 0;
}

static int bmp_send_peerup(struct bmp *bmp)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node;
	int len;
	struct stream *s;

	bgp = bgp_get_default();
	if (!bgp)
		return 0;

	s = stream_new(BGP_MAX_PACKET_SIZE);
	bmp_common_hdr(s, BMP_VERSION_3, BMP_TYPE_PEER_UP_NOTIFICATION);

	/* Walk down all peers */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {

		/* Per-Peer Header */
		bmp_per_peer_hdr(s, peer);

		/* Local Address (16 bytes) */
		if (peer->su_local->sa.sa_family == AF_INET6)
			stream_put(s, &peer->su_local->sin6.sin6_addr, 16);
		else if (peer->su_local->sa.sa_family == AF_INET) {
			stream_putl(s, 0);
			stream_putl(s, 0);
			stream_putl(s, 0);
			stream_put_in_addr(s, &peer->su_local->sin.sin_addr);
		}

		/* Local Port, Remote Port */
		if (peer->su_local->sa.sa_family == AF_INET6)
			stream_putw(s, peer->su_local->sin6.sin6_port);
		else if (peer->su_local->sa.sa_family == AF_INET)
			stream_putw(s, peer->su_local->sin.sin_port);
		if (peer->su_remote->sa.sa_family == AF_INET6)
			stream_putw(s, peer->su_remote->sin6.sin6_port);
		else if (peer->su_remote->sa.sa_family == AF_INET)
			stream_putw(s, peer->su_remote->sin.sin_port);

		/* Sent OPEN Message */

		/* Received OPEN Message */

		/* Information (variabl) */

		len = stream_get_endp(s);
#define BGP_BMP_MAX_PACKET_SIZE	1024
		if (len > BGP_BMP_MAX_PACKET_SIZE) {
			/* Send PeerUp Message */
			stream_putl_at(s, BMP_LENGTH_POS, len); //message length is set.
			stream_fifo_push(bmp->obuf, s);

			/* Prepare subsequent PeerUp Message */
			s = stream_new(BGP_MAX_PACKET_SIZE);
			bmp_common_hdr(s, BMP_VERSION_3, BMP_TYPE_PEER_UP_NOTIFICATION);
		}
	}

	bmp_send_packets(bmp);

	return 0;
}

void bmp_mirror_packet(struct peer *peer, struct stream *packet)
{
	struct bmp *bmp;
	int len;
	struct stream *s;

	bmp = bmp_default;
	if (!bmp)
		return;

	s = stream_new(BGP_MAX_PACKET_SIZE);

	bmp_common_hdr(s, BMP_VERSION_3, BMP_TYPE_ROUTE_MIRRORING);
	bmp_per_peer_hdr(s, peer);

	/* BMP Mirror TLV. */
#define BMP_MIRROR_TLV_TYPE_BGP_MESSAGE 0
	stream_putw(s, BMP_MIRROR_TLV_TYPE_BGP_MESSAGE);
	stream_putw(s, stream_get_endp(packet)); //a 2-byte length field.

	/* Put contents of mirrored packet. */
	stream_put(s, STREAM_DATA(packet), stream_get_endp(packet));

	len = stream_get_endp(s);
	stream_putl_at(s, BMP_LENGTH_POS, len); //message length is set.

	stream_fifo_push(bmp->obuf, s);
	bmp_send_packets(bmp);
}

static int bmp_event(struct thread *thread)
{
	int ret;
	struct bmp *bmp = THREAD_ARG(thread);
	bmp->t_event = NULL;

	switch(bmp->state) {
	case BMP_Initiation:
		zlog_info("bmp: %s: state: initiation\n", bmp->remote);
		bmp_send_initiation(bmp);
		bmp->state = BMP_PeerUp;
		BMP_EVENT_ADD(bmp);
		break;

	case BMP_PeerUp:
		zlog_info("bmp: %s: state: peerup\n", bmp->remote);
		bmp_send_peerup(bmp);
		bmp->state = BMP_MonitorInit;
		BMP_EVENT_ADD(bmp);
		break;

	case BMP_MonitorInit:
		zlog_info("bmp: %s: state: monitor_init\n", bmp->remote);
		//bmp_monitor_init(bmp);
		bmp->state = BMP_Monitor;
		BMP_EVENT_ADD(bmp);
		break;

	case BMP_Monitor:
		ret = 0;
		zlog_info("bmp: %s: state: monitor\n", bmp->remote);
		//ret = bmp_send_monitor(bmp);
		if (ret > 0)
			bmp->state = BMP_Monitor;
		else
			bmp->state = BMP_EndofRIB;
		BMP_EVENT_ADD(bmp);
		break;

	case BMP_EndofRIB:
		zlog_info("bmp: %s: state: endofrib\n", bmp->remote);
		//bmp_send_endofrib(bmp);
		bmp->state = BMP_Mirror;
		BMP_EVENT_ADD(bmp);
		break;

	case BMP_Mirror:
		zlog_info("bmp: %s: state: mirror\n", bmp->remote);
		//No next event needs to be scheduled.
		break;

	case BMP_None:
		zlog_info("bmp: %s: state: none\n", bmp->remote);
		break;

	default:
		zlog_info("bmp: %s: state: default\n", bmp->remote);
		break;
	}
	return 0;
}

/* Accept BMP connection. */
static int bmp_accept(struct thread *thread)
{
	int bmp_sock;
	union sockunion su;
	struct prefix p;
	int on = 1;
	struct access_list *acl = NULL;
	enum filter_type ret;
	int retval;
	char buf[SU_ADDRSTRLEN];
	struct bmp *bmp;

	accept_sock = THREAD_FD(thread);

	/* We continue hearing BMP socket. */
	bmp_serv_thread = thread_add_read(bm->master, bmp_accept, NULL,
					accept_sock, NULL);

	memset(&su, 0, sizeof(union sockunion));

	/* We can handle IPv4 or IPv6 socket. */
	bmp_sock = sockunion_accept(accept_sock, &su);
	if (bmp_sock < 0) {
		zlog_info("bmp: accept_sock failed: %s\n",
                          safe_strerror (errno));
		return -1;
	}
	set_nonblocking(bmp_sock);
	set_cloexec(bmp_sock);

	sockunion2hostprefix(&su, &p);

	acl = NULL;
	switch (p.family) {
	case AF_INET:
		acl = access_list_lookup(AFI_IP, bmp_acl_name);
		break;
	case AF_INET6:
		acl = access_list_lookup(AFI_IP6, bmp_acl6_name);
		break;
	default:
		break;
	}

	ret = FILTER_PERMIT;
	if (acl) {
		ret = access_list_apply(acl, &p);
	}

	sockunion2str(&su, buf, SU_ADDRSTRLEN);
	if (ret == FILTER_DENY) {
		zlog_info ("BMP conn refused from %s", buf);
		close(bmp_sock);
		return 0;
	}

	retval = setsockopt(bmp_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&on,
			sizeof(on));
	if (retval < 0)
		zlog_info("can't set sockopt to bmp_sock : %s",
			  safe_strerror(errno));

	zlog_info("BMP connection from %s", buf);

	/* Allocate new BMP structure and set up default values. */
	bmp = bmp_new(bmp_sock);
	strncpy(bmp->remote, buf, sizeof (bmp->remote));

	/* Add read/write thread. */
	thread_add_read(bm->master, bmp_read, bmp, bmp->socket,
		&bmp->t_read);
#if 0
	thread_add_write(bm->master, bmp_write, bmp, bmp->socket,
		&bmp->t_write);
#endif

	if (!bmp_default)
		bmp_default = bmp;

	bmp->state = BMP_Initiation;
	thread_add_event(bm->master, bmp_event, bmp, 0,
			&bmp->t_event);

	return 0;
}

void bmp_serv_sock(const char *hostname, unsigned short port)
{
	int ret;
	struct addrinfo req;
	struct addrinfo *ainfo;
	struct addrinfo *ainfo_save;
	int sock;
	char port_str[BUFSIZ];

	memset(&req, 0, sizeof(struct addrinfo));
	req.ai_flags = AI_PASSIVE;
	req.ai_family = AF_UNSPEC;
	req.ai_socktype = SOCK_STREAM;

	snprintf(port_str, sizeof(port_str), "%d", port);

	ret = getaddrinfo(hostname, port_str, &req, &ainfo);

	if (ret != 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL, "getaddrinfo failed: %s",
			     gai_strerror(ret));
		exit(1);
	}

	ainfo_save = ainfo;

	do {
		if (ainfo->ai_family != AF_INET && ainfo->ai_family != AF_INET6)
			continue;

		sock = socket(ainfo->ai_family, ainfo->ai_socktype,
			      ainfo->ai_protocol);
		if (sock < 0)
			continue;

		sockopt_v6only(ainfo->ai_family, sock);
		sockopt_reuseaddr(sock);
		sockopt_reuseport(sock);
		set_cloexec(sock);

		ret = bind(sock, ainfo->ai_addr, ainfo->ai_addrlen);
		if (ret < 0) {
			close(sock); /* Avoid sd leak. */
			continue;
		}

		ret = listen(sock, 3);
		if (ret < 0) {
			close(sock); /* Avoid sd leak. */
			continue;
		}

		bmp_serv_thread = thread_add_read(bm->master, bmp_accept,
					NULL, sock, NULL);

	} while ((ainfo = ainfo->ai_next) != NULL);

	freeaddrinfo(ainfo_save);
}

void bgp_bmp_init()
{
	bmp_serv_sock("localhost", 60000);
}


