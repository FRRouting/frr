/*
 * Zebra API server.
 * Portions:
 *   Copyright (C) 1997-1999  Kunihiro Ishiguro
 *   Copyright (C) 2015-2018  Cumulus Networks, Inc.
 *   et al.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

/* clang-format off */
#include <errno.h>                /* for errno */
#include <netinet/in.h>           /* for sockaddr_in */
#include <stdint.h>               /* for uint8_t */
#include <stdio.h>                /* for snprintf */
#include <sys/socket.h>           /* for sockaddr_storage, AF_UNIX, accept... */
#include <sys/stat.h>             /* for umask, mode_t */
#include <sys/un.h>               /* for sockaddr_un */
#include <time.h>                 /* for NULL, tm, gmtime, time_t */
#include <unistd.h>               /* for close, unlink, ssize_t */

#include "lib/buffer.h"           /* for BUFFER_EMPTY, BUFFER_ERROR, BUFFE... */
#include "lib/command.h"          /* for vty, install_element, CMD_SUCCESS... */
#include "lib/hook.h"             /* for DEFINE_HOOK, DEFINE_KOOH, hook_call */
#include "lib/linklist.h"         /* for ALL_LIST_ELEMENTS_RO, ALL_LIST_EL... */
#include "lib/libfrr.h"           /* for frr_zclient_addr */
#include "lib/log.h"              /* for zlog_warn, zlog_debug, safe_strerror */
#include "lib/memory.h"           /* for MTYPE_TMP, XCALLOC, XFREE */
#include "lib/monotime.h"         /* for monotime, ONE_DAY_SECOND, ONE_WEE... */
#include "lib/network.h"          /* for set_nonblocking */
#include "lib/privs.h"            /* for zebra_privs_t, ZPRIVS_LOWER, ZPRI... */
#include "lib/route_types.h"      /* for ZEBRA_ROUTE_MAX */
#include "lib/sockopt.h"          /* for setsockopt_so_recvbuf, setsockopt... */
#include "lib/sockunion.h"        /* for sockopt_reuseaddr, sockopt_reuseport */
#include "lib/stream.h"           /* for STREAM_SIZE, stream (ptr only), ... */
#include "lib/thread.h"           /* for thread (ptr only), THREAD_ARG, ... */
#include "lib/vrf.h"              /* for vrf_info_lookup, VRF_DEFAULT */
#include "lib/vty.h"              /* for vty_out, vty (ptr only) */
#include "lib/zassert.h"          /* for assert */
#include "lib/zclient.h"          /* for zmsghdr, ZEBRA_HEADER_SIZE, ZEBRA... */

#include "zebra/debug.h"          /* for various debugging macros */
#include "zebra/rib.h"            /* for rib_score_proto */
#include "zebra/zapi_msg.h"       /* for zserv_handle_commands */
#include "zebra/zebra_vrf.h"      /* for zebra_vrf_lookup_by_id, zvrf */
#include "zebra/zserv.h"          /* for zserv */
/* clang-format on */

/* Event list of zebra. */
enum event { ZEBRA_READ, ZEBRA_WRITE };
/* privileges */
extern struct zebra_privs_t zserv_privs;
/* post event into client */
static void zebra_event(struct zserv *client, enum event event);


/* Public interface --------------------------------------------------------- */

int zebra_server_send_message(struct zserv *client, struct stream *msg)
{
	stream_fifo_push(client->obuf_fifo, msg);
	zebra_event(client, ZEBRA_WRITE);
	return 0;
}

/* Lifecycle ---------------------------------------------------------------- */

/* Hooks for client connect / disconnect */
DEFINE_HOOK(zapi_client_connect, (struct zserv *client), (client));
DEFINE_KOOH(zapi_client_close, (struct zserv *client), (client));

/* free zebra client information. */
static void zebra_client_free(struct zserv *client)
{
	hook_call(zapi_client_close, client);

	/* Close file descriptor. */
	if (client->sock) {
		unsigned long nroutes;

		close(client->sock);
		nroutes = rib_score_proto(client->proto, client->instance);
		zlog_notice(
			"client %d disconnected. %lu %s routes removed from the rib",
			client->sock, nroutes,
			zebra_route_string(client->proto));
		client->sock = -1;
	}

	/* Free stream buffers. */
	if (client->ibuf_work)
		stream_free(client->ibuf_work);
	if (client->obuf_work)
		stream_free(client->obuf_work);
	if (client->ibuf_fifo)
		stream_fifo_free(client->ibuf_fifo);
	if (client->obuf_fifo)
		stream_fifo_free(client->obuf_fifo);
	if (client->wb)
		buffer_free(client->wb);

	/* Release threads. */
	if (client->t_read)
		thread_cancel(client->t_read);
	if (client->t_write)
		thread_cancel(client->t_write);
	if (client->t_suicide)
		thread_cancel(client->t_suicide);

	/* Free bitmaps. */
	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++)
		for (int i = 0; i < ZEBRA_ROUTE_MAX; i++)
			vrf_bitmap_free(client->redist[afi][i]);

	vrf_bitmap_free(client->redist_default);
	vrf_bitmap_free(client->ifinfo);
	vrf_bitmap_free(client->ridinfo);

	XFREE(MTYPE_TMP, client);
}

/*
 * Called from client thread to terminate itself.
 */
static void zebra_client_close(struct zserv *client)
{
	listnode_delete(zebrad.client_list, client);
	zebra_client_free(client);
}

/* Make new client. */
static void zebra_client_create(int sock)
{
	struct zserv *client;
	int i;
	afi_t afi;

	client = XCALLOC(MTYPE_TMP, sizeof(struct zserv));

	/* Make client input/output buffer. */
	client->sock = sock;
	client->ibuf_fifo = stream_fifo_new();
	client->obuf_fifo = stream_fifo_new();
	client->ibuf_work = stream_new(ZEBRA_MAX_PACKET_SIZ);
	client->obuf_work = stream_new(ZEBRA_MAX_PACKET_SIZ);
	client->wb = buffer_new(0);

	/* Set table number. */
	client->rtm_table = zebrad.rtm_table_default;

	client->connect_time = monotime(NULL);
	/* Initialize flags */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			client->redist[afi][i] = vrf_bitmap_init();
	client->redist_default = vrf_bitmap_init();
	client->ifinfo = vrf_bitmap_init();
	client->ridinfo = vrf_bitmap_init();

	/* by default, it's not a synchronous client */
	client->is_synchronous = 0;

	/* Add this client to linked list. */
	listnode_add(zebrad.client_list, client);

	zebra_vrf_update_all(client);

	hook_call(zapi_client_connect, client);

	/* start read loop */
	zebra_event(client, ZEBRA_READ);
}

static int zserv_delayed_close(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);

	client->t_suicide = NULL;
	zebra_client_close(client);
	return 0;
}

/*
 * Log zapi message to zlog.
 *
 * errmsg (optional)
 *    Debugging message
 *
 * msg
 *    The message
 *
 * hdr (optional)
 *    The message header
 */
static void zserv_log_message(const char *errmsg, struct stream *msg,
			      struct zmsghdr *hdr)
{
	zlog_debug("Rx'd ZAPI message");
	if (errmsg)
		zlog_debug("%s", errmsg);
	if (hdr) {
		zlog_debug(" Length: %d", hdr->length);
		zlog_debug("Command: %s", zserv_command_string(hdr->command));
		zlog_debug("    VRF: %u", hdr->vrf_id);
	}
	zlog_hexdump(msg->data, STREAM_READABLE(msg));
}

static int zserv_flush_data(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);

	client->t_write = NULL;
	if (client->t_suicide) {
		zebra_client_close(client);
		return -1;
	}
	switch (buffer_flush_available(client->wb, client->sock)) {
	case BUFFER_ERROR:
		zlog_warn(
			"%s: buffer_flush_available failed on zserv client fd %d, closing",
			__func__, client->sock);
		zebra_client_close(client);
		client = NULL;
		break;
	case BUFFER_PENDING:
		client->t_write = NULL;
		thread_add_write(zebrad.master, zserv_flush_data, client,
				 client->sock, &client->t_write);
		break;
	case BUFFER_EMPTY:
		break;
	}

	if (client)
		client->last_write_time = monotime(NULL);
	return 0;
}

/*
 * Write a single packet.
 */
static int zserv_write(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);
	struct stream *msg;
	int writerv;

	if (client->t_suicide)
		return -1;

	if (client->is_synchronous)
		return 0;

	msg = stream_fifo_pop(client->obuf_fifo);
	stream_set_getp(msg, 0);
	client->last_write_cmd = stream_getw_from(msg, 6);

	writerv = buffer_write(client->wb, client->sock, STREAM_DATA(msg),
			       stream_get_endp(msg));

	stream_free(msg);

	switch (writerv) {
	case BUFFER_ERROR:
		zlog_warn(
			"%s: buffer_write failed to zserv client fd %d, closing",
			__func__, client->sock);
		/*
		 * Schedule a delayed close since many of the functions that
		 * call this one do not check the return code. They do not
		 * allow for the possibility that an I/O error may have caused
		 * the client to be deleted.
		 */
		client->t_suicide = NULL;
		thread_add_event(zebrad.master, zserv_delayed_close, client, 0,
				 &client->t_suicide);
		return -1;
	case BUFFER_EMPTY:
		THREAD_OFF(client->t_write);
		break;
	case BUFFER_PENDING:
		thread_add_write(zebrad.master, zserv_flush_data, client,
				 client->sock, &client->t_write);
		break;
	}

	if (client->obuf_fifo->count)
		zebra_event(client, ZEBRA_WRITE);

	client->last_write_time = monotime(NULL);
	return 0;
}

#if defined(HANDLE_ZAPI_FUZZING)
static void zserv_write_incoming(struct stream *orig, uint16_t command)
{
	char fname[MAXPATHLEN];
	struct stream *copy;
	int fd = -1;

	copy = stream_dup(orig);
	stream_set_getp(copy, 0);

	zserv_privs.change(ZPRIVS_RAISE);
	snprintf(fname, MAXPATHLEN, "%s/%u", DAEMON_VTY_DIR, command);
	fd = open(fname, O_CREAT | O_WRONLY | O_EXCL, 0644);
	stream_flush(copy, fd);
	close(fd);
	zserv_privs.change(ZPRIVS_LOWER);
	stream_free(copy);
}
#endif

static int zserv_process_messages(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);
	struct zebra_vrf *zvrf;
	struct zmsghdr hdr;
	struct stream *msg;
	bool hdrvalid;

	do {
		msg = stream_fifo_pop(client->ibuf_fifo);

		/* break if out of messages */
		if (!msg)
			continue;

		/* read & check header */
		hdrvalid = zapi_parse_header(msg, &hdr);
		if (!hdrvalid && IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV) {
			const char *emsg = "Message has corrupt header";
			zserv_log_message(emsg, msg, NULL);
		}
		if (!hdrvalid)
			continue;

		hdr.length -= ZEBRA_HEADER_SIZE;
		/* lookup vrf */
		zvrf = zebra_vrf_lookup_by_id(hdr.vrf_id);
		if (!zvrf && IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV) {
			const char *emsg = "Message specifies unknown VRF";
			zserv_log_message(emsg, msg, &hdr);
		}
		if (!zvrf)
			continue;

		/* process commands */
		zserv_handle_commands(client, &hdr, msg, zvrf);

	} while (msg);

	return 0;
}

/* Handler of zebra service request. */
static int zserv_read(struct thread *thread)
{
	int sock;
	struct zserv *client;
	size_t already;
#if defined(HANDLE_ZAPI_FUZZING)
	int packets = 1;
#else
	int packets = zebrad.packets_to_process;
#endif
	/* Get thread data.  Reset reading thread because I'm running. */
	sock = THREAD_FD(thread);
	client = THREAD_ARG(thread);

	if (client->t_suicide) {
		zebra_client_close(client);
		return -1;
	}

	while (packets) {
		struct zmsghdr hdr;
		ssize_t nb;
		bool hdrvalid;
		char errmsg[256];

		already = stream_get_endp(client->ibuf_work);

		/* Read length and command (if we don't have it already). */
		if (already < ZEBRA_HEADER_SIZE) {
			nb = stream_read_try(client->ibuf_work, sock,
					     ZEBRA_HEADER_SIZE - already);
			if ((nb == 0 || nb == -1) && IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("connection closed socket [%d]",
					   sock);
			if ((nb == 0 || nb == -1))
				goto zread_fail;
			if (nb != (ssize_t)(ZEBRA_HEADER_SIZE - already)) {
				/* Try again later. */
				break;
			}
			already = ZEBRA_HEADER_SIZE;
		}

		/* Reset to read from the beginning of the incoming packet. */
		stream_set_getp(client->ibuf_work, 0);

		/* Fetch header values */
		hdrvalid = zapi_parse_header(client->ibuf_work, &hdr);

		if (!hdrvalid) {
			snprintf(errmsg, sizeof(errmsg),
				 "%s: Message has corrupt header", __func__);
			zserv_log_message(errmsg, client->ibuf_work, NULL);
			goto zread_fail;
		}

		/* Validate header */
		if (hdr.marker != ZEBRA_HEADER_MARKER
		    || hdr.version != ZSERV_VERSION) {
			snprintf(
				errmsg, sizeof(errmsg),
				"Message has corrupt header\n%s: socket %d version mismatch, marker %d, version %d",
				__func__, sock, hdr.marker, hdr.version);
			zserv_log_message(errmsg, client->ibuf_work, &hdr);
			goto zread_fail;
		}
		if (hdr.length < ZEBRA_HEADER_SIZE) {
			snprintf(
				errmsg, sizeof(errmsg),
				"Message has corrupt header\n%s: socket %d message length %u is less than header size %d",
				__func__, sock, hdr.length, ZEBRA_HEADER_SIZE);
			zserv_log_message(errmsg, client->ibuf_work, &hdr);
			goto zread_fail;
		}
		if (hdr.length > STREAM_SIZE(client->ibuf_work)) {
			snprintf(
				errmsg, sizeof(errmsg),
				"Message has corrupt header\n%s: socket %d message length %u exceeds buffer size %lu",
				__func__, sock, hdr.length,
				(unsigned long)STREAM_SIZE(client->ibuf_work));
			goto zread_fail;
		}

		/* Read rest of data. */
		if (already < hdr.length) {
			nb = stream_read_try(client->ibuf_work, sock,
					     hdr.length - already);
			if ((nb == 0 || nb == -1) && IS_ZEBRA_DEBUG_EVENT)
				zlog_debug(
					"connection closed [%d] when reading zebra data",
					sock);
			if ((nb == 0 || nb == -1))
				goto zread_fail;
			if (nb != (ssize_t)(hdr.length - already)) {
				/* Try again later. */
				break;
			}
		}

#if defined(HANDLE_ZAPI_FUZZING)
		zserv_write_incoming(client->ibuf_work, command);
#endif

		/* Debug packet information. */
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("zebra message comes from socket [%d]",
				   sock);

		if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
			zserv_log_message(NULL, client->ibuf_work, &hdr);

		client->last_read_time = monotime(NULL);
		client->last_read_cmd = hdr.command;

		stream_set_getp(client->ibuf_work, 0);
		struct stream *msg = stream_dup(client->ibuf_work);

		stream_fifo_push(client->ibuf_fifo, msg);

		if (client->t_suicide)
			goto zread_fail;

		--packets;
		stream_reset(client->ibuf_work);
	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("Read %d packets",
			   zebrad.packets_to_process - packets);

	/* Schedule job to process those packets */
	thread_add_event(zebrad.master, &zserv_process_messages, client, 0,
			 NULL);

	/* Reschedule ourselves */
	zebra_event(client, ZEBRA_READ);

	return 0;

zread_fail:
	zebra_client_close(client);
	return -1;
}

static void zebra_event(struct zserv *client, enum event event)
{
	switch (event) {
	case ZEBRA_READ:
		thread_add_read(zebrad.master, zserv_read, client, client->sock,
				&client->t_read);
		break;
	case ZEBRA_WRITE:
		thread_add_write(zebrad.master, zserv_write, client,
				 client->sock, &client->t_write);
		break;
	}
}

/* Accept code of zebra server socket. */
static int zebra_accept(struct thread *thread)
{
	int accept_sock;
	int client_sock;
	struct sockaddr_in client;
	socklen_t len;

	accept_sock = THREAD_FD(thread);

	/* Reregister myself. */
	thread_add_read(zebrad.master, zebra_accept, NULL, accept_sock, NULL);

	len = sizeof(struct sockaddr_in);
	client_sock = accept(accept_sock, (struct sockaddr *)&client, &len);

	if (client_sock < 0) {
		zlog_warn("Can't accept zebra socket: %s",
			  safe_strerror(errno));
		return -1;
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(client_sock);

	/* Create new zebra client. */
	zebra_client_create(client_sock);

	return 0;
}

/* Make zebra server socket, wiping any existing one (see bug #403). */
void zebra_zserv_socket_init(char *path)
{
	int ret;
	int sock;
	mode_t old_mask;
	struct sockaddr_storage sa;
	socklen_t sa_len;

	if (!frr_zclient_addr(&sa, &sa_len, path))
		/* should be caught in zebra main() */
		return;

	/* Set umask */
	old_mask = umask(0077);

	/* Make UNIX domain socket. */
	sock = socket(sa.ss_family, SOCK_STREAM, 0);
	if (sock < 0) {
		zlog_warn("Can't create zserv socket: %s",
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		return;
	}

	if (sa.ss_family != AF_UNIX) {
		sockopt_reuseaddr(sock);
		sockopt_reuseport(sock);
	} else {
		struct sockaddr_un *suna = (struct sockaddr_un *)&sa;
		if (suna->sun_path[0])
			unlink(suna->sun_path);
	}

	zserv_privs.change(ZPRIVS_RAISE);
	setsockopt_so_recvbuf(sock, 1048576);
	setsockopt_so_sendbuf(sock, 1048576);
	zserv_privs.change(ZPRIVS_LOWER);

	if (sa.ss_family != AF_UNIX && zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");

	ret = bind(sock, (struct sockaddr *)&sa, sa_len);
	if (ret < 0) {
		zlog_warn("Can't bind zserv socket on %s: %s", path,
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		close(sock);
		return;
	}
	if (sa.ss_family != AF_UNIX && zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");

	ret = listen(sock, 5);
	if (ret < 0) {
		zlog_warn("Can't listen to zserv socket %s: %s", path,
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		close(sock);
		return;
	}

	umask(old_mask);

	thread_add_read(zebrad.master, zebra_accept, NULL, sock, NULL);
}

#define ZEBRA_TIME_BUF 32
static char *zserv_time_buf(time_t *time1, char *buf, int buflen)
{
	struct tm *tm;
	time_t now;

	assert(buf != NULL);
	assert(buflen >= ZEBRA_TIME_BUF);
	assert(time1 != NULL);

	if (!*time1) {
		snprintf(buf, buflen, "never   ");
		return (buf);
	}

	now = monotime(NULL);
	now -= *time1;
	tm = gmtime(&now);

	if (now < ONE_DAY_SECOND)
		snprintf(buf, buflen, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min,
			 tm->tm_sec);
	else if (now < ONE_WEEK_SECOND)
		snprintf(buf, buflen, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour,
			 tm->tm_min);
	else
		snprintf(buf, buflen, "%02dw%dd%02dh", tm->tm_yday / 7,
			 tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
	return buf;
}

static void zebra_show_client_detail(struct vty *vty, struct zserv *client)
{
	char cbuf[ZEBRA_TIME_BUF], rbuf[ZEBRA_TIME_BUF];
	char wbuf[ZEBRA_TIME_BUF], nhbuf[ZEBRA_TIME_BUF], mbuf[ZEBRA_TIME_BUF];

	vty_out(vty, "Client: %s", zebra_route_string(client->proto));
	if (client->instance)
		vty_out(vty, " Instance: %d", client->instance);
	vty_out(vty, "\n");

	vty_out(vty, "------------------------ \n");
	vty_out(vty, "FD: %d \n", client->sock);
	vty_out(vty, "Route Table ID: %d \n", client->rtm_table);

	vty_out(vty, "Connect Time: %s \n",
		zserv_time_buf(&client->connect_time, cbuf, ZEBRA_TIME_BUF));
	if (client->nh_reg_time) {
		vty_out(vty, "Nexthop Registry Time: %s \n",
			zserv_time_buf(&client->nh_reg_time, nhbuf,
				       ZEBRA_TIME_BUF));
		if (client->nh_last_upd_time)
			vty_out(vty, "Nexthop Last Update Time: %s \n",
				zserv_time_buf(&client->nh_last_upd_time, mbuf,
					       ZEBRA_TIME_BUF));
		else
			vty_out(vty, "No Nexthop Update sent\n");
	} else
		vty_out(vty, "Not registered for Nexthop Updates\n");

	vty_out(vty, "Last Msg Rx Time: %s \n",
		zserv_time_buf(&client->last_read_time, rbuf, ZEBRA_TIME_BUF));
	vty_out(vty, "Last Msg Tx Time: %s \n",
		zserv_time_buf(&client->last_write_time, wbuf, ZEBRA_TIME_BUF));
	if (client->last_read_time)
		vty_out(vty, "Last Rcvd Cmd: %s \n",
			zserv_command_string(client->last_read_cmd));
	if (client->last_write_time)
		vty_out(vty, "Last Sent Cmd: %s \n",
			zserv_command_string(client->last_write_cmd));
	vty_out(vty, "\n");

	vty_out(vty, "Type        Add        Update     Del \n");
	vty_out(vty, "================================================== \n");
	vty_out(vty, "IPv4        %-12d%-12d%-12d\n", client->v4_route_add_cnt,
		client->v4_route_upd8_cnt, client->v4_route_del_cnt);
	vty_out(vty, "IPv6        %-12d%-12d%-12d\n", client->v6_route_add_cnt,
		client->v6_route_upd8_cnt, client->v6_route_del_cnt);
	vty_out(vty, "Redist:v4   %-12d%-12d%-12d\n", client->redist_v4_add_cnt,
		0, client->redist_v4_del_cnt);
	vty_out(vty, "Redist:v6   %-12d%-12d%-12d\n", client->redist_v6_add_cnt,
		0, client->redist_v6_del_cnt);
	vty_out(vty, "Connected   %-12d%-12d%-12d\n", client->ifadd_cnt, 0,
		client->ifdel_cnt);
	vty_out(vty, "BFD peer    %-12d%-12d%-12d\n", client->bfd_peer_add_cnt,
		client->bfd_peer_upd8_cnt, client->bfd_peer_del_cnt);
	vty_out(vty, "Interface Up Notifications: %d\n", client->ifup_cnt);
	vty_out(vty, "Interface Down Notifications: %d\n", client->ifdown_cnt);
	vty_out(vty, "VNI add notifications: %d\n", client->vniadd_cnt);
	vty_out(vty, "VNI delete notifications: %d\n", client->vnidel_cnt);
	vty_out(vty, "L3-VNI add notifications: %d\n", client->l3vniadd_cnt);
	vty_out(vty, "L3-VNI delete notifications: %d\n", client->l3vnidel_cnt);
	vty_out(vty, "MAC-IP add notifications: %d\n", client->macipadd_cnt);
	vty_out(vty, "MAC-IP delete notifications: %d\n", client->macipdel_cnt);

	vty_out(vty, "\n");
	return;
}

static void zebra_show_client_brief(struct vty *vty, struct zserv *client)
{
	char cbuf[ZEBRA_TIME_BUF], rbuf[ZEBRA_TIME_BUF];
	char wbuf[ZEBRA_TIME_BUF];

	vty_out(vty, "%-8s%12s %12s%12s%8d/%-8d%8d/%-8d\n",
		zebra_route_string(client->proto),
		zserv_time_buf(&client->connect_time, cbuf, ZEBRA_TIME_BUF),
		zserv_time_buf(&client->last_read_time, rbuf, ZEBRA_TIME_BUF),
		zserv_time_buf(&client->last_write_time, wbuf, ZEBRA_TIME_BUF),
		client->v4_route_add_cnt + client->v4_route_upd8_cnt,
		client->v4_route_del_cnt,
		client->v6_route_add_cnt + client->v6_route_upd8_cnt,
		client->v6_route_del_cnt);
}

struct zserv *zebra_find_client(uint8_t proto, unsigned short instance)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client)) {
		if (client->proto == proto && client->instance == instance)
			return client;
	}

	return NULL;
}

/* This command is for debugging purpose. */
DEFUN (show_zebra_client,
       show_zebra_client_cmd,
       "show zebra client",
       SHOW_STR
       ZEBRA_STR
       "Client information\n")
{
	struct listnode *node;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zebra_show_client_detail(vty, client);

	return CMD_SUCCESS;
}

/* This command is for debugging purpose. */
DEFUN (show_zebra_client_summary,
       show_zebra_client_summary_cmd,
       "show zebra client summary",
       SHOW_STR
       ZEBRA_STR
       "Client information brief\n"
       "Brief Summary\n")
{
	struct listnode *node;
	struct zserv *client;

	vty_out(vty,
		"Name    Connect Time    Last Read  Last Write  IPv4 Routes       IPv6 Routes    \n");
	vty_out(vty,
		"--------------------------------------------------------------------------------\n");

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zebra_show_client_brief(vty, client);

	vty_out(vty, "Routes column shows (added+updated)/deleted\n");
	return CMD_SUCCESS;
}

#if defined(HANDLE_ZAPI_FUZZING)
void zserv_read_file(char *input)
{
	int fd;
	struct zserv *client = NULL;
	struct thread t;

	zebra_client_create(-1);
	client = zebrad.client_list->head->data;
	t.arg = client;

	fd = open(input, O_RDONLY | O_NONBLOCK);
	t.u.fd = fd;

	zebra_client_read(&t);

	close(fd);
}
#endif

void zserv_init(void)
{
	/* Client list init. */
	zebrad.client_list = list_new();
	zebrad.client_list->del = (void (*)(void *))zebra_client_free;

	install_element(ENABLE_NODE, &show_zebra_client_cmd);
	install_element(ENABLE_NODE, &show_zebra_client_summary_cmd);
}
