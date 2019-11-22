/*
 * This is an implementation of MLAG Functionality
 *
 * Module name: Zebra MLAG
 *
 * Author: sathesh Kumar karra <sathk@cumulusnetworks.com>
 *
 * Copyright (C) 2019 Cumulus Networks http://www.cumulusnetworks.com
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
#include "zebra.h"

#include "hook.h"
#include "module.h"
#include "thread.h"
#include "frr_pthread.h"
#include "libfrr.h"
#include "version.h"
#include "network.h"

#include "lib/stream.h"

#include "zebra/debug.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_mlag.h"
#include "zebra/zebra_mlag_private.h"

#include <sys/un.h>


/*
 * This file will have platform specific apis to communicate with MCLAG.
 *
 */

#ifdef HAVE_CUMULUS

static struct thread_master *zmlag_master;
static int mlag_socket;

static int zebra_mlag_connect(struct thread *thread);
static int zebra_mlag_read(struct thread *thread);

/*
 * Write the data to MLAGD
 */
int zebra_mlag_private_write_data(uint8_t *data, uint32_t len)
{
	int rc = 0;

	if (IS_ZEBRA_DEBUG_MLAG) {
		zlog_debug("%s: Writing %d length Data to clag", __func__, len);
		zlog_hexdump(data, len);
	}
	rc = write(mlag_socket, data, len);
	return rc;
}

static void zebra_mlag_sched_read(void)
{
	thread_add_read(zmlag_master, zebra_mlag_read, NULL, mlag_socket,
			&zrouter.mlag_info.t_read);
}

static int zebra_mlag_read(struct thread *thread)
{
	uint32_t *msglen;
	uint32_t h_msglen;
	uint32_t tot_len, curr_len = mlag_rd_buf_offset;

	/*
	 * Received message in sock_stream looks like below
	 * | len-1 (4 Bytes) | payload-1 (len-1) |
	 *   len-2 (4 Bytes) | payload-2 (len-2) | ..
	 *
	 * Idea is read one message completely, then process, until message is
	 * read completely, keep on reading from the socket
	 */
	if (curr_len < ZEBRA_MLAG_LEN_SIZE) {
		ssize_t data_len;

		data_len = read(mlag_socket, mlag_rd_buffer + curr_len,
				ZEBRA_MLAG_LEN_SIZE - curr_len);
		if (data_len == 0 || data_len == -1) {
			if (IS_ZEBRA_DEBUG_MLAG)
				zlog_debug("MLAG connection closed socket : %d",
					   mlag_socket);
			close(mlag_socket);
			zebra_mlag_handle_process_state(MLAG_DOWN);
			return -1;
		}
		mlag_rd_buf_offset += data_len;
		if (data_len != (ssize_t)ZEBRA_MLAG_LEN_SIZE - curr_len) {
			/* Try again later */
			zebra_mlag_sched_read();
			return 0;
		}
		curr_len = ZEBRA_MLAG_LEN_SIZE;
	}

	/* Get the actual packet length */
	msglen = (uint32_t *)mlag_rd_buffer;
	h_msglen = ntohl(*msglen);

	/* This will be the actual length of the packet */
	tot_len = h_msglen + ZEBRA_MLAG_LEN_SIZE;

	if (curr_len < tot_len) {
		ssize_t data_len;

		data_len = read(mlag_socket, mlag_rd_buffer + curr_len,
				tot_len - curr_len);
		if (data_len == 0 || data_len == -1) {
			if (IS_ZEBRA_DEBUG_MLAG)
				zlog_debug("MLAG connection closed socket : %d",
					   mlag_socket);
			close(mlag_socket);
			zebra_mlag_handle_process_state(MLAG_DOWN);
			return -1;
		}
		mlag_rd_buf_offset += data_len;
		if (data_len != (ssize_t)tot_len - curr_len) {
			/* Try again later */
			zebra_mlag_sched_read();
			return 0;
		}
	}

	if (IS_ZEBRA_DEBUG_MLAG) {
		zlog_debug("Received a MLAG Message from socket: %d, len:%u ",
			   mlag_socket, tot_len);
		zlog_hexdump(mlag_rd_buffer, tot_len);
	}

	tot_len -= ZEBRA_MLAG_LEN_SIZE;

	/* Process the packet */
	zebra_mlag_process_mlag_data(mlag_rd_buffer + ZEBRA_MLAG_LEN_SIZE,
				     tot_len);

	/* Register read thread. */
	zebra_mlag_reset_read_buffer();
	zebra_mlag_sched_read();
	return 0;
}

static int zebra_mlag_connect(struct thread *thread)
{
	struct sockaddr_un svr = {0};
	struct ucred ucred;
	socklen_t len = 0;

	/* Reset the Timer-running flag */
	zrouter.mlag_info.timer_running = false;

	svr.sun_family = AF_UNIX;
#define MLAG_SOCK_NAME "/var/run/clag-zebra.socket"
	strlcpy(svr.sun_path, MLAG_SOCK_NAME, sizeof(MLAG_SOCK_NAME) + 1);

	mlag_socket = socket(svr.sun_family, SOCK_STREAM, 0);
	if (mlag_socket < 0)
		return -1;

	if (connect(mlag_socket, (struct sockaddr *)&svr, sizeof(svr)) == -1) {
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug(
				"Unable to connect to %s try again in 10 secs",
				svr.sun_path);
		close(mlag_socket);
		zrouter.mlag_info.timer_running = true;
		thread_add_timer(zmlag_master, zebra_mlag_connect, NULL, 10,
				 &zrouter.mlag_info.t_read);
		return 0;
	}
	len = sizeof(struct ucred);
	ucred.pid = getpid();

	set_nonblocking(mlag_socket);
	setsockopt(mlag_socket, SOL_SOCKET, SO_PEERCRED, &ucred, len);

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: Connection with MLAG is established ",
			   __func__);

	thread_add_read(zmlag_master, zebra_mlag_read, NULL, mlag_socket,
			&zrouter.mlag_info.t_read);
	/*
	 * Connection is established with MLAGD, post to clients
	 */
	zebra_mlag_handle_process_state(MLAG_UP);
	return 0;
}

/*
 * Currently we are doing polling later we will look for better options
 */
void zebra_mlag_private_monitor_state(void)
{
	thread_add_event(zmlag_master, zebra_mlag_connect, NULL, 0,
			 &zrouter.mlag_info.t_read);
}

int zebra_mlag_private_open_channel(void)
{
	zmlag_master = zrouter.mlag_info.th_master;

	if (zrouter.mlag_info.connected == true) {
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug("%s: Zebra already connected to MLAGD",
				   __func__);
		return 0;
	}

	if (zrouter.mlag_info.timer_running == true) {
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug(
				"%s: Connection retry is in progress for MLAGD",
				__func__);
		return 0;
	}

	if (zrouter.mlag_info.clients_interested_cnt) {
		/*
		 * Connect only if any clients are showing interest
		 */
		thread_add_event(zmlag_master, zebra_mlag_connect, NULL, 0,
				 &zrouter.mlag_info.t_read);
	}
	return 0;
}

int zebra_mlag_private_close_channel(void)
{
	if (zmlag_master == NULL)
		return -1;

	if (zrouter.mlag_info.clients_interested_cnt) {
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug("%s: still %d clients are connected, skip",
				   __func__,
				   zrouter.mlag_info.clients_interested_cnt);
		return -1;
	}

	/*
	 * Post the De-register to MLAG, so that it can do necesasry cleanup
	 */
	zebra_mlag_send_deregister();

	return 0;
}

void zebra_mlag_private_cleanup_data(void)
{
	zmlag_master = NULL;
	zrouter.mlag_info.connected = false;
	zrouter.mlag_info.timer_running = false;

	close(mlag_socket);
}

#else  /*HAVE_CUMULUS */

int zebra_mlag_private_write_data(uint8_t *data, uint32_t len)
{
	return 0;
}

void zebra_mlag_private_monitor_state(void)
{
}

int zebra_mlag_private_open_channel(void)
{
	return 0;
}

int zebra_mlag_private_close_channel(void)
{
	return 0;
}

void zebra_mlag_private_cleanup_data(void)
{
}
#endif /*HAVE_CUMULUS*/
