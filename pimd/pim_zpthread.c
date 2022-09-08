/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

#include <zebra.h>
#include <lib/log.h>
#include <lib/lib_errors.h>

#include "pimd.h"
#include "pim_instance.h"
#include "pim_mlag.h"
#include "pim_zebra.h"

extern struct zclient *zclient;

#define PIM_MLAG_POST_LIMIT 100

int32_t mlag_bulk_cnt;

static void pim_mlag_zebra_fill_header(enum mlag_msg_type msg_type)
{
	uint32_t fill_msg_type = msg_type;
	uint16_t data_len;
	uint16_t msg_cnt = 1;

	if (msg_type == MLAG_MSG_NONE)
		return;

	switch (msg_type) {
	case MLAG_REGISTER:
	case MLAG_DEREGISTER:
		data_len = sizeof(struct mlag_msg);
		break;
	case MLAG_MROUTE_ADD:
		data_len = sizeof(struct mlag_mroute_add);
		fill_msg_type = MLAG_MROUTE_ADD_BULK;
		break;
	case MLAG_MROUTE_DEL:
		data_len = sizeof(struct mlag_mroute_del);
		fill_msg_type = MLAG_MROUTE_DEL_BULK;
		break;
	default:
		data_len = 0;
		break;
	}

	stream_reset(router->mlag_stream);
	/* ADD Hedaer */
	stream_putl(router->mlag_stream, fill_msg_type);
	/*
	 * In case of Bulk actual size & msg_cnt will be updated
	 * just before writing onto zebra
	 */
	stream_putw(router->mlag_stream, data_len);
	stream_putw(router->mlag_stream, msg_cnt);

	if (PIM_DEBUG_MLAG)
		zlog_debug(":%s: msg_type: %d/%d len %d",
			   __func__, msg_type, fill_msg_type, data_len);
}

static void pim_mlag_zebra_flush_buffer(void)
{
	uint32_t msg_type;

	/* Stream had bulk messages update the Hedaer */
	if (mlag_bulk_cnt > 1) {
		/*
		 * No need to reset the pointer, below api reads from data[0]
		 */
		STREAM_GETL(router->mlag_stream, msg_type);
		if (msg_type == MLAG_MROUTE_ADD_BULK) {
			stream_putw_at(
				router->mlag_stream, 4,
				(mlag_bulk_cnt * sizeof(struct mlag_mroute_add)));
			stream_putw_at(router->mlag_stream, 6, mlag_bulk_cnt);
		} else if (msg_type == MLAG_MROUTE_DEL_BULK) {
			stream_putw_at(
				router->mlag_stream, 4,
				(mlag_bulk_cnt * sizeof(struct mlag_mroute_del)));
			stream_putw_at(router->mlag_stream, 6, mlag_bulk_cnt);
		} else {
			flog_err(EC_LIB_ZAPI_ENCODE,
				"unknown bulk message type %d bulk_count %d",
				msg_type, mlag_bulk_cnt);
			stream_reset(router->mlag_stream);
			mlag_bulk_cnt = 0;
			return;
		}
	}

	zclient_send_mlag_data(zclient, router->mlag_stream);
stream_failure:
	stream_reset(router->mlag_stream);
	mlag_bulk_cnt = 0;
}

/*
 * Only ROUTE add & Delete will be bulked.
 * Buffer will be flushed, when
 * 1) there were no messages in the queue
 * 2) Curr_msg_type != prev_msg_type
 */

static void pim_mlag_zebra_check_for_buffer_flush(uint32_t curr_msg_type,
						  uint32_t prev_msg_type)
{
	/* First Message, keep bulking */
	if (prev_msg_type == MLAG_MSG_NONE) {
		mlag_bulk_cnt = 1;
		return;
	}

	/*msg type is route add & delete, keep bulking */
	if (curr_msg_type == prev_msg_type
	    && (curr_msg_type == MLAG_MROUTE_ADD
		|| curr_msg_type == MLAG_MROUTE_DEL)) {
		mlag_bulk_cnt++;
		return;
	}

	pim_mlag_zebra_flush_buffer();
}

/*
 * Thsi thread reads the clients data from the Gloabl queue and encodes with
 * protobuf and pass on to the MLAG socket.
 */
static void pim_mlag_zthread_handler(struct thread *event)
{
	struct stream *read_s;
	uint32_t wr_count = 0;
	uint32_t prev_msg_type = MLAG_MSG_NONE;
	uint32_t curr_msg_type = MLAG_MSG_NONE;

	router->zpthread_mlag_write = NULL;
	wr_count = stream_fifo_count_safe(router->mlag_fifo);

	if (PIM_DEBUG_MLAG)
		zlog_debug(":%s: Processing MLAG write, %d messages in queue",
			   __func__, wr_count);

	if (wr_count == 0)
		return;

	for (wr_count = 0; wr_count < PIM_MLAG_POST_LIMIT; wr_count++) {
		/* FIFO is empty,wait for teh message to be add */
		if (stream_fifo_count_safe(router->mlag_fifo) == 0)
			break;

		read_s = stream_fifo_pop_safe(router->mlag_fifo);
		if (!read_s) {
			zlog_debug(":%s: Got a NULL Messages, some thing wrong",
				   __func__);
			break;
		}
		STREAM_GETL(read_s, curr_msg_type);
		/*
		 * Check for Buffer Overflow,
		 * MLAG Can't process more than 'PIM_MLAG_BUF_LIMIT' bytes
		 */
		if (router->mlag_stream->endp + read_s->endp + ZEBRA_HEADER_SIZE
		    > MLAG_BUF_LIMIT)
			pim_mlag_zebra_flush_buffer();

		pim_mlag_zebra_check_for_buffer_flush(curr_msg_type,
						      prev_msg_type);

		/*
		 * First message to Buffer, fill the Header
		 */
		if (router->mlag_stream->endp == 0)
			pim_mlag_zebra_fill_header(curr_msg_type);

		/*
		 * add the data now
		 */
		stream_put(router->mlag_stream, read_s->data + read_s->getp,
			   read_s->endp - read_s->getp);

		stream_free(read_s);
		prev_msg_type = curr_msg_type;
	}

stream_failure:
	/*
	 * we are here , because
	 * 1. Queue might be empty
	 * 2. we crossed the max Q Read limit
	 * In any acse flush the buffer towards zebra
	 */
	pim_mlag_zebra_flush_buffer();

	if (wr_count >= PIM_MLAG_POST_LIMIT)
		pim_mlag_signal_zpthread();
}


int pim_mlag_signal_zpthread(void)
{
	if (router->master) {
		if (PIM_DEBUG_MLAG)
			zlog_debug(":%s: Scheduling PIM MLAG write Thread",
				   __func__);
		thread_add_event(router->master, pim_mlag_zthread_handler, NULL,
				 0, &router->zpthread_mlag_write);
	}
	return (0);
}
