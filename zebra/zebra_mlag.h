/* Zebra mlag header.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef __ZEBRA_MLAG_H__
#define __ZEBRA_MLAG_H__

#include "mlag.h"
#include "zclient.h"
#include "zebra/zserv.h"

#ifdef HAVE_PROTOBUF
#include "mlag/mlag.pb-c.h"
#endif

#define ZEBRA_MLAG_BUF_LIMIT 2048
#define ZEBRA_MLAG_LEN_SIZE 4

extern uint8_t mlag_wr_buffer[ZEBRA_MLAG_BUF_LIMIT];
extern uint8_t mlag_rd_buffer[ZEBRA_MLAG_BUF_LIMIT];
extern uint32_t mlag_rd_buf_offset;

static inline void zebra_mlag_reset_read_buffer(void)
{
	mlag_rd_buf_offset = 0;
}

enum zebra_mlag_state {
	MLAG_UP = 1,
	MLAG_DOWN = 2,
};

void zebra_mlag_init(void);
void zebra_mlag_terminate(void);
enum mlag_role zebra_mlag_get_role(void);
void zebra_mlag_client_register(ZAPI_HANDLER_ARGS);
void zebra_mlag_client_unregister(ZAPI_HANDLER_ARGS);
void zebra_mlag_forward_client_msg(ZAPI_HANDLER_ARGS);
void zebra_mlag_send_register(void);
void zebra_mlag_send_deregister(void);
void zebra_mlag_handle_process_state(enum zebra_mlag_state state);
void zebra_mlag_process_mlag_data(uint8_t *data, uint32_t len);
/*
 * ProtoBuffer Api's
 */
int zebra_mlag_protobuf_encode_client_data(struct stream *s,
					   uint32_t *msg_type);
int zebra_mlag_protobuf_decode_message(struct stream *s, uint8_t *data,
				       uint32_t len);
#endif
