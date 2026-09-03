// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra mlag header.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 */
#ifndef __ZEBRA_MLAG_H__
#define __ZEBRA_MLAG_H__

#include "mlag.h"
#include "zclient.h"
#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZEBRA_MLAG_BUF_LIMIT 32768
#define ZEBRA_MLAG_LEN_SIZE 4

extern uint8_t mlag_wr_buffer[ZEBRA_MLAG_BUF_LIMIT];
extern uint8_t mlag_rd_buffer[ZEBRA_MLAG_BUF_LIMIT];

static inline void zebra_mlag_reset_read_buffer(void)
{
	memset(mlag_wr_buffer, 0, ZEBRA_MLAG_BUF_LIMIT);
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

#define HOOKS_DECLARE
#include "lib/hooks_begin.h"
#include "zebra/zebra_mlag_hooks.h"
#include "lib/hooks_end.h"

#ifdef __cplusplus
}
#endif

#endif
