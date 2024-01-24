// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Definitions for prescriptive topology module (PTM).
 * Copyright (C) 1998, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
 */

#ifndef _ZEBRA_PTM_H
#define _ZEBRA_PTM_H

extern const char ZEBRA_PTM_SOCK_NAME[];
#define ZEBRA_PTM_MAX_SOCKBUF 3200 /* 25B *128 ports */
#define ZEBRA_PTM_SEND_MAX_SOCKBUF 512

#define ZEBRA_PTM_BFD_CLIENT_FLAG_REG   (1 << 1) /* client registered with BFD */

#include "zebra/zserv.h"
#include "zebra/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Zebra ptm context block */
struct zebra_ptm_cb {
	int ptm_sock; /* ptm file descriptor. */

	struct buffer *wb; /* Buffer of data waiting to be written to ptm. */

	struct event *t_read;  /* Thread for read */
	struct event *t_write; /* Thread for write */
	struct event *t_timer; /* Thread for timer */

	char *out_data;
	char *in_data;
	int reconnect_time;

	int ptm_enable;
	int pid;
	uint8_t client_flags[ZEBRA_ROUTE_MAX];
};

#define ZEBRA_PTM_STATUS_DOWN 0
#define ZEBRA_PTM_STATUS_UP 1
#define ZEBRA_PTM_STATUS_UNKNOWN 2

/* For interface ptm-enable configuration. */
#define ZEBRA_IF_PTM_ENABLE_OFF    0
#define ZEBRA_IF_PTM_ENABLE_ON     1
#define ZEBRA_IF_PTM_ENABLE_UNSPEC 2

#define IS_BFD_ENABLED_PROTOCOL(protocol)                                      \
	((protocol) == ZEBRA_ROUTE_BGP || (protocol) == ZEBRA_ROUTE_OSPF ||    \
	 (protocol) == ZEBRA_ROUTE_OSPF6 || (protocol) == ZEBRA_ROUTE_ISIS ||  \
	 (protocol) == ZEBRA_ROUTE_PIM ||                                      \
	 (protocol) == ZEBRA_ROUTE_OPENFABRIC ||                               \
	 (protocol) == ZEBRA_ROUTE_STATIC || (protocol) == ZEBRA_ROUTE_RIP)

void zebra_ptm_init(void);
void zebra_ptm_finish(void);
void zebra_ptm_connect(struct event *t);
int zebra_ptm_get_enable_state(void);

#if HAVE_BFDD == 0
void zebra_global_ptm_enable(void);
void zebra_global_ptm_disable(void);
void zebra_if_ptm_enable(struct interface *ifp);
void zebra_if_ptm_disable(struct interface *ifp);
#endif

/* ZAPI message handlers */
void zebra_ptm_bfd_dst_register(ZAPI_HANDLER_ARGS);
void zebra_ptm_bfd_dst_deregister(ZAPI_HANDLER_ARGS);
void zebra_ptm_bfd_client_register(ZAPI_HANDLER_ARGS);
#if HAVE_BFDD > 0
void zebra_ptm_bfd_dst_replay(ZAPI_HANDLER_ARGS);
#endif /* HAVE_BFDD */

void zebra_ptm_show_status(struct vty *vty, json_object *json,
			   struct interface *ifp);
void zebra_ptm_if_init(struct zebra_if *zebra_ifp);
void zebra_ptm_if_set_ptm_state(struct interface *ifp,
				struct zebra_if *zebra_ifp);

#ifdef __cplusplus
}
#endif

#endif
