/*
 * BFD daemon adapter header
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
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

#ifndef _BFDD_H_
#define _BFDD_H_

#include "bfdd/bfdctl.h"

#include "json.h"
#include "openbsd-queue.h"
#include "thread.h"

/*
 * Control socket functions
 */
#define BFDD_ADAPTER_CSOCK_TIMEOUT (4000)

#ifdef BFD_DEBUG
#define BFDD_JSON_CONV_OPTIONS (JSON_C_TO_STRING_PRETTY)
#else
#define BFDD_JSON_CONV_OPTIONS (0)
#endif

typedef int (*bfd_control_recv_cb)(struct bfd_control_msg *, bool *, void *);
typedef int (*bfd_reconfigure_cb)(int, void *);

int bfd_control_init(const char *path);
uint16_t bfd_control_send(int sd, enum bc_msg_type bmt, const void *data,
			  size_t datalen);
int bfd_control_recv(int sd, bfd_control_recv_cb cb, void *arg);

/* Client-side API (for BGP/OSPF/etc...) */
struct bfdd_adapter_ctx {
	/* BFD daemon control socket. */
	char bac_ctlpath[256];
	int bac_csock;
	struct thread *bac_threcv;
	struct thread *bac_thinit;

	/* Daemon master thread. */
	struct thread_master *bac_master;

	/* Callback: what to do when receiving a notification. */
	bfd_control_recv_cb bac_read;
	void *bac_read_arg;

	/* Callback for daemon reconfiguration. */
	bfd_reconfigure_cb bac_reconfigure;
	void *bac_reconfigure_arg;
};

void bfd_adapter_init(struct bfdd_adapter_ctx *bac);
int bfd_control_call(struct bfdd_adapter_ctx *bac, enum bc_msg_type bmt,
		     const void *data, size_t datalen);


/*
 * Control socket command building
 */
struct json_object *bfd_ctrl_new_json(void);
void bfd_ctrl_add_peer(struct json_object *msg, struct bfd_peer_cfg *bpc);
void bfd_ctrl_add_peer_bylabel(struct json_object *msg,
			       struct bfd_peer_cfg *bpc);


/*
 * Utilities functions
 */
const char *satostr(struct sockaddr_any *sa);
int strtosa(const char *addr, struct sockaddr_any *sa);
int sa_cmp(const struct sockaddr_any *sa, const struct sockaddr_any *san);
void integer2timestr(uint64_t time, char *buf, size_t buflen);
const char *diag2str(uint8_t diag);


/*
 * JSON helpers to build queries.
 */
int json_object_add_string(struct json_object *jo, const char *key,
			   const char *str);
int json_object_add_bool(struct json_object *jo, const char *key, bool boolean);
int json_object_add_int(struct json_object *jo, const char *key, int64_t value);


/*
 * JSON helpers to parse queries/response.
 */
enum bfd_response_status {
	BRS_UNKNOWN = 0,
	BRS_OK = 1,
	BRS_ERROR = 2,
};

struct bfdd_response {
	enum bfd_response_status br_status;
	char br_message[256];
};

int bfd_response_parse(const char *json, struct bfdd_response *br);

#endif /* _BFDD_H_ */
