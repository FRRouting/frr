/*
 * BFD daemon adapter header
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
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

#ifndef _BFDD_H_
#define _BFDD_H_

#include <json-c/json.h>

#include "bfdd/bfdctl.h"

#include "openbsd-queue.h"
#include "thread.h"

/*
 * Control socket functions
 */
typedef int (*bfd_control_recv_cb)(struct bfd_control_msg *, bool *, void *);

int bfd_control_init(void);
uint16_t bfd_control_send(int sd, enum bc_msg_type bmt, const void *data,
			  size_t datalen);
int bfd_control_recv(int sd, bfd_control_recv_cb cb, void *arg);


/*
 * Control socket command building
 */
struct json_object *bfd_ctrl_new_json(void);
void bfd_ctrl_add_peer(struct json_object *msg, struct bfd_peer_cfg *bpc);


/*
 * Utilities functions
 */
const char *satostr(struct sockaddr_any *sa);
int strtosa(const char *addr, struct sockaddr_any *sa);
int sa_cmp(const struct sockaddr_any *sa, const struct sockaddr_any *san);


/*
 * JSON helpers to build queries.
 */
int json_object_add_string(struct json_object *jo, const char *key,
			   const char *str);
int json_object_add_bool(struct json_object *jo, const char *key, bool boolean);
int json_object_add_int(struct json_object *jo, const char *key, int64_t value);

#endif /* _BFDD_H_ */
